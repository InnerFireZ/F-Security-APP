#!/usr/bin/env python3
"""
VNC Network Scanner & Credential Tester
========================================
Scans a subnet for VNC services, tests provided passwords,
captures screenshots of successful sessions, and exports results.

WARNING: For AUTHORIZED penetration testing and security auditing ONLY.
Unauthorized access to computer systems is illegal (e.g., CFAA, Computer Misuse Act).
You must have explicit written permission to test any system you do not own.

Usage:
  python3 vnc_scanner.py --subnet 192.168.1.0/24 --passwords pass1 pass2 --output results.txt
  python3 vnc_scanner.py --subnet 10.0.0.0/24 --password-file passwords.txt --ports 5900 5901 5902
  python3 vnc_scanner.py --subnet 192.168.1.0/24 --no-password  # test for no-auth VNC
"""

import argparse
import asyncio
import ipaddress
import io
import os
import socket
import struct
import sys
import time
import numpy as np
import traceback
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ─── Dependency checks ────────────────────────────────────────────────────────

try:
    import nmap
except ImportError:
    print("[!] python-nmap not installed. Run: pip3 install python-nmap")
    sys.exit(1)

try:
    from PIL import Image
except ImportError:
    print("[!] Pillow not installed. Run: pip3 install Pillow")
    sys.exit(1)

# Check that Xvfb and xtightvncviewer are available for screenshots
SCREENSHOTS_OK = True   # pure-Python RFB reader — no external tools needed

# ─── Constants ────────────────────────────────────────────────────────────────

BANNER_TIMEOUT  = 3      # seconds for RFB banner read
AUTH_TIMEOUT    = 6      # seconds for full auth handshake
SCREENSHOT_WAIT = 5      # seconds to wait for desktop to render
VNC_MAGIC       = b"RFB "

DEFAULT_PORTS = [5900, 5901, 5902, 5903, 5904, 5800, 5801]

# Auth result codes
AUTH_OK           = 0
AUTH_FAILED       = 1
AUTH_TOOMANY      = 2
AUTH_NO_CREDS     = "NO_AUTH"  # security type 1 = no authentication needed

# Security type IDs
SEC_NONE    = 1
SEC_VNC     = 2

# ─── VNC DES Authentication (raw, no external VNC lib needed) ─────────────────

def _reverse_bits(byte: int) -> int:
    """Reverse the 8 bits of a byte (VNC DES key quirk)."""
    result = 0
    for _ in range(8):
        result = (result << 1) | (byte & 1)
        byte >>= 1
    return result

def _make_vnc_des_key(password: str) -> bytes:
    """
    VNC DES key derivation:
    - Truncate/pad password to 8 bytes
    - Reverse bits of each byte (VNC-specific quirk)
    """
    raw = password.encode("latin-1", errors="replace")[:8].ljust(8, b"\x00")
    return bytes(_reverse_bits(b) for b in raw)

def _des_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt data using DES ECB (16 bytes = 2 DES blocks)."""
    try:
        from unicrypto.symmetric import DES, MODE_ECB  # available via aardwolf dep
        cipher = DES(key, MODE_ECB)
        return cipher.encrypt(data)
    except ImportError:
        pass
    # Fallback: pyDES (bundled with pyVNC on Kali)
    try:
        from pyVNC.pyDes import des, ECB, PAD_NORMAL
        cipher = des(key, ECB, pad=None, padmode=PAD_NORMAL)
        return cipher.encrypt(data)
    except ImportError:
        pass
    # Last resort: pycryptodome
    try:
        from Crypto.Cipher import DES
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(data)
    except ImportError:
        raise RuntimeError(
            "No DES implementation found. Install pycryptodome: pip3 install pycryptodome"
        )

# ─── Raw VNC protocol helper ─────────────────────────────────────────────────

class VNCProbeResult:
    __slots__ = ("host", "port", "is_vnc", "server_version",
                 "security_types", "auth_status", "auth_msg",
                 "screenshot_path", "error")

    def __init__(self, host, port):
        self.host           = host
        self.port           = port
        self.is_vnc         = False
        self.server_version = None
        self.security_types = []
        self.auth_status    = None   # AUTH_OK / AUTH_FAILED / AUTH_TOOMANY / "NO_AUTH" / None
        self.auth_msg       = ""
        self.screenshot_path = None
        self.error          = None


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket, raise on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def verify_and_auth_vnc(host: str, port: int, password: str | None,
                        timeout: float = AUTH_TIMEOUT) -> VNCProbeResult:
    """
    Connect to host:port and:
      1. Validate the RFB banner (eliminates false positives)
      2. Negotiate security type
      3. Attempt authentication with the given password (or no-auth)
    Returns a VNCProbeResult.
    """
    result = VNCProbeResult(host, port)
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        # ── Step 1: Read server banner ────────────────────────────────────────
        banner = _recv_exact(sock, 12)
        if not banner.startswith(VNC_MAGIC):
            result.error = f"Not VNC (banner: {banner[:12]!r})"
            return result

        result.is_vnc = True
        result.server_version = banner.decode("ascii", errors="replace").strip()

        # ── Step 2: Send client version ───────────────────────────────────────
        # Prefer 3.8; fall back to 3.3 for older servers
        srv_minor = int(banner[8:11])
        client_ver = b"RFB 003.008\n" if srv_minor >= 7 else b"RFB 003.003\n"
        sock.sendall(client_ver)

        # ── Step 3: Negotiate security ────────────────────────────────────────
        if srv_minor >= 7:
            # RFB 3.7+ sends number of security types then the list
            num_types_raw = _recv_exact(sock, 1)
            num_types = num_types_raw[0]
            if num_types == 0:
                # Server sent error reason
                reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
                reason = _recv_exact(sock, reason_len).decode("utf-8", errors="replace")
                result.error = f"Server rejected connection: {reason}"
                return result
            sec_types = list(_recv_exact(sock, num_types))
            result.security_types = sec_types
        else:
            # RFB 3.3: server dictates security type (4 bytes)
            sec_type_raw = _recv_exact(sock, 4)
            sec_type = struct.unpack("!I", sec_type_raw)[0]
            if sec_type == 0:
                reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
                reason = _recv_exact(sock, reason_len).decode("utf-8", errors="replace")
                result.error = f"Server rejected connection: {reason}"
                return result
            sec_types = [sec_type]
            result.security_types = sec_types

        # ── Step 4: Select security type ──────────────────────────────────────
        # Priority: try SEC_NONE first if no password, else SEC_VNC
        if password is None:
            if SEC_NONE in sec_types:
                chosen = SEC_NONE
            elif SEC_VNC in sec_types:
                # Can't auth without a password
                result.auth_status = AUTH_FAILED
                result.auth_msg = "Server requires password but none provided"
                return result
            else:
                result.auth_status = AUTH_FAILED
                result.auth_msg = f"Unsupported security types: {sec_types}"
                return result
        else:
            if SEC_VNC in sec_types:
                chosen = SEC_VNC
            elif SEC_NONE in sec_types:
                chosen = SEC_NONE  # No auth needed even though password was given
            else:
                result.auth_status = AUTH_FAILED
                result.auth_msg = f"Unsupported security types: {sec_types}"
                return result

        if srv_minor >= 7:
            sock.sendall(bytes([chosen]))  # send chosen security type

        # ── Step 5: Security handshake ────────────────────────────────────────
        if chosen == SEC_NONE:
            # RFB 3.8 adds SecurityResult even for no-auth
            if srv_minor >= 8:
                result_raw = _recv_exact(sock, 4)
                sec_result = struct.unpack("!I", result_raw)[0]
                if sec_result == 0:
                    result.auth_status = AUTH_NO_CREDS
                    result.auth_msg = "No authentication required"
                else:
                    try:
                        reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
                        reason = _recv_exact(sock, min(reason_len, 256)).decode("utf-8", errors="replace")
                    except Exception:
                        reason = "Unknown"
                    result.auth_status = AUTH_FAILED
                    result.auth_msg = f"Security result failed: {reason}"
            else:
                result.auth_status = AUTH_NO_CREDS
                result.auth_msg = "No authentication required (RFB 3.3)"
            return result

        elif chosen == SEC_VNC:
            # Receive 16-byte DES challenge
            challenge = _recv_exact(sock, 16)

            # Encrypt challenge with VNC DES key
            key = _make_vnc_des_key(password)
            response = _des_ecb_encrypt(key, challenge)
            sock.sendall(response)

            # Read SecurityResult (4 bytes)
            result_raw = _recv_exact(sock, 4)
            sec_result = struct.unpack("!I", result_raw)[0]

            if sec_result == AUTH_OK:
                result.auth_status = AUTH_OK
                result.auth_msg = f"Authentication succeeded with password: {password!r}"
            elif sec_result == AUTH_TOOMANY:
                result.auth_status = AUTH_TOOMANY
                result.auth_msg = "Too many authentication failures (server locked)"
            else:
                # sec_result == 1 (failed); RFB 3.8 sends reason
                result.auth_status = AUTH_FAILED
                reason = "Bad password"
                if srv_minor >= 8:
                    try:
                        reason_len = struct.unpack("!I", _recv_exact(sock, 4))[0]
                        reason = _recv_exact(sock, min(reason_len, 256)).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                result.auth_msg = reason
            return result

        else:
            result.auth_status = AUTH_FAILED
            result.auth_msg = f"Unhandled security type {chosen}"
            return result

    except socket.timeout:
        result.error = "Connection timed out"
        return result
    except ConnectionRefusedError:
        result.error = "Connection refused"
        return result
    except Exception as e:
        result.error = str(e)
        return result
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ─── Screenshot capture: pure-Python raw RFB framebuffer reader ──────────────
#
# Directly reads the VNC framebuffer over TCP.  No X11, no external tools,
# no scrollbars, no window chrome, no colour-depth surprises.
#
# Protocol flow (read-only — nothing is written to the target desktop):
#   auth  →  ClientInit (shared=1)  →  ServerInit  →  SetPixelFormat
#   →  SetEncodings (RAW only)  →  FramebufferUpdateRequest (full, non-incremental)
#   →  read FramebufferUpdate rectangles  →  save PNG via PIL
#
# Pixel format requested: 32 bpp, RGB, little-endian
#   r_shift=0  → byte 0 = Red
#   g_shift=8  → byte 1 = Green
#   b_shift=16 → byte 2 = Blue
#   byte 3     = unused padding

_ENC_RAW         =    0
_ENC_DESKTOP_SZ  = -223   # pseudo: server reports new desktop dimensions
_ENC_LAST_RECT   = -224   # pseudo: signals end of rectangle list early


def _buf_to_rgb_png(img_buf: bytearray, w: int, h: int,
                    bpp_bytes: int, r_byte: int, g_byte: int, b_byte: int,
                    out_path: str):
    """Convert a raw VNC pixel buffer to an RGB PNG using numpy channel indexing."""
    arr = np.frombuffer(bytes(img_buf), dtype=np.uint8).reshape(h, w, bpp_bytes)
    rgb = np.stack([arr[:, :, r_byte], arr[:, :, g_byte], arr[:, :, b_byte]], axis=2)
    Image.fromarray(rgb.astype(np.uint8), "RGB").save(out_path, "PNG")


def _recv_update(sock, img_buf: bytearray, stride: int, bpp_bytes: int):
    """Read one FramebufferUpdate, blit RAW rects into img_buf. Returns (rects_blitted, w, h)."""
    w = stride // bpp_bytes
    h = len(img_buf) // stride
    rects_blitted = 0
    while True:
        msg_type = _recv_exact(sock, 1)[0]
        if msg_type == 0:           # FramebufferUpdate
            _recv_exact(sock, 1)    # padding
            n_rects = struct.unpack("!H", _recv_exact(sock, 2))[0]
            for _ in range(n_rects):
                rx, ry, rw, rh = struct.unpack("!HHHH", _recv_exact(sock, 8))
                enc = struct.unpack("!i", _recv_exact(sock, 4))[0]
                if enc == _ENC_RAW:
                    n_bytes  = rw * rh * bpp_bytes
                    pix_data = _recv_exact(sock, n_bytes)
                    row_sz   = rw * bpp_bytes
                    for row in range(rh):
                        dst = (ry + row) * stride + rx * bpp_bytes
                        src = row * row_sz
                        img_buf[dst : dst + row_sz] = pix_data[src : src + row_sz]
                    rects_blitted += 1
                elif enc == _ENC_DESKTOP_SZ:
                    w, h   = rw, rh
                    stride = w * bpp_bytes
                    img_buf[:] = bytearray(h * stride)
                elif enc == _ENC_LAST_RECT:
                    break
                # other pseudo-encodings: no payload, skip
            return rects_blitted, w, h
        elif msg_type == 2:         # Bell — ignore
            pass
        elif msg_type == 3:         # ServerCutText — drain & discard
            _recv_exact(sock, 3)
            clen = struct.unpack("!I", _recv_exact(sock, 4))[0]
            if 0 < clen < 10_000_000:
                _recv_exact(sock, clen)
        else:
            raise RuntimeError(f"Unexpected VNC message type {msg_type}")


def take_screenshot(host: str, port: int, password: str | None,
                    out_path: str, wait: float = SCREENSHOT_WAIT) -> tuple[bool, str]:
    """
    Capture VNC desktop by reading the raw RFB framebuffer directly.
    Pure read-only — auth + SetEncodings + FramebufferUpdateRequest only.
    No keyboard/mouse events sent. Works from multiple threads (no shared state).

    Key insight: most VNC servers send an all-black initial full-frame, then
    populate real content on subsequent incremental updates.  We drain the
    blank frame first, then poll until we get non-black pixel data.
    """
    fb_timeout = max(wait + 15.0, 30.0)
    sock       = None
    w = h      = 0
    img_buf    = bytearray(0)
    stride     = 0
    bpp_bytes  = 4
    r_byte = 2; g_byte = 1; b_byte = 0   # sensible defaults (BGRX)

    try:
        sock = socket.create_connection((host, port), timeout=fb_timeout)
        sock.settimeout(fb_timeout)

        # ── RFB Handshake ─────────────────────────────────────────────────
        banner = _recv_exact(sock, 12)
        if not banner.startswith(b"RFB "):
            return False, "Not a VNC server"
        srv_minor = int(banner[8:11])
        sock.sendall(b"RFB 003.008\n" if srv_minor >= 7 else b"RFB 003.003\n")

        if srv_minor >= 7:
            n = _recv_exact(sock, 1)[0]
            if n == 0:
                rlen = struct.unpack("!I", _recv_exact(sock, 4))[0]
                return False, _recv_exact(sock, rlen).decode("utf-8", errors="replace")
            sec_types = list(_recv_exact(sock, n))
        else:
            st = struct.unpack("!I", _recv_exact(sock, 4))[0]
            if st == 0:
                rlen = struct.unpack("!I", _recv_exact(sock, 4))[0]
                return False, _recv_exact(sock, rlen).decode("utf-8", errors="replace")
            sec_types = [st]

        # ── Authentication ─────────────────────────────────────────────────
        if password and SEC_VNC in sec_types:
            if srv_minor >= 7:
                sock.sendall(bytes([SEC_VNC]))
            challenge = _recv_exact(sock, 16)
            key = _make_vnc_des_key(password)
            sock.sendall(_des_ecb_encrypt(key, challenge))
            if srv_minor >= 8:
                res = struct.unpack("!I", _recv_exact(sock, 4))[0]
                if res != 0:
                    try:
                        rlen = struct.unpack("!I", _recv_exact(sock, 4))[0]
                        reason = _recv_exact(sock, min(rlen, 256)).decode("utf-8", errors="replace")
                    except Exception:
                        reason = "Authentication failed"
                    return False, reason
        elif SEC_NONE in sec_types:
            if srv_minor >= 7:
                sock.sendall(bytes([SEC_NONE]))
            if srv_minor >= 8:
                res = struct.unpack("!I", _recv_exact(sock, 4))[0]
                if res != 0:
                    return False, "Server rejected no-auth"
        else:
            return False, "No compatible auth type"

        # ── ClientInit + ServerInit ────────────────────────────────────────
        sock.sendall(b"\x01")   # shared=1

        w = struct.unpack("!H", _recv_exact(sock, 2))[0]
        h = struct.unpack("!H", _recv_exact(sock, 2))[0]
        pf = _recv_exact(sock, 16)   # server native pixel format
        nlen = struct.unpack("!I", _recv_exact(sock, 4))[0]
        _recv_exact(sock, nlen)       # desktop name (ignored)

        if w == 0 or h == 0:
            return False, f"Invalid desktop size {w}x{h}"

        # Derive PIL decoder from server shifts:
        # pf[10]=r_shift pf[11]=g_shift pf[12]=b_shift, each a multiple of 8
        # byte_index = shift // 8  (little-endian 32bpp)
        bpp_bytes = pf[0] // 8
        r_byte = pf[10] // 8   # byte index of Red channel in each pixel
        g_byte = pf[11] // 8   # byte index of Green
        b_byte = pf[12] // 8   # byte index of Blue

        stride  = w * bpp_bytes
        img_buf = bytearray(h * stride)

        # ── SetEncodings: RAW only ────────────────────────────────────────
        sock.sendall(struct.pack("!BBHi", 2, 0, 1, _ENC_RAW))

        # ── Step 1: full (non-incremental) — drains the initial blank frame ─
        sock.sendall(struct.pack("!BBHHHH", 3, 0, 0, 0, w, h))
        _, w, h = _recv_update(sock, img_buf, stride, bpp_bytes)
        stride = w * bpp_bytes

        # ── Step 2: incremental polls — wait for real desktop content ─────
        max_polls = max(int(wait), 6)
        for _ in range(max_polls):
            sock.sendall(struct.pack("!BBHHHH", 3, 1, 0, 0, w, h))
            rects, w, h = _recv_update(sock, img_buf, stride, bpp_bytes)
            stride = w * bpp_bytes
            if rects > 0 and any(img_buf):
                break
            time.sleep(0.5)

        if not any(img_buf):
            return False, "Desktop returned only black frames (session may be locked)"

        # ── Save PNG ──────────────────────────────────────────────────────
        _buf_to_rgb_png(img_buf, w, h, bpp_bytes, r_byte, g_byte, b_byte, out_path)
        return True, ""

    except socket.timeout:
        if any(img_buf) and w > 0 and h > 0:
            try:
                _buf_to_rgb_png(img_buf, w, h, bpp_bytes, r_byte, g_byte, b_byte, out_path)
                return True, "(partial — socket timeout mid-transfer)"
            except Exception:
                pass
        return False, "Timed out waiting for framebuffer"
    except Exception as e:
        return False, f"Screenshot error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

# ─── Port scanner (nmap-based) ────────────────────────────────────────────────

# Services that are definitively NOT VNC — skip them at the nmap layer.
# We rely on RFB banner verification for everything else (no false-negative risk).
_NON_VNC_SERVICES = frozenset([
    "ssh", "http", "https", "ftp", "smtp", "pop3", "imap",
    "telnet", "rdp", "ms-wbt-server", "smb", "netbios-ssn",
    "microsoft-ds", "mysql", "mssql", "postgresql", "oracle",
    "ldap", "kerberos", "ntp", "snmp", "dns", "mdns",
])


def scan_subnet(subnet: str, ports: list[int], nmap_timeout: int = 30,
                verbose: bool = True) -> list[tuple[str, int]]:
    """
    Discover open ports using a fast TCP connect scan (no -sV).
    We skip service-version detection entirely here — the RFB banner check
    in verify_and_auth_vnc() is the authoritative false-positive filter.

    Only ports whose nmap-reported service name is definitively non-VNC
    are dropped at this stage.
    """
    open_endpoints = []
    port_str = ",".join(str(p) for p in ports)

    nm = nmap.PortScanner()

    if verbose:
        print(f"[*] nmap TCP scan  →  {subnet}  ports {port_str}")
        print(f"    (skipping -sV to avoid host-timeout false-negatives)\n")

    # -sT : TCP connect (works without root; reliable across all networks)
    # --open: only return open ports
    # -T4 : aggressive timing (safe on LAN)
    # NO --host-timeout — let each host complete; nmap's own -T4 timing handles it
    # NO -sV  — service detection is slow and was killing results with tight timeouts
    args = f"-sT --open -T4 -p {port_str}"

    try:
        nm.scan(hosts=subnet, arguments=args)
    except nmap.PortScannerError as e:
        # Might be a permissions issue (e.g. SYN scan requested as non-root)
        print(f"[!] nmap error: {e}")
        print("[!] Retrying with explicit -sT …")
        try:
            nm.scan(hosts=subnet, arguments=f"-sT --open -T4 -p {port_str}")
        except Exception as e2:
            print(f"[!] nmap failed: {e2}")
            return open_endpoints

    all_hosts = nm.all_hosts()
    if verbose:
        print(f"[*] nmap found {len(all_hosts)} host(s) with candidate ports open\n")

    for host in all_hosts:
        if nm[host].state() != "up":
            continue
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_data = nm[host][proto][port]
                state   = port_data.get("state", "")
                name    = port_data.get("name", "").lower()
                product = port_data.get("product", "").lower()

                if state != "open":
                    continue

                # Drop only unambiguously non-VNC services (nmap's port-DB names).
                # Everything else goes to the RFB banner check.
                if name in _NON_VNC_SERVICES:
                    if not any(kw in product for kw in ("vnc", "rfb")):
                        if verbose:
                            print(f"  [-] {host}:{port} — skipped (nmap: {name})")
                        continue

                open_endpoints.append((host, port))
                if verbose:
                    hint = name or "unknown"
                    print(f"  [+] Candidate  {host}:{port}  [{hint}]")

    return open_endpoints


# ─── Core scan logic ──────────────────────────────────────────────────────────

def scan_one(host: str, port: int, passwords: list[str | None],
             screenshot_dir: str | None, verbose: bool,
             auth_timeout: float) -> list[VNCProbeResult]:
    """
    For a single (host, port): verify VNC service, then try each password.
    Returns a list of VNCProbeResult (one per tested credential).
    """
    results = []

    # ── 1. Quick banner check (no password) to confirm it's actually VNC ──
    probe = verify_and_auth_vnc(host, port, None, timeout=BANNER_TIMEOUT)
    if not probe.is_vnc:
        if verbose and probe.error:
            print(f"  [-] {host}:{port} — not VNC: {probe.error}")
        return []

    if verbose:
        print(f"  [~] {host}:{port} — VNC confirmed  "
              f"(version: {probe.server_version}, sec-types: {probe.security_types})")

    # ── 2. Check for no-auth access ───────────────────────────────────────
    if SEC_NONE in probe.security_types:
        r = verify_and_auth_vnc(host, port, None, timeout=auth_timeout)
        if r.auth_status == AUTH_NO_CREDS:
            if verbose:
                print(f"  [!!!] {host}:{port} — NO AUTH REQUIRED (open access!)")
            _maybe_screenshot(r, screenshot_dir, host, port, None, verbose)
            results.append(r)
            return results  # no point trying passwords if already open

    # ── 3. Try each password ──────────────────────────────────────────────
    for pwd in passwords:
        if pwd is None:
            continue

        r = verify_and_auth_vnc(host, port, pwd, timeout=auth_timeout)

        if r.auth_status == AUTH_OK:
            if verbose:
                print(f"  [+] {host}:{port} — SUCCESS with password: {pwd!r}")
            _maybe_screenshot(r, screenshot_dir, host, port, pwd, verbose)
            results.append(r)
            # Found a working password — no need to brute-force further
            # (comment next line out if you want to try ALL passwords anyway)
            break

        elif r.auth_status == AUTH_TOOMANY:
            if verbose:
                print(f"  [!] {host}:{port} — Server locked after too many attempts")
            results.append(r)
            break  # stop trying — server won't accept more attempts

        elif r.auth_status == AUTH_FAILED:
            if verbose:
                print(f"  [-] {host}:{port} — failed with {pwd!r}: {r.auth_msg}")

        elif r.error:
            if verbose:
                print(f"  [?] {host}:{port} — error: {r.error}")

    return results


def _maybe_screenshot(result: VNCProbeResult, screenshot_dir: str | None,
                      host: str, port: int, pwd: str | None, verbose: bool):
    """Attempt a screenshot and attach path to result."""
    if screenshot_dir is None:
        return
    if not SCREENSHOTS_OK:
        if verbose:
            print("  [!] Screenshots unavailable — need: Xvfb, xtightvncviewer, ImageMagick")
        return

    os.makedirs(screenshot_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"vnc_{host.replace(':', '_')}_{port}_{ts}.png"
    out_path = os.path.join(screenshot_dir, fname)

    if verbose:
        print(f"  [*] Taking screenshot → {out_path}")

    ok, err = take_screenshot(host, port, pwd, out_path)
    if ok:
        result.screenshot_path = out_path
        if verbose:
            print(f"  [*] Screenshot saved: {out_path}")
    else:
        if verbose:
            print(f"  [!] Screenshot failed: {err}")


# ─── Output / reporting ───────────────────────────────────────────────────────

def write_report(successes: list[VNCProbeResult], output_file: str,
                 subnet: str, passwords: list, start_time: datetime):
    """Write a human-readable + machine-parseable report."""
    end_time = datetime.now()
    duration = end_time - start_time

    lines = [
        "=" * 72,
        "  VNC SCAN RESULTS",
        "=" * 72,
        f"  Target Subnet : {subnet}",
        f"  Scan Started  : {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Scan Ended    : {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration      : {duration}",
        f"  Successes     : {len(successes)}",
        "=" * 72,
        "",
    ]

    if not successes:
        lines.append("  No successful authentications found.")
    else:
        lines.append("  SUCCESSFUL CONNECTIONS:")
        lines.append("")
        for r in successes:
            status_label = {
                AUTH_OK:      "AUTH_SUCCESS",
                AUTH_NO_CREDS: "NO_AUTH_REQUIRED",
            }.get(r.auth_status, str(r.auth_status))

            lines.append(f"  ┌─ {r.host}:{r.port}")
            lines.append(f"  │  Status       : {status_label}")
            lines.append(f"  │  VNC Version  : {r.server_version}")
            lines.append(f"  │  Security     : {r.security_types}")
            lines.append(f"  │  Auth Message : {r.auth_msg}")
            if r.screenshot_path:
                lines.append(f"  │  Screenshot   : {r.screenshot_path}")
            else:
                lines.append(f"  │  Screenshot   : (none taken)")
            lines.append(f"  └──────────────────────────────")
            lines.append("")

    lines += [
        "=" * 72,
        "  CSV FORMAT (host,port,status,version,screenshot)",
        "=" * 72,
    ]
    for r in successes:
        status_label = {
            AUTH_OK:      "AUTH_SUCCESS",
            AUTH_NO_CREDS: "NO_AUTH_REQUIRED",
        }.get(r.auth_status, str(r.auth_status))
        lines.append(
            f"{r.host},{r.port},{status_label},"
            f"{r.server_version},{r.screenshot_path or ''}"
        )

    report = "\n".join(lines) + "\n"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n[*] Report saved to: {output_file}")
    return report


# ─── Entry point ─────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="VNC subnet scanner with credential testing and screenshots",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Make subnet optional so interactive mode can fill it in
    p.add_argument("--subnet",
                   help="Target subnet or IP range in CIDR notation "
                        "(e.g. 192.168.1.0/24, 10.0.0.0/8). "
                        "Prompted interactively if omitted.")
    p.add_argument("--passwords", nargs="+", metavar="PASS",
                   help="One or more passwords to test")
    p.add_argument("--password-file", metavar="FILE",
                   help="File with one password per line")
    p.add_argument("--no-password", action="store_true",
                   help="Also test for VNC servers with no authentication required")
    p.add_argument("--ports", nargs="+", type=int, default=DEFAULT_PORTS,
                   metavar="PORT",
                   help=f"Ports to scan (default: {DEFAULT_PORTS})")
    p.add_argument("--output",   default="vnc_scan_results.txt",
                   help="Output text file path (default: vnc_scan_results.txt)")
    p.add_argument("--screenshots-dir", default="vnc_screenshots",
                   metavar="DIR",
                   help="Directory to store screenshots (default: vnc_screenshots). "
                        "Use --no-screenshots to disable.")
    p.add_argument("--no-screenshots", action="store_true",
                   help="Disable screenshot capture")
    p.add_argument("--screenshot-wait", type=float, default=SCREENSHOT_WAIT,
                   metavar="SEC",
                   help=f"Seconds to wait before screenshot (default: {SCREENSHOT_WAIT})")
    p.add_argument("--threads",  type=int, default=20,
                   help="Concurrent threads for credential testing (default: 20)")
    p.add_argument("--timeout",  type=float, default=AUTH_TIMEOUT,
                   help=f"Auth timeout per host in seconds (default: {AUTH_TIMEOUT})")
    p.add_argument("--nmap-timeout", type=int, default=30,
                   help="nmap per-host timeout in seconds for -sT scan (default: 30)")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-host verbose output")
    p.add_argument("--confirm", action="store_true",
                   help="Skip the authorization confirmation prompt")
    return p.parse_args()


def _interactive_banner():
    """Print the interactive-mode header."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║              VNC Network Scanner & Credential Tester         ║
║        Authorized Penetration Testing Tool — Kali Linux      ║
╚══════════════════════════════════════════════════════════════╝
""")


def _prompt_subnet() -> str:
    """Interactively prompt for and validate a subnet."""
    examples = "e.g. 192.168.1.0/24 · 10.0.0.0/8 · 172.16.0.0/16 · 192.168.1.5 (single host)"
    while True:
        raw = input(f"  [?] Target IP range / subnet ({examples}): ").strip()
        if not raw:
            print("      → Cannot be empty. Try again.")
            continue
        # Accept bare IP (treat as /32) or proper CIDR
        if "/" not in raw:
            raw = raw + "/32"
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return str(net)
        except ValueError:
            print(f"      → Invalid format: {raw!r}. Use CIDR notation like 192.168.1.0/24")


def _prompt_passwords() -> list:
    """
    Interactively prompt for passwords.
    Returns list of password strings (may include None for no-auth test).
    """
    passwords = []
    print()
    print("  Enter passwords to test (one per line).")
    print("  Press Enter on an empty line when done.")
    print("  Tips:")
    print("    • Type  NOAUTH  to also test servers with no authentication required")
    print("    • Type  FILE:<path>  to load passwords from a file")
    print("    • Common VNC defaults: password, 1234, admin, vnc, raspberry")
    print()

    while True:
        try:
            pwd = input("  Password (blank to finish): ")
        except EOFError:
            break

        if pwd == "":
            if not passwords:
                print("      → Enter at least one password (or NOAUTH).")
                continue
            break

        if pwd.upper() == "NOAUTH":
            if None not in passwords:
                passwords.append(None)
                print("      → Will test for no-auth VNC servers.")
            continue

        if pwd.upper().startswith("FILE:"):
            fpath = pwd[5:].strip()
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    loaded = [ln.rstrip("\n\r") for ln in f if ln.strip()]
                loaded = [p for p in loaded if p not in passwords]
                passwords.extend(loaded)
                print(f"      → Loaded {len(loaded)} password(s) from {fpath}")
            except FileNotFoundError:
                print(f"      → File not found: {fpath}")
            continue

        if pwd not in passwords:
            passwords.append(pwd)

    return passwords


def _prompt_options(args) -> dict:
    """Ask about optional settings (ports, screenshots, output file)."""
    print()
    # Ports
    port_input = input(
        f"  [?] Ports to scan (Enter for defaults {DEFAULT_PORTS}): "
    ).strip()
    ports = DEFAULT_PORTS
    if port_input:
        try:
            ports = [int(p.strip()) for p in port_input.replace(",", " ").split() if p.strip()]
            if not ports:
                ports = DEFAULT_PORTS
        except ValueError:
            print("      → Invalid port(s), using defaults.")
            ports = DEFAULT_PORTS

    # Screenshots
    scr_ans = input(
        "  [?] Take screenshots of successful sessions? [Y/n]: "
    ).strip().lower()
    take_screenshots = scr_ans not in ("n", "no")

    # Output file
    out_file = input(
        "  [?] Output file name [vnc_scan_results.txt]: "
    ).strip() or "vnc_scan_results.txt"

    return {
        "ports": ports,
        "take_screenshots": take_screenshots,
        "output": out_file,
    }


def main():
    args = parse_args()
    verbose = not args.quiet

    # ── Detect interactive mode (no subnet or no passwords given) ─────────
    interactive = (args.subnet is None) or (
        not args.passwords
        and not args.password_file
        and not args.no_password
    )

    if interactive:
        _interactive_banner()

    # ── Get subnet ────────────────────────────────────────────────────────
    subnet = args.subnet
    if subnet is None:
        subnet = _prompt_subnet()

    # ── Validate subnet ───────────────────────────────────────────────────
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        print(f"[!] Invalid subnet: {e}")
        sys.exit(1)

    # ── Build password list ───────────────────────────────────────────────
    passwords: list = []
    if args.no_password:
        passwords.append(None)

    if args.passwords:
        passwords.extend(args.passwords)

    if args.password_file:
        try:
            with open(args.password_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    pwd = line.rstrip("\n\r")
                    if pwd and pwd not in passwords:
                        passwords.append(pwd)
        except FileNotFoundError:
            print(f"[!] Password file not found: {args.password_file}")
            sys.exit(1)

    # Interactive password collection
    if not passwords:
        passwords = _prompt_passwords()

    if not passwords:
        print("[!] No passwords specified. Aborting.")
        sys.exit(1)

    # ── Interactive options ───────────────────────────────────────────────
    ports = args.ports
    output_file = args.output
    screenshot_dir = None if args.no_screenshots else args.screenshots_dir

    if interactive:
        opts = _prompt_options(args)
        ports = opts["ports"]
        output_file = opts["output"]
        if not opts["take_screenshots"]:
            screenshot_dir = None

    # Screenshots use pure-Python RFB — always available (PIL only)

    # ── Authorization reminder ────────────────────────────────────────────
    if not args.confirm:
        print("\n" + "=" * 60)
        print("  AUTHORIZATION REQUIRED")
        print("=" * 60)
        print(f"  You are about to scan: {subnet}")
        print("  Only proceed if you have explicit written authorization")
        print("  to test ALL systems in this subnet.")
        print("=" * 60)
        confirm = input("\n  Type 'yes' to confirm you are authorized: ").strip().lower()
        if confirm != "yes":
            print("Aborted.")
            sys.exit(0)
        print()

    # ── Phase 1: nmap scan ────────────────────────────────────────────────
    start_time = datetime.now()
    print(f"\n{'='*60}")
    print(f"  VNC Scanner — {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"[*] Subnet      : {subnet}")
    print(f"[*] Ports       : {ports}")
    print(f"[*] Passwords   : {len([p for p in passwords if p is not None])} password(s) + "
          f"{'no-auth test' if None in passwords else 'no no-auth test'}")
    print(f"[*] Output      : {output_file}")
    print(f"[*] Screenshots : {screenshot_dir or 'disabled'}")
    print()

    open_endpoints = scan_subnet(
        subnet, ports, nmap_timeout=args.nmap_timeout, verbose=verbose
    )

    if not open_endpoints:
        print("\n[*] No open VNC candidate ports found.")
        write_report([], output_file, subnet, passwords, start_time)
        return

    total = len(open_endpoints)
    print(f"\n[*] Found {total} candidate port(s). Verifying VNC + testing credentials …\n")

    # ── Phase 2: VNC validation + auth testing ────────────────────────────
    all_successes: list[VNCProbeResult] = []
    all_results: list[VNCProbeResult]   = []

    def worker(host_port):
        host, port = host_port
        return scan_one(
            host, port, passwords, screenshot_dir,
            verbose=verbose, auth_timeout=args.timeout
        )

    # Progress bar — stays pinned at the bottom while per-host messages scroll above.
    progress = tqdm(
        total=total,
        desc="Testing targets",
        unit="host",
        dynamic_ncols=True,
        leave=True,
        position=0,
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        postfix={"success": 0},
    )

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(worker, ep): ep for ep in open_endpoints}
        for future in as_completed(futures):
            ep = futures[future]
            try:
                results = future.result()
                all_results.extend(results)
                for r in results:
                    if r.auth_status in (AUTH_OK, AUTH_NO_CREDS):
                        all_successes.append(r)
                        # Print success line above the bar
                        tqdm.write(
                            f"  [✔] {r.host}:{r.port}  —  {r.auth_msg}"
                            + (f"  →  {r.screenshot_path}" if r.screenshot_path else "")
                        )
            except Exception as e:
                if verbose:
                    tqdm.write(f"  [!] Worker error for {ep}: {e}")
            finally:
                progress.set_postfix(success=len(all_successes), refresh=False)
                progress.update(1)

    progress.close()

    # ── Phase 3: Report ───────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — {len(all_successes)} successful connection(s)")
    print(f"{'='*60}\n")

    report = write_report(all_successes, output_file, subnet, passwords, start_time)
    print(report)


if __name__ == "__main__":
    main()
