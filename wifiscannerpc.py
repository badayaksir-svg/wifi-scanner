#!/usr/bin/env python3
"""
Wi-Fi Scanner + Handshake Capture + Bruteforce Demo
For Assignment Purpose Only
Works on Windows (basic scan) and Linux (full monitor mode)
"""

import subprocess
import time
import signal
import sys
import os
import platform
from itertools import product
import ctypes

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, RadioTap, EAPOL, wrpcap, conf
except ImportError:
    print("❌ scapy not installed!")
    print("   Run: pip install scapy")
    sys.exit(1)

# ================= CONFIG =================
SCAN_DURATION = 15
CAPTURE_DURATION = 60
OUTPUT_PCAP = "handshake.pcap"
INTERFACE = "wlan0"          # Change if needed on Linux

# Globals
STOP_SNIFFING = False
MONITOR_MODE_ACTIVE = False

# ────────────────────────────────────────────────

def is_admin():
    if platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0

def scan_wifi_windows():
    print("\n🔍 Scanning nearby Wi-Fi networks using netsh...")
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True, stderr=subprocess.STDOUT
        )
        print(output)
    except Exception as e:
        print(f"❌ netsh failed: {e}")
        print("   → Run PowerShell as Administrator + enable Location services")

def enable_monitor_mode(iface):
    global MONITOR_MODE_ACTIVE
    print(f"→ Enabling monitor mode on {iface}...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["iw", iface, "set", "monitor", "control"], check=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        MONITOR_MODE_ACTIVE = True
        print("✅ Monitor mode enabled!")
    except Exception:
        print("❌ Failed to enable monitor mode (run with sudo or use airmon-ng)")

def disable_monitor_mode(iface):
    global MONITOR_MODE_ACTIVE
    if MONITOR_MODE_ACTIVE:
        try:
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            subprocess.run(["iw", iface, "set", "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            MONITOR_MODE_ACTIVE = False
            print("✅ Monitor mode disabled")
        except:
            pass

def scan_wifi_linux(iface):
    networks = {}
    def handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3.upper()
            if bssid in networks: return
            ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore') or "<hidden>"
            signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "N/A"
            channel = getattr(pkt[RadioTap], "Channel", "N/A") if pkt.haslayer(RadioTap) else "N/A"
            networks[bssid] = {"ssid": ssid, "signal": signal, "channel": channel}
            print(f"Found → {ssid:<30} | {bssid} | Ch:{channel} | Sig:{signal}")

    print(f"\nScanning on {iface} for {SCAN_DURATION} seconds...\n")
    sniff(iface=iface, prn=handler, timeout=SCAN_DURATION, store=0)
    return networks

def capture_handshake(iface, target_bssid, target_ssid):
    packets = []
    count = 0
    def handler(pkt):
        nonlocal count
        if pkt.haslayer(EAPOL):
            count += 1
            packets.append(pkt)
            print(f"EAPOL packet #{count} captured")
            if count >= 4:
                print("✅ Full 4-way handshake captured!")
                return True
        return False

    print(f"\nCapturing handshake for {target_ssid} ({target_bssid})...")
    sniff(iface=iface, prn=handler, timeout=CAPTURE_DURATION, stop_filter=lambda x: False)
    
    if packets:
        wrpcap(OUTPUT_PCAP, packets)
        print(f"✅ Handshake saved to {OUTPUT_PCAP}")
    else:
        print("❌ No handshake captured")

# ================= BRUTEFORCE / DICTIONARY DEMO =================
def bruteforce_demo():
    print("\n" + "="*60)
    print("🔐 EDUCATIONAL BRUTEFORCE + DICTIONARY DEMO")
    print("   ONLY FOR YOUR OWN TEST NETWORK!")
    print("   This is a simulation - real cracking needs hashcat/aircrack-ng")
    print("="*60)

    ssid = input("\nEnter target SSID for demo: ").strip()
    mode = input("Choose (d)ictionary or (b)ruteforce numeric: ").strip().lower()

    if mode == "d":
        # Small demo wordlist (add more if you want)
        wordlist = ["123456", "password", "admin", "letmein", "qwerty", "welcome", 
                   "12345678", "abc123", "password123", "iloveyou"]
        print(f"\nTrying {len(wordlist)} common passwords...")
        for pwd in wordlist:
            print(f"Trying → {pwd}")
            time.sleep(0.4)  # simulate delay
            if pwd in ["123456", "password", "admin"]:   # Change this to your test password
                print(f"\n🎉 PASSWORD CRACKED: {pwd}")
                print(f"   Network: {ssid}")
                return
        print("❌ Password not in demo wordlist")

    elif mode == "b":
        length = int(input("Enter length to bruteforce (20 digits max recommended): "))
        if length > 20:
            print("Too long for demo (would take hours)")
            return
        chars = "0123456789"
        print(f"\nBruteforcing {length}-digit passwords...")
        for candidate in product(chars, repeat=length):
            pwd = "".join(candidate)
            print(f"Trying → {pwd}", end="\r")
            time.sleep(0.03)   # simulate real delay
            if pwd == "123456"[:length]:   # Change to your test password
                print(f"\n\n🎉 PASSWORD CRACKED: {pwd}")
                print(f"   Network: {ssid}")
                return
        print("❌ Not found in range")

    else:
        print("Invalid choice")

# ────────────────────────────────────────────────

def main():
    print("Wi-Fi Scanner + Handshake + Bruteforce Demo Tool")
    print("────────────────────────────────────────────────────")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Running as Admin: {is_admin()}\n")

    while True:
        print("\n1. Scan nearby Wi-Fi networks")
        print("2. Capture handshake (Linux only)")
        print("3. Bruteforce / Dictionary Demo (educational)")
        print("4. Exit")
        choice = input("\nEnter choice (1-4): ").strip()

        if choice == "1":
            if platform.system() == "Windows":
                scan_wifi_windows()
            else:
                networks = scan_wifi_linux(INTERFACE)
                if networks:
                    print("\nFound networks:")
                    for bssid, info in networks.items():
                        print(f"  {info['ssid']:<30} {bssid}  Ch:{info['channel']}  Sig:{info['signal']}")

        elif choice == "2":
            if platform.system() != "Linux":
                print("❌ Handshake capture only works on Linux with monitor mode")
                continue
            bssid = input("Enter target BSSID: ").strip()
            ssid = input("Enter target SSID: ").strip()
            capture_handshake(INTERFACE, bssid, ssid)

        elif choice == "3":
            bruteforce_demo()

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStopped by user.")
    except Exception as e:
        print(f"\nError: {e}")