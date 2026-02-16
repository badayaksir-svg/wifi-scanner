#!/usr/bin/env python3
import subprocess
import time
import signal
import sys
import os
from scapy.all import (
    sniff, Dot11, Dot11Beacon, Dot11Deauth, RadioTap, sendp, EAPOL, wrpcap, conf
)

# ================= CONFIG =================
INTERFACE = "wlan0"           # ← CHANGE THIS to your actual interface name!
SCAN_DURATION = 15            # seconds
CAPTURE_DURATION = 60         # seconds
OUTPUT_PCAP = "handshake.pcap"

# Global control
STOP_SNIFFING = False
MONITOR_MODE_ACTIVE = False
CAPTURED_PACKETS = []

def signal_handler(sig, frame):
    global STOP_SNIFFING
    print("\n[Ctrl+C] Stopping gracefully...")
    STOP_SNIFFING = True
    cleanup()

def cleanup():
    global MONITOR_MODE_ACTIVE
    if MONITOR_MODE_ACTIVE:
        print(f"→ Disabling monitor mode on {INTERFACE}...")
        try:
            subprocess.run(["ip", "link", "set", INTERFACE, "down"], check=True)
            subprocess.run(["iw", INTERFACE, "set", "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", INTERFACE, "up"], check=True)
            MONITOR_MODE_ACTIVE = False
            print("Monitor mode disabled.")
        except Exception as e:
            print(f"Warning: Could not disable monitor mode → {e}")

def enable_monitor_mode():
    global MONITOR_MODE_ACTIVE
    print(f"→ Trying to put {INTERFACE} into monitor mode...")
    try:
        subprocess.run(["ip", "link", "set", INTERFACE, "down"], check=True)
        subprocess.run(["iw", INTERFACE, "set", "monitor", "control"], check=True)
        subprocess.run(["ip", "link", "set", INTERFACE, "up"], check=True)
        MONITOR_MODE_ACTIVE = True
        print(f"Success: {INTERFACE} is now in monitor mode")
    except subprocess.CalledProcessError as e:
        print("\nERROR: Failed to enable monitor mode.")
        print("Common fixes:")
        print("  1. Run script with sudo")
        print("  2. Check interface name with 'iwconfig' or 'ip link'")
        print("  3. Make sure your Wi-Fi adapter supports monitor mode")
        print("  4. Try: sudo airmon-ng start wlan0   (if you have aircrack-ng)")
        sys.exit(1)
    except FileNotFoundError:
        print("ERROR: 'ip' or 'iw' command not found. Install them:")
        print("  sudo apt install iproute2 iw    (Ubuntu/Debian)")
        print("  sudo dnf install iproute iw     (Fedora)")
        sys.exit(1)

def scan_wifi():
    networks = {}  # bssid → info

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3.upper()
            if bssid in networks:
                return
            try:
                ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore').strip()
            except:
                ssid = "<hidden>"
            signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "N/A"
            channel = pkt[RadioTap].Channel if pkt.haslayer(RadioTap) else "N/A"
            crypto = pkt[Dot11Beacon].network_stats().get("crypto", "Unknown")

            networks[bssid] = {
                "ssid": ssid or "<hidden>",
                "channel": channel,
                "signal": signal,
                "crypto": ", ".join(crypto) if isinstance(crypto, set) else crypto
            }
            print(f"Found → {ssid:<30} | {bssid} | Ch: {channel} | Sig: {signal}")

    print(f"\nScanning on {INTERFACE} for {SCAN_DURATION} seconds...\n")
    try:
        sniff(iface=INTERFACE, prn=packet_handler, timeout=SCAN_DURATION, store=0)
    except Exception as e:
        print(f"\nSniffing failed: {e}")
        print("→ Did you enable monitor mode? Are you running as root?")

    if not networks:
        print("No networks found. Possible reasons:")
        print(" - No Wi-Fi activity nearby")
        print(" - Wrong channel / interface")
        print(" - Adapter not in monitor mode")

    return networks

def capture_handshake(target_bssid, target_ssid):
    global CAPTURED_PACKETS, STOP_SNIFFING
    CAPTURED_PACKETS = []
    eapol_count = 0

    def eapol_handler(pkt):
        nonlocal eapol_count
        if pkt.haslayer(EAPOL):
            eapol_count += 1
            CAPTURED_PACKETS.append(pkt)
            print(f"EAPOL packet captured ({eapol_count}/4+)")
            if eapol_count >= 4:
                print("→ Full 4-way handshake likely captured!")
                return True  # stop
        return STOP_SNIFFING

    print(f"\nCapturing handshake for: {target_ssid} ({target_bssid})")
    print(f"Duration: {CAPTURE_DURATION} seconds (or until handshake found)\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=eapol_handler,
            timeout=CAPTURE_DURATION,
            stop_filter=lambda x: STOP_SNIFFING,
            filter=f"ether host {target_bssid.lower()}"
        )
    except Exception as e:
        print(f"Capture error: {e}")

    if CAPTURED_PACKETS:
        try:
            wrpcap(OUTPUT_PCAP, CAPTURED_PACKETS)
            print(f"\nSuccess! Saved {len(CAPTURED_PACKETS)} packets → {OUTPUT_PCAP}")
        except Exception as e:
            print(f"Failed to save PCAP: {e}")
    else:
        print("\nNo handshake captured. Tips:")
        print(" - Make sure a device is connecting")
        print(" - Use deauth attack (carefully!)")
        print(" - Increase capture duration")

# ────────────────────────────────────────────────

# if __name__ == "__main__":
#     if os.getpid() != 0:
#         print("ERROR: This script must be run as root (sudo)!")
#         sys.exit(1)
 
    signal.signal(signal.SIGINT, signal_handler)

    print("Wi-Fi Scanner & Handshake Capture Tool")
    print("───────────────────────────────────────\n")

    try:
        enable_monitor_mode()

        # Step 1: Scan
        print("=== Starting Wi-Fi Scan ===")
        found = scan_wifi()

        if found:
            print("\nFound networks:")
            for bssid, info in sorted(found.items(), key=lambda x: x[1]["signal"] if isinstance(x[1]["signal"], int) else -999, reverse=True):
                print(f"  {info['ssid']:<25} {bssid}  Ch:{info['channel']:>3}  Sig:{info['signal']:>4}  {info['crypto']}")

            # Optional: pick one for capture (you can also do this in GUI)
            # Example:
            # target_bssid = "AA:BB:CC:DD:EE:FF"
            # target_ssid = "MyWiFi"
            # capture_handshake(target_bssid, target_ssid)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\nUnexpected error: {e}")
    finally:
        cleanup()
        print("\nDone.")