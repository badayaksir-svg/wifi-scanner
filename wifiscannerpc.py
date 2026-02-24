#!/usr/bin/env python3
"""
Wi-Fi Scanner & WPA Handshake Capturer
- Works best on Linux with monitor-mode capable adapter
- Very limited / no monitor mode on Windows (fallback to netsh scan)

Requirements (Linux):
    sudo apt install python3-scapy iproute2 iw aircrack-ng   (optional for easier mode switching)
"""

import subprocess
import time
import signal
import sys
import os
import platform
import ctypes

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, RadioTap, EAPOL, wrpcap, conf,
        IFACES, get_if_list
    )
except ImportError:
    print("ERROR: scapy is not installed.")
    print("Run: pip install scapy")
    sys.exit(1)

# ================= CONFIG =================
DEFAULT_INTERFACE = "wlan0"           # change this
SCAN_DURATION     = 20                # seconds
CAPTURE_DURATION  = 90                # seconds
OUTPUT_PCAP       = "handshake.pcap"

# Globals
STOP_SNIFFING     = False
MONITOR_MODE_ACTIVE = False
CAPTURED_PACKETS  = []

# ────────────────────────────────────────────────

def is_root():
    """Check if running as root/administrator"""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

def get_suitable_interface():
    """Try to suggest a possible monitor capable interface"""
    if platform.system() != "Linux":
        return DEFAULT_INTERFACE

    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "IEEE 802.11" in line:
                iface = line.split()[0]
                if iface != "lo":
                    return iface
    except:
        pass
    return DEFAULT_INTERFACE

def enable_monitor_mode_linux(iface):
    global MONITOR_MODE_ACTIVE
    print(f"→ Putting interface {iface} into monitor mode...")

    commands = [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "monitor", "control"],
        ["ip", "link", "set", iface, "up"],
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {' '.join(cmd)}")
            print(f"stderr: {e.stderr.decode(errors='replace')}")
            print("\nCommon fixes:")
            print("  • Run with sudo / as Administrator")
            print("  • Use: sudo airmon-ng start wlan0   (recommended)")
            print("  • Check if adapter supports monitor mode")
            sys.exit(1)
        except FileNotFoundError:
            print("ERROR: 'ip' or 'iw' command not found.")
            print("Install: sudo apt install iproute2 iw")
            sys.exit(1)

    MONITOR_MODE_ACTIVE = True
    print(f"→ Monitor mode enabled on {iface}")

def disable_monitor_mode_linux(iface):
    global MONITOR_MODE_ACTIVE
    if not MONITOR_MODE_ACTIVE:
        return

    print(f"→ Disabling monitor mode on {iface}...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True)
        subprocess.run(["iw", iface, "set", "type", "managed"], check=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        MONITOR_MODE_ACTIVE = False
        print("Monitor mode disabled.")
    except Exception as e:
        print(f"Warning: Could not disable monitor mode → {e}")

def scan_wifi_linux(iface):
    networks = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3.upper()
            if bssid in networks:
                return
            ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore').strip() or "<hidden>"
            signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else "N/A"
            channel = pkt[RadioTap].Channel if pkt.haslayer(RadioTap) else "N/A"
            crypto = pkt[Dot11Beacon].network_stats().get("crypto", set())

            networks[bssid] = {
                "ssid": ssid,
                "channel": channel,
                "signal": signal,
                "crypto": ", ".join(sorted(crypto)) if crypto else "Open"
            }
            print(f"  {ssid:<32}  {bssid}  Ch:{channel:>3}  Sig:{signal:>4}  {networks[bssid]['crypto']}")

    print(f"\nScanning on {iface} for ~{SCAN_DURATION} seconds...\n")
    try:
        sniff(iface=iface, prn=packet_handler, timeout=SCAN_DURATION, store=0)
    except Exception as e:
        print(f"Sniffing failed: {e}")
        print("→ Make sure interface is in monitor mode and you have permission.")

    return networks

def scan_wifi_windows():
    print("\nWindows mode: using netsh (no monitor mode / no raw 802.11 packets)")
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True, stderr=subprocess.STDOUT
        )
        print(out.strip())
    except Exception as e:
        print(f"Failed to run netsh: {e}")
        print("Try running PowerShell as Administrator.")

def capture_handshake(iface, target_bssid, target_ssid):
    global CAPTURED_PACKETS, STOP_SNIFFING
    CAPTURED_PACKETS = []
    eapol_count = 0

    def handler(pkt):
        nonlocal eapol_count
        if pkt.haslayer(EAPOL):
            eapol_count += 1
            CAPTURED_PACKETS.append(pkt)
            print(f"  EAPOL #{eapol_count} captured")
            if eapol_count >= 4:
                print("→ Full 4-way handshake likely captured!")
                return True
        return STOP_SNIFFING

    print(f"\nCapturing WPA handshake for {target_ssid} ({target_bssid})")
    print(f"  Duration: up to {CAPTURE_DURATION} seconds\n")

    try:
        sniff(
            iface=iface,
            prn=handler,
            timeout=CAPTURE_DURATION,
            stop_filter=lambda x: STOP_SNIFFING,
            filter=f"ether host {target_bssid.lower()}"
        )
    except Exception as e:
        print(f"Capture failed: {e}")

    if CAPTURED_PACKETS:
        try:
            wrpcap(OUTPUT_PCAP, CAPTURED_PACKETS)
            print(f"\nSaved {len(CAPTURED_PACKETS)} packets → {OUTPUT_PCAP}")
        except Exception as e:
            print(f"Failed to write pcap: {e}")
    else:
        print("\nNo handshake captured.")
        print("Tips:")
        print(" • Connect a device to the network during capture")
        print(" • Use a deauth attack (ethically, only your network!)")
        print(" • Increase CAPTURE_DURATION")

# ────────────────────────────────────────────────

def main():
    global STOP_SNIFFING

    print("Wi-Fi Scanner & Handshake Capture Tool")
    print("───────────────────────────────────────")
    print(f"Platform: {platform.system()} {platform.release()}\n")

    if not is_root():
        if platform.system() == "Windows":
            print("WARNING: Running without Administrator rights → raw packet capture will likely fail")
        else:
            print("ERROR: This script should be run as root (sudo)")
            print("       Try:  sudo python3 this_script.py")
            # sys.exit(1)   # comment if you want to allow non-root testing

    iface = get_suitable_interface()
    print(f"Using interface: {iface}  (change in config if needed)\n")

    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))

    if platform.system() == "Linux":
        try:
            enable_monitor_mode_linux(iface)
            print("\n=== Wi-Fi Scan ===")
            networks = scan_wifi_linux(iface)

            if networks:
                print("\nStrongest networks (sorted by signal):")
                sorted_nets = sorted(
                    networks.items(),
                    key=lambda x: x[1]["signal"] if isinstance(x[1]["signal"], (int,float)) else -1000,
                    reverse=True
                )
                for bssid, info in sorted_nets[:15]:
                    print(f"  {info['ssid']:<32}  {bssid}  Ch:{info['channel']:>3}  Sig:{info['signal']:>4}  {info['crypto']}")

                # Uncomment to auto-capture from strongest network (for testing only)
                # strongest = sorted_nets[0]
                # capture_handshake(iface, strongest[0], strongest[1]["ssid"])

        except KeyboardInterrupt:
            print("\nInterrupted by user.")
        except Exception as e:
            print(f"\nError: {e}")
        finally:
            disable_monitor_mode_linux(iface)
    else:
        # Windows fallback
        scan_wifi_windows()

    print("\nDone.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"\nUnexpected error: {type(e).__name__}: {e}")
        