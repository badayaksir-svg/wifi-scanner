# Wi-Fi Scanner & Security Tool

> **ST4017CMD – Introduction to Programming**  
> College Coursework Submission

---

## 📋 Overview

A Python-based Wi-Fi security tool that demonstrates core programming concepts including **network scanning**, **packet capture**, and **dictionary-based analysis**. The project is available in both a command-line interface (CLI) and a graphical user interface (GUI) built with Tkinter.

---

## ✨ Features

- **Wi-Fi Scanning** – Detects nearby wireless networks, displaying SSID, BSSID, and signal strength
- **Handshake Capture** – Captures WPA/WPA2 4-way EAPOL handshakes via packet sniffing *(Linux only)*
- **Dictionary Attack** – Tests captured handshakes against a wordlist using `aircrack-ng`
- **Dual Interface** – Run as a terminal CLI (`main.py`) or a windowed GUI (`gui.py`)
- **Cross-platform** – Windows scan support via `netsh`; full feature set on Linux

---

## 🗂️ Project Structure

```
wifi-scanner/
├── main.py          # Console / CLI version
├── gui.py           # GUI version (Tkinter)
├── rockyou.txt      # Wordlist for dictionary attack (not included – see setup)
├── handshake.pcap   # Output file from handshake capture
├── README.md        # Project documentation
└── .gitignore
```

---

## 🔧 Requirements

- Python 3.8+
- [Scapy](https://scapy.net/) – packet sniffing and crafting
- `aircrack-ng` – password cracking backend *(Linux)*
- A wireless adapter capable of **monitor mode** *(for capture features on Linux)*

Install Python dependencies:

```bash
pip install scapy
```

Install `aircrack-ng` on Linux:

```bash
sudo apt install aircrack-ng
```

---

## 🚀 Usage

### Console Version

```bash
python main.py
```

Follow the on-screen menu:

| Option | Action |
|--------|--------|
| `1` | Scan nearby Wi-Fi networks |
| `2` | Capture WPA handshake *(Linux only)* |
| `3` | Run dictionary attack |
| `4` | Stop current operation |
| `5` | Exit |

### GUI Version

```bash
python gui.py
```

Use the buttons in the interface to **Scan**, **Capture**, **Attack**, or **Stop** operations. Logs are displayed in real-time in the output panel.

---

## ⚙️ Configuration

Key settings at the top of both `main.py` and `gui.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | `wlan0` | Wireless interface name |
| `SCAN_DURATION` | `20` | Scan time in seconds |
| `CAPTURE_DURATION` | `90` | Max capture time in seconds |
| `OUTPUT_PCAP` | `handshake.pcap` | Output file for captured packets |
| `ROCKYOU_PATH` | `rockyou.txt` | Path to the wordlist |
| `MAX_ROCKYOU_LINES` | `100,000` | Max lines read from wordlist |

---

## ⚠️ Disclaimer

> This tool was developed **strictly for educational purposes** as part of college coursework.  
> Use only on networks and devices **you own or have explicit permission to test**.  
> Unauthorised access to computer systems is illegal under the **Computer Misuse Act 1990** (UK) and equivalent laws worldwide.

---

## 📚 Concepts Demonstrated

This project covers the following programming concepts relevant to **ST4017CMD**:

- Object-oriented programming (GUI class design)
- Multi-threading with `threading.Thread` and `threading.Event`
- Inter-thread communication using `queue.Queue`
- File I/O and external process management (`subprocess`)
- Third-party library usage (Scapy, Tkinter)
- Error handling with `try/except`
- Cross-platform conditional logic

---

## 📄 License

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
