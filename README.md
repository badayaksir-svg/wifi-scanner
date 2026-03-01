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

**Step-by-step:**

1. Open your terminal and navigate to the project folder
2. Run `python main.py`
3. Choose option `1` to scan — nearby networks will appear with their SSID, BSSID and signal strength
4. On Linux, choose option `2`, enter the target BSSID and SSID to begin capturing a handshake — wait until 4 EAPOL packets are captured
5. Choose option `3`, enter the SSID to run the dictionary attack against the saved `handshake.pcap`
6. Use option `4` at any time to stop a running operation
7. Use option `5` to exit cleanly

### GUI Version

```bash
python gui.py
```

> ⚠️ Always close the window using the **✕ button**. Do **not** press Ctrl+C while the GUI is open as this will force-quit the application.

**Step-by-step:**

1. Run `python gui.py` — a window will open
2. Click **Scan Wi-Fi** to discover nearby networks — results appear in the log panel in real time
3. On Linux, click **Capture Handshake**, enter the BSSID and SSID when prompted — the tool listens for EAPOL packets and saves them to `handshake.pcap`
4. Click **Start Attack**, enter the target SSID — `aircrack-ng` will run against the captured handshake using `rockyou.txt`
5. Click **Stop** at any time to cancel the current operation
6. Click **Clear Log** to clear the output panel

---

## ⚠️ Limitations

### Platform Limitations
- **Handshake capture** only works on **Linux** — it requires a wireless adapter that supports monitor mode, which is not available on standard Windows Wi-Fi drivers
- **Dictionary attack** requires `aircrack-ng` to be installed — this is a Linux tool and is not natively available on Windows without additional setup (e.g. WSL)
- On **Windows**, only the **Wi-Fi Scan** feature is fully functional, using the built-in `netsh` command

### Hardware Limitations
- A **monitor mode-capable wireless adapter** is required for packet sniffing on Linux — most built-in laptop Wi-Fi cards do not support this
- Signal strength readings (`dBm`) may not be available on all adapters or drivers

### Software Limitations
- The tool relies on **Scapy** for packet sniffing, which requires **administrator/root privileges** to capture raw packets
- The dictionary attack is only as effective as the wordlist provided — passwords not present in `rockyou.txt` will not be found
- `rockyou.txt` is **not included** in this repository due to its large file size (~130MB) — it must be sourced separately
- The capture timeout is fixed at 90 seconds — if no handshake occurs in that window, the capture stops with no result

### Security Limitations
- The tool does not support **WPA3** networks — only WPA/WPA2 handshake-based attacks are implemented
- No de-authentication packet injection is implemented — the tool passively waits for a handshake rather than forcing one

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

## ⚖️ Legal Policies

### Legal Use Only
This tool must only be used on networks and devices that you **own** or have been given **explicit written permission** to test. Using this tool without authorisation is a criminal offence in most countries.

### United Kingdom
- **Computer Misuse Act 1990** — Unauthorised access to computer systems carries a penalty of up to **10 years imprisonment**. Sections 1, 2, and 3 directly apply to unauthorised network access and interception.
- **Investigatory Powers Act 2016** — Unlawful interception of communications is a serious criminal offence.
- **Data Protection Act 2018 / UK GDPR** — Capturing network traffic containing personal data without consent violates data protection law and can result in significant fines.

### European Union
- **Directive on Attacks Against Information Systems (2013/40/EU)** — Criminalises unauthorised access, interception, and interference with information systems across all EU member states.

### United States
- **Computer Fraud and Abuse Act (CFAA)** — Unauthorised access to computer networks is a federal crime carrying penalties of up to **20 years imprisonment** for repeat offences.
- **Electronic Communications Privacy Act (ECPA)** — Unlawful interception of electronic communications is prohibited.

### International
Most countries have equivalent cybercrime legislation. Ignorance of the law is not a valid defence. Always verify local laws before using this tool.

---

## 🌍 How This Tool Can Affect Others

Understanding the potential impact of this tool is essential for responsible use.

### Privacy
- Packet sniffing can capture **unencrypted network traffic** from other users on the same network, exposing personal data, login credentials, and browsing activity without their knowledge.
- Even capturing handshake packets involves intercepting data transmitted by devices belonging to other people.

### Network Disruption
- Running this tool on a shared or public network can **degrade performance** for other users by generating excessive traffic or interfering with normal network operations.

### Reputational & Academic Consequences
- Misuse of this tool, even unintentionally, can result in **disciplinary action** from your college or university, including expulsion.
- It can also result in a **permanent criminal record**, which affects future employment, particularly in IT and cybersecurity careers.

### Ethical Responsibility
- Security tools like this exist to help professionals **protect** systems, not exploit them. Ethical use means always obtaining permission, documenting your actions, and reporting vulnerabilities responsibly.
- If used in a lab or controlled environment for learning, ensure all participants are aware and have consented.

> **In short:** Always ask yourself — *"Do I have permission to do this?"* If the answer is anything other than a clear yes, do not proceed.

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
