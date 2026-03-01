# Wi-Fi Scanner & Security Tool

> **Module: ST4017CMD – Introduction to Programming**
> **Submission Type: College Coursework**

---

## 📑 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Project Structure](#️-project-structure)
4. [How It Works](#-how-it-works)
5. [Requirements](#-requirements)
6. [Installation & Setup](#️-installation--setup)
7. [Configuration](#️-configuration)
8. [Usage – Console Version](#-usage--console-version)
9. [Usage – GUI Version](#️-usage--gui-version)
10. [Limitations](#-limitations)
11. [Legal Policies](#️-legal-policies)
12. [How This Tool Can Affect Others](#-how-this-tool-can-affect-others)
13. [Programming Concepts Demonstrated](#-programming-concepts-demonstrated)
14. [License](#-license)

---

## 📋 Overview

This project is a **Python-based Wi-Fi security and analysis tool** developed as part of the ST4017CMD Introduction to Programming coursework. It demonstrates practical application of Python programming by combining network scanning, packet capture, and password analysis into a single tool.

The tool is designed to help understand how Wi-Fi networks communicate and how WPA/WPA2 security protocols work at a technical level. It is available in two versions:

- **`main.py`** — A text-based console application that runs entirely in the terminal
- **`gui.py`** — A graphical desktop application built with Python's Tkinter library

Both versions provide the same core functionality but cater to different preferences and use cases.

> ⚠️ This tool is built **strictly for educational and coursework purposes**. It must only be used in controlled environments on networks you own or have explicit permission to test.

---

## ✨ Features

### 1. Wi-Fi Network Scanning
The tool scans the surrounding area for wireless networks and displays key information about each one. On **Windows**, this uses the built-in `netsh` command. On **Linux**, it uses Scapy to sniff beacon frames broadcast by wireless access points.

Each discovered network shows:
- **SSID** — the human-readable name of the network (e.g. `HomeNetwork`)
- **BSSID** — the MAC address of the router/access point (e.g. `AA:BB:CC:DD:EE:FF`)
- **Signal strength** — measured in dBm (e.g. `-65 dBm`), where a value closer to 0 means a stronger signal

### 2. WPA Handshake Capture *(Linux only)*
When a device connects to a WPA/WPA2 network, it performs a **4-way handshake** — an exchange of 4 EAPOL (Extensible Authentication Protocol over LAN) packets that authenticate the device. This tool listens for and captures those packets.

Once all 4 packets are captured, they are saved to a file called `handshake.pcap`. This file is needed for the dictionary attack step.

### 3. Dictionary Attack
Using the captured `handshake.pcap` file and a wordlist (`rockyou.txt`), the tool calls `aircrack-ng` to attempt to recover the Wi-Fi password. It works by hashing each password in the wordlist and comparing it against the captured handshake until a match is found.

### 4. Dual Interface (CLI + GUI)
The project provides two ways to interact with the tool:
- A **terminal menu** (`main.py`) for users comfortable with the command line
- A **graphical window** (`gui.py`) with buttons, a real-time log panel, and status bar

### 5. Cross-Platform Support
- **Windows**: Wi-Fi scanning works out of the box via `netsh`
- **Linux**: All features are available including handshake capture and dictionary attack

---

## 🗂️ Project Structure

```
wifi-scanner/
│
├── main.py           # Console (CLI) version of the tool
├── gui.py            # GUI version of the tool (Tkinter)
├── rockyou.txt       # Password wordlist – NOT included (must be sourced separately)
├── handshake.pcap    # Output file created after a successful handshake capture
├── README.md         # This documentation file
└── .gitignore        # Specifies files Git should not track
```

**What each file does:**

| File | Purpose |
|------|---------|
| `main.py` | Runs the tool as a terminal application with a numbered menu |
| `gui.py` | Runs the tool as a graphical window application |
| `rockyou.txt` | A large wordlist of common passwords used in the dictionary attack |
| `handshake.pcap` | Binary packet capture file created by the handshake capture feature |
| `.gitignore` | Prevents sensitive or large files (like `rockyou.txt`) from being uploaded to GitHub |

---

## 🔍 How It Works

Understanding what happens behind the scenes helps explain the programming concepts involved.

### Step 1 — Scanning
When you start a Wi-Fi scan, the tool puts your wireless adapter into **monitor mode** (Linux) or uses `netsh` (Windows). In monitor mode, the adapter can receive all Wi-Fi frames in the air, not just those addressed to your device. Wireless routers constantly broadcast **beacon frames** that announce their presence. The tool uses **Scapy** to capture these frames and extract the SSID, BSSID, and signal strength from each one.

### Step 2 — Handshake Capture
When a client device (phone, laptop, etc.) connects to a WPA/WPA2 network, both devices exchange 4 EAPOL packets to verify the password without sending it directly. This is called the **4-way handshake**. The tool listens passively for these packets and saves them to `handshake.pcap` once all 4 are received.

### Step 3 — Dictionary Attack
The saved `handshake.pcap` is passed to `aircrack-ng` along with `rockyou.txt`. Aircrack-ng takes each password from the list, derives what the EAPOL packets would look like if that password were correct, and compares it to the captured data. If there is a match, the password has been found. This is called a **dictionary attack** because it relies on a pre-existing list of words rather than trying every possible character combination.

---

## 🔧 Requirements

Before running this tool, make sure the following are installed on your system.

### Software Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.8 or higher | Core language the tool is written in |
| Scapy | Latest | Packet sniffing and network analysis |
| aircrack-ng | Latest | Performs the dictionary attack on captured handshakes |
| Tkinter | Included with Python | Provides the GUI window and widgets |

### Hardware Requirements
- A **Wi-Fi adapter** is required for scanning
- For handshake capture on Linux, the adapter must support **monitor mode** — most USB Wi-Fi adapters support this, but most built-in laptop adapters do not

### Operating System Compatibility

| Feature | Windows | Linux |
|---------|---------|-------|
| Wi-Fi Scan | ✅ | ✅ |
| Handshake Capture | ❌ | ✅ |
| Dictionary Attack | ⚠️ Requires WSL | ✅ |
| GUI | ✅ | ✅ |

---

## 🛠️ Installation & Setup

Follow these steps carefully to get the tool running on your machine.

### Step 1 — Clone or Download the Repository

If you have Git installed:
```bash
git clone https://github.com/your-username/wifi-scanner.git
cd wifi-scanner
```

Or download the ZIP from GitHub and extract it to a folder.

### Step 2 — Create a Virtual Environment (Recommended)

A virtual environment keeps your project's dependencies separate from your system Python installation.

```bash
# Create the virtual environment
python -m venv env

# Activate it on Windows
env\Scripts\activate

# Activate it on Linux/Mac
source env/bin/activate
```

You should see `(env)` appear at the start of your terminal prompt, confirming it is active.

### Step 3 — Install Python Dependencies

```bash
pip install scapy
```

This installs the Scapy library which handles all packet sniffing functionality.

### Step 4 — Install aircrack-ng (Linux only)

```bash
sudo apt update
sudo apt install aircrack-ng
```

To verify it installed correctly:
```bash
aircrack-ng --help
```

### Step 5 — Obtain rockyou.txt (Optional — needed for dictionary attack only)

`rockyou.txt` is a widely used password wordlist containing over 14 million common passwords. It is not included in this repository due to its large file size (~130MB).

You can obtain it from:
- Kali Linux: it is pre-installed at `/usr/share/wordlists/rockyou.txt.gz`
- Or source it from a reputable cybersecurity resource

Once obtained, place it in the same folder as `main.py` and `gui.py`.

### Step 6 — Verify Everything Works

Run this command to confirm all dependencies are correctly installed:
```bash
python -c "import tkinter; import scapy; print('All dependencies installed successfully!')"
```

If you see `All dependencies installed successfully!` — you are ready to run the tool.

---

## ⚙️ Configuration

Both `main.py` and `gui.py` share a set of configuration variables near the top of each file. You can edit these to customise the tool's behaviour without changing any of the core logic.

| Variable | Default Value | What It Does |
|----------|--------------|--------------|
| `INTERFACE` | `wlan0` | The name of your wireless network adapter. On Linux this is usually `wlan0` or `wlan1`. Check yours with `ip link`. |
| `SCAN_DURATION` | `20` | How many seconds the scan runs for before stopping automatically. Increase this for more thorough results. |
| `CAPTURE_DURATION` | `90` | Maximum time in seconds the tool will wait for a handshake before giving up. |
| `OUTPUT_PCAP` | `handshake.pcap` | The filename where captured handshake packets are saved. |
| `ROCKYOU_PATH` | `rockyou.txt` | The path to your password wordlist. Change this if your file is stored elsewhere. |
| `MAX_ROCKYOU_LINES` | `100,000` | Limits how many lines are read from `rockyou.txt` to keep the attack manageable. |
| `MAX_WORKERS` | `8` | Number of parallel threads used during the dictionary attack. |

**Example — changing the interface name:**
```python
INTERFACE = "wlan1"   # Change from wlan0 to wlan1
```

---

## 💻 Usage — Console Version

The console version (`main.py`) runs entirely in your terminal and is controlled through a numbered menu.

### How to Run

```bash
python main.py
```

### The Menu

When you run the script, you will see:

```
============================================================
      Wi-Fi Tool – rockyou Dictionary Attack
============================================================
1. Scan Wi-Fi
2. Capture Handshake (Linux only)
3. Dictionary Attack
4. Stop current operation
5. Exit
============================================================
```

### Option 1 — Scan Wi-Fi

**What it does:** Scans for nearby wireless networks and prints each one to the terminal.

**Steps:**
1. Type `1` and press Enter
2. The tool begins scanning — on Linux it sniffs beacon frames, on Windows it runs `netsh`
3. As networks are discovered, they appear in the terminal with their SSID, BSSID and signal strength
4. Scanning runs for `SCAN_DURATION` seconds (default: 20 seconds) then stops automatically

**Example output:**
```
[+] Scanning on wlan0...
Found → HomeNetwork               | AA:BB:CC:DD:EE:FF | Sig:-62
Found → OfficeWifi                | 11:22:33:44:55:66 | Sig:-75
[+] Scan finished
```

### Option 2 — Capture Handshake *(Linux only)*

**What it does:** Listens for a WPA/WPA2 4-way handshake between a client device and an access point.

**Steps:**
1. Type `2` and press Enter
2. Enter the **BSSID** of the target network (e.g. `AA:BB:CC:DD:EE:FF`) — found from the scan output
3. Enter the **SSID** of the target network (e.g. `HomeNetwork`)
4. The tool begins listening for EAPOL packets
5. Wait for a device to connect (or reconnect) to the target network
6. Once all 4 EAPOL packets are captured, the handshake is saved to `handshake.pcap`

**Example output:**
```
[+] Capturing handshake for HomeNetwork...
[+] EAPOL packet #1 captured
[+] EAPOL packet #2 captured
[+] EAPOL packet #3 captured
[+] EAPOL packet #4 captured
[+] Full 4-way handshake captured!
[+] Saved to handshake.pcap
```

### Option 3 — Dictionary Attack

**What it does:** Attempts to recover the Wi-Fi password by running `aircrack-ng` against the captured handshake using `rockyou.txt`.

**Steps:**
1. Make sure `handshake.pcap` exists in the project folder (run Option 2 first)
2. Make sure `rockyou.txt` is in the project folder
3. Type `3` and press Enter
4. Enter the **SSID** of the target network
5. `aircrack-ng` will begin testing passwords from the wordlist — output streams to the terminal
6. If the password is found, it will be displayed on screen

### Option 4 — Stop Current Operation

**What it does:** Sends a stop signal to any currently running background thread (scan, capture, or attack). The operation will finish its current task and then exit cleanly rather than crashing.

### Option 5 — Exit

**What it does:** Exits the application cleanly and returns to the normal terminal prompt.

---

## 🖥️ Usage — GUI Version

The GUI version (`gui.py`) provides a graphical window with buttons and a real-time log panel, making it easier to use without memorising menu options.

### How to Run

```bash
python gui.py
```

> ⚠️ **Important:** Always close the application using the **✕ button** in the top corner of the window. Do **not** press Ctrl+C in the terminal while the GUI is open — this immediately force-quits the app and produces a `KeyboardInterrupt` error. This is normal Python behaviour, not a bug in the code.

### The Interface Layout

| Section | Description |
|---------|-------------|
| **Header bar** | Shows the app name and your operating system / machine name |
| **Log panel** | Scrollable area where all activity is displayed in real time |
| **Button bar** | Row of buttons for triggering each action |
| **Status bar** | Shows the current status of the most recent operation |

### Button — Scan Wi-Fi

**What it does:** Starts a Wi-Fi scan in a background thread so the GUI stays responsive during the scan.

**Steps:**
1. Click the **Scan Wi-Fi** button
2. On Windows, results from `netsh` appear in the log panel
3. On Linux, discovered networks appear one by one in green text as they are found
4. The scan runs for `SCAN_DURATION` seconds and stops automatically

### Button — Capture Handshake *(Linux only)*

**What it does:** Opens dialog boxes asking for the target BSSID and SSID, then starts listening for EAPOL handshake packets in the background.

**Steps:**
1. Click **Capture Handshake**
2. A dialog box appears — type the **BSSID** (e.g. `AA:BB:CC:DD:EE:FF`) and click OK
3. Another dialog appears — type the **SSID** (e.g. `HomeNetwork`) and click OK
4. Watch the log panel — each captured EAPOL packet appears as it arrives
5. Once 4 packets are captured, a success message appears and the file is saved

> ⚠️ On Windows, clicking this button will display a warning that this feature is not supported on the current platform.

### Button — Start Attack

**What it does:** Opens a dialog asking for the target SSID, then runs `aircrack-ng` as a background process and streams its output into the log panel.

**Steps:**
1. Click **Start Attack**
2. Enter the **SSID** of the target network in the dialog box and click OK
3. The attack begins — `aircrack-ng` output appears line by line in the log panel
4. If the password is found, a pop-up notification appears showing the recovered password

### Button — Stop

**What it does:** Sets a stop flag that signals all running background threads to finish their current step and exit. This works for scans, captures, and attacks.

### Button — Clear Log

**What it does:** Erases all text from the log panel. Useful for clearing old output before starting a new operation.

### Log Panel Colour Codes

| Colour | Meaning |
|--------|---------|
| Grey | General information and ready messages |
| Blue `[+]` | Status updates — operation started or in progress |
| Green `[✓]` | Success — network found, handshake captured, password recovered |
| Red `[✗]` | Errors — missing file, tool not installed, operation failed |
| Orange `[~]` | Warnings — stop requested, non-critical issues |

---

## ⚠️ Limitations

This section outlines what the tool cannot do and explains the technical reasons why.

### Platform Limitations

**Handshake capture is Linux-only.**
This feature requires the wireless adapter to be placed into monitor mode, a capability of the Linux wireless driver stack (`cfg80211` / `mac80211`). Windows wireless drivers do not expose raw 802.11 frame capture to user applications, making this feature technically impossible on Windows without specialist hardware.

**Dictionary attack requires `aircrack-ng`.**
`aircrack-ng` is a Linux-native tool. It can be run on Windows via WSL (Windows Subsystem for Linux) but this adds significant complexity and is not officially supported within this project.

**On Windows, only Wi-Fi scanning is fully functional.**
The scan uses `netsh wlan show networks`, a built-in Windows command. This works without any additional software but provides less detail than the Linux Scapy-based scan and cannot show signal strength in the same format.

### Hardware Limitations

**Monitor mode adapter required for capture.**
Most built-in laptop Wi-Fi cards (Intel, Realtek, Broadcom) do not support monitor mode. A compatible external USB Wi-Fi adapter (such as the Alfa AWUS036ACH) is needed for the handshake capture feature on Linux.

**Signal strength readings may be unavailable.**
The `dBm_AntSignal` value is extracted from the RadioTap header of captured frames. Not all adapters include this information, so signal strength may display as `N/A` on some systems.

### Software Limitations

**Root or administrator privileges are required.**
Scapy needs raw socket access to capture network packets. On Linux, the script must be run with `sudo`. On Windows, the terminal must be run as Administrator.

**The attack can only find passwords in the wordlist.**
The dictionary attack tests passwords from `rockyou.txt` only. Any password that is not present in the wordlist — for example, a long, randomly generated password — will not be found. This is a fundamental limitation of all dictionary-based attacks.

**`rockyou.txt` is not included in the repository.**
The file is approximately 130MB and is not appropriate for a Git repository. It must be sourced and placed in the project folder manually before the dictionary attack feature can be used.

**The capture has a fixed timeout.**
The handshake capture waits a maximum of 90 seconds (`CAPTURE_DURATION`). If no device connects to the target network in that time window, the capture stops with no result and must be restarted manually.

### Security Limitations

**WPA3 is not supported.**
WPA3 uses Simultaneous Authentication of Equals (SAE), which is fundamentally different from the 4-way handshake used in WPA and WPA2. This tool only supports WPA/WPA2 networks.

**No deauthentication injection.**
Professional penetration testing tools can force a device off a network and capture the handshake when it automatically reconnects. This tool only passively waits for a natural connection, meaning you may need to wait a significant amount of time.

---

## ⚖️ Legal Policies

### Authorised Use Only

This tool must only ever be used on networks and devices that you **personally own** or where you have received **explicit written permission** from the network owner. Testing any network without such permission — even if you can technically see or reach it — is a criminal offence in most countries.

---

### United Kingdom Law

**Computer Misuse Act 1990**
This is the primary UK law covering computer crime and contains three offences directly applicable to this tool:

- **Section 1** — Unauthorised access to computer material. Simply scanning or probing a network you do not have permission to access constitutes an offence. Penalty: up to **2 years imprisonment** and/or a fine.
- **Section 2** — Unauthorised access with intent to commit a further offence (for example, capturing a handshake to gain credentials for unauthorised access). Penalty: up to **5 years imprisonment**.
- **Section 3** — Unauthorised acts with intent to impair a computer or network. Penalty: up to **10 years imprisonment**.

**Investigatory Powers Act 2016**
Commonly referred to as the "Snoopers' Charter", this Act makes the unlawful interception of private communications a serious criminal offence. Packet sniffing on a network you do not own may constitute illegal interception under this legislation.

**Data Protection Act 2018 / UK GDPR**
Network traffic may contain personal data such as login credentials, private messages, and browsing history. Capturing this data without a lawful basis violates UK data protection law and can result in significant financial penalties issued by the Information Commissioner's Office (ICO).

---

### European Union Law

**Directive on Attacks Against Information Systems (2013/40/EU)**
This directive requires all EU member states to criminalise unauthorised access to information systems, illegal interception of electronic data, and interference with data or systems. It reflects the same standards as UK law and applies across all EU countries.

---

### United States Law

**Computer Fraud and Abuse Act (CFAA)**
The primary US federal cybercrime law. It prohibits accessing any computer or network without authorisation or in excess of authorised access. Penalties range from fines for minor offences to **20 years imprisonment** for aggravated or repeat violations.

**Electronic Communications Privacy Act (ECPA)**
Prohibits the unlawful interception of wire, oral, and electronic communications. Packet sniffing on a network you do not own is likely to constitute illegal interception under this Act.

---

### International Law

Most countries are signatories to or have enacted legislation based on the **Council of Europe Convention on Cybercrime (Budapest Convention)**, which establishes a global framework for criminalising unauthorised computer access and interception. Regardless of where you are, using this tool without authorisation carries serious legal risk. Claiming not to know the law is not a valid defence in any jurisdiction.

---

## 🌍 How This Tool Can Affect Others

It is important to understand that security tools do not only affect their intended target — they can have wide-reaching unintended consequences for many people. This section explains those risks in detail.

### 1. Violation of Privacy
When this tool sniffs packets on a wireless network, it captures data from **all devices** broadcasting on that frequency — not only the intended target. This means nearby phones, laptops, smart TVs, and IoT devices belonging to other people may inadvertently have their network activity intercepted. That traffic can contain sensitive personal information such as usernames, passwords, banking sessions, private messages, and browsing history. Capturing this data without consent is a serious invasion of privacy, regardless of whether the information is actually read or stored.

### 2. Network Performance Degradation
Running continuous packet sniffing or monitoring on a shared network — such as a university campus network, office Wi-Fi, or public hotspot — can consume bandwidth and increase the processing load on network infrastructure. In some scenarios, this degrades the connection quality for other legitimate users who depend on that network for studying, working, or communicating.

### 3. Unintended Security Alerts
If a network owner or IT security team detects unusual activity such as packet sniffing or handshake capture attempts on their network, it will trigger a security incident response. This wastes the time and resources of IT staff who must investigate, change credentials, and assess whether a breach occurred — even if the actual intent was innocent.

### 4. Academic Consequences
For students, misusing this tool — even unintentionally — on a college or university network can result in:
- **Formal disciplinary proceedings** under the institution's acceptable use policy
- **Suspension or permanent expulsion** from the course
- **Referral to the police** for investigation under the Computer Misuse Act 1990
- A **criminal record** that will appear on DBS checks and background screening, significantly harming future career prospects in IT, finance, law, or any security-cleared profession

### 5. Damage to Professional Reputation
The cybersecurity industry depends on trust. Professionals in this field are expected to act ethically and responsibly. Being associated with the unauthorised use of security tools — even as a student — can damage your professional reputation before your career has even started.

### 6. Ethical Responsibility as a Developer
Creating security tools carries a moral obligation. The cybersecurity community operates under clear ethical principles: always obtain authorisation, cause no unnecessary harm, disclose vulnerabilities through responsible channels, and use technical knowledge to protect people rather than to exploit them. As the developer of this project, it is your responsibility to ensure it is used only as intended and to communicate its educational purpose clearly.

> **Final reminder:** Before running any part of this tool, always ask yourself — *"Do I have clear, explicit permission to do this?"* If the answer is anything other than a definite yes, do not proceed.

---

## 📚 Programming Concepts Demonstrated

This project demonstrates the following core programming concepts as required by the **ST4017CMD Introduction to Programming** module:

### Object-Oriented Programming (OOP)
The GUI version (`gui.py`) is structured around a single class — `WiFiToolGUI` — that encapsulates the entire application. The constructor (`__init__`) builds the interface by calling private methods (`_build_header`, `_build_log`, `_build_buttons`, etc.). This demonstrates the OOP principles of **encapsulation** (keeping related logic together inside a class) and **abstraction** (hiding complex implementation details behind simple method names).

### Multi-threading
Both versions use Python's `threading.Thread` to run network operations in background threads. This is essential because scanning, capturing, and attacking can take many seconds or minutes — running them on the main thread would freeze the GUI or block the terminal menu entirely. A shared `threading.Event` object (`stop_event`) provides a thread-safe mechanism to signal running threads to stop gracefully.

### Inter-thread Communication with Queues
A `queue.Queue` object (`result_queue`) is used to safely pass messages from background worker threads back to the main thread for display. This is necessary because Tkinter's GUI widgets can only be updated safely from the main thread. The `update_from_queue` method is called every 150ms by the Tkinter event loop using `root.after()`, draining the queue and updating the log panel with any new messages.

### Subprocess Management
The dictionary attack uses `subprocess.Popen` to launch `aircrack-ng` as a child process and stream its standard output line by line in real time. This demonstrates how Python programs can interact with external tools installed on the operating system, bridging Python code with native command-line utilities.

### File I/O
The tool performs both text and binary file operations. `rockyou.txt` is read line by line as a text file with UTF-8 encoding and error handling. Captured packets are written to `handshake.pcap` as a binary file using Scapy's `wrpcap` function. This demonstrates Python's ability to handle different file types and formats.

### Error Handling
`try/except` blocks are used throughout both files to catch and handle exceptions gracefully — including `ImportError` when Scapy is not installed, `FileNotFoundError` when `aircrack-ng` is missing, and general `Exception` catching during network operations. Rather than crashing, the tool logs a descriptive error message and continues running, providing a much better user experience.

### Third-Party Library Integration
The project integrates two significant third-party libraries:
- **Scapy** — a powerful Python library for constructing, sending, capturing, and analysing network packets at a low level
- **Tkinter** — Python's built-in GUI toolkit, used here to build a multi-component windowed application with labels, buttons, scrolled text areas, and dialog boxes

### Cross-Platform Conditional Logic
`platform.system()` is used at multiple points to detect the current operating system and adjust behaviour accordingly — using `netsh` on Windows and Scapy on Linux for scanning, and disabling capture features on non-Linux systems with a user-friendly warning message. This demonstrates how to write portable Python code that adapts to its runtime environment.

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
