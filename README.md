# NetSpear v2.0

<img width="1280" height="320" alt="NetSpea1r Banner" src="https://github.com/user-attachments/assets/5de1b60a-f1c8-4172-9c65-408be55b5946" />

### Developed & Maintained by **OpenNET LLC**

NetSpear is an advanced modular cybersecurity assessment framework engineered for **authorized penetration testing**, **network reconnaissance**, and **controlled security research environments**.

Built by **OpenNET LLC**, NetSpear v2.0 integrates automated reconnaissance, web-layer analysis, vulnerability detection, reporting, controlled exploitation helpers, and comprehensive post-exploitation capabilities into a single streamlined toolkit leveraging Nmap, Metasploit, Hydra, Scapy, and custom-developed modules.

> **LEGAL NOTICE**  
> NetSpear may ONLY be used on systems you own or have explicit written authorization to test.  
> Misuse may violate local and international law. The authors and OpenNET LLC accept no liability for unlawful use.

---

## What's New in v2.0

NetSpear v2.0 introduces major enhancements including:

- **Database Persistence** - SQLite/PostgreSQL storage for all scan data, vulnerabilities, and sessions
- **REST API** - Full REST API for automation and integration
- **Session Management** - Track and manage active exploitation sessions
- **Credential Management** - Secure, encrypted credential storage and reuse
- **Post-Exploitation Framework** - Comprehensive post-exploitation capabilities
- **Workflow Automation** - Playbook system for automated assessments
- **Network Topology Mapping** - Visual network relationship mapping
- **Vulnerability Prioritization** - CVSS scoring and risk-based prioritization
- **Evidence Collection** - Screenshot capture and PoC storage
- **Cloud Enumeration** - AWS, GCP, and Azure resource discovery
- **Scan Scheduling** - Automated time-based scanning
- **Notification System** - Multi-channel alerts (Email, Slack, Teams)
- **Scanner Integration** - Import from Nessus, OpenVAS, Burp Suite
- **Cleaner UI** - Collapsible menu sections for better organization

---

## Key Features

### Core Functionality

- Interactive, menu-driven **NetSpear Network Analyzer** CLI with collapsible sections
- Scan profiles: `quick`, `full`, `vuln`, `stealth`, `deep`
- Scan modes: **Safe Scan**, **Stealth Scan**, **Standard Scan**, **Fast Scan**, **Full Scan**
- **Multi-target threaded scans**
- Optional **rustscan/masscan prescan** for high-speed discovery
- Automatic **Nmap service detection**
- **CVE extraction + vulnerability mapping**
- **Metasploit exploit helper** (module suggestions + payload hints)
- **Payload generator** (Windows, Linux, macOS, Android, raw shellcode)
- **Web enumeration pipeline**: WhatWeb, Wappalyzer, WAFW00F, ffuf/gobuster/feroxbuster, nuclei
- **OSINT mode** with GeoIP + HTTP fingerprinting (+ optional SpiderFoot)
- **Hydra brute-force helpers** (SSH, FTP)
- **HTML + JSON reporting** with exposure score, anomaly detection, tech highlights
- Environment-variable configuration (override tool paths, presets)
- Privilege checks, safety prompts, and structured logging

### Advanced Features (v2.0)

- **Database Persistence** - Store all scan results, vulnerabilities, and historical data
- **REST API** - Full REST API with FastAPI for automation and CI/CD integration
- **Session Management** - Track active Meterpreter, shell, and SSH sessions
- **Credential Management** - Encrypted credential storage with reuse and spraying capabilities
- **Post-Exploitation** - System enumeration, privilege escalation, persistence, lateral movement
- **Workflow Automation** - JSON-defined playbooks with conditional execution
- **Network Topology** - Automatic network mapping with relationship visualization
- **Vulnerability Prioritization** - CVSS scoring, risk assessment, and remediation priorities
- **Evidence Collection** - Screenshot capture, PoC storage with SHA-256 hashing
- **Cloud Enumeration** - AWS S3, GCP Storage, Azure resource discovery
- **Scan Scheduling** - Interval, cron, and one-time scheduled scans
- **Notification System** - Email, Slack, Teams, and webhook notifications
- **Wordlist Management** - Custom wordlist creation and categorization
- **Scanner Integration** - Import vulnerabilities from Nessus, OpenVAS, Burp Suite

---

## Requirements

### Python Dependencies

```bash
pip install -r NetSpear/requirements.txt
```

**Core Requirements:**
- `scapy` - Network packet manipulation
- `python-nmap` - Nmap Python interface
- `sqlalchemy>=2.0.0` - Database ORM
- `fastapi>=0.104.0` - REST API framework
- `uvicorn[standard]>=0.24.0` - ASGI server
- `pydantic>=2.0.0` - Data validation
- `cryptography>=41.0.0` - Credential encryption
- `apscheduler>=3.10.0` - Task scheduling
- `requests>=2.31.0` - HTTP requests
- `pyyaml>=6.0` - YAML configuration
- `selenium>=4.15.0` - Screenshot capture (optional)
- `boto3>=1.29.0` - AWS integration (optional)
- `psycopg2-binary>=2.9.0` - PostgreSQL support (optional)

### External Tools

**Required:**
- `nmap` - Network scanning

**Recommended:**
- `msfvenom`, `msfconsole` - Metasploit framework
- `hydra` - Password brute-forcing
- `whatweb` - Web technology detection
- `wappalyzer` - Web application analysis
- `wafw00f` - WAF detection
- `nuclei` - Vulnerability scanner
- `ffuf` / `gobuster` / `feroxbuster` - Directory enumeration
- `sqlmap` - SQL injection testing
- `rustscan` or `masscan` - High-speed port scanning
- `sfcli` - SpiderFoot CLI for OSINT

**Environment Variable Overrides:**

```
NMAP_PATH, MSFCONSOLE_PATH, MSFVENOM_PATH, HYDRA_PATH, GOBUSTER_PATH,
FFUF_PATH, MASSCAN_PATH, RUSTSCAN_PATH, NUCLEI_PATH, WHATWEB_PATH,
WAPPALYZER_PATH, FEROXBUSTER_PATH, WAFW00F_PATH, SQLMAP_PATH, SPIDERFOOT_PATH
```

---

## Installation

### Fast Install Script (macOS/Linux/Windows)

1. Clone the repository and run the installer:
```bash
git clone https://github.com/<your-user>/NetSpear.git
cd NetSpear
chmod +x install.sh
./install.sh
```

- **macOS/Linux**: Installs tools via Homebrew/apt/pacman when available, pip installs Python dependencies, and creates a `netspear` launcher in `/usr/local/bin` or `~/.local/bin`
- **Windows**: Run from Git Bash/WSL/PowerShell. If `winget` is present, the script uses it for packages; creates `netspear.cmd` in `~/AppData/Local/Microsoft/WindowsApps` (or `~/bin`). Add that folder to PATH if needed.

2. Run from anywhere:
```bash
netspear
```

### Manual Installation

1. **Clone the Repository**
```bash
git clone https://github.com/<your-user>/NetSpear.git
cd NetSpear
```

2. **Create Virtual Environment (Recommended)**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install Python Dependencies**
```bash
pip install -r NetSpear/requirements.txt
```

4. **Install External Tools**

Use your system's package manager:
- **Debian/Ubuntu**: `sudo apt install nmap metasploit-framework hydra`
- **macOS**: `brew install nmap`
- **Arch Linux**: `sudo pacman -S nmap`

---

## Usage

### Interactive Mode (Recommended)

```bash
python3 NetSpear/main.py
```

### Command-Line Mode

```bash
python3 NetSpear/main.py --target 192.168.1.10 --scan-type vuln --stealth
```

**Available Flags:**
- `--target <IP>` - Target IP address
- `--scan-type <type>` - Scan type: `quick`, `full`, `vuln`, `stealth`, `deep`
- `--stealth` - Enable stealth mode
- `--proxy <url>` - Proxy URL (e.g., `socks5://127.0.0.1:9050`)

**Help:**
```bash
python3 NetSpear/main.py -h
```

### REST API Server

Start the REST API server from the menu (option 62) or directly:

```python
from NetSpear.api import run_api_server
from NetSpear.main import NetSpearNetworkAnalyzer

analyzer = NetSpearNetworkAnalyzer()
run_api_server(host="127.0.0.1", port=8000, analyzer=analyzer)
```

API Documentation available at: `http://127.0.0.1:8000/docs`

---

## Interactive Menu System

NetSpear v2.0 features a clean, collapsible menu interface. Sections can be expanded/collapsed for better organization.

### Menu Structure

```
[ 1 — RECONNAISSANCE ]
  01. Passive Reconnaissance (OSINT)
  02. Active Reconnaissance (Network Scan)
  03. Comprehensive Target Analysis
  04. OSINT Intelligence Gathering

[ 2 — SCANNING ]
  10. Quick Port Scan
  11. Comprehensive Port Scan
  12. Vulnerability Assessment
  13. Stealth Port Scan
  14. Multi-Target Scan

[ 3 — EXPLOITATION & TESTING ]
  20. Generate Payloads
  21. Generate Payload Pack (mode-aware)
  22. Credential Testing (mode-aware)
  [3+] ▶ Show Advanced Exploitation

[ 4 — REPORTING ]
  30. Generate Report
  31. View Gathered Intelligence
  [4+] ▶ Show Advanced Reporting

[ 5 — CONFIGURATION / SYSTEM ]
  40. Configure Scan Mode
  41. Reset Target
  42. Plugin Management (BETA)
  43. Create Config File
  [5+] ▶ Show Advanced Features (BETA)
  00. Exit
```

### Expanding Sections

To view advanced options, type the section expander code:

- **Type `3+`** - Show/hide Advanced Exploitation (SYN Flood, MAC Spoofing, ARP/DNS Poisoning)
- **Type `4+`** - Show/hide Advanced Reporting (Archive, Clear Reports)
- **Type `5+`** - Show/hide Advanced Features (BETA):
  - 50. Session Management (BETA)
  - 51. Credential Management (BETA)
  - 52. Post-Exploitation (BETA)
  - 53. Workflow Automation (BETA)
  - 54. Vulnerability Prioritization (BETA)
  - 55. Network Topology (BETA)
  - 56. Evidence Collection (BETA)
  - 57. Cloud Enumeration (BETA)
  - 58. Scan Scheduling (BETA)
  - 59. Notifications (BETA)
  - 60. Wordlist Management (BETA)
  - 61. Scanner Integration (BETA)
  - 62. Start API Server (BETA)

---

## Configuration

### Configuration Files

NetSpear supports YAML and JSON configuration files. Create one using menu option 43 or manually:

**Configuration File Locations** (searched in order):
1. `~/.netspear/config.yaml`
2. `~/.netspear/config.json`
3. `./netspear.yaml`
4. `./netspear.json`
5. `NetSpear/config.yaml`
6. `NetSpear/config.json`

**Example Configuration** (`~/.netspear/config.yaml`):

```yaml
version: "2.0"
tool_paths:
  nmap: "nmap"
  msfvenom: "msfvenom"
  hydra: "hydra"
reports_dir: "~/.netspear/reports"
max_workers: 8
max_scan_timeout: 300
logging:
  level: "INFO"
  format: "text"  # or "json"
  file: "~/.netspear/netspear.log"
scan_defaults:
  mode: "SAFE"
  stealth: false
database:
  url: null  # null for SQLite, or "postgresql://user:pass@host/db"
  path: "~/.netspear/netspear.db"
```

### Database Configuration

**SQLite (Default):**
- Automatically created at `~/.netspear/netspear.db`
- No additional setup required

**PostgreSQL:**
```bash
export NETSPEAR_DB_URL="postgresql://user:password@localhost/netspear"
```

---

## Database Features

NetSpear v2.0 includes comprehensive database persistence:

### Stored Data

- **Scans** - Complete scan results with timestamps
- **Ports** - Port scan data with service versions
- **Vulnerabilities** - CVE data with severity and CVSS scores
- **Credentials** - Encrypted credential storage
- **Sessions** - Active exploitation sessions
- **Network Topology** - Network relationships and connections
- **Evidence** - Screenshots and proof-of-concept files
- **Workflows** - Workflow definitions and execution history
- **Notifications** - Alert history

### Database Access

The database is automatically initialized on first run. Access via the API or through the menu system.

---

## 🔌 REST API

NetSpear v2.0 includes a full REST API for automation:

### Endpoints

- `GET /` - API information
- `GET /health` - Health check
- `POST /api/v1/scans` - Create and execute scan
- `GET /api/v1/scans` - List all scans
- `GET /api/v1/scans/{uuid}` - Get scan details
- `GET /api/v1/vulnerabilities` - List vulnerabilities
- `POST /api/v1/credentials` - Add credential
- `GET /api/v1/credentials` - List credentials
- `GET /api/v1/sessions` - List active sessions
- `POST /api/v1/workflows` - Create workflow
- `POST /api/v1/workflows/{uuid}/execute` - Execute workflow

### API Documentation

Interactive API documentation available at `/docs` when the API server is running.

---

## Advanced Features

### Session Management

Track and manage active exploitation sessions:
- Create session records for Meterpreter, shell, SSH sessions
- Execute commands and log output
- System enumeration through sessions
- Session lifecycle management

### Credential Management

Secure credential storage with encryption:
- Encrypted password storage using Fernet
- Credential reuse across scans
- Credential spraying support
- Password analysis and statistics

### Post-Exploitation Framework

Comprehensive post-exploitation capabilities:
- System enumeration (OS, network, users, processes)
- Privilege escalation detection
- Persistence establishment
- Lateral movement support
- Data exfiltration

### Workflow Automation

JSON-defined playbooks:
- Chain multiple operations
- Conditional execution
- Parallel task execution
- Workflow execution tracking

### Network Topology Mapping

Automatic network relationship mapping:
- Build topology from scan data
- Visualize network relationships
- Find attack paths between hosts
- Export to JSON, DOT, GraphML formats

### Vulnerability Prioritization

Risk-based vulnerability prioritization:
- CVSS score calculation
- Risk score with asset criticality
- Remediation priority ranking
- Batch prioritization

---

## Project Structure

```
NetSpear/
├── main.py                    # Main CLI entry point
├── database.py                # Database models and persistence
├── api.py                     # REST API endpoints
├── session_manager.py         # Session management
├── credential_manager.py      # Credential management
├── post_exploitation.py       # Post-exploitation framework
├── workflow_engine.py         # Workflow automation
├── vulnerability_scorer.py    # Vulnerability prioritization
├── topology_mapper.py         # Network topology mapping
├── evidence_collector.py      # Evidence collection
├── cloud_enumeration.py       # Cloud platform enumeration
├── scheduler.py               # Scan scheduling
├── notifier.py                # Notification system
├── wordlist_manager.py        # Wordlist management
├── scanner_integration.py     # External scanner integration
├── network_scanning.py        # Nmap engine + prescan logic
├── payloads.py                # Payload generator
├── attacks.py                 # Offensive modules
├── exploits.py                # Exploit mapper + MSF integration
├── reporting.py               # HTML/JSON report builder
├── enhanced_recon.py          # Enhanced reconnaissance
├── config_loader.py           # Configuration management
├── structured_logging.py      # Structured logging system
├── progress_tracker.py        # Progress tracking
├── error_handler.py           # Error handling utilities
├── plugin_system.py           # Plugin architecture
├── utils.py                   # Helper functions
├── config.py                  # Tool paths and defaults
├── requirements.txt           # Python dependencies
├── plugins/                   # Plugin directory
├── Reports/                   # Generated reports
└── templates/                 # Report templates
```

---

## Scan Profiles

**Quick Scan:**
```
-F -T5 --max-rtt-timeout 50ms
```

**Full Scan:**
```
-p- -A -T5 --osscan-guess
```

**Vulnerability Scan:**
```
--script=vuln -T5 --min-rate 3000
```

**Stealth Scan:**
```
-sS -T2 --max-retries 1 -Pn --spoof-mac 0
```

**Deep Scan:**
```
-sV -sC -O -T5 --min-rate 2000
```

---

## Security Considerations

### Credential Encryption

- Credentials are encrypted using Fernet symmetric encryption
- **IMPORTANT**: Change the default encryption key in production
- Encryption key should be stored securely (environment variable or key management system)

### Database Security

- SQLite databases should have proper file permissions (600)
- PostgreSQL should use strong authentication
- Database files contain sensitive information - secure appropriately

### API Security

- REST API currently has no authentication - add authentication in production
- Use HTTPS in production environments
- Implement rate limiting and access controls

---

## Plugin System

NetSpear supports plugins for extending functionality. See `PLUGINS.md` for plugin development guide.

Plugin types:
- **ReconPlugin** - Extend reconnaissance capabilities
- **ScanPlugin** - Add custom scanning methods
- **ReportPlugin** - Custom report formats

---

## Reporting

NetSpear generates comprehensive reports in multiple formats:

- **HTML Reports** - Dark mode, interactive, includes:
  - Exposure scores
  - Open ports and services
  - CVE information
  - Web anomalies
  - Recommendations
  - Network topology (when available)

- **JSON Reports** - Machine-readable format for automation

Reports are stored in the `Reports/` directory and can be archived automatically.

---

## Troubleshooting

### Database Issues

If database initialization fails:
1. Check file permissions on `~/.netspear/` directory
2. For PostgreSQL, verify connection string and permissions
3. Check logs in `~/.netspear/netspear.log`

### API Server Issues

If API server fails to start:
1. Check if port 8000 is available
2. Verify FastAPI and uvicorn are installed
3. Check firewall settings

### Tool Not Found Errors

1. Verify external tools are installed and in PATH
2. Use environment variables to override tool paths
3. Check configuration file tool_paths section

---

## Contributing

Contributions are welcome! Please see `CONTRIBUTING.md` for guidelines.

---

## License

See `License` file for details.

---

## Maintainer

**© OpenNET LLC — Cybersecurity Division**  
Advanced tools for secure networks, enterprise defense, and professional penetration testing.

If you use NetSpear in research or assessments, please attribute:  
"NetSpear Network Analyzer v2.0 — OpenNET LLC"

---

## Documentation

- `CONFIG.md` - Configuration guide
- `PLUGINS.md` - Plugin development guide
- `CHANGELOG_v2.0.md` - Version 2.0 changelog
- `IMPLEMENTATION_SUMMARY.md` - Feature implementation summary

---

## Beta Features

Features marked with **(BETA)** are experimental and may have limitations:
- Session Management
- Credential Management
- Post-Exploitation Framework
- Workflow Automation
- Vulnerability Prioritization
- Network Topology
- Evidence Collection
- Cloud Enumeration
- Scan Scheduling
- Notifications
- Wordlist Management
- Scanner Integration
- REST API

These features are actively developed and may change in future versions.

---

**NetSpear v2.0 - Taking Network Security Assessment to the Next Level**
