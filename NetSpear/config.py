import os
from pathlib import Path

# Centralized defaults for tool paths and file locations. Override with env vars if needed.
DEFAULT_TOOL_PATHS = {
    "nmap": os.getenv("NMAP_PATH", "nmap"),
    "msfvenom": os.getenv("MSFVENOM_PATH", "msfvenom"),
    "msfconsole": os.getenv("MSFCONSOLE_PATH", "msfconsole"),
    "hydra": os.getenv("HYDRA_PATH", "hydra"),
    "gobuster": os.getenv("GOBUSTER_PATH", "gobuster"),
    "feroxbuster": os.getenv("FEROXBUSTER_PATH", "feroxbuster"),
    "whatweb": os.getenv("WHATWEB_PATH", "whatweb"),
    "wappalyzer": os.getenv("WAPPALYZER_PATH", "wappalyzer"),
    "ffuf": os.getenv("FFUF_PATH", "ffuf"),
    "masscan": os.getenv("MASSCAN_PATH", "masscan"),
    "rustscan": os.getenv("RUSTSCAN_PATH", "rustscan"),
    "nuclei": os.getenv("NUCLEI_PATH", "nuclei"),
    "wafw00f": os.getenv("WAFW00F_PATH", "wafw00f"),
    "sqlmap": os.getenv("SQLMAP_PATH", "sqlmap"),
    "spiderfoot": os.getenv("SPIDERFOOT_PATH", "sfcli"),
}

# Where reports and archives live.
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = Path(os.getenv("ECHELONX_REPORTS_DIR", BASE_DIR / "Reports"))
ARCHIVE_DIR = REPORTS_DIR / "Archive"

# Archive/cleanup behavior.
ARCHIVE_GRACE_SECONDS = 5  # Do not move/delete files modified in the last few seconds.

# Scan defaults.
MAX_SCAN_TIMEOUT = 300
MAX_WORKERS = max(1, os.cpu_count() * 2 if os.cpu_count() else 4)

# Wordlist defaults for directory enumeration
DEFAULT_WORDLIST_PATH = os.getenv(
    "GOBUSTER_WORDLIST",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
)

ALTERNATIVE_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
]
