import ipaddress
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Optional

WHITE = "\033[97m"
RESET = "\033[0m"

def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        private_ranges = ["127.", "192.168.", "10.", "172.16.", "169.254."]
        if any(ip.startswith(r) for r in private_ranges):
            print(WHITE + "⚠️ Warning: Target is a private/local IP. Are you sure? (y/n): " + RESET, end='')
            return input().strip().lower() == "y"
        return True
    except ValueError:
        print(WHITE + "Invalid IP address format." + RESET)
        return False

def check_privileges() -> bool:
    try:
        if os.geteuid() != 0:
            print(WHITE + "This operation requires root privileges. Run with sudo." + RESET)
            return False
        return True
    except AttributeError:
        # Windows compatibility: no geteuid.
        return True

def detect_primary_interface() -> Optional[str]:
    """Best-effort detection of a usable network interface for MAC spoofing."""
    system = platform.system()
    if system == "Linux":
        sysfs = Path("/sys/class/net")
        if sysfs.exists():
            candidates = sorted(p.name for p in sysfs.iterdir() if p.is_dir() and p.name != "lo")
            for name in candidates:
                try:
                    state = (sysfs / name / "operstate").read_text().strip()
                    if state == "up":
                        return name
                except OSError:
                    continue
            if candidates:
                return candidates[0]
    if system == "Darwin":
        return "en0"
    return None

def exit_cleanly() -> None:
    print(WHITE + "Shutting down the application safely." + RESET)
    logging.info("Application terminated successfully.")
    sys.exit(0)
