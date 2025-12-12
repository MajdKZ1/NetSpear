import ipaddress
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlparse

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

def validate_port(port: Union[int, str]) -> bool:
    """Validate that a port number is in the valid range (1-65535)."""
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return True
        else:
            print(WHITE + f"Invalid port number: {port_num}. Port must be between 1 and 65535." + RESET)
            return False
    except (ValueError, TypeError):
        print(WHITE + f"Invalid port format: {port}" + RESET)
        return False

def validate_url(url: str) -> bool:
    """Validate that a string is a valid URL."""
    if not url or not isinstance(url, str):
        return False
    
    # Add http:// if no scheme is present
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        result = urlparse(url)
        # Check if it has at least a netloc (domain)
        if result.netloc:
            return True
        return False
    except Exception:
        return False

def validate_file_path(file_path: str, must_exist: bool = True) -> bool:
    """Validate that a file path is valid and optionally exists."""
    if not file_path or not isinstance(file_path, str):
        return False
    
    try:
        path = Path(file_path)
        if must_exist:
            return path.exists() and path.is_file()
        else:
            # Just check if it's a valid path format
            return True
    except Exception:
        return False
