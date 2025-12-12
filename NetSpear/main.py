#!/usr/bin/env python3
"""
NetSpear Network Analyzer - Main Entry Point

A comprehensive network security assessment framework for authorized penetration testing.
Built by OpenNET LLC.
"""
import argparse
import random
import subprocess
import os
import sys
import platform
import logging
import threading
import time
import socket
import json
import shutil
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Any, Optional, List, Dict, Tuple
from pathlib import Path

# Allow running the script from any working directory by forcing cwd to the file's directory.
PROJECT_ROOT = Path(__file__).resolve().parent
if Path.cwd() != PROJECT_ROOT:
    os.chdir(PROJECT_ROOT)
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DEFAULT_TOOL_PATHS
from utils import (
    WHITE, RESET, setup_logging, exit_cleanly, check_privileges, 
    detect_primary_interface, validate_ip, validate_port, validate_url, validate_file_path
)
from error_handler import QuickError, safe_file_check, safe_tool_check
from progress_tracker import ProgressTracker, ProgressStage
from network_scanning import NetworkScanner
from payloads import PayloadGenerator
from attacks import NetworkAttacker
from reporting import ReportGenerator
from exploits import ExploitRunner
from enhanced_recon import EnhancedReconnaissance
from config_loader import ConfigLoader, create_default_config
from structured_logging import setup_structured_logging, get_logger
from plugin_system import PluginManager, ReconPlugin, ScanPlugin, ReportPlugin
from database import init_database, get_db_manager
from session_manager import SessionManager
from credential_manager import CredentialManager
from post_exploitation import PostExploitationFramework
from workflow_engine import WorkflowEngine
from vulnerability_scorer import VulnerabilityScorer
from topology_mapper import TopologyMapper
from evidence_collector import EvidenceCollector
from cloud_enumeration import CloudEnumerator
from scheduler import ScanScheduler
from notifier import NotificationManager
from wordlist_manager import WordlistManager
from scanner_integration import ScannerIntegration
from api import set_analyzer, run_api_server

# Define NetSpear Purple options
NETSPEAR_PURPLE_TRUECOLOR = "\033[38;2;122;6;205m"  # NetSpear Purple #7A06CD (RGB: 122, 6, 205)
NETSPEAR_PURPLE_FALLBACK = "\033[95m"               # Bright magenta fallback

# Choose the color based on preference (try truecolor first, fallback if it looks gray)
NETSPEAR_PURPLE = NETSPEAR_PURPLE_TRUECOLOR  # Switch to NETSPEAR_PURPLE_FALLBACK if gray persists

MODE_COLORS = {
    "SAFE": "\033[92m",
    "STEALTH": "\033[96m",
    "AGGRESSIVE": "\033[93m",
    "INTENSIVE": "\033[95m",
    "COMPREHENSIVE": "\033[91m",
}

MODE_LABELS = {
    "SAFE": "Safe Scan",
    "STEALTH": "Stealth Scan",
    "AGGRESSIVE": "Standard Scan",
    "INTENSIVE": "Intensive Scan",
    "COMPREHENSIVE": "Comprehensive Scan",
}

class NetSpearNetworkAnalyzer:
    """
    Main NetSpear Network Analyzer class.
    
    Provides an interactive CLI for network reconnaissance, scanning, exploitation,
    and reporting. Integrates multiple security tools including Nmap, Metasploit,
    Hydra, and various web enumeration tools.
    
    Attributes:
        scanner: NetworkScanner instance for port and service scanning
        payload_generator: PayloadGenerator instance for creating payloads
        attacker: NetworkAttacker instance for network attacks
        reporter: ReportGenerator instance for creating reports
        exploit_runner: ExploitRunner instance for vulnerability exploitation
        mode: Current operation mode (SAFE, STEALTH, AGGRESSIVE, INTENSIVE, COMPREHENSIVE)
        current_target_info: Dictionary storing current target information
    """
    
    def __init__(self):
        # Load configuration
        self.config_loader = ConfigLoader()
        self.tool_paths = self.config_loader.get_tool_paths()
        
        # Setup structured logging
        log_config = self.config_loader.get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO").upper(), logging.INFO)
        log_format = log_config.get("format", "text")
        log_file = Path(log_config.get("file")) if log_config.get("file") else None
        setup_structured_logging(log_level, log_format, log_file)
        self.logger = get_logger(__name__)
        
        # Initialize database
        db_url = os.getenv("NETSPEAR_DB_URL")
        db_path = Path(os.getenv("NETSPEAR_DB_PATH")) if os.getenv("NETSPEAR_DB_PATH") else None
        self.db_manager = init_database(db_url, db_path)
        
        # Initialize components
        self.scanner = NetworkScanner()
        self.payload_generator = PayloadGenerator()
        self.attacker = NetworkAttacker()
        self.reporter = ReportGenerator(base_dir=self.config_loader.get_reports_dir())
        self.exploit_runner = ExploitRunner()
        self.args = self._parse_args()
        self.mode = self.config_loader.get("scan_defaults", {}).get("mode", "SAFE")
        self.advanced_mode = False
        self.current_target_info: Dict[str, Any] = {}
        self.enhanced_recon = EnhancedReconnaissance(self.tool_paths)
        self.expanded_sections: Dict[str, bool] = {
            "advanced": False,
            "exploitation": False,
            "reporting": False,
        }
        
        # Initialize new feature modules
        self.session_manager = SessionManager()
        self.credential_manager = CredentialManager()
        self.post_exploit = PostExploitationFramework(self.session_manager)
        self.workflow_engine = WorkflowEngine(analyzer=self)
        self.vuln_scorer = VulnerabilityScorer()
        self.topology_mapper = TopologyMapper()
        self.evidence_collector = EvidenceCollector()
        self.cloud_enumerator = CloudEnumerator(self.tool_paths)
        self.scan_scheduler = ScanScheduler(analyzer=self)
        self.notifier = NotificationManager()
        self.wordlist_manager = WordlistManager()
        self.scanner_integration = ScannerIntegration()
        
        # Initialize plugin system
        self.plugin_manager = PluginManager()
        self.plugin_manager.set_context({
            "scanner": self.scanner,
            "reporter": self.reporter,
            "tool_paths": self.tool_paths,
            "config": self.config_loader.config,
            "db": self.db_manager,
        })
        plugins_loaded = self.plugin_manager.load_plugins()
        if plugins_loaded > 0:
            self.logger.info(f"Loaded {plugins_loaded} plugin(s)")
        
        self._clear_screen()

    def _mode_label(self, mode: Optional[str] = None) -> str:
        mode = (mode or self.mode or "").upper()
        return MODE_LABELS.get(mode, mode.title() if mode else "-")

    def _mode_payload_pack_label(self) -> str:
        mode = (self.mode or "").upper()
        variants = {
            "SAFE": "Generate Payload Pack (Safe payloads)",
            "STEALTH": "Generate Payload Pack (Stealthy payloads)",
            "AGGRESSIVE": "Generate Payload Pack (Standard payloads)",
            "INTENSIVE": "Generate Payload Pack (Intensive payloads)",
            "COMPREHENSIVE": "Generate Payload Pack (Comprehensive payloads)",
        }
        return variants.get(mode, "Generate Payload Pack")

    def _mode_brute_label(self) -> str:
        mode = (self.mode or "").upper()
        variants = {
            "SAFE": "Credential Testing (safe timing)",
            "STEALTH": "Credential Testing (stealth timing)",
            "AGGRESSIVE": "Credential Testing (standard timing)",
            "INTENSIVE": "Credential Testing (intensive timing)",
            "COMPREHENSIVE": "Credential Testing (comprehensive timing)",
        }
        return variants.get(mode, "Credential Testing")

    def _cache_target_minimal(self, ip: Optional[str], label: str) -> None:
        if not ip:
            return
        now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        self.current_target_info = {
            "ip": ip,
            "label": label,
            "mode": self.mode,
            "open_ports": self.current_target_info.get("open_ports", 0),
            "vulns": self.current_target_info.get("vulns", 0),
            "web_anomalies": self.current_target_info.get("web_anomalies", 0),
            "last_action": now,
            "last_scan": self.current_target_info.get("last_scan", "None"),
        }

    def _parse_args(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(description="NetSpear Network Analyzer (Built by OpenNET LLC)")
        parser.add_argument("--target", help="Target IP address")
        parser.add_argument("--scan-type", choices=["quick", "full", "vuln", "stealth"], default="quick")
        parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
        parser.add_argument("--proxy", help="Proxy address (e.g., socks5://127.0.0.1:9050)")
        return parser.parse_args()

    def _set_mode(self, mode: str) -> None:
        mode = mode.upper()
        if mode not in MODE_COLORS:
            print(WHITE + f"Unknown mode '{mode}'. Keeping current mode: {self.mode}." + RESET)
            return
        self.mode = mode
        # Advanced tiers unlock comprehensive suggestions.
        self.advanced_mode = mode in {"COMPREHENSIVE", "INTENSIVE", "AGGRESSIVE"}
        color = MODE_COLORS.get(mode, WHITE)
        print(color + f"[+] Mode set to {self._mode_label(mode)}" + RESET)
        if self.current_target_info:
            self.current_target_info["mode"] = mode

    def _update_current_target(self, ip: str, label: str, scan_result: Dict[str, Any], vulns: List[Dict[str, Any]], web_enum: Optional[Dict[str, Any]] = None) -> None:
        if not ip:
            return
        ports = scan_result.get("ports", []) if scan_result else []
        open_ports = [p for p in ports if p.get("state") == "open"]
        web_enum = web_enum or {}
        web_anoms = len(web_enum.get("errors") or []) + len(web_enum.get("admin_hits") or []) + len(web_enum.get("dir_enum") or []) + len(web_enum.get("nuclei") or []) + len(web_enum.get("sqlmap") or [])
        self.current_target_info = {
            "ip": ip,
            "label": label,
            "mode": self.mode,
            "open_ports": len(open_ports),
            "vulns": len(vulns or []),
            "web_anomalies": web_anoms,
            "last_action": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "last_scan": (scan_result or {}).get("timestamp") or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }

    def _prompt_target(self, default_ip: Optional[str]) -> Optional[str]:
        prompt = "Enter target IP"
        if default_ip:
            prompt += f" (press Enter to reuse {default_ip})"
        prompt += ": "
        val = input(WHITE + prompt + RESET).strip()
        if not val and default_ip:
            return default_ip
        return val or None

    def _show_gathered_info(self) -> None:
        info = self.current_target_info
        if not info:
            print(WHITE + "No target cached yet. Run a scan or recon first." + RESET)
            return
        print(WHITE + "\n=== Gathered Info ===" + RESET)
        print(WHITE + f"Target: {info.get('ip','-')} ({info.get('label','-')})" + RESET)
        print(WHITE + f"Mode: {self._mode_label(info.get('mode'))}" + RESET)
        print(WHITE + f"Open ports: {info.get('open_ports',0)} | Vulnerabilities: {info.get('vulns',0)} | Web anomalies: {info.get('web_anomalies',0)}" + RESET)
        print(WHITE + f"Last action: {info.get('last_action','-')}" + RESET)

    def _reset_target(self) -> None:
        self.current_target_info = {}
        print(WHITE + "Current target cleared." + RESET)

    def banner(self) -> None:
        print(f"""{NETSPEAR_PURPLE}
              
      ,__,
     (•.•)  ----►
    <)   )╯  NSP
     ""  ""

{NETSPEAR_PURPLE}          NetSpear Network Analyzer{RESET}
{WHITE}WARNING: Authorized ethical testing only. Unauthorized use is strictly prohibited.{RESET}
{NETSPEAR_PURPLE}Built and developed by © OpenNET LLC — All rights reserved.{RESET}
""")
        if input(WHITE + "Do you agree to use this tool responsibly? (y/n): " + RESET).lower() != "y":
            exit_cleanly()

    def _handle_multi_target_scan(self) -> None:
        targets = input(WHITE + "Enter IPs (comma-separated): " + RESET).split(",")
        results = self.scanner.multi_target_scan(targets, self.args.scan_type, self.args.stealth, self.args.proxy, self.mode)
        for ip, (scan_result, vulnerabilities) in results.items():
            suggestions = self._build_suggestions(scan_result, vulnerabilities)
            self.reporter.add_scan(ip, f"Multi-Target ({self.args.scan_type})", scan_result, vulnerabilities, suggestions)
            self._update_current_target(ip, f"Multi-Target ({self.args.scan_type})", scan_result, vulnerabilities)
            self._print_suggestions(suggestions)

    def _confirm(self, message: str) -> bool:
        """Prompt user for confirmation with proper output flushing."""
        sys.stdout.flush()  # Ensure previous output is displayed
        response = input(WHITE + message + RESET).strip().lower()
        sys.stdout.flush()  # Ensure response is processed
        return response == "y"

    def _build_suggestions(self, scan_result: Dict[str, str], vulnerabilities: List[Dict[str, str]]) -> List[str]:
        ports = scan_result.get("ports", [])
        if not ports:
            return []
        suggestions: List[str] = []
        for port in ports:
            if port.get("state") != "open":
                continue
            num = port.get("port")
            service = port.get("service", "").lower()
            proto = port.get("protocol", "").lower()
            if num in {80, 443} or service in {"http", "https"}:
                suggestions.append("Web (80/443) open: enumerate dirs (gobuster/feroxbuster), fingerprint tech (whatweb/wappalyzer), hunt SQLi/XSS/RCE, check admin panels.")
                suggestions.append("Web app review: session flags (HttpOnly/Secure/SameSite), auth flows/MFA, TLS config/ciphers, outdated components, access controls/request filtering.")
                if self.advanced_mode:
                    suggestions.append("Advanced: run nmap --script vuln/nikto, probe uploads for webshell, test weak HTTP auth, try default creds on common panels.")
            if num == 22 or service == "ssh":
                suggestions.append("SSH open: check weak creds and banner versions; brute with hydra if allowed; enumerate authorized_keys if filesystem access found.")
            if num == 21 or service == "ftp":
                suggestions.append("FTP open: test anonymous login, list writable dirs, attempt put/get for dropper; check for cleartext creds reuse.")
            if num == 23 or service == "telnet":
                suggestions.append("Telnet open: banner leakage and vendor defaults; hydra brute with device-specific defaults.")
            if num in {139, 445} or service in {"smb", "microsoft-ds"}:
                suggestions.append("SMB open: enum shares (smbclient, crackmapexec), check null sessions, run nmap smb-vuln* (EternalBlue/SMBghost), look for SMB signing off.")
            if num in {3389} or service == "ms-wbt-server":
                suggestions.append("RDP open: verify NLA; on legacy Windows check BlueKeep/CVE-2019-0708; consider pass-the-hash with valid creds.")
            if num in {3306} or service == "mysql":
                suggestions.append("MySQL open: test weak creds; if FILE priv, write UDF for code exec; check version for known CVEs.")
            if num in {1433} or service == "mssql":
                suggestions.append("MSSQL open: default/weak creds, enable xp_cmdshell for OS exec; check for SA password reuse.")
            if num in {5432} or service == "postgresql":
                suggestions.append("Postgres open: weak creds; abuse COPY TO PROGRAM for code exec if allowed; check pg_hba.conf for wide access.")
            if num in {6379} or service == "redis":
                suggestions.append("Redis open: unauthenticated? Use CONFIG SET dir/dbfilename to plant SSH key or cron reverse shell.")
            if num in {11211} or service == "memcached":
                suggestions.append("Memcached open: unauthenticated read/write; inspect for secrets; note amplification risk.")
            if num in {161} or service == "snmp":
                suggestions.append("SNMP open: try public/private communities; dump users/config; if write allowed, change routes or set creds.")
            if num in {5900} or service == "vnc":
                suggestions.append("VNC open: test for no-password/weak password; check for security type None.")
            if num in {25, 587} or service in {"smtp", "smtps"}:
                suggestions.append("SMTP open: VRFY/EXPN user enum; check open relay; inspect mail software for known CVEs.")
            if num in {389, 636} or service in {"ldap", "ldaps"}:
                suggestions.append("LDAP open: attempt null bind; enumerate users/groups; check for anonymous access to sensitive attributes.")
            if num in {9200, 9300} or "elasticsearch" in service:
                suggestions.append("Elasticsearch open: test for unauthenticated access; run _cat APIs; check for RCE CVEs on old versions.")
            if num in {27017, 27018} or "mongo" in service:
                suggestions.append("MongoDB open: check for unauthenticated access; dump dbs; look for exposed credentials.")
        if vulnerabilities and self.advanced_mode:
            suggestions.append("Vuln scan flagged issues—chain with Metasploit modules suggested above for rapid exploitation.")
        return suggestions

    def _resolve_target_input(self, target_type: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Return (display_name, resolved_ip, url_for_http, raw_input)."""
        prompt_map = {
            "website": "Enter website URL (e.g., https://example.com): ",
            "ip": "Enter target IP: ",
            "server": "Enter hostname/server (e.g., intranet.local): ",
        }
        raw = input(WHITE + prompt_map[target_type] + RESET).strip()
        if not raw:
            return None, None, None, None

        url = None
        hostname = raw
        if target_type == "website":
            parsed = urlparse(raw if "://" in raw else "http://" + raw)
            hostname = parsed.hostname or raw
            url = parsed.geturl() if parsed.hostname else ("http://" + raw)
        elif target_type == "server":
            hostname = raw.split("/")[0]
            url = f"http://{hostname}"

        resolved_ip: Optional[str] = None
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                resolved_ip = hostname
            except ValueError:
                try:
                    resolved_ip = socket.gethostbyname(hostname)
                except socket.gaierror:
                    print(WHITE + f"Could not resolve {hostname}. Check the hostname or DNS." + RESET)
                    return hostname, None, url, raw

        return hostname, resolved_ip, url, raw

    def _geo_lookup(self, ip: str) -> Dict[str, str]:
        if not ip:
            return {}
        try:
            with urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,mobile,proxy,hosting,query,timezone", timeout=6) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "timezone": data.get("timezone"),
                        "proxy": data.get("proxy"),
                        "hosting": data.get("hosting"),
                    }
        except (URLError, HTTPError) as exc:
            logging.debug("Geo lookup failed for %s: %s", ip, exc)
        except TimeoutError as exc:
            logging.debug("Geo lookup timeout for %s: %s", ip, exc)
        except Exception as exc:
            logging.warning("Unexpected error during geo lookup: %s", exc)
        return {}

    def _http_fingerprint(self, url: Optional[str]) -> Dict[str, str]:
        if not url:
            return {}
        try:
            req = Request(url, method="HEAD", headers={"User-Agent": "NetSpear-Intel/1.0"})
            with urlopen(req, timeout=8) as resp:
                headers = {k: v for k, v in resp.headers.items()}
                return {
                    "url": url,
                    "final_url": resp.geturl(),
                    "status": getattr(resp, "status", None),
                    "server": headers.get("Server"),
                    "powered_by": headers.get("X-Powered-By"),
                    "content_type": headers.get("Content-Type"),
                }
        except (URLError, HTTPError) as exc:
            logging.debug("HTTP fingerprint failed for %s: %s", url, exc)
            return {"url": url, "error": str(exc)}
        except TimeoutError as exc:
            logging.debug("HTTP fingerprint timeout for %s: %s", url, exc)
            return {"url": url, "error": f"Timeout: {exc}"}
        except Exception as exc:
            logging.warning("Unexpected error during HTTP fingerprint: %s", exc)
            return {"url": url, "error": str(exc)}

    def _passive_recon(self, ip: Optional[str]) -> None:
        """Perform passive reconnaissance using OSINT sources."""
        if not ip:
            print(QuickError.invalid_input("target", "No target provided"))
            return
        if not validate_ip(ip):
            return
        
        print(WHITE + "Starting passive reconnaissance (OSINT)..." + RESET)
        recon_data = self.enhanced_recon.passive_recon_parallel(ip, "ip")
        
        # Execute recon plugins
        recon_plugins = self.plugin_manager.get_plugins_by_type(ReconPlugin)
        for plugin in recon_plugins:
            try:
                plugin_data = plugin.gather_intel(ip, "ip")
                if plugin_data:
                    recon_data[f"plugin_{plugin.name}"] = plugin_data
            except Exception as e:
                self.logger.error(f"Plugin {plugin.name} failed: {e}")
        
        recon_entry = {
            "input": ip,
            "target": ip,
            "resolved_ip": ip,
            "type": "ip",
            "geo": recon_data.get("geoip", {}),
            "dns": recon_data.get("dns", {}),
            "whois": recon_data.get("whois", {}),
            "shodan": recon_data.get("shodan", {}),
            "http": recon_data.get("http", {}),
            "scan": {},
            "vulnerabilities": [],
            "suggestions": [],
            "web_enum": {},
            "osint": {
                "subdomains": recon_data.get("subdomains", []),
                "certificates": recon_data.get("certificates", {}),
                "errors": recon_data.get("errors", [])
            },
        }
        self.reporter.add_recon(recon_entry)
        self._cache_target_minimal(ip, "Passive Reconnaissance")
        print(WHITE + f"✓ Passive reconnaissance completed for {ip}" + RESET)
        if recon_data.get("errors"):
            print(WHITE + f"  Note: {len(recon_data['errors'])} tool(s) unavailable or failed" + RESET)
        
        # Display quick summary
        if recon_data.get("geoip"):
            geo = recon_data["geoip"]
            if geo.get("country"):
                print(WHITE + f"  Location: {geo.get('city', '')}, {geo.get('country', '')}" + RESET)
        if recon_data.get("subdomains"):
            print(WHITE + f"  Subdomains found: {len(recon_data['subdomains'])}" + RESET)
    
    def _enhanced_osint_recon(self) -> None:
        """Perform comprehensive OSINT reconnaissance on a domain or IP."""
        print(WHITE + "\n=== OSINT Intelligence Gathering ===" + RESET)
        print(WHITE + "[1] IP Address" + RESET)
        print(WHITE + "[2] Domain Name" + RESET)
        print(WHITE + "[3] URL/Website" + RESET)
        choice = input(WHITE + "Select target type (1-3): " + RESET).strip()
        
        target_type_map = {"1": ("ip", "IP Address"), "2": ("domain", "Domain Name"), "3": ("url", "URL/Website")}
        if choice not in target_type_map:
            print(QuickError.invalid_input("target type", "Choose 1, 2, or 3"))
            return
        
        recon_type, type_label = target_type_map[choice]
        target = input(WHITE + f"Enter {type_label}: " + RESET).strip()
        
        if not target:
            print(QuickError.invalid_input("target", "Target cannot be empty"))
            return
        
        if recon_type == "ip" and not validate_ip(target):
            return
        
        print(WHITE + f"\nStarting OSINT intelligence gathering on {target}..." + RESET)
        recon_data = self.enhanced_recon.passive_recon_parallel(target, recon_type)
        
        # Display results
        print(WHITE + "\n=== Reconnaissance Results ===" + RESET)
        
        if recon_data.get("geoip"):
            geo = recon_data["geoip"]
            print(WHITE + "\n[GeoIP Information]" + RESET)
            if geo.get("country"):
                print(WHITE + f"  Country: {geo.get('country')}" + RESET)
            if geo.get("city"):
                print(WHITE + f"  City: {geo.get('city')}" + RESET)
            if geo.get("isp"):
                print(WHITE + f"  ISP: {geo.get('isp')}" + RESET)
            if geo.get("org"):
                print(WHITE + f"  Organization: {geo.get('org')}" + RESET)
        
        if recon_data.get("dns"):
            dns = recon_data["dns"]
            print(WHITE + "\n[DNS Records]" + RESET)
            for record_type, records in dns.items():
                if records:
                    print(WHITE + f"  {record_type}: {', '.join(records[:5])}" + RESET)
        
        if recon_data.get("subdomains"):
            subdomains = recon_data["subdomains"]
            print(WHITE + f"\n[Subdomains Found: {len(subdomains)}]" + RESET)
            for sub in subdomains[:10]:  # Show first 10
                print(WHITE + f"  • {sub}" + RESET)
            if len(subdomains) > 10:
                print(WHITE + f"  ... and {len(subdomains) - 10} more" + RESET)
        
        if recon_data.get("whois"):
            whois = recon_data["whois"]
            print(WHITE + "\n[WHOIS Information]" + RESET)
            for key, values in list(whois.items())[:5]:  # Show first 5 fields
                if values:
                    print(WHITE + f"  {key}: {values[0] if isinstance(values, list) else values}" + RESET)
        
        if recon_data.get("http"):
            http = recon_data["http"]
            print(WHITE + "\n[HTTP Information]" + RESET)
            if http.get("server"):
                print(WHITE + f"  Server: {http.get('server')}" + RESET)
            if http.get("status"):
                print(WHITE + f"  Status: {http.get('status')}" + RESET)
        
        # Save to report
        recon_entry = {
            "input": target,
            "target": target,
            "resolved_ip": target if recon_type == "ip" else None,
            "type": recon_type,
            "geo": recon_data.get("geoip", {}),
            "dns": recon_data.get("dns", {}),
            "whois": recon_data.get("whois", {}),
            "shodan": recon_data.get("shodan", {}),
            "http": recon_data.get("http", {}),
            "scan": {},
            "vulnerabilities": [],
            "suggestions": [],
            "web_enum": {},
            "osint": {
                "subdomains": recon_data.get("subdomains", []),
                "certificates": recon_data.get("certificates", {}),
                "errors": recon_data.get("errors", [])
            },
        }
        self.reporter.add_recon(recon_entry)
        if recon_type == "ip":
            self._cache_target_minimal(target, "OSINT Intelligence Gathering")
        
        if recon_data.get("errors"):
            print(WHITE + f"\n⚠ Note: {len(recon_data['errors'])} tool(s) unavailable or failed" + RESET)
        
        print(WHITE + "\n✓ OSINT intelligence gathering completed!" + RESET)

    def _active_recon(self, ip: Optional[str]) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
        if not ip:
            return {}, []
        return self.scanner.run_nmap_scan(ip, "deep", self.args.stealth, self.args.proxy, self.mode)

    def information_gathering(self) -> None:
        print(WHITE + "\n=== Target Type ===" + RESET)
        print(WHITE + "[1] Website/URL" + RESET)
        print(WHITE + "[2] IP Address" + RESET)
        print(WHITE + "[3] Hostname/Server" + RESET)
        choice = input(WHITE + "Select target type (1-3): " + RESET).strip()
        target_type = {"1": "website", "2": "ip", "3": "server"}.get(choice)
        if not target_type:
            print(WHITE + "Invalid target type." + RESET)
            return

        hostname, resolved_ip, url, raw = self._resolve_target_input(target_type)
        if not resolved_ip:
            print(WHITE + "Cannot proceed without a valid IP." + RESET)
            return
        if not validate_ip(resolved_ip):
            return

        # Use comprehensive reconnaissance for better results
        print(WHITE + "Starting comprehensive target analysis..." + RESET)
        recon_type = "domain" if target_type in {"website", "server"} else "ip"
        recon_target = hostname if target_type in {"website", "server"} else resolved_ip
        enhanced_recon_data = self.enhanced_recon.passive_recon_parallel(recon_target, recon_type)
        
        geo = enhanced_recon_data.get("geoip", self._geo_lookup(resolved_ip))
        http_info = enhanced_recon_data.get("http", self._http_fingerprint(url if target_type in {"website", "server"} else None))

        scan_result, vulnerabilities = self.scanner.run_nmap_scan(resolved_ip, "deep", self.args.stealth, self.args.proxy, self.mode)
        suggestions = self._build_suggestions(scan_result, vulnerabilities)
        web_enum = self._prompt_web_actions(target_ip=resolved_ip, scan_result=scan_result, auto_prompt=False)
        
        # SpiderFoot OSINT sweep
        spiderfoot_runs: List[Dict[str, Any]] = []
        print()  # Add blank line for clarity
        if self._is_tool_available("spiderfoot") and self._confirm("Run SpiderFoot OSINT sweep? (y/n): "):
            sf_cmd = [self.tool_paths["spiderfoot"], "-s", hostname or resolved_ip, "-max-threads", "10"]
            spiderfoot_runs.append(self._run_cmd_capture(sf_cmd, "spiderfoot osint sweep", timeout=180, show_progress=True))
            suggestions.append("OSINT: review SpiderFoot sweep for additional attack surface.")
        elif not self._is_tool_available("spiderfoot"):
            suggestions.append("SpiderFoot not installed; install for automated OSINT.")
        if scan_result:
            self.reporter.add_scan(resolved_ip, "Recon Deep Scan", scan_result, vulnerabilities, suggestions, web_enum)
            self._update_current_target(resolved_ip, "Recon Deep Scan", scan_result, vulnerabilities, web_enum)
        else:
            self._cache_target_minimal(resolved_ip, "Recon Deep Scan")
        recon_entry = {
            "input": raw,
            "target": hostname,
            "resolved_ip": resolved_ip,
            "type": target_type,
            "geo": geo,
            "dns": enhanced_recon_data.get("dns", {}),
            "whois": enhanced_recon_data.get("whois", {}),
            "shodan": enhanced_recon_data.get("shodan", {}),
            "http": http_info,
            "scan": scan_result,
            "vulnerabilities": vulnerabilities,
            "suggestions": suggestions,
            "web_enum": web_enum or {},
            "osint": {
                "spiderfoot": spiderfoot_runs if spiderfoot_runs else [],
                "subdomains": enhanced_recon_data.get("subdomains", []),
                "certificates": enhanced_recon_data.get("certificates", {}),
                "errors": enhanced_recon_data.get("errors", [])
            },
        }
        self.reporter.add_recon(recon_entry)
        self._print_suggestions(suggestions)
        
        # Exploitation prompt
        if vulnerabilities:
            print()  # Add blank line for clarity
            if self._confirm("Attempt exploitation on detected vulns? (y/n): "):
                self.exploit_vulnerabilities(resolved_ip, vulnerabilities)
        
        # Report export prompt
        print()  # Add blank line for clarity
        if self._confirm("Export recon report now? (y/n): "):
            self.reporter.generate_report()

    def _prompt_web_actions(self, target_ip: str, scan_result: Dict[str, str], auto_prompt: bool = True) -> Dict[str, Any]:
        ports = scan_result.get("ports", []) or []
        http_ports = [p for p in ports if p.get("state") == "open" and (p.get("port") in {80, 443} or p.get("service", "").lower() in {"http", "https"})]
        if not http_ports:
            return {}
        if auto_prompt and not self._confirm("Web service detected (80/443). Run web enumeration now? (y/n): "):
            return {}

        port_entry = http_ports[0]
        port_num = port_entry.get("port")
        scheme = "https" if port_num == 443 or port_entry.get("service", "").lower() == "https" else "http"
        base_url = f"{scheme}://{target_ip}"
        print(WHITE + f"\n[+] Web enumeration starting on {base_url}" + RESET)

        web_enum: Dict[str, Any] = {"base_url": base_url, "fingerprint": [], "dir_enum": [], "admin_hits": [], "errors": [], "waf": [], "nuclei": [], "sqlmap": []}

        # Fingerprint tech
        if self._is_tool_available("whatweb"):
            web_enum["fingerprint"].append(self._run_cmd_capture([self.tool_paths["whatweb"], base_url], "whatweb fingerprint"))
        else:
            msg = "whatweb not found; skipping fingerprint."
            web_enum["errors"].append(msg)
            print(WHITE + msg + RESET)

        if self._is_tool_available("wappalyzer"):
            browser_path = self._find_browser_executable()
            if not browser_path:
                msg = "wappalyzer skipped: no browser driver found (set WAPPALYZER_BROWSER to firefox/chromium)."
                web_enum["errors"].append(msg)
                print(WHITE + msg + RESET)
            else:
                wapp_cmd = [self.tool_paths["wappalyzer"], "-i", base_url]
                result = self._run_cmd_capture(wapp_cmd, "wappalyzer fingerprint", extra_env={"WAPPALYZER_BROWSER": browser_path})
                web_enum["fingerprint"].append(result)
                if result.get("returncode", 1) != 0:
                    web_enum["errors"].append("wappalyzer failed; check browser path or install Firefox/Chromium.")
        else:
            msg = "wappalyzer not found; skipping tech stack detection."
            web_enum["errors"].append(msg)
            print(WHITE + msg + RESET)

        if self._is_tool_available("wafw00f"):
            waf_result = self._run_cmd_capture([self.tool_paths["wafw00f"], base_url], "wafw00f probe")
            web_enum["waf"].append(waf_result)
            stdout = (waf_result.get("stdout") or "").strip()
            if stdout:
                first_line = stdout.splitlines()[0]
                web_enum["errors"].append(f"WAF detection: {first_line}")
        else:
            web_enum["errors"].append("wafw00f not found; skipping WAF detection.")

        # Directory brute-force
        from config import DEFAULT_WORDLIST_PATH, ALTERNATIVE_WORDLISTS
        wordlist = os.getenv("GOBUSTER_WORDLIST", DEFAULT_WORDLIST_PATH)
        
        # Try to find an available wordlist with better error handling
        if not safe_file_check(wordlist, must_exist=True):
            found = False
            for alt_wordlist in ALTERNATIVE_WORDLISTS:
                if safe_file_check(alt_wordlist, must_exist=True):
                    wordlist = alt_wordlist
                    logging.info(f"Using alternative wordlist: {wordlist}")
                    found = True
                    break
            if not found:
                print(QuickError.file_not_found(
                    wordlist, 
                    "Install wordlists: sudo apt install wordlists || Set GOBUSTER_WORDLIST env var"
                ))
                wordlist = None
        
        if wordlist and self._is_tool_available("ffuf"):
            if safe_file_check(wordlist, must_exist=True):
                web_enum["dir_enum"].append(self._run_cmd_capture([self.tool_paths["ffuf"], "-u", base_url.rstrip("/") + "/FUZZ", "-w", wordlist, "-t", "50", "-mc", "200,301,302,401,403"], "ffuf directory scan"))
            else:
                msg = f"Wordlist missing ({wordlist}); skipping ffuf."
                web_enum["errors"].append(msg)
                print(WHITE + msg + RESET)
        elif wordlist and self._is_tool_available("gobuster"):
            if safe_file_check(wordlist, must_exist=True):
                web_enum["dir_enum"].append(self._run_cmd_capture([self.tool_paths["gobuster"], "dir", "-u", base_url, "-w", wordlist, "-q", "-t", "50"], "gobuster directory scan"))
            else:
                msg = f"Wordlist missing ({wordlist}); skipping gobuster."
                web_enum["errors"].append(msg)
                print(WHITE + msg + RESET)
        elif wordlist and self._is_tool_available("feroxbuster"):
            if safe_file_check(wordlist, must_exist=True):
                web_enum["dir_enum"].append(self._run_cmd_capture([self.tool_paths["feroxbuster"], "-u", base_url, "-w", wordlist, "-q"], "feroxbuster directory scan"))
            else:
                msg = f"Wordlist missing ({wordlist}); skipping feroxbuster."
                web_enum["errors"].append(msg)
                print(WHITE + msg + RESET)
        else:
            msg = "No directory brute tool found (gobuster/feroxbuster). Install to enable dir enum."
            web_enum["errors"].append(msg)
            print(WHITE + msg + RESET)

        # Quick admin panel probe via HEAD requests.
        from config import ADMIN_ENDPOINTS
        print(WHITE + "Probing common admin endpoints..." + RESET)
        for path in ADMIN_ENDPOINTS:
            url = base_url + path
            try:
                req = Request(url, method="HEAD", headers={"User-Agent": "NetSpear-AdminProbe/1.0"})
                with urlopen(req, timeout=5) as resp:
                    status = getattr(resp, "status", None)
                    if status and status < 400:
                        msg = f"{url} (status {status})"
                        web_enum["admin_hits"].append(msg)
                        print(WHITE + f"  [+] Potential admin endpoint: {msg}" + RESET)
            except HTTPError as e:
                if e.code in {401, 403}:
                    msg = f"{url} (status {e.code})"
                    web_enum["admin_hits"].append(msg)
                    print(WHITE + f"  [+] Restricted endpoint (possible admin): {msg}" + RESET)
            except (URLError, TimeoutError) as exc:
                web_enum["errors"].append(f"{url} probe failed: {exc}")
                continue

        # Nuclei template scan (HTTP)
        if self._is_tool_available("nuclei"):
            nuclei_cmd = [self.tool_paths["nuclei"], "-u", base_url, "-severity", "low,medium,high,critical", "-nc", "-silent"]
            nuclei_result = self._run_cmd_capture(nuclei_cmd, "nuclei HTTP templates")
            web_enum["nuclei"].append(nuclei_result)
            if nuclei_result.get("returncode", 1) != 0:
                web_enum["errors"].append("nuclei scan failed (check templates/install).")
        else:
            web_enum["errors"].append("nuclei not found; skipping HTTP template scan.")

        # Optional SQLMap hook
        print()  # Add blank line for clarity
        if self._is_tool_available("sqlmap") and self._confirm("Run sqlmap on a URL/param? (y/n): "):
            target_url = input(WHITE + f"Enter target URL (default: {base_url}): " + RESET).strip() or base_url
            sqlmap_cmd = [self.tool_paths["sqlmap"], "-u", target_url, "--batch", "--random-agent", "--level", "1", "--risk", "1"]
            sqlmap_result = self._run_cmd_capture(sqlmap_cmd, f"sqlmap ({target_url})")
            web_enum["sqlmap"].append(sqlmap_result)
            if sqlmap_result.get("returncode", 1) != 0:
                web_enum["errors"].append(f"sqlmap run failed for {target_url}")

        return web_enum


    def _print_suggestions(self, suggestions: List[str]) -> None:
        if not suggestions:
            return
        print(WHITE + "\nAttack suggestions:" + RESET)
        for i, s in enumerate(suggestions, 1):
            print(WHITE + f"  [{i}] {s}" + RESET)

    def _is_tool_available(self, tool_key: str) -> bool:
        """Check if a tool is available with better error handling."""
        cmd = self.tool_paths.get(tool_key, tool_key)
        alias_map = {
            "spiderfoot": [cmd, "sfcli", "spiderfoot", "spiderfoot-cli"],
        }
        candidates = alias_map.get(tool_key, [cmd])
        for candidate in candidates:
            if candidate and shutil.which(candidate):
                self.tool_paths[tool_key] = candidate
                return True
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, timeout=5, check=False)
            if result.returncode == 0 or "version" in result.stdout.lower() or "version" in result.stderr.lower():
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception as e:
            logging.debug(f"Tool check failed for {tool_key}: {e}")
        return False

    def _run_cmd_capture(self, cmd: List[str], desc: str, extra_env: Optional[Dict[str, str]] = None, timeout: int = 120, show_progress: bool = False, requires_sudo: bool = False) -> Dict[str, str]:
        print(WHITE + f"> {desc}: {' '.join(cmd)}" + RESET)

        def _progress_worker(done: threading.Event) -> None:
            bar_len = 28
            percent = 0
            while not done.is_set():
                percent = min(percent + 4, 96)
                filled = int(bar_len * percent / 100)
                bar = "█" * filled + "░" * (bar_len - filled)
                sys.stdout.write(f"\r{NETSPEAR_PURPLE}Task Progress [{bar}] {percent:3d}%{RESET}")
                sys.stdout.flush()
                if percent >= 96:
                    percent = 82
                time.sleep(0.18)
            bar = "█" * bar_len
            sys.stdout.write(f"\r{NETSPEAR_PURPLE}Task Progress [{bar}] 100%{RESET}\n")
            sys.stdout.flush()

        done_event = threading.Event()
        worker: Optional[threading.Thread] = None
        if show_progress:
            worker = threading.Thread(target=_progress_worker, args=(done_event,), daemon=True)
            worker.start()

        try:
            env = os.environ.copy()
            if extra_env:
                env.update(extra_env)
            use_sudo = requires_sudo and hasattr(os, "geteuid") and os.geteuid() != 0
            full_cmd = ["sudo"] + cmd if use_sudo else cmd
            if use_sudo:
                print(WHITE + "Root privileges required. Sudo may prompt for your password." + RESET)
            proc = subprocess.run(
                full_cmd,
                capture_output=not use_sudo,
                text=True,
                check=False,
                env=env,
                timeout=timeout,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if stdout:
                print(stdout)
            if stderr:
                print(stderr)
            return {"cmd": " ".join(full_cmd), "stdout": stdout, "stderr": stderr, "returncode": proc.returncode}
        except subprocess.TimeoutExpired:
            msg = f"{desc} timed out after {timeout}s"
            print(WHITE + msg + RESET)
            logging.warning(msg)
            return {"cmd": " ".join(full_cmd if use_sudo else cmd), "stdout": "", "stderr": msg, "returncode": -2}
        except (OSError, ValueError, FileNotFoundError) as exc:
            msg = f"{desc} failed: {exc}"
            print(WHITE + msg + RESET)
            logging.error(msg)
            return {"cmd": " ".join(full_cmd if use_sudo else cmd), "stdout": "", "stderr": msg, "returncode": -1}
        except Exception as exc:
            msg = f"{desc} failed with unexpected error: {exc}"
            print(WHITE + msg + RESET)
            logging.exception(f"Unexpected error in {desc}")
            return {"cmd": " ".join(full_cmd if use_sudo else cmd), "stdout": "", "stderr": msg, "returncode": -1}
        finally:
            done_event.set()
            if worker:
                worker.join()

    def _find_browser_executable(self) -> Optional[str]:
        candidates = [
            os.getenv("WAPPALYZER_BROWSER"),
            "/usr/bin/firefox",
            "/usr/bin/firefox-esr",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/snap/bin/firefox",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def _archive_reports(self) -> None:
        prompt = WHITE + "Archive reports older than how many days? (default 7, 0 for all): " + RESET
        entry = input(prompt).strip()
        if entry == "":
            days = 7
        else:
            try:
                days = int(entry)
            except ValueError:
                print(WHITE + "Invalid number. Aborting archive." + RESET)
                return
        if days < 0:
            print(WHITE + "Days cannot be negative." + RESET)
            return
        days_param = None if days == 0 else days
        moved = self.reporter.archive_old_reports(days_param)
        print(WHITE + f"Archived {moved} report(s) to Reports/Archive." + RESET)

    def _clear_reports(self) -> None:
        confirm = input(WHITE + "Clear all reports in Reports/? This cannot be undone. Continue? (y/n): " + RESET).lower()
        if confirm != "y":
            print(WHITE + "Clear operation cancelled." + RESET)
            return
        if not self._confirm("Second confirmation—clear all reports? (y/n): "):
            print(WHITE + "Clear operation cancelled." + RESET)
            return
        removed = self.reporter.clear_all_reports()
        print(WHITE + f"Removed {removed} report(s)." + RESET)

    def _clear_archived_reports(self) -> None:
        confirm = input(WHITE + "Clear all archived reports under Reports/Archive/? This cannot be undone. Continue? (y/n): " + RESET).lower()
        if confirm != "y":
            print(WHITE + "Clear archived operation cancelled." + RESET)
            return
        if not self._confirm("Second confirmation—clear all archived reports? (y/n): "):
            print(WHITE + "Clear archived operation cancelled." + RESET)
            return
        removed = self.reporter.clear_archived_reports()
        print(WHITE + f"Removed {removed} archived report(s)." + RESET)

    def _set_scan_mode(self) -> None:
        """Configure scan operation mode."""
        modes = {
            "1": "SAFE",
            "2": "STEALTH",
            "3": "AGGRESSIVE",
            "4": "INTENSIVE",
            "5": "COMPREHENSIVE",
        }
        print(WHITE + "\n=== Scan Mode Configuration ===" + RESET)
        print(WHITE + "  [1] Safe Scan          – Lowest impact, conservative defaults" + RESET)
        print(WHITE + "  [2] Stealth Scan       – Reduced-noise scanning" + RESET)
        print(WHITE + "  [3] Standard Scan      – Balanced speed and coverage" + RESET)
        print(WHITE + "  [4] Intensive Scan     – Accelerated scanning with comprehensive checks" + RESET)
        print(WHITE + "  [5] Comprehensive Scan – Maximum coverage and intensity" + RESET)
        choice = input(WHITE + "Choose mode (1-5): " + RESET).strip()
        mode = modes.get(choice)
        if not mode:
            print(WHITE + "Invalid mode selection." + RESET)
            return
        self._set_mode(mode)

    def _install_hint(self, tool: str) -> str:
        if tool.lower() == "wappalyzer":
            return "npm install -g wappalyzer  # requires Node.js"
        system = platform.system()
        if system == "Linux":
            return f"sudo apt install {tool}  # or use your distro package manager"
        if system == "Darwin":
            return f"brew install {tool}"
        if system == "Windows":
            return f"choco install {tool}  # or winget if available"
        return f"Install {tool} with your platform package manager."

    def check_dependencies(self) -> bool:
        required_tools = ["nmap", "msfvenom", "msfconsole", "hydra"]
        optional_tools = ["gobuster", "feroxbuster", "whatweb", "wappalyzer"]
        missing_required = []
        missing_optional = []
        for tool in required_tools + optional_tools:
            try:
                subprocess.run([self.tool_paths[tool], "--version"], capture_output=True, text=True, timeout=10, check=False)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                if tool in required_tools:
                    missing_required.append(tool)
                else:
                    missing_optional.append(tool)
        try:
            import scapy  # noqa: F401
        except ImportError:
            missing_required.append("scapy (python package)")

        if missing_required or missing_optional:
            print(WHITE + "Missing dependencies detected:" + RESET)
            for tool in missing_required:
                hint_target = tool.split()[0] if " " in tool else tool
                print(WHITE + f" - {tool} (required): {self._install_hint(hint_target)}" + RESET)
            for tool in missing_optional:
                hint_target = tool.split()[0] if " " in tool else tool
                print(WHITE + f" - {tool} (optional): {self._install_hint(hint_target)}" + RESET)
        if missing_required:
            print(WHITE + "Required tools are missing. Install them or rerun after fixing." + RESET)
            return False
        return True

    def spoof_mac(self) -> None:
        if not check_privileges():
            return
        iface = detect_primary_interface()
        if not iface:
            print(WHITE + "Could not determine a primary network interface to spoof." + RESET)
            return
        new_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        system = platform.system()
        cmd = ["sudo", "ip", "link", "set", "dev", iface, "address", new_mac] if system == "Linux" else ["sudo", "ifconfig", iface, "ether", new_mac]
        try:
            subprocess.run(cmd, check=True)
            print(WHITE + f"MAC address on {iface} changed to {new_mac}." + RESET)
        except subprocess.CalledProcessError as e:
            print(WHITE + f"Failed to change MAC: {str(e)}" + RESET)

    def _handle_syn_flood(self, target_ip: Optional[str]) -> None:
        """Handle SYN flood attack with proper input validation."""
        if not target_ip:
            print(WHITE + "No target IP provided." + RESET)
            return
        if not validate_ip(target_ip):
            return
        port_input = input(WHITE + "Enter target port: " + RESET).strip()
        if not port_input:
            print(WHITE + "Port number is required." + RESET)
            return
        try:
            port = int(port_input)
            if not validate_port(port):
                return
            self.attacker.syn_flood(target_ip, port)
        except ValueError:
            print(WHITE + f"Invalid port number: {port_input}" + RESET)

    def exploit_vulnerabilities(self, target_ip: str, vulnerabilities: List[Dict[str, str]]) -> None:
        if not vulnerabilities:
            print(WHITE + "No exploitable vulnerabilities found." + RESET)
            return
        
        print(WHITE + "\n=== Exploitable Vulnerabilities ===" + RESET)
        exploitable = []
        for i, vuln in enumerate(vulnerabilities, 1):
            exploit_module = self.exploit_runner.suggest_exploit(vuln)
            payload = self.exploit_runner.suggest_payload(vuln)
            print(WHITE + f"{i}. {vuln.get('cve', 'Unknown CVE')} on Port {vuln['port']}/{vuln['protocol']}: {vuln.get('description', 'No description')}" + RESET)
            print(WHITE + f"   Service: {vuln['service']} {vuln['version']}" + RESET)
            if exploit_module:
                print(WHITE + f"   Suggested Exploit: {exploit_module} with payload {payload}" + RESET)
                exploitable.append((vuln, exploit_module))
            else:
                print(WHITE + "   No known exploit available." + RESET)
        
        if not exploitable:
            print(WHITE + "No exploits available for detected vulnerabilities." + RESET)
            return

        if input(WHITE + "Would you like to exploit these vulnerabilities? (y/n): " + RESET).lower() == "y":
            lhost = input(WHITE + "Enter your IP (LHOST) for reverse shells (e.g., 192.168.1.100): " + RESET)
            try:
                lport_input = input(WHITE + "Enter a port (LPORT) for reverse shells (e.g., 4444): " + RESET).strip()
                if not lport_input:
                    print(WHITE + "Port number is required." + RESET)
                    return
                lport = int(lport_input)
                if not validate_port(lport):
                    return
            except ValueError as e:
                print(WHITE + f"Invalid port: {e}" + RESET)
                return
            
            for vuln, exploit_module in exploitable:
                self.exploit_runner.run_exploit(target_ip, exploit_module, vuln, lhost, lport)

    def main_menu(self) -> None:
        self.banner()
        if not self.check_dependencies():
            print(WHITE + "Required tools are missing. Install nmap, metasploit, hydra, and scapy." + RESET)
            return

        while True:
            options = self._base_options()
            mode_actions, mode_sections = self._mode_specific_options()
            options.update(mode_actions)
            sections = self._base_sections() + mode_sections
            self._display_menu(sections)
            # Calculate max code excluding expandable section codes
            valid_codes = [int(k) for k in options.keys() if k not in ["3+", "4+", "5+"] and (k.isdigit() or k.lstrip("0").isdigit())]
            max_code = max(valid_codes) if valid_codes else 62
            choice = input(WHITE + f"\nEnter your choice (00-{max_code:02d}, or 3+/4+/5+ to expand sections): " + RESET).strip()
            normalized_choice = choice.lstrip("0") or "0"
            
            # Handle expandable/collapsible sections
            if normalized_choice == "3+" or choice == "3+":
                self.expanded_sections["exploitation"] = not self.expanded_sections.get("exploitation", False)
                continue
            elif normalized_choice == "4+" or choice == "4+":
                self.expanded_sections["reporting"] = not self.expanded_sections.get("reporting", False)
                continue
            elif normalized_choice == "5+" or choice == "5+":
                self.expanded_sections["advanced"] = not self.expanded_sections.get("advanced", False)
                continue
            
            action = options.get(normalized_choice)
            if not action:
                print(WHITE + "Invalid choice." + RESET)
                continue
            if action.get("destructive") and not self._confirm("This action can be disruptive. Continue? (y/n): "):
                print(WHITE + "Operation cancelled." + RESET)
                continue
            target_ip = None
            if action.get("needs_target"):
                target_ip = self._prompt_target(self.current_target_info.get("ip"))
                self._cache_target_minimal(target_ip, action["desc"])
            try:
                result = action["handler"](target_ip)
                if result and isinstance(result, tuple) and len(result) == 2:
                    scan_result, vulnerabilities = result
                    suggestions = self._build_suggestions(scan_result, vulnerabilities)
                    web_enum = self._prompt_web_actions(target_ip, scan_result)
                    self.reporter.add_scan(target_ip, action["desc"], scan_result, vulnerabilities, suggestions, web_enum)
                    self._update_current_target(target_ip, action["desc"], scan_result, vulnerabilities, web_enum)
                    self._print_suggestions(suggestions)
                    if "vuln" in action["desc"].lower() and vulnerabilities:
                        self.exploit_vulnerabilities(target_ip, vulnerabilities)
            except KeyboardInterrupt:
                print(WHITE + "Operation aborted by user." + RESET)
            except (KeyboardInterrupt, SystemExit):
                raise
            except (ValueError, OSError, FileNotFoundError) as exc:
                print(WHITE + f"Error running '{action['desc']}': {exc}" + RESET)
                logging.error("Menu action failed: %s - %s", action["desc"], exc)
            except Exception as exc:
                print(WHITE + f"Unexpected error running '{action['desc']}': {exc}" + RESET)
                logging.exception("Unexpected error in menu action: %s", action["desc"])

    def _base_options(self) -> Dict[str, Dict[str, Any]]:
        return {
            "1": {"desc": "Passive Reconnaissance (OSINT)", "handler": lambda ip: self._passive_recon(ip), "needs_target": True},
            "2": {"desc": "Active Reconnaissance (Network Scan)", "handler": lambda ip: self._active_recon(ip), "needs_target": True},
            "3": {"desc": "Comprehensive Target Analysis", "handler": lambda _: self.information_gathering(), "needs_target": False},
            "4": {"desc": "OSINT Intelligence Gathering", "handler": lambda _: self._enhanced_osint_recon(), "needs_target": False},
            "10": {"desc": "Quick Port Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "quick", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "11": {"desc": "Comprehensive Port Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "full", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "12": {"desc": "Vulnerability Assessment", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "vuln", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "13": {"desc": "Stealth Port Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "stealth", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "14": {"desc": "Multi-Target Scan", "handler": lambda _: self._handle_multi_target_scan(), "needs_target": False},
            "20": {"desc": "Generate Payloads", "handler": lambda ip: self.payload_generator.generate_payloads(ip), "needs_target": True},
            "21": {"desc": self._mode_payload_pack_label(), "handler": lambda ip: self.payload_generator.generate_mode_payloads(self.mode, ip), "needs_target": True},
            "22": {"desc": self._mode_brute_label(), "handler": lambda ip: self.attacker.credential_testing(ip), "needs_target": True},
            "23": {"desc": "Network Stress Test", "handler": lambda ip: self._handle_syn_flood(ip), "needs_target": True, "destructive": True},
            "24": {"desc": "MAC Address Spoofing", "handler": lambda _: self.spoof_mac(), "needs_target": False},
            "25": {"desc": "ARP Cache Poisoning Test", "handler": lambda ip: self.attacker.arp_spoof(ip, input(WHITE + "Enter gateway IP: " + RESET)), "needs_target": True, "destructive": True},
            "26": {"desc": "DNS Cache Poisoning Test", "handler": lambda ip: self.attacker.dns_poison(ip, input(WHITE + "Enter fake IP: " + RESET)), "needs_target": True, "destructive": True},
            "30": {"desc": "Generate Report", "handler": lambda _: self.reporter.generate_report(), "needs_target": False},
            "31": {"desc": "View Gathered Intelligence", "handler": lambda _: self._show_gathered_info(), "needs_target": False},
            "32": {"desc": "Archive Old Reports", "handler": lambda _: self._archive_reports(), "needs_target": False},
            "33": {"desc": "Clear Reports", "handler": lambda _: self._clear_reports(), "needs_target": False, "destructive": True},
            "34": {"desc": "Clear Archives", "handler": lambda _: self._clear_archived_reports(), "needs_target": False, "destructive": True},
            "40": {"desc": "Configure Scan Mode", "handler": lambda _: self._set_scan_mode(), "needs_target": False},
            "41": {"desc": "Reset Target", "handler": lambda _: self._reset_target(), "needs_target": False},
            "42": {"desc": "Plugin Management (BETA)", "handler": lambda _: self._plugin_management(), "needs_target": False},
            "43": {"desc": "Create Config File", "handler": lambda _: self._create_config(), "needs_target": False},
            "50": {"desc": "Session Management", "handler": lambda _: self._session_management(), "needs_target": False},
            "51": {"desc": "Credential Management", "handler": lambda _: self._credential_management(), "needs_target": False},
            "52": {"desc": "Post-Exploitation", "handler": lambda _: self._post_exploitation_menu(), "needs_target": False},
            "53": {"desc": "Workflow Automation", "handler": lambda _: self._workflow_menu(), "needs_target": False},
            "54": {"desc": "Vulnerability Prioritization", "handler": lambda _: self._prioritize_vulnerabilities(), "needs_target": False},
            "55": {"desc": "Network Topology", "handler": lambda _: self._topology_menu(), "needs_target": False},
            "56": {"desc": "Evidence Collection", "handler": lambda _: self._evidence_menu(), "needs_target": False},
            "57": {"desc": "Cloud Enumeration", "handler": lambda _: self._cloud_enum_menu(), "needs_target": False},
            "58": {"desc": "Scan Scheduling", "handler": lambda _: self._scheduler_menu(), "needs_target": False},
            "59": {"desc": "Notifications", "handler": lambda _: self._notification_menu(), "needs_target": False},
            "60": {"desc": "Wordlist Management", "handler": lambda _: self._wordlist_menu(), "needs_target": False},
            "61": {"desc": "Scanner Integration", "handler": lambda _: self._scanner_integration_menu(), "needs_target": False},
            "62": {"desc": "Start API Server", "handler": lambda _: self._start_api_server(), "needs_target": False},
            "0": {"desc": "Exit", "handler": lambda _: self._exit(), "needs_target": False}
        }

    def _mode_specific_options(self) -> Tuple[Dict[str, Dict[str, Any]], List[Tuple[str, List[Tuple[str, str]]]]]:
        return {}, []

    def _base_sections(self) -> List[Tuple[str, List[Tuple[str, str]]]]:
        payload_pack_label = self._mode_payload_pack_label()
        brute_label = self._mode_brute_label()
        return [
            ("1 — RECONNAISSANCE", [
                ("01", "Passive Reconnaissance (OSINT)"),
                ("02", "Active Reconnaissance (Network Scan)"),
                ("03", "Comprehensive Target Analysis"),
                ("04", "OSINT Intelligence Gathering")
            ]),
            ("2 — SCANNING", [
                ("10", "Quick Port Scan"),
                ("11", "Comprehensive Port Scan"),
                ("12", "Vulnerability Assessment"),
                ("13", "Stealth Port Scan"),
                ("14", "Multi-Target Scan")
            ]),
            ("3 — EXPLOITATION & TESTING", [
                ("20", "Generate Payloads"),
                ("21", payload_pack_label),
                ("22", brute_label),
                ("3+", "▶ Show Advanced Exploitation" if not self.expanded_sections.get("exploitation") else "▼ Hide Advanced Exploitation"),
            ] + ([
                ("23", "Network Stress Test (BETA)"),
                ("24", "MAC Address Spoofing (BETA)"),
                ("25", "ARP Cache Poisoning Test (BETA)"),
                ("26", "DNS Cache Poisoning Test (BETA)"),
            ] if self.expanded_sections.get("exploitation") else [])),
            ("4 — REPORTING", [
                ("30", "Generate Report"),
                ("31", "View Gathered Intelligence"),
                ("4+", "▶ Show Advanced Reporting" if not self.expanded_sections.get("reporting") else "▼ Hide Advanced Reporting"),
            ] + ([
                ("32", "Archive Old Reports"),
                ("33", "Clear Reports"),
                ("34", "Clear Archives"),
            ] if self.expanded_sections.get("reporting") else [])),
            ("5 — CONFIGURATION / SYSTEM", [
                ("40", "Configure Scan Mode"),
                ("41", "Reset Target"),
                ("42", "Plugin Management (BETA)"),
                ("43", "Create Config File"),
                ("5+", "▶ Show Advanced Features (BETA)" if not self.expanded_sections.get("advanced") else "▼ Hide Advanced Features (BETA)"),
            ] + ([
                # Advanced Features (shown when expanded)
                ("50", "Session Management (BETA)"),
                ("51", "Credential Management (BETA)"),
                ("52", "Post-Exploitation (BETA)"),
                ("53", "Workflow Automation (BETA)"),
                ("54", "Vulnerability Prioritization (BETA)"),
                ("55", "Network Topology (BETA)"),
                ("56", "Evidence Collection (BETA)"),
                ("57", "Cloud Enumeration (BETA)"),
                ("58", "Scan Scheduling (BETA)"),
                ("59", "Notifications (BETA)"),
                ("60", "Wordlist Management (BETA)"),
                ("61", "Scanner Integration (BETA)"),
                ("62", "Start API Server (BETA)"),
            ] if self.expanded_sections.get("advanced") else []) + [
                ("00", "Exit")
            ]),
        ]

    def _display_menu(self, sections: Optional[List[Tuple[str, List[Tuple[str, str]]]]] = None) -> None:
        mode = self.mode
        mode_color = MODE_COLORS.get(mode, WHITE)
        colored_mode = mode_color + f"{self._mode_label(mode)}" + RESET
        header = [
            "┌─────────────────────────────────────────────────────────────┐",
            "│              NETSPEAR NETWORK ANALYZER v2.0                │",
            f"│                    Mode: {colored_mode:<20}│",
            "│              © 2025 OpenNET LLC - All Rights Reserved       │",
            "└─────────────────────────────────────────────────────────────┘",
        ]
        sections = sections or self._base_sections()
        for line in header:
            print(NETSPEAR_PURPLE + line + RESET)
        for title, items in sections:
            print(WHITE + f"\n[ {title} ]" + RESET)
            for code, label in items:
                if label:  # Filter out None/empty items (collapsed sections)
                    # Highlight expandable sections
                    if code.endswith("+"):
                        print(NETSPEAR_PURPLE + f"  [{code}] {label}" + RESET)
                    else:
                        print(WHITE + f"  [{code}] {label}" + RESET)
        print(NETSPEAR_PURPLE + "\n" + self._menu_footer_text() + RESET)

    def _menu_footer_text(self) -> str:
        info = self.current_target_info or {}
        target = info.get("ip", "None")
        status = "Loaded" if info else "Idle"
        last_scan = info.get("last_scan") or "None"
        return f"Target: {target} | Status: {status} | Last Scan: {last_scan}"

    def _clear_screen(self) -> None:
        # Clear terminal for a clean, tool-like interface across platforms.
        os.system("cls" if os.name == "nt" else "clear")

    def _session_management(self) -> None:
        """Session management menu."""
        print(WHITE + "\n=== Session Management ===" + RESET)
        print(WHITE + "[1] List Active Sessions" + RESET)
        print(WHITE + "[2] Create Session" + RESET)
        print(WHITE + "[3] Execute Command" + RESET)
        print(WHITE + "[4] Enumerate System" + RESET)
        choice = input(WHITE + "Select option (1-4): " + RESET).strip()
        
        if choice == "1":
            sessions = self.session_manager.get_active_sessions()
            for session in sessions:
                print(WHITE + f"  {session.session_uuid}: {session.session_type} on {session.target_ip} ({'active' if session.active else 'inactive'})" + RESET)
        elif choice == "2":
            target_ip = input(WHITE + "Target IP: " + RESET).strip()
            session_type = input(WHITE + "Session type (meterpreter/shell/ssh): " + RESET).strip()
            session = self.session_manager.create_session(session_type, target_ip)
            if session:
                print(WHITE + f"Created session: {session.session_uuid}" + RESET)
        elif choice == "3":
            session_uuid = input(WHITE + "Session UUID: " + RESET).strip()
            command = input(WHITE + "Command: " + RESET).strip()
            result = self.post_exploit.execute_command(session_uuid, command)
            print(WHITE + f"Result: {result}" + RESET)
        elif choice == "4":
            session_uuid = input(WHITE + "Session UUID: " + RESET).strip()
            enum = self.post_exploit.enumerate_system(session_uuid)
            print(WHITE + f"Enumeration: {enum}" + RESET)
    
    def _credential_management(self) -> None:
        """Credential management menu."""
        print(WHITE + "\n=== Credential Management ===" + RESET)
        print(WHITE + "[1] Add Credential" + RESET)
        print(WHITE + "[2] List Credentials" + RESET)
        print(WHITE + "[3] Find Credentials" + RESET)
        print(WHITE + "[4] Export Credentials" + RESET)
        choice = input(WHITE + "Select option (1-4): " + RESET).strip()
        
        if choice == "1":
            target_ip = input(WHITE + "Target IP: " + RESET).strip()
            service = input(WHITE + "Service (ssh/ftp/smb): " + RESET).strip()
            username = input(WHITE + "Username: " + RESET).strip()
            password = input(WHITE + "Password: " + RESET).strip()
            cred = self.credential_manager.add_credential(target_ip, service, username, password)
            if cred:
                print(WHITE + f"Added credential: {cred.id}" + RESET)
        elif choice == "2":
            creds = self.credential_manager.find_credentials()
            for cred in creds:
                print(WHITE + f"  {cred['username']}@{cred['target_ip']}:{cred['service']} ({'verified' if cred['verified'] else 'unverified'})" + RESET)
        elif choice == "3":
            target_ip = input(WHITE + "Target IP (optional): " + RESET).strip() or None
            service = input(WHITE + "Service (optional): " + RESET).strip() or None
            creds = self.credential_manager.find_credentials(target_ip=target_ip, service=service)
            for cred in creds:
                print(WHITE + f"  {cred['username']}@{cred.get('target_ip', 'N/A')}:{cred['service']}" + RESET)
        elif choice == "4":
            format = input(WHITE + "Format (csv/json): " + RESET).strip() or "csv"
            export = self.credential_manager.export_credentials(format)
            print(WHITE + export[:500] + RESET)  # Show first 500 chars
    
    def _post_exploitation_menu(self) -> None:
        """Post-exploitation menu."""
        print(WHITE + "\n=== Post-Exploitation ===" + RESET)
        session_uuid = input(WHITE + "Session UUID: " + RESET).strip()
        print(WHITE + "[1] System Enumeration" + RESET)
        print(WHITE + "[2] Privilege Escalation Check" + RESET)
        print(WHITE + "[3] Establish Persistence" + RESET)
        choice = input(WHITE + "Select option (1-3): " + RESET).strip()
        
        if choice == "1":
            enum = self.post_exploit.enumerate_system(session_uuid)
            print(WHITE + f"Enumeration complete. Check logs for details." + RESET)
        elif choice == "2":
            opps = self.post_exploit.check_privilege_escalation(session_uuid)
            print(WHITE + f"Found {len(opps.get('opportunities', []))} opportunities" + RESET)
        elif choice == "3":
            method = input(WHITE + "Method (auto/service/cron): " + RESET).strip() or "auto"
            result = self.post_exploit.establish_persistence(session_uuid, method)
            print(WHITE + f"Persistence: {result.get('note', '')}" + RESET)
    
    def _workflow_menu(self) -> None:
        """Workflow automation menu."""
        print(WHITE + "\n=== Workflow Automation ===" + RESET)
        print(WHITE + "[1] List Workflows" + RESET)
        print(WHITE + "[2] Create Workflow" + RESET)
        print(WHITE + "[3] Execute Workflow" + RESET)
        choice = input(WHITE + "Select option (1-3): " + RESET).strip()
        
        if choice == "1":
            workflows = self.workflow_engine.list_workflows()
            for wf in workflows:
                print(WHITE + f"  {wf.workflow_uuid}: {wf.name} ({'enabled' if wf.enabled else 'disabled'})" + RESET)
        elif choice == "2":
            name = input(WHITE + "Workflow name: " + RESET).strip()
            desc = input(WHITE + "Description: " + RESET).strip()
            print(WHITE + "Workflow creation requires JSON steps. Use API for advanced workflows." + RESET)
        elif choice == "3":
            workflow_uuid = input(WHITE + "Workflow UUID: " + RESET).strip()
            target = input(WHITE + "Target (optional): " + RESET).strip() or None
            execution = self.workflow_engine.execute_workflow(workflow_uuid, target)
            if execution:
                print(WHITE + f"Execution started: {execution.execution_uuid}" + RESET)
    
    def _prioritize_vulnerabilities(self) -> None:
        """Prioritize vulnerabilities."""
        target_ip = input(WHITE + "Target IP (optional, press Enter for all): " + RESET).strip() or None
        count = self.vuln_scorer.batch_prioritize(target_ip)
        print(WHITE + f"Prioritized {count} vulnerabilities" + RESET)
        vulns = self.vuln_scorer.get_prioritized_vulnerabilities(target_ip=target_ip, limit=10)
        for vuln in vulns:
            print(WHITE + f"  CVE: {vuln.get('cve', 'N/A')}, Risk: {vuln.get('risk_score', 0):.2f}, Priority: {vuln.get('remediation_priority', 0)}" + RESET)
    
    def _topology_menu(self) -> None:
        """Network topology menu."""
        print(WHITE + "\n=== Network Topology ===" + RESET)
        print(WHITE + "[1] Build Topology from Scans" + RESET)
        print(WHITE + "[2] View Topology Graph" + RESET)
        print(WHITE + "[3] Export Topology" + RESET)
        choice = input(WHITE + "Select option (1-3): " + RESET).strip()
        
        if choice == "1":
            topology = self.topology_mapper.build_topology_from_scans()
            print(WHITE + f"Topology built: {topology['node_count']} nodes, {topology['edge_count']} edges" + RESET)
        elif choice == "2":
            target_ip = input(WHITE + "Root IP (optional): " + RESET).strip() or None
            graph = self.topology_mapper.get_topology_graph(target_ip)
            print(WHITE + f"Graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges" + RESET)
        elif choice == "3":
            format = input(WHITE + "Format (json/dot/graphml): " + RESET).strip() or "json"
            export = self.topology_mapper.export_topology(format)
            print(WHITE + export[:500] + RESET)
    
    def _evidence_menu(self) -> None:
        """Evidence collection menu."""
        print(WHITE + "\n=== Evidence Collection ===" + RESET)
        print(WHITE + "[1] List Evidence" + RESET)
        print(WHITE + "[2] Capture Screenshot" + RESET)
        choice = input(WHITE + "Select option (1-2): " + RESET).strip()
        
        if choice == "1":
            evidence = self.evidence_collector.list_evidence()
            for ev in evidence:
                print(WHITE + f"  {ev.evidence_uuid}: {ev.evidence_type} - {ev.filename}" + RESET)
        elif choice == "2":
            url = input(WHITE + "URL: " + RESET).strip()
            evidence = self.evidence_collector.capture_screenshot(url)
            if evidence:
                print(WHITE + f"Screenshot saved: {evidence.filename}" + RESET)
    
    def _cloud_enum_menu(self) -> None:
        """Cloud enumeration menu."""
        print(WHITE + "\n=== Cloud Enumeration ===" + RESET)
        domain = input(WHITE + "Domain: " + RESET).strip()
        print(WHITE + "[1] AWS" + RESET)
        print(WHITE + "[2] GCP" + RESET)
        print(WHITE + "[3] Azure" + RESET)
        choice = input(WHITE + "Select platform (1-3): " + RESET).strip()
        
        if choice == "1":
            results = self.cloud_enumerator.enumerate_aws(domain)
            print(WHITE + f"AWS: {len(results.get('s3_buckets', []))} buckets found" + RESET)
        elif choice == "2":
            results = self.cloud_enumerator.enumerate_gcp(domain)
            print(WHITE + f"GCP: {len(results.get('storage_buckets', []))} buckets found" + RESET)
        elif choice == "3":
            results = self.cloud_enumerator.enumerate_azure(domain)
            print(WHITE + f"Azure: {len(results.get('storage_accounts', []))} accounts found" + RESET)
    
    def _scheduler_menu(self) -> None:
        """Scan scheduling menu."""
        print(WHITE + "\n=== Scan Scheduling ===" + RESET)
        print(WHITE + "[1] List Scheduled Jobs" + RESET)
        print(WHITE + "[2] Schedule Scan" + RESET)
        choice = input(WHITE + "Select option (1-2): " + RESET).strip()
        
        if choice == "1":
            jobs = self.scan_scheduler.list_jobs()
            for job in jobs:
                print(WHITE + f"  {job['job_id']}: {job['name']} (next: {job.get('next_run', 'N/A')})" + RESET)
        elif choice == "2":
            target_ip = input(WHITE + "Target IP: " + RESET).strip()
            scan_type = input(WHITE + "Scan type (quick/full/vuln): " + RESET).strip() or "quick"
            interval = input(WHITE + "Interval (minutes): " + RESET).strip()
            try:
                interval_min = int(interval)
                job_id = self.scan_scheduler.schedule_scan(target_ip, scan_type, "interval", interval_minutes=interval_min)
                if job_id:
                    print(WHITE + f"Scheduled scan: {job_id}" + RESET)
            except ValueError:
                print(WHITE + "Invalid interval" + RESET)
    
    def _notification_menu(self) -> None:
        """Notification menu."""
        print(WHITE + "\n=== Notifications ===" + RESET)
        print(WHITE + "Configure notification channels via environment variables:" + RESET)
        print(WHITE + "  - SMTP_SERVER, SMTP_USER, SMTP_PASSWORD for email" + RESET)
        print(WHITE + "  - SLACK_WEBHOOK_URL for Slack" + RESET)
        print(WHITE + "  - TEAMS_WEBHOOK_URL for Teams" + RESET)
    
    def _wordlist_menu(self) -> None:
        """Wordlist management menu."""
        print(WHITE + "\n=== Wordlist Management ===" + RESET)
        print(WHITE + "[1] List Wordlists" + RESET)
        print(WHITE + "[2] Create Wordlist" + RESET)
        choice = input(WHITE + "Select option (1-2): " + RESET).strip()
        
        if choice == "1":
            wordlists = self.wordlist_manager.list_wordlists()
            for wl in wordlists:
                print(WHITE + f"  {wl['name']}: {wl.get('word_count', 0)} words" + RESET)
        elif choice == "2":
            name = input(WHITE + "Wordlist name: " + RESET).strip()
            words_input = input(WHITE + "Words (comma-separated): " + RESET).strip()
            words = [w.strip() for w in words_input.split(",")]
            path = self.wordlist_manager.create_wordlist(name, words)
            print(WHITE + f"Created wordlist: {path}" + RESET)
    
    def _scanner_integration_menu(self) -> None:
        """Scanner integration menu."""
        print(WHITE + "\n=== Scanner Integration ===" + RESET)
        print(WHITE + "[1] Import Nessus" + RESET)
        print(WHITE + "[2] Import OpenVAS" + RESET)
        print(WHITE + "[3] Import Burp Suite" + RESET)
        choice = input(WHITE + "Select scanner (1-3): " + RESET).strip()
        
        file_path = input(WHITE + "File path: " + RESET).strip()
        target_ip = input(WHITE + "Target IP: " + RESET).strip()
        
        from pathlib import Path
        if choice == "1":
            count = self.scanner_integration.import_nessus(Path(file_path), target_ip)
            print(WHITE + f"Imported {count} vulnerabilities" + RESET)
        elif choice == "2":
            count = self.scanner_integration.import_openvas(Path(file_path), target_ip)
            print(WHITE + f"Imported {count} vulnerabilities" + RESET)
        elif choice == "3":
            count = self.scanner_integration.import_burp(Path(file_path), target_ip)
            print(WHITE + f"Imported {count} vulnerabilities" + RESET)
    
    def _plugin_management(self) -> None:
        """Plugin management menu."""
        print(WHITE + "\n=== Plugin Management ===" + RESET)
        plugins = self.plugin_manager.list_plugins()
        if not plugins:
            print(WHITE + "No plugins loaded." + RESET)
            return
        
        print(WHITE + "Loaded plugins:" + RESET)
        for i, plugin in enumerate(plugins, 1):
            status = "enabled" if plugin.get("enabled") else "disabled"
            print(WHITE + f"  [{i}] {plugin['name']} v{plugin['version']} - {status}" + RESET)
            if plugin.get("description"):
                print(WHITE + f"      {plugin['description']}" + RESET)
    
    def _create_config(self) -> None:
        """Create default configuration file."""
        try:
            from config_loader import create_default_config
            config_path = create_default_config()
            if config_path:
                print(WHITE + f"Created default configuration at: {config_path}" + RESET)
            else:
                print(WHITE + "Failed to create configuration file." + RESET)
        except Exception as e:
            print(WHITE + f"Error creating config: {e}" + RESET)
    
    def _start_api_server(self) -> None:
        """Start REST API server."""
        host = input(WHITE + "Host (default: 127.0.0.1): " + RESET).strip() or "127.0.0.1"
        port = input(WHITE + "Port (default: 8000): " + RESET).strip() or "8000"
        try:
            port_num = int(port)
            print(WHITE + f"Starting API server on {host}:{port_num}" + RESET)
            print(WHITE + "Press Ctrl+C to stop" + RESET)
            set_analyzer(self)
            run_api_server(host=host, port=port_num, analyzer=self)
        except ValueError:
            print(WHITE + "Invalid port number" + RESET)
        except KeyboardInterrupt:
            print(WHITE + "\nAPI server stopped" + RESET)
    
    def _exit(self) -> None:
        # Clear once on exit for a clean terminal.
        if hasattr(self, 'scan_scheduler'):
            self.scan_scheduler.shutdown()
        if hasattr(self, 'db_manager'):
            self.db_manager.close()
        self._clear_screen()
        exit_cleanly()

if __name__ == "__main__":
    # Note: NetSpear requires root privileges for certain operations (ARP spoofing, SYN flood, etc.)
    # Users should run with sudo explicitly: sudo python3 main.py
    # Auto-elevation has been removed for security reasons.
    analyzer = NetSpearNetworkAnalyzer()
    analyzer.main_menu()
    
