#!/usr/bin/env python3
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
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Any
from pathlib import Path
from typing import Optional, List, Dict, Tuple

# Allow running the script from any working directory by forcing cwd to the file's directory.
PROJECT_ROOT = Path(__file__).resolve().parent
if Path.cwd() != PROJECT_ROOT:
    os.chdir(PROJECT_ROOT)
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DEFAULT_TOOL_PATHS
from utils import WHITE, RESET, setup_logging, exit_cleanly, check_privileges, detect_primary_interface, validate_ip
from network_scanning import NetworkScanner
from payloads import PayloadGenerator
from attacks import NetworkAttacker
from reporting import ReportGenerator
from exploits import ExploitRunner

# Define NetSpear Purple options
NETSPEAR_PURPLE_TRUECOLOR = "\033[38;2;122;6;205m"  # NetSpear Purple #7A06CD (RGB: 122, 6, 205)
NETSPEAR_PURPLE_FALLBACK = "\033[95m"               # Bright magenta fallback

# Choose the color based on preference (try truecolor first, fallback if it looks gray)
NETSPEAR_PURPLE = NETSPEAR_PURPLE_TRUECOLOR  # Switch to NETSPEAR_PURPLE_FALLBACK if gray persists

MODE_COLORS = {
    "SAFE": "\033[92m",
    "STEALTH": "\033[96m",
    "AGGRESSIVE": "\033[93m",
    "INSANE": "\033[95m",
    "KILLER": "\033[91m",
}

class NetSpearNetworkAnalyzer:
    def __init__(self):
        setup_logging()
        self.scanner = NetworkScanner()
        self.payload_generator = PayloadGenerator()
        self.attacker = NetworkAttacker()
        self.reporter = ReportGenerator()
        self.exploit_runner = ExploitRunner()
        self.args = self._parse_args()
        self.tool_paths = DEFAULT_TOOL_PATHS.copy()
        self.mode = "SAFE"
        self.killer_mode = False
        self.current_target_info: Dict[str, Any] = {}
        self._clear_screen()

    def _cache_target_minimal(self, ip: Optional[str], label: str) -> None:
        if not ip:
            return
        now = datetime.utcnow().isoformat() + "Z"
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
        # Aggressive tiers unlock killer-style suggestions.
        self.killer_mode = mode in {"KILLER", "INSANE", "AGGRESSIVE"}
        color = MODE_COLORS.get(mode, WHITE)
        print(color + f"[+] Mode set to {mode}" + RESET)
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
            "last_action": datetime.utcnow().isoformat() + "Z",
            "last_scan": (scan_result or {}).get("timestamp") or datetime.utcnow().isoformat() + "Z",
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
        print(WHITE + f"Mode: {info.get('mode','-')}" + RESET)
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
        return input(WHITE + message + RESET).strip().lower() == "y"

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
                if self.killer_mode:
                    suggestions.append("Killer: run nmap --script vuln/nikto, probe uploads for webshell, brute weak HTTP auth, try default creds on common panels.")
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
        if vulnerabilities and self.killer_mode:
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
        except Exception as exc:  # noqa: BLE001
            logging.debug("Geo lookup failed for %s: %s", ip, exc)
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
        except Exception as exc:  # noqa: BLE001
            logging.debug("HTTP fingerprint failed for %s: %s", url, exc)
            return {"url": url, "error": str(exc)}

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

        geo = self._geo_lookup(resolved_ip)
        http_info = self._http_fingerprint(url if target_type in {"website", "server"} else None)

        scan_result, vulnerabilities = self.scanner.run_nmap_scan(resolved_ip, "deep", self.args.stealth, self.args.proxy)
        suggestions = self._build_suggestions(scan_result, vulnerabilities)
        web_enum = self._prompt_web_actions(target_ip=resolved_ip, scan_result=scan_result, auto_prompt=False)
        spiderfoot_runs: List[Dict[str, Any]] = []
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
            "http": http_info,
            "scan": scan_result,
            "vulnerabilities": vulnerabilities,
            "suggestions": suggestions,
            "web_enum": web_enum or {},
            "osint": {"spiderfoot": spiderfoot_runs} if spiderfoot_runs else {},
        }
        self.reporter.add_recon(recon_entry)
        self._print_suggestions(suggestions)
        if vulnerabilities and self._confirm("Attempt exploitation on detected vulns? (y/n): "):
            self.exploit_vulnerabilities(resolved_ip, vulnerabilities)
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
        wordlist = os.getenv("GOBUSTER_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
        if self._is_tool_available("ffuf"):
            if os.path.exists(wordlist):
                web_enum["dir_enum"].append(self._run_cmd_capture([self.tool_paths["ffuf"], "-u", base_url.rstrip("/") + "/FUZZ", "-w", wordlist, "-t", "50", "-mc", "200,301,302,401,403"], "ffuf directory scan"))
            else:
                msg = f"Wordlist missing ({wordlist}); skipping ffuf."
                web_enum["errors"].append(msg)
                print(WHITE + msg + RESET)
        elif self._is_tool_available("gobuster"):
            if os.path.exists(wordlist):
                web_enum["dir_enum"].append(self._run_cmd_capture([self.tool_paths["gobuster"], "dir", "-u", base_url, "-w", wordlist, "-q", "-t", "50"], "gobuster directory scan"))
            else:
                msg = f"Wordlist missing ({wordlist}); skipping gobuster."
                web_enum["errors"].append(msg)
                print(WHITE + msg + RESET)
        elif self._is_tool_available("feroxbuster"):
            if os.path.exists(wordlist):
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
        admin_paths = ["/admin", "/login", "/dashboard", "/cp", "/administrator", "/manage", "/panel"]
        print(WHITE + "Probing common admin endpoints..." + RESET)
        for path in admin_paths:
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
            subprocess.run([cmd, "--version"], capture_output=True, timeout=5, check=False)
            return True
        except Exception:
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
            return {"cmd": " ".join(cmd), "stdout": "", "stderr": msg, "returncode": -2}
        except Exception as exc:  # noqa: BLE001
            msg = f"{desc} failed: {exc}"
            print(WHITE + msg + RESET)
            return {"cmd": " ".join(cmd), "stdout": "", "stderr": msg, "returncode": -1}
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

    def _toggle_killer_mode(self) -> None:
        modes = {
            "1": "SAFE",
            "2": "STEALTH",
            "3": "AGGRESSIVE",
            "4": "INSANE",
            "5": "KILLER",
        }
        print(WHITE + "\nSelect Mode:" + RESET)
        print(WHITE + "  [1] SAFE (green)    — minimal footprint, safer defaults" + RESET)
        print(WHITE + "  [2] STEALTH (cyan)  — low-noise scans/attacks" + RESET)
        print(WHITE + "  [3] AGGRESSIVE (yellow) — faster scans, more noise" + RESET)
        print(WHITE + "  [4] INSANE (magenta)  — very fast, minimal retries" + RESET)
        print(WHITE + "  [5] KILLER (red)    — maximum aggression" + RESET)
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
                lport = int(input(WHITE + "Enter a port (LPORT) for reverse shells (e.g., 4444): " + RESET))
                if not (1 <= lport <= 65535):
                    raise ValueError("Port must be between 1 and 65535.")
            except ValueError as e:
                print(WHITE + f"Invalid port: {str(e)}" + RESET)
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
            killer_actions, killer_sections = self._killer_mode_options()
            options.update(killer_actions)
            sections = self._base_sections() + killer_sections
            self._display_menu(sections)
            max_code = max(int(k) for k in options.keys())
            choice = input(WHITE + f"\nEnter your choice (00-{max_code:02d}): " + RESET).strip()
            normalized_choice = choice.lstrip("0") or "0"
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
            except Exception as exc:
                print(WHITE + f"Error running '{action['desc']}': {exc}" + RESET)
                logging.exception("Menu action failed: %s", action["desc"])

    def _base_options(self) -> Dict[str, Dict[str, Any]]:
        return {
            "1": {"desc": "Quick Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "quick", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "2": {"desc": "Full Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "full", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "3": {"desc": "Vulnerability Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "vuln", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "4": {"desc": "Stealth Scan", "handler": lambda ip: self.scanner.run_nmap_scan(ip, "stealth", self.args.stealth, self.args.proxy, self.mode), "needs_target": True},
            "5": {"desc": "Multi-Target Scan", "handler": lambda _: self._handle_multi_target_scan(), "needs_target": False},
            "6": {"desc": "Generate Payloads", "handler": lambda ip: self.payload_generator.generate_payloads(ip), "needs_target": True},
            "7": {"desc": "Brute Force Test", "handler": lambda ip: self.attacker.brute_force_overdrive(ip), "needs_target": True},
            "8": {"desc": "ARP Spoofing", "handler": lambda ip: self.attacker.arp_spoof(ip, input(WHITE + "Enter gateway IP: " + RESET)), "needs_target": True, "destructive": True},
            "9": {"desc": "DNS Poisoning", "handler": lambda ip: self.attacker.dns_poison(ip, input(WHITE + "Enter fake IP: " + RESET)), "needs_target": True, "destructive": True},
            "10": {"desc": "SYN Flood", "handler": lambda ip: self.attacker.syn_flood(ip, int(input(WHITE + "Enter target port: " + RESET))), "needs_target": True, "destructive": True},
            "11": {"desc": "Generate Report", "handler": lambda _: self.reporter.generate_report(), "needs_target": False},
            "12": {"desc": "Spoof MAC", "handler": lambda _: self.spoof_mac(), "needs_target": False},
            "13": {"desc": "Archive Old Reports", "handler": lambda _: self._archive_reports(), "needs_target": False},
            "14": {"desc": "Clear All Reports", "handler": lambda _: self._clear_reports(), "needs_target": False, "destructive": True},
            "15": {"desc": "Clear Archived Reports", "handler": lambda _: self._clear_archived_reports(), "needs_target": False, "destructive": True},
            "16": {"desc": "Set Mode", "handler": lambda _: self._toggle_killer_mode(), "needs_target": False},
            "17": {"desc": "Information Gathering", "handler": lambda _: self.information_gathering(), "needs_target": False},
            "18": {"desc": "View Gathered Info", "handler": lambda _: self._show_gathered_info(), "needs_target": False},
            "19": {"desc": "Reset Target", "handler": lambda _: self._reset_target(), "needs_target": False},
            "0": {"desc": "Exit", "handler": lambda _: self._exit(), "needs_target": False}
        }

    def _killer_mode_options(self) -> Tuple[Dict[str, Dict[str, Any]], List[Tuple[str, List[Tuple[str, str]]]]]:
        if self.mode != "KILLER":
            return {}, []

        def run_custom(label: str, args: str, prompt_target: bool = True, apply_mode: bool = False) -> Dict[str, Any]:
            return {
                "desc": label,
                "handler": lambda ip: self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label=label, apply_mode_tuning=apply_mode),
                "needs_target": prompt_target,
            }

        def udp_deep_handler(ip: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
            if not ip:
                return {}, []
            full = self._confirm("Run full 65k UDP sweep? (high noise/slow) (y/n): ")
            args = "-sU -T4 --max-retries 1 --min-rate 1000 " + ("-p-" if full else "--top-ports 500")
            return self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label="UDP Deep Recon", apply_mode_tuning=False)

        def decoy_handler(ip: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
            if not ip:
                return {}, []
            try:
                count = int(input(WHITE + "How many decoys? (5-20, default 10): " + RESET) or "10")
            except ValueError:
                count = 10
            count = max(5, min(20, count))
            args = f"-p- -A -T5 -D RND:{count}"
            return self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label="Decoy Aggressive Scan", apply_mode_tuning=False)

        def zombie_handler(ip: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
            if not ip:
                return {}, []
            zombie = input(WHITE + "Enter zombie host IP (predictable IPID): " + RESET).strip()
            if not zombie:
                print(WHITE + "Zombie host required for idle scan." + RESET)
                return {}, []
            args = f"-sI {zombie}"
            return self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label="Zombie Idle Scan", apply_mode_tuning=False)

        def slowloris_handler(ip: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
            if not ip:
                return {}, []
            args = "-p80,443 --script http-slowloris-check --max-retries 1 -T4"
            return self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label="Slowloris Analysis Scan", apply_mode_tuning=False)

        def iot_handler(ip: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
            if not ip:
                return {}, []
            args = "-sV -p 80,1900,5683,1883,8883 --script upnp-info,mqtt-subscribe,mqtt-connect,coap-resources"
            return self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label="IoT Fingerprint + Load Scan", apply_mode_tuning=False)

        def hellfire_handler(ip: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
            if not ip:
                return {}, []
            if not self._confirm("HELLFIRE will hammer the target. Continue? (y/n): "):
                return {}, []
            if not self._confirm("Last warning: authorized testing only. Proceed? (y/n): "):
                return {}, []
            args = "-p- -A -T5 -f -D RND:10 --script vuln,exploit,brute,malware"
            return self.scanner.run_nmap_scan(ip, "custom", self.args.stealth, self.args.proxy, self.mode, custom_args=args, scan_label="HELLFIRE Scan", apply_mode_tuning=False)

        actions: Dict[str, Dict[str, Any]] = {
            "20": run_custom("Ultra-Aggressive Deep Scan", "-p- -A -T5 --script vuln,exploit,malware,auth,brute", apply_mode=False),
            "21": {"desc": "UDP Deep Recon", "handler": udp_deep_handler, "needs_target": True},
            "22": run_custom("Fragmented Evasion Scan", "-f", apply_mode=False),
            "23": {"desc": "Decoy Aggressive Scan", "handler": decoy_handler, "needs_target": True},
            "24": {"desc": "Zombie Idle Scan", "handler": zombie_handler, "needs_target": True},
            "25": run_custom("ACK Firewall Analysis Scan", "-sA", apply_mode=False),
            "26": run_custom("FIN Scan", "-sF", apply_mode=False),
            "27": run_custom("NULL Scan", "-sN", apply_mode=False),
            "28": run_custom("XMAS Scan", "-sX", apply_mode=False),
            "29": {"desc": "Slowloris Analysis Scan", "handler": slowloris_handler, "needs_target": True},
            "30": run_custom("RPC/DCOM Deep Enum", "--script=rpcinfo,dcom,nbstat,smb-enum-shares,smb-vuln*", apply_mode=False),
            "31": run_custom("SSL/TLS Deep Audit Scan", "--script ssl* -p 443,8443,9443", apply_mode=False),
            "32": {"desc": "IoT Fingerprint + Load Scan", "handler": iot_handler, "needs_target": True},
            "33": {"desc": "HELLFIRE Scan", "handler": hellfire_handler, "needs_target": True, "destructive": True},
        }

        killer_section = [
            ("KILLER MODE SCANS", [
                ("20", "Ultra-Aggressive Deep Scan"),
                ("21", "UDP Deep Recon"),
                ("22", "Fragmented Evasion Scan"),
                ("23", "Decoy Aggressive Scan"),
                ("24", "Zombie Idle Scan"),
                ("25", "ACK Firewall Analysis Scan"),
                ("26", "FIN Scan"),
                ("27", "NULL Scan"),
                ("28", "XMAS Scan"),
                ("29", "Slowloris Analysis Scan"),
                ("30", "RPC/DCOM Deep Enum"),
                ("31", "SSL/TLS Deep Audit Scan"),
                ("32", "IoT Fingerprint + Load Scan"),
                ("33", "HELLFIRE Scan"),
            ])
        ]

        return actions, killer_section

    def _base_sections(self) -> List[Tuple[str, List[Tuple[str, str]]]]:
        return [
            ("SCANNING", [("01", "Quick Scan"), ("02", "Full Scan"), ("03", "Vulnerability Scan"), ("04", "Stealth Scan"), ("05", "Multi-Target Scan")]),
            ("PAYLOADS & ATTACKS", [("06", "Generate Payloads"), ("07", "Brute Force Test"), ("10", "SYN Flood"), ("12", "Spoof MAC")]),
            ("SPOOFING / MITM", [("08", "ARP Spoofing"), ("09", "DNS Poisoning")]),
            ("REPORTING", [("11", "Generate Report"), ("13", "Archive Old Reports"), ("14", "Clear All Reports"), ("15", "Clear Archived Reports")]),
            ("RECON", [("17", "Information Gathering")]),
            ("SYSTEM", [("16", "Set Mode"), ("18", "View Gathered Info"), ("19", "Reset Target"), ("00", "Exit")]),
        ]

    def _display_menu(self, sections: Optional[List[Tuple[str, List[Tuple[str, str]]]]] = None) -> None:
        mode = self.mode
        mode_color = MODE_COLORS.get(mode, WHITE)
        colored_mode = mode_color + f"{mode}" + RESET
        header = [
            "┌───────────────────────────────────────────────────────────┐",
            "│                   NETSPEAR NETWORK ANALYZER               │",
            f"│                      Version 1.0  |  Mode: {colored_mode:<12}│",
            "└───────────────────────────────────────────────────────────┘",
        ]
        sections = sections or self._base_sections()
        for line in header:
            print(NETSPEAR_PURPLE + line + RESET)
        for title, items in sections:
            print(WHITE + f"\n[ {title} ]" + RESET)
            for code, label in items:
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

    def _exit(self) -> None:
        # Clear once on exit for a clean terminal.
        self._clear_screen()
        exit_cleanly()

if __name__ == "__main__":
    try:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print(WHITE + "Elevating to root with sudo for full NetSpear capabilities..." + RESET)
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception:
        pass
    analyzer = NetSpearNetworkAnalyzer()
    analyzer.main_menu()
