import threading
import sys
import time
import logging
import subprocess
import re
import os
from typing import Dict, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap
import shutil

from config import MAX_SCAN_TIMEOUT, MAX_WORKERS
from utils import WHITE, RESET, validate_ip

# Import advanced vulnerability scanner
try:
    from advanced_vuln_scanner import AdvancedVulnerabilityScanner
    ADVANCED_SCANNER_AVAILABLE = True
except ImportError:
    ADVANCED_SCANNER_AVAILABLE = False
    logging.warning("Advanced vulnerability scanner not available")

NETSPEAR_PURPLE = "\033[38;2;122;6;205m"

def spinner_task(done_event: threading.Event) -> None:
    progress_bar_task(done_event)


def progress_bar_task(done_event: threading.Event) -> None:
    bar_len = 32
    percent = 0
    while not done_event.is_set():
        percent = min(percent + 3, 97)
        filled = int(bar_len * percent / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(f"\r{NETSPEAR_PURPLE}Scan Progress [{bar}] {percent:3d}%{RESET}")
        sys.stdout.flush()
        if percent >= 97:
            percent = 85
        time.sleep(0.15)
    filled = bar_len
    bar = "█" * filled
    sys.stdout.write(f"\r{NETSPEAR_PURPLE}Scan Progress [{bar}] 100%{RESET}\n")
    sys.stdout.flush()

class NetworkScanner:
    def __init__(self, enable_advanced_scanning: bool = True):
        self.scan_results = {}
        self.enable_advanced_scanning = enable_advanced_scanning and ADVANCED_SCANNER_AVAILABLE
        self.advanced_scanner = None
        if self.enable_advanced_scanning:
            try:
                nvd_api_key = os.getenv("NVD_API_KEY")
                self.advanced_scanner = AdvancedVulnerabilityScanner(nvd_api_key=nvd_api_key)
                logging.info("Advanced vulnerability scanner initialized")
            except Exception as e:
                logging.warning(f"Failed to initialize advanced scanner: {e}")
                self.enable_advanced_scanning = False

    def _requires_root_args(self, args: str) -> bool:
        raw_flags = ["-sS", "-sU", "-sA", "-sN", "-sF", "-sX", "-f", "-D", "-O"]
        if "-A" in args:
            return True  # -A implies OS detection which needs raw sockets
        return any(flag in args for flag in raw_flags)

    def _tool_exists(self, tool: str) -> bool:
        return bool(shutil.which(tool))

    def _fast_prescan(self, target_ip: str, mode: str) -> List[int]:
        """Use masscan/rustscan to quickly identify open ports before Nmap."""
        aggressive = mode.upper() in {"AGGRESSIVE", "INSANE", "KILLER"}
        if not aggressive:
            return []
        ports: set[int] = set()
        timeout = 30
        if self._tool_exists("rustscan"):
            cmd = ["rustscan", "-a", target_ip, "-r", "1-65535", "--ulimit", "4096", "--timeout", "5000", "--scan-order", "serial"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                for line in (res.stdout or "").splitlines():
                    m = re.search(r"Open\s+(\d+)", line)
                    if m:
                        ports.add(int(m.group(1)))
            except Exception:
                logging.debug("rustscan prescan failed", exc_info=True)
        elif self._tool_exists("masscan"):
            cmd = ["masscan", target_ip, "-p1-65535", "--rate", "5000"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                for line in (res.stdout or "").splitlines():
                    m = re.search(r"open port\s+(\d+)", line)
                    if m:
                        ports.add(int(m.group(1)))
            except Exception:
                logging.debug("masscan prescan failed", exc_info=True)
        return sorted(ports)

    def run_nmap_scan(
        self,
        target_ip: str,
        scan_type: str,
        stealth: bool = False,
        proxy: Optional[str] = None,
        mode: str = "SAFE",
        *,
        custom_args: Optional[str] = None,
        scan_label: Optional[str] = None,
        apply_mode_tuning: bool = True,
    ) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
        if not validate_ip(target_ip):
            return {}, []
        
        nm = nmap.PortScanner()
        scan_args = {
            "quick": "-F -T5 --max-rtt-timeout 50ms",
            "full": "-p- -T5 -A --osscan-guess",
            "vuln": "--script=vuln -T5 --min-rate 3000",
            "stealth": "-sS -T2 --max-retries 1 -Pn --spoof-mac 0",
            "brute": "--script ssh-brute,ftp-brute,mysql-brute,telnet-brute -T5",
            "deep": "-sV -sC -O -T5 --min-rate 2000"
        }
        args = custom_args if custom_args else scan_args.get(scan_type, scan_args["quick"])
        label = scan_label or scan_type
        if apply_mode_tuning and not custom_args:
            if stealth and scan_type != "stealth":
                args += " -sS -T2 --max-retries 1 -Pn"
            mode = (mode or "SAFE").upper()
            if mode == "STEALTH":
                args += " -T2 --max-retries 1 -Pn"
            elif mode == "AGGRESSIVE":
                args += " -T4 --min-rate 2000"
            elif mode == "INSANE":
                args += " -T5 --min-rate 4000 --max-retries 1"
            elif mode == "KILLER":
                args += " -T5 --min-rate 6000 --max-retries 0"
            pre_ports = self._fast_prescan(target_ip, mode)
            if pre_ports:
                args = args.replace("-p-", "")
                args += f" -p {','.join(str(p) for p in pre_ports)}"
        if proxy:
            args += f" --proxy {proxy}"
        
        requires_root = self._requires_root_args(args)
        use_sudo = requires_root and hasattr(os, "geteuid") and os.geteuid() != 0
        if use_sudo:
            print(WHITE + "Root is required for raw packet flags (stealth/decoy/OS detect). Sudo will prompt for your password now." + RESET)
            try:
                subprocess.run(["sudo", "-v"], check=True)
            except subprocess.CalledProcessError:
                print(WHITE + "Sudo authentication failed; aborting scan." + RESET)
                return {}, []
        logging.info(f"Initiating scan on {target_ip} with {label} settings.")
        print(WHITE + f"Starting network scan on {target_ip}—preparing detailed report." + RESET)
        
        done_event = threading.Event()
        spinner_thread = threading.Thread(target=spinner_task, args=(done_event,))
        spinner_thread.start()

        try:
            nm.scan(target_ip, arguments=args, timeout=MAX_SCAN_TIMEOUT, sudo=use_sudo)
        except nmap.PortScannerError as e:
            logging.error(f"Nmap scan failed: {str(e)}")
            print(WHITE + f"Nmap scan failed: {str(e)}. Check target or permissions." + RESET)
            done_event.set()
            spinner_thread.join()
            return {}, []
        except PermissionError:
            logging.error("Permission denied. Run with sudo.")
            print(WHITE + "Permission denied. Please run with sudo privileges." + RESET)
            done_event.set()
            spinner_thread.join()
            return {}, []
        
        done_event.set()
        spinner_thread.join()

        if not nm.all_hosts() or target_ip not in nm.all_hosts():
            logging.error(f"No response from {target_ip}")
            print(WHITE + f"No response from {target_ip}—target may be offline or unreachable." + RESET)
            return {}, []

        host_state = nm[target_ip].state()
        result = {"host_state": host_state, "scan_type": label}
        port_details = []
        vulnerabilities = []
        for proto in nm[target_ip].all_protocols():
            ports = nm[target_ip][proto].keys()
            for port in sorted(ports):
                port_info = nm[target_ip][proto][port]
                port_details.append({
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", "")
                })
                result[f"{proto}_{port}"] = port_info["state"]
                service = port_info.get("name", "unknown")
                version = port_info.get("version", "")
                if "script" in port_info and scan_type == "vuln":
                    for script_id, output in port_info["script"].items():
                        result[script_id] = output
                        if "vuln" in script_id.lower():
                            vuln_data = self._parse_vulnerability(script_id, output, target_ip, port, proto, service, version)
                            if vuln_data:
                                vulnerabilities.append(vuln_data)

        result["ports"] = port_details
        self.scan_results[target_ip] = result
        
        # Run advanced vulnerability scanning if enabled (for vuln scans or when explicitly requested)
        if self.enable_advanced_scanning and self.advanced_scanner and (scan_type == "vuln" or scan_type == "deep" or scan_type == "full"):
            try:
                logging.info(f"Running advanced vulnerability scan on {target_ip}")
                advanced_vulns = self.advanced_scanner.scan_comprehensive(
                    target_ip,
                    port_details,
                    result
                )
                # Merge advanced vulnerabilities with Nmap findings
                # Avoid duplicates by checking CVE and port
                existing_cves = {(v.get("cve"), v.get("port")) for v in vulnerabilities if isinstance(v, dict) and v.get("cve")}
                existing_descriptions = {(v.get("description", ""), v.get("port")) for v in vulnerabilities if isinstance(v, dict)}
                for adv_vuln in advanced_vulns:
                    if not isinstance(adv_vuln, dict):
                        continue
                    vuln_key = (adv_vuln.get("cve"), adv_vuln.get("port"))
                    desc_key = (adv_vuln.get("description", ""), adv_vuln.get("port"))
                    # Add if new CVE or if no CVE but unique description
                    if (vuln_key not in existing_cves or not vuln_key[0]) and desc_key not in existing_descriptions:
                        vulnerabilities.append(adv_vuln)
                        if vuln_key[0]:
                            existing_cves.add(vuln_key)
                        existing_descriptions.add(desc_key)
                logging.info(f"Advanced scan found {len(advanced_vulns)} additional vulnerabilities")
            except Exception as e:
                logging.error(f"Advanced vulnerability scan failed: {e}")
        
        # Only print vulnerabilities if we have them and it's a vuln scan, or if advanced scanning found some
        should_print_vulns = (scan_type == "vuln" and vulnerabilities) or (self.enable_advanced_scanning and vulnerabilities)
        self._print_scan_results(nm, target_ip, vulnerabilities if should_print_vulns else [])
        return result, vulnerabilities

    def _parse_vulnerability(self, script_id: str, output: str, target_ip: str, port: int, proto: str, service: str, version: str) -> Optional[Dict[str, str]]:
        """Parse Nmap vuln script output for exploitable vulnerabilities with enhanced parsing."""
        lines = output.split('\n')
        vuln_info = {
            "target_ip": target_ip,
            "port": port,
            "protocol": proto,
            "service": service,
            "version": version,
            "script_id": script_id,
            "category": "nmap_script",
            "detection_method": "nmap_vuln_script"
        }
        
        # Enhanced CVE extraction - handle multiple CVEs
        cves = []
        description_parts = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract all CVEs from the line
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', line, re.IGNORECASE)
            for cve in cve_matches:
                if cve.upper() not in cves:
                    cves.append(cve.upper())
            
            # Extract vulnerability state
            if "VULNERABLE" in line.upper() or "VULN" in line.upper():
                description_parts.append(line)
            elif "State:" in line:
                state = line.split("State:")[1].strip()
                vuln_info["state"] = state
                if "VULNERABLE" in state.upper():
                    description_parts.append(f"State: {state}")
            elif "IDs:" in line:
                ids = line.split("IDs:")[1].strip()
                vuln_info["ids"] = ids
                # Extract CVEs from IDs field
                id_cves = re.findall(r'CVE-\d{4}-\d{4,}', ids, re.IGNORECASE)
                for cve in id_cves:
                    if cve.upper() not in cves:
                        cves.append(cve.upper())
            elif "Title:" in line:
                title = line.split("Title:")[1].strip()
                description_parts.append(title)
            elif line and not line.startswith("|") and len(line) > 10:
                # Potential description line
                if not any(keyword in line.upper() for keyword in ["PORT", "STATE", "SERVICE", "VERSION"]):
                    description_parts.append(line)
        
        # Set CVE (use first one if multiple)
        if cves:
            vuln_info["cve"] = cves[0]
            if len(cves) > 1:
                vuln_info["additional_cves"] = cves[1:]
        
        # Set description
        if description_parts:
            vuln_info["description"] = " | ".join(description_parts[:3])  # Limit to first 3 parts
        elif "cve" in vuln_info:
            vuln_info["description"] = f"Vulnerability detected: {vuln_info['cve']}"
        
        # Determine severity from script output
        if "critical" in output.lower() or "CRITICAL" in output:
            vuln_info["severity"] = "critical"
        elif "high" in output.lower() or "HIGH" in output:
            vuln_info["severity"] = "high"
        elif "medium" in output.lower() or "MEDIUM" in output:
            vuln_info["severity"] = "medium"
        elif "low" in output.lower() or "LOW" in output:
            vuln_info["severity"] = "low"
        else:
            vuln_info["severity"] = "medium"  # Default
        
        return vuln_info if ("cve" in vuln_info or "description" in vuln_info) else None

    def multi_target_scan(self, targets: List[str], scan_type: str, stealth: bool, proxy: Optional[str], mode: str = "SAFE") -> Dict[str, Tuple[Dict[str, str], List[Dict[str, str]]]]:
        valid_targets = [ip for ip in targets if validate_ip(ip)]
        if not valid_targets:
            return {}
        max_workers = min(50, len(valid_targets), MAX_WORKERS)
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.run_nmap_scan, ip, scan_type, stealth, proxy, mode): ip for ip in valid_targets}
            try:
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        scan_result, vuln_result = future.result()
                        results[ip] = (scan_result, vuln_result)
                        self.scan_results[ip] = scan_result
                    except Exception as e:
                        logging.error(f"Error scanning {ip}: {str(e)}")
            except KeyboardInterrupt:
                logging.warning("Multi-target scan cancelled by user.")
                for fut in futures:
                    fut.cancel()
        logging.info("Multi-target scan completed.")
        return results

    def _print_scan_results(self, nm: nmap.PortScanner, target_ip: str, vulnerabilities: List[Dict[str, str]]) -> None:
        print(WHITE + f"\n=== Network Analysis Report for {target_ip} ===" + RESET)
        print(WHITE + f"Host: {target_ip} - State: {nm[target_ip].state()}" + RESET)
        for proto in nm[target_ip].all_protocols():
            print(WHITE + f"\nProtocol: {proto.upper()}:" + RESET)
            for port in sorted(nm[target_ip][proto].keys()):
                port_info = nm[target_ip][proto][port]
                print(WHITE + f"Port {port}/{proto}: {port_info.get('state', 'unknown')} - Service: {port_info.get('name', 'unknown')} ({port_info.get('version', '')})" + RESET)
        
        if vulnerabilities:
            print(WHITE + "\n=== Detected Vulnerabilities ===" + RESET)
            for i, vuln in enumerate(vulnerabilities, 1):
                # Ensure vuln is a dictionary
                if not isinstance(vuln, dict):
                    logging.warning(f"Vulnerability {i} is not a dictionary: {type(vuln)}")
                    continue
                
                port = vuln.get('port', 'N/A')
                protocol = vuln.get('protocol', 'tcp')
                cve = vuln.get('cve', 'Unknown CVE')
                description = vuln.get('description', 'No description')
                service = vuln.get('service', 'unknown')
                version = vuln.get('version', '')
                
                print(WHITE + f"{i}. Port {port}/{protocol} - {cve}: {description}" + RESET)
                if service or version:
                    version_str = f" {version}" if version else ""
                    print(WHITE + f"   Service: {service}{version_str}" + RESET)
