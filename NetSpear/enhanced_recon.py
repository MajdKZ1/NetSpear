"""
Enhanced reconnaissance module for NetSpear Network Analyzer.

Provides comprehensive OSINT and reconnaissance capabilities using multiple tools
with parallel processing for maximum efficiency.
"""
import subprocess
import logging
import os
import json
import re
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from utils import WHITE, RESET, validate_ip, validate_url
from error_handler import QuickError, safe_tool_check, safe_file_check
from progress_tracker import MultiTaskProgressTracker, ProgressStage
from config import MAX_WORKERS

class EnhancedReconnaissance:
    """Enhanced reconnaissance with multiple tools and parallel processing."""
    
    def __init__(self, tool_paths: Dict[str, str]):
        """
        Initialize enhanced reconnaissance.
        
        Args:
            tool_paths: Dictionary of tool names to their paths
        """
        self.tool_paths = tool_paths
        self.max_workers = MAX_WORKERS
    
    def passive_recon_parallel(self, target: str, target_type: str = "ip") -> Dict[str, Any]:
        """
        Perform comprehensive passive reconnaissance in parallel.
        
        Args:
            target: Target IP, domain, or URL
            target_type: Type of target (ip, domain, url)
        
        Returns:
            Dictionary containing all reconnaissance data
        """
        results = {
            "target": target,
            "type": target_type,
            "geo": {},
            "dns": {},
            "subdomains": [],
            "whois": {},
            "shodan": {},
            "certificates": {},
            "dns_records": {},
            "http_headers": {},
            "technologies": [],
            "errors": []
        }
        
        # Determine tasks based on available tools
        tasks = []
        
        # GeoIP lookup (always available)
        tasks.append(("geoip", self._geoip_lookup, target))
        
        # DNS enumeration
        if target_type in ["domain", "url"]:
            domain = target.split("://")[-1].split("/")[0] if "://" in target else target
            tasks.append(("dns", self._dns_enumeration, domain))
            tasks.append(("subdomains", self._subdomain_enumeration, domain))
            tasks.append(("certificates", self._certificate_enumeration, domain))
        
        # WHOIS lookup
        if target_type in ["ip", "domain"]:
            tasks.append(("whois", self._whois_lookup, target))
        
        # Shodan (if available)
        if safe_tool_check("shodan"):
            tasks.append(("shodan", self._shodan_lookup, target))
        
        # Censys (if available)
        if safe_tool_check("censys"):
            tasks.append(("censys", self._censys_lookup, target))
        
        # HTTP/HTTPS fingerprinting
        if target_type in ["url", "domain"]:
            url = target if "://" in target else f"https://{target}"
            tasks.append(("http", self._http_analysis, url))
        
        # Run all tasks in parallel
        if not tasks:
            logging.warning("No reconnaissance tasks available")
            return results
        
        tracker = MultiTaskProgressTracker(len(tasks), "Reconnaissance")
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                for task_id, func, arg in tasks:
                    future = executor.submit(func, arg)
                    futures[future] = task_id
                    tracker.task_started(task_id, task_id)
                
                for future in as_completed(futures):
                    task_id = futures[future]
                    try:
                        task_result = future.result(timeout=60)
                        if task_result:
                            results[task_id] = task_result
                        tracker.task_completed(task_id)
                    except Exception as e:
                        error_msg = f"{task_id} failed: {str(e)}"
                        results["errors"].append(error_msg)
                        tracker.task_failed(task_id, str(e))
                        logging.error(error_msg)
        finally:
            if tasks:
                tracker.finish()
        
        return results
    
    def _geoip_lookup(self, target: str) -> Dict[str, Any]:
        """Perform GeoIP lookup."""
        try:
            from urllib.request import urlopen
            from urllib.error import URLError, HTTPError
            
            # Try ip-api.com first
            if validate_ip(target):
                url = f"http://ip-api.com/json/{target}?fields=status,country,regionName,city,isp,org,as,mobile,proxy,hosting,query,timezone"
                with urlopen(url, timeout=6) as resp:
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
        except Exception as e:
            logging.debug(f"GeoIP lookup failed: {e}")
        return {}
    
    def _dns_enumeration(self, domain: str) -> Dict[str, List[str]]:
        """Perform DNS enumeration."""
        records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        }
        
        # Use dig if available
        if safe_tool_check("dig"):
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
            for rtype in record_types:
                try:
                    cmd = ["dig", "+short", domain, rtype]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                        records[rtype] = lines
                except Exception as e:
                    logging.debug(f"DNS {rtype} lookup failed: {e}")
        elif safe_tool_check("nslookup"):
            # Fallback to nslookup
            try:
                cmd = ["nslookup", domain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Parse nslookup output
                    for line in result.stdout.splitlines():
                        if "Address:" in line:
                            addr = line.split("Address:")[-1].strip()
                            if addr and addr not in records["A"]:
                                records["A"].append(addr)
            except Exception as e:
                logging.debug(f"nslookup failed: {e}")
        
        return records
    
    def _subdomain_enumeration(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple tools."""
        subdomains = set()
        
        # Try amass
        if safe_tool_check("amass"):
            try:
                cmd = ["amass", "enum", "-passive", "-d", domain, "-json", "/dev/stdout"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        try:
                            data = json.loads(line)
                            if "name" in data:
                                subdomains.add(data["name"])
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logging.debug(f"amass failed: {e}")
        
        # Try sublist3r
        if safe_tool_check("sublist3r"):
            try:
                cmd = ["sublist3r", "-d", domain, "-t", "10", "-o", "/dev/stdout"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line and "." in line:
                            subdomains.add(line)
            except Exception as e:
                logging.debug(f"sublist3r failed: {e}")
        
        # Try findomain
        if safe_tool_check("findomain"):
            try:
                cmd = ["findomain", "-t", domain, "-q"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line:
                            subdomains.add(line)
            except Exception as e:
                logging.debug(f"findomain failed: {e}")
        
        return sorted(list(subdomains))
    
    def _whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup."""
        if not safe_tool_check("whois"):
            return {}
        
        try:
            cmd = ["whois", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                # Parse whois output
                whois_data = {}
                for line in result.stdout.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip().lower()
                        value = value.strip()
                        if key and value:
                            if key not in whois_data:
                                whois_data[key] = []
                            whois_data[key].append(value)
                return whois_data
        except Exception as e:
            logging.debug(f"WHOIS lookup failed: {e}")
        return {}
    
    def _shodan_lookup(self, target: str) -> Dict[str, Any]:
        """Perform Shodan lookup (requires API key)."""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return {"error": "SHODAN_API_KEY not set"}
        
        try:
            cmd = ["shodan", "host", target, "--format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            logging.debug(f"Shodan lookup failed: {e}")
        return {}
    
    def _censys_lookup(self, target: str) -> Dict[str, Any]:
        """Perform Censys lookup (requires API credentials)."""
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            return {"error": "CENSYS_API_ID and CENSYS_API_SECRET not set"}
        
        try:
            cmd = ["censys", "search", target, "--format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            logging.debug(f"Censys lookup failed: {e}")
        return {}
    
    def _certificate_enumeration(self, domain: str) -> Dict[str, Any]:
        """Enumerate SSL/TLS certificates."""
        cert_data = {}
        
        # Try certbot/certificate transparency logs
        if safe_tool_check("ctfr"):
            try:
                cmd = ["ctfr", "-d", domain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    cert_data["subdomains"] = result.stdout.splitlines()
            except Exception as e:
                logging.debug(f"ctfr failed: {e}")
        
        return cert_data
    
    def _http_analysis(self, url: str) -> Dict[str, Any]:
        """Perform HTTP/HTTPS analysis."""
        try:
            from urllib.request import urlopen, Request
            from urllib.error import URLError, HTTPError
            
            req = Request(url, method="HEAD", headers={"User-Agent": "NetSpear-Intel/1.0"})
            with urlopen(req, timeout=8) as resp:
                headers = dict(resp.headers)
                return {
                    "status": getattr(resp, "status", None),
                    "server": headers.get("Server"),
                    "powered_by": headers.get("X-Powered-By"),
                    "content_type": headers.get("Content-Type"),
                    "headers": headers
                }
        except Exception as e:
            logging.debug(f"HTTP analysis failed: {e}")
            return {"error": str(e)}

