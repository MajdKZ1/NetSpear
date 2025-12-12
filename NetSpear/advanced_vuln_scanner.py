"""
Advanced Professional-Grade Vulnerability Scanner for NetSpear.

This module provides comprehensive vulnerability detection including:
- Real CVSS database integration (NVD API)
- Service version fingerprinting with CVE lookup
- Web application vulnerability scanning
- TLS/SSL deep analysis
- Security headers analysis
- Configuration misconfiguration detection
- False positive reduction and verification
"""
import logging
import re
import json
import ssl
import socket
import subprocess
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from database import Vulnerability
from utils import validate_ip, validate_url

logger = logging.getLogger(__name__)

# CVE Database cache to reduce API calls
CVE_CACHE: Dict[str, Dict[str, Any]] = {}
CVE_CACHE_TTL = 86400  # 24 hours


class AdvancedVulnerabilityScanner:
    """
    Professional-grade vulnerability scanner with multiple detection methods.
    """
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        """
        Initialize advanced vulnerability scanner.
        
        Args:
            nvd_api_key: Optional NVD API key for higher rate limits
        """
        self.nvd_api_key = nvd_api_key or None
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = self._create_session()
        
        # Known vulnerable versions database (can be expanded)
        self.vulnerable_versions = self._load_vulnerable_versions()
        
        # Web vulnerability payloads
        self.web_payloads = self._load_web_payloads()
        
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _load_vulnerable_versions(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load known vulnerable software versions."""
        # This can be expanded with a database or file
        return {
            "openssh": [
                {"version": "<7.4", "cves": ["CVE-2016-10009", "CVE-2016-10010"]},
                {"version": "<8.0", "cves": ["CVE-2018-15473"]},
            ],
            "apache": [
                {"version": "<2.4.41", "cves": ["CVE-2019-0211", "CVE-2019-0217"]},
                {"version": "<2.4.46", "cves": ["CVE-2020-11984", "CVE-2020-11985"]},
            ],
            "nginx": [
                {"version": "<1.18.0", "cves": ["CVE-2020-12440"]},
                {"version": "<1.19.6", "cves": ["CVE-2021-23017"]},
            ],
        }
    
    def _load_web_payloads(self) -> Dict[str, List[str]]:
        """Load web vulnerability test payloads."""
        return {
            "sqli": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND 1=1--",
                "admin'--",
                "' OR 1=1#",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://localhost",
                "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/",
            ],
            "command_injection": [
                "; ls",
                "| whoami",
                "& cat /etc/passwd",
                "`id`",
                "$(uname -a)",
            ],
        }
    
    def scan_comprehensive(
        self,
        target_ip: str,
        ports: List[Dict[str, Any]],
        scan_result: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Perform comprehensive vulnerability scanning.
        
        Args:
            target_ip: Target IP address
            ports: List of open ports with service information
            scan_result: Existing scan results
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # 1. Service version fingerprinting with CVE lookup
        logger.info(f"Starting service version fingerprinting for {target_ip}")
        version_vulns = self._scan_service_versions(target_ip, ports)
        vulnerabilities.extend(version_vulns)
        
        # 2. Web application vulnerability scanning
        web_ports = [p for p in ports if p.get("port") in [80, 443, 8080, 8443] 
                    or p.get("service", "").lower() in ["http", "https"]]
        if web_ports:
            logger.info(f"Starting web application scanning for {target_ip}")
            web_vulns = self._scan_web_application(target_ip, web_ports)
            vulnerabilities.extend(web_vulns)
        
        # 3. TLS/SSL vulnerability analysis
        tls_ports = [p for p in ports if p.get("port") in [443, 8443, 636, 993, 995]
                    or "ssl" in p.get("service", "").lower() or "tls" in p.get("service", "").lower()]
        if tls_ports:
            logger.info(f"Starting TLS/SSL analysis for {target_ip}")
            tls_vulns = self._scan_tls_ssl(target_ip, tls_ports)
            vulnerabilities.extend(tls_vulns)
        
        # 4. Configuration misconfiguration detection
        logger.info(f"Starting misconfiguration detection for {target_ip}")
        config_vulns = self._scan_misconfigurations(target_ip, ports)
        vulnerabilities.extend(config_vulns)
        
        # 5. Weak credentials detection
        logger.info(f"Starting weak credentials detection for {target_ip}")
        cred_vulns = self._scan_weak_credentials(target_ip, ports)
        vulnerabilities.extend(cred_vulns)
        
        # 6. Database-specific vulnerabilities
        db_ports = [p for p in ports if p.get("service", "").lower() in 
                   ["mysql", "postgresql", "mssql", "mongodb", "redis", "elasticsearch"]]
        if db_ports:
            logger.info(f"Starting database vulnerability scanning for {target_ip}")
            db_vulns = self._scan_databases(target_ip, db_ports)
            vulnerabilities.extend(db_vulns)
        
        # 7. Enrich vulnerabilities with CVSS scores
        logger.info(f"Enriching vulnerabilities with CVSS scores")
        enriched_vulns = []
        for vuln in vulnerabilities:
            enriched = self._enrich_vulnerability(vuln)
            enriched_vulns.append(enriched)
        
        # 8. Filter false positives
        logger.info(f"Filtering false positives")
        filtered_vulns = self.filter_false_positives(enriched_vulns)
        
        return filtered_vulns
    
    def _scan_service_versions(
        self,
        target_ip: str,
        ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Scan service versions and match against CVE database."""
        vulnerabilities = []
        
        for port_info in ports:
            service = port_info.get("service", "").lower()
            version = port_info.get("version", "").strip()
            port = port_info.get("port")
            protocol = port_info.get("protocol", "tcp")
            
            if not version:
                continue
            
            # Extract version number
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
            if not version_match:
                continue
            
            version_num = version_match.group(1)
            
            # Check against known vulnerable versions
            service_key = service.split()[0] if service else ""
            if service_key in self.vulnerable_versions:
                for vuln_entry in self.vulnerable_versions[service_key]:
                    if self._version_matches(version_num, vuln_entry["version"]):
                        for cve in vuln_entry["cves"]:
                            vulnerabilities.append({
                                "target_ip": target_ip,
                                "port": port,
                                "protocol": protocol,
                                "service": service,
                                "version": version,
                                "cve": cve,
                                "description": f"Vulnerable {service} version {version} detected",
                                "severity": "high",
                                "category": "version_vulnerability",
                                "detection_method": "version_fingerprinting",
                            })
            
            # Query NVD for CVEs related to this service and version
            cves = self._query_cve_by_service_version(service, version)
            for cve in cves:
                vulnerabilities.append({
                    "target_ip": target_ip,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "cve": cve["id"],
                    "description": cve.get("description", f"Known vulnerability in {service} {version}"),
                    "severity": self._cve_severity_to_level(cve.get("cvss_score", 0)),
                    "cvss_score": cve.get("cvss_score"),
                    "category": "version_vulnerability",
                    "detection_method": "cve_database",
                })
        
        return vulnerabilities
    
    def _scan_web_application(
        self,
        target_ip: str,
        web_ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Scan web applications for common vulnerabilities."""
        vulnerabilities = []
        
        for port_info in web_ports:
            port = port_info.get("port")
            protocol = "https" if port in [443, 8443] else "http"
            base_url = f"{protocol}://{target_ip}:{port}"
            
            # 1. Security headers check
            header_vulns = self._check_security_headers(base_url)
            vulnerabilities.extend(header_vulns)
            
            # 2. TLS/SSL configuration (if HTTPS)
            if protocol == "https":
                tls_vulns = self._check_tls_configuration(target_ip, port)
                vulnerabilities.extend(tls_vulns)
            
            # 3. Technology fingerprinting and known vulnerabilities
            tech_vulns = self._fingerprint_web_tech(base_url)
            vulnerabilities.extend(tech_vulns)
            
            # 4. Directory traversal and file disclosure
            file_vulns = self._test_file_disclosure(base_url)
            vulnerabilities.extend(file_vulns)
            
            # 5. Information disclosure
            info_vulns = self._test_information_disclosure(base_url)
            vulnerabilities.extend(info_vulns)
        
        return vulnerabilities
    
    def _check_security_headers(self, url: str) -> List[Dict[str, Any]]:
        """Check for missing or misconfigured security headers."""
        vulnerabilities = []
        
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            # Required security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": None,  # Should be present for HTTPS
                "Content-Security-Policy": None,
                "Referrer-Policy": None,
            }
            
            parsed = urlparse(url)
            is_https = parsed.scheme == "https"
            
            for header, expected_value in security_headers.items():
                if header not in headers:
                    severity = "medium" if header == "Strict-Transport-Security" and is_https else "low"
                    vulnerabilities.append({
                        "target_ip": parsed.hostname,
                        "port": parsed.port or (443 if is_https else 80),
                        "service": "http" if not is_https else "https",
                        "cve": None,
                        "description": f"Missing security header: {header}",
                        "severity": severity,
                        "category": "security_headers",
                        "detection_method": "header_analysis",
                    })
                elif expected_value and header in headers:
                    actual = headers[header]
                    if isinstance(expected_value, list):
                        if actual not in expected_value:
                            vulnerabilities.append({
                                "target_ip": parsed.hostname,
                                "port": parsed.port or (443 if is_https else 80),
                                "service": "http" if not is_https else "https",
                                "cve": None,
                                "description": f"Misconfigured {header}: {actual} (expected one of {expected_value})",
                                "severity": "low",
                                "category": "security_headers",
                                "detection_method": "header_analysis",
                            })
                    elif expected_value not in actual:
                        vulnerabilities.append({
                            "target_ip": parsed.hostname,
                            "port": parsed.port or (443 if is_https else 80),
                            "service": "http" if not is_https else "https",
                            "cve": None,
                            "description": f"Misconfigured {header}: {actual} (expected {expected_value})",
                            "severity": "low",
                            "category": "security_headers",
                            "detection_method": "header_analysis",
                        })
            
            # Check for sensitive information in headers
            sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in sensitive_headers:
                if header in headers:
                    vulnerabilities.append({
                        "target_ip": parsed.hostname,
                        "port": parsed.port or (443 if is_https else 80),
                        "service": "http" if not is_https else "https",
                        "cve": None,
                        "description": f"Information disclosure: {header} header reveals {headers[header]}",
                        "severity": "info",
                        "category": "information_disclosure",
                        "detection_method": "header_analysis",
                    })
        
        except Exception as e:
            logger.debug(f"Security headers check failed for {url}: {e}")
        
        return vulnerabilities
    
    def _check_tls_configuration(self, host: str, port: int) -> List[Dict[str, Any]]:
        """Check TLS/SSL configuration for vulnerabilities."""
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version in ["TLSv1", "TLSv1.1"]:
                        vulnerabilities.append({
                            "target_ip": host,
                            "port": port,
                            "service": "https",
                            "cve": None,
                            "description": f"Deprecated TLS version in use: {tls_version}",
                            "severity": "high",
                            "category": "tls_configuration",
                            "detection_method": "tls_analysis",
                        })
                    
                    # Check cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        # Check for weak ciphers
                        weak_ciphers = ["RC4", "DES", "MD5", "NULL", "EXPORT"]
                        if any(weak in cipher_name for weak in weak_ciphers):
                            vulnerabilities.append({
                                "target_ip": host,
                                "port": port,
                                "service": "https",
                                "cve": None,
                                "description": f"Weak cipher suite: {cipher_name}",
                                "severity": "high",
                                "category": "tls_configuration",
                                "detection_method": "tls_analysis",
                            })
                    
                    # Check certificate
                    cert = ssock.getpeercert()
                    if cert:
                        # Check certificate expiration
                        not_after = cert.get("notAfter")
                        if not_after:
                            try:
                                expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_until_expiry = (expire_date - datetime.now()).days
                                if days_until_expiry < 30:
                                    vulnerabilities.append({
                                        "target_ip": host,
                                        "port": port,
                                        "service": "https",
                                        "cve": None,
                                        "description": f"SSL certificate expires in {days_until_expiry} days",
                                        "severity": "medium" if days_until_expiry < 7 else "low",
                                        "category": "tls_configuration",
                                        "detection_method": "certificate_analysis",
                                    })
                            except Exception:
                                pass
        
        except Exception as e:
            logger.debug(f"TLS configuration check failed for {host}:{port}: {e}")
        
        return vulnerabilities
    
    def _scan_tls_ssl(
        self,
        target_ip: str,
        tls_ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Deep TLS/SSL vulnerability scanning."""
        vulnerabilities = []
        
        for port_info in tls_ports:
            port = port_info.get("port")
            tls_vulns = self._check_tls_configuration(target_ip, port)
            vulnerabilities.extend(tls_vulns)
            
            # Use testssl.sh or similar if available
            # For now, we do basic checks above
        
        return vulnerabilities
    
    def _fingerprint_web_tech(self, url: str) -> List[Dict[str, Any]]:
        """Fingerprint web technologies and check for known vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            content = response.text[:5000]  # First 5KB
            
            # Detect technologies
            technologies = {}
            
            # Server detection
            if "Server" in headers:
                server = headers["Server"]
                technologies["server"] = server
                # Check for known vulnerable versions
                if "Apache" in server:
                    version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
                    if version_match:
                        version = version_match.group(1)
                        # Check against known CVEs
                        cves = self._query_cve_by_service_version("apache", version)
                        for cve in cves:
                            vulnerabilities.append({
                                "target_ip": urlparse(url).hostname,
                                "port": urlparse(url).port or (443 if "https" in url else 80),
                                "service": "http",
                                "cve": cve["id"],
                                "description": f"Vulnerable Apache version detected: {version}",
                                "severity": self._cve_severity_to_level(cve.get("cvss_score", 0)),
                                "category": "web_technology",
                                "detection_method": "technology_fingerprinting",
                            })
            
            # Framework detection from content
            if "wp-content" in content or "wp-includes" in content:
                technologies["cms"] = "WordPress"
                # Check WordPress version
                version_match = re.search(r'wp-json/wp/v(\d+\.\d+)', content)
                if not version_match:
                    version_match = re.search(r'ver=(\d+\.\d+\.\d+)', content)
                if version_match:
                    wp_version = version_match.group(1)
                    # WordPress vulnerabilities are common
                    vulnerabilities.append({
                        "target_ip": urlparse(url).hostname,
                        "port": urlparse(url).port or (443 if "https" in url else 80),
                        "service": "http",
                        "cve": None,
                        "description": f"WordPress {wp_version} detected - check for known CVEs",
                        "severity": "medium",
                        "category": "web_technology",
                        "detection_method": "technology_fingerprinting",
                    })
        
        except Exception as e:
            logger.debug(f"Web technology fingerprinting failed for {url}: {e}")
        
        return vulnerabilities
    
    def _test_file_disclosure(self, url: str) -> List[Dict[str, Any]]:
        """Test for file disclosure vulnerabilities."""
        vulnerabilities = []
        
        test_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/proc/version",
            "/.env",
            "/.git/config",
            "/web.config",
            "/.htaccess",
        ]
        
        for path in test_paths:
            try:
                test_url = url.rstrip("/") + path
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    content = response.text[:200]
                    # Check if it looks like a sensitive file
                    if any(indicator in content for indicator in ["root:", "#!/", "[core]", "<?xml"]):
                        vulnerabilities.append({
                            "target_ip": urlparse(url).hostname,
                            "port": urlparse(url).port or (443 if "https" in url else 80),
                            "service": "http",
                            "cve": None,
                            "description": f"Potential file disclosure: {path}",
                            "severity": "high",
                            "category": "file_disclosure",
                            "detection_method": "path_traversal_test",
                        })
            except Exception:
                continue
        
        return vulnerabilities
    
    def _test_information_disclosure(self, url: str) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test error pages
            error_url = url.rstrip("/") + "/nonexistent-page-12345"
            response = self.session.get(error_url, timeout=5)
            
            if response.status_code in [400, 500]:
                content = response.text.lower()
                # Check for stack traces or sensitive info
                if any(indicator in content for indicator in ["stack trace", "exception", "sql syntax", "database error"]):
                    vulnerabilities.append({
                        "target_ip": urlparse(url).hostname,
                        "port": urlparse(url).port or (443 if "https" in url else 80),
                        "service": "http",
                        "cve": None,
                        "description": "Information disclosure in error messages",
                        "severity": "medium",
                        "category": "information_disclosure",
                        "detection_method": "error_analysis",
                    })
        except Exception:
            pass
        
        return vulnerabilities
    
    def _scan_misconfigurations(
        self,
        target_ip: str,
        ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Scan for common misconfigurations."""
        vulnerabilities = []
        
        for port_info in ports:
            port = port_info.get("port")
            service = port_info.get("service", "").lower()
            
            # SMB misconfigurations
            if service == "smb" or port in [139, 445]:
                # Check for SMB signing disabled
                vulnerabilities.append({
                    "target_ip": target_ip,
                    "port": port,
                    "service": service,
                    "cve": None,
                    "description": "SMB service detected - verify SMB signing is enabled",
                    "severity": "medium",
                    "category": "misconfiguration",
                    "detection_method": "service_analysis",
                })
            
            # FTP anonymous access
            if service == "ftp" or port == 21:
                vulnerabilities.append({
                    "target_ip": target_ip,
                    "port": port,
                    "service": service,
                    "cve": None,
                    "description": "FTP service detected - verify anonymous access is disabled",
                    "severity": "medium",
                    "category": "misconfiguration",
                    "detection_method": "service_analysis",
                })
            
            # SNMP public community
            if service == "snmp" or port == 161:
                vulnerabilities.append({
                    "target_ip": target_ip,
                    "port": port,
                    "service": service,
                    "cve": None,
                    "description": "SNMP service detected - verify public community string is changed",
                    "severity": "high",
                    "category": "misconfiguration",
                    "detection_method": "service_analysis",
                })
        
        return vulnerabilities
    
    def _scan_weak_credentials(
        self,
        target_ip: str,
        ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect services with weak or default credentials."""
        vulnerabilities = []
        
        # This would typically integrate with Hydra or similar
        # For now, we flag services that commonly have weak credentials
        
        weak_cred_services = {
            "ssh": {"port": 22, "severity": "high"},
            "ftp": {"port": 21, "severity": "medium"},
            "telnet": {"port": 23, "severity": "high"},
            "mysql": {"port": 3306, "severity": "high"},
            "postgresql": {"port": 5432, "severity": "high"},
            "mssql": {"port": 1433, "severity": "high"},
            "rdp": {"port": 3389, "severity": "high"},
        }
        
        for port_info in ports:
            service = port_info.get("service", "").lower()
            port = port_info.get("port")
            
            for svc_name, svc_info in weak_cred_services.items():
                if svc_name in service or port == svc_info["port"]:
                    vulnerabilities.append({
                        "target_ip": target_ip,
                        "port": port,
                        "service": service,
                        "cve": None,
                        "description": f"{service.upper()} service detected - verify strong credentials are used",
                        "severity": svc_info["severity"],
                        "category": "weak_credentials",
                        "detection_method": "service_analysis",
                    })
        
        return vulnerabilities
    
    def _scan_databases(
        self,
        target_ip: str,
        db_ports: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Scan database services for vulnerabilities."""
        vulnerabilities = []
        
        for port_info in db_ports:
            service = port_info.get("service", "").lower()
            port = port_info.get("port")
            version = port_info.get("version", "")
            
            # Check for unauthenticated access
            if service in ["redis", "mongodb", "memcached", "elasticsearch"]:
                vulnerabilities.append({
                    "target_ip": target_ip,
                    "port": port,
                    "service": service,
                    "cve": None,
                    "description": f"{service.upper()} detected - verify authentication is enabled",
                    "severity": "critical",
                    "category": "database_security",
                    "detection_method": "database_analysis",
                })
            
            # Version-specific vulnerabilities
            if version:
                cves = self._query_cve_by_service_version(service, version)
                for cve in cves:
                    vulnerabilities.append({
                        "target_ip": target_ip,
                        "port": port,
                        "service": service,
                        "version": version,
                        "cve": cve["id"],
                        "description": cve.get("description", f"Known vulnerability in {service} {version}"),
                        "severity": self._cve_severity_to_level(cve.get("cvss_score", 0)),
                        "cvss_score": cve.get("cvss_score"),
                        "category": "database_security",
                        "detection_method": "cve_database",
                    })
        
        return vulnerabilities
    
    def _query_cve_by_service_version(
        self,
        service: str,
        version: str
    ) -> List[Dict[str, Any]]:
        """Query NVD API for CVEs related to service and version."""
        cves = []
        
        # Check cache first
        cache_key = f"{service}:{version}"
        if cache_key in CVE_CACHE:
            cached = CVE_CACHE[cache_key]
            if time.time() - cached.get("timestamp", 0) < CVE_CACHE_TTL:
                return cached.get("cves", [])
        
        try:
            # Query NVD API
            query = f"{service} {version}"
            params = {
                "keywordSearch": query,
                "resultsPerPage": 20,
            }
            
            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key
            
            response = self.session.get(self.nvd_base_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id")
                    
                    # Get CVSS score
                    cvss_score = None
                    metrics = cve_data.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0]
                        cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0]
                        cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0]
                        cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                    
                    # Get description
                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    if cve_id:
                        cves.append({
                            "id": cve_id,
                            "description": description,
                            "cvss_score": cvss_score,
                        })
            
            # Cache results
            CVE_CACHE[cache_key] = {
                "cves": cves,
                "timestamp": time.time(),
            }
            
            # Rate limiting - be respectful
            time.sleep(0.6)  # NVD allows 50 requests per 30 seconds without API key
        
        except Exception as e:
            logger.debug(f"CVE query failed for {service} {version}: {e}")
        
        return cves
    
    def _enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich vulnerability with CVSS score and additional metadata."""
        cve = vuln.get("cve")
        
        if cve and not vuln.get("cvss_score"):
            # Query NVD for this specific CVE
            cve_data = self._get_cve_details(cve)
            if cve_data:
                vuln["cvss_score"] = cve_data.get("cvss_score")
                vuln["cvss_vector"] = cve_data.get("cvss_vector")
                if not vuln.get("description"):
                    vuln["description"] = cve_data.get("description", "")
                # Update severity based on CVSS
                if vuln["cvss_score"]:
                    vuln["severity"] = self._cve_severity_to_level(vuln["cvss_score"])
        
        # Add timestamps
        vuln["discovered_at"] = datetime.now(timezone.utc).isoformat()
        
        # Add risk score calculation
        if not vuln.get("risk_score"):
            vuln["risk_score"] = self._calculate_risk_score(vuln)
        
        return vuln
    
    def _get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed CVE information from NVD."""
        # Check cache
        if cve_id in CVE_CACHE:
            cached = CVE_CACHE[cve_id]
            if time.time() - cached.get("timestamp", 0) < CVE_CACHE_TTL:
                return cached.get("data")
        
        try:
            url = f"{self.nvd_base_url}?cveId={cve_id}"
            params = {}
            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key
            
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    
                    # Extract CVSS
                    cvss_score = None
                    cvss_vector = None
                    metrics = cve_data.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_metric = metrics["cvssMetricV31"][0]
                        cvss_data = cvss_metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                    elif "cvssMetricV30" in metrics:
                        cvss_metric = metrics["cvssMetricV30"][0]
                        cvss_data = cvss_metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                    elif "cvssMetricV2" in metrics:
                        cvss_metric = metrics["cvssMetricV2"][0]
                        cvss_data = cvss_metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                    
                    # Extract description
                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    result = {
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "description": description,
                    }
                    
                    # Cache
                    CVE_CACHE[cve_id] = {
                        "data": result,
                        "timestamp": time.time(),
                    }
                    
                    time.sleep(0.6)  # Rate limiting
                    return result
        
        except Exception as e:
            logger.debug(f"Failed to get CVE details for {cve_id}: {e}")
        
        return None
    
    def _cve_severity_to_level(self, cvss_score: Optional[float]) -> str:
        """Convert CVSS score to severity level."""
        if not cvss_score:
            return "unknown"
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        return "info"
    
    def _calculate_risk_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate risk score for vulnerability."""
        base_score = vuln.get("cvss_score", 5.0)
        
        # Adjustments
        severity = vuln.get("severity", "medium")
        severity_multiplier = {
            "critical": 1.3,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8,
            "info": 0.5,
        }.get(severity, 1.0)
        
        # Category adjustments
        category = vuln.get("category", "")
        if category in ["database_security", "weak_credentials"]:
            base_score *= 1.2
        
        risk_score = base_score * severity_multiplier
        return min(10.0, max(0.0, risk_score))
    
    def _version_matches(self, version: str, pattern: str) -> bool:
        """Check if version matches pattern (e.g., '<7.4')."""
        try:
            if pattern.startswith("<"):
                target_version = pattern[1:].strip()
                return self._compare_versions(version, target_version) < 0
            elif pattern.startswith(">"):
                target_version = pattern[1:].strip()
                return self._compare_versions(version, target_version) > 0
            elif pattern.startswith("<="):
                target_version = pattern[2:].strip()
                return self._compare_versions(version, target_version) <= 0
            elif pattern.startswith(">="):
                target_version = pattern[2:].strip()
                return self._compare_versions(version, target_version) >= 0
            else:
                return version == pattern
        except Exception:
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        try:
            v1_parts = [int(x) for x in v1.split(".")]
            v2_parts = [int(x) for x in v2.split(".")]
            
            # Pad with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0
        except Exception:
            return 0
    
    def verify_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a vulnerability to reduce false positives.
        
        Args:
            vuln: Vulnerability dictionary
            
        Returns:
            Updated vulnerability with verification status
        """
        verification_status = "unverified"
        confidence = "medium"
        
        # High confidence indicators
        if vuln.get("cve") and vuln.get("cvss_score") and vuln.get("cvss_score") >= 7.0:
            confidence = "high"
            verification_status = "verified"
        
        # Medium confidence - version match with CVE
        elif vuln.get("cve") and vuln.get("version") and vuln.get("detection_method") == "cve_database":
            confidence = "medium"
            verification_status = "likely"
        
        # Low confidence - generic findings
        elif not vuln.get("cve") and vuln.get("category") in ["security_headers", "information_disclosure"]:
            confidence = "low"
            verification_status = "unverified"
        
        # Check for false positive patterns
        description = vuln.get("description", "").lower()
        false_positive_indicators = [
            "not vulnerable",
            "patched",
            "fixed in",
            "resolved",
            "mitigated",
        ]
        
        if any(indicator in description for indicator in false_positive_indicators):
            verification_status = "false_positive"
            confidence = "high"
        
        vuln["verification_status"] = verification_status
        vuln["confidence"] = confidence
        
        return vuln
    
    def filter_false_positives(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out likely false positives from vulnerability list.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Filtered list with false positives removed
        """
        verified_vulns = []
        
        for vuln in vulnerabilities:
            # Verify each vulnerability
            verified = self.verify_vulnerability(vuln)
            
            # Only exclude if marked as false positive with high confidence
            if verified.get("verification_status") == "false_positive" and verified.get("confidence") == "high":
                logger.debug(f"Filtering false positive: {verified.get('cve') or verified.get('description')}")
                continue
            
            verified_vulns.append(verified)
        
        return verified_vulns

