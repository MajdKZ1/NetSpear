"""
Integration with external vulnerability scanners (Nessus, OpenVAS, Qualys, Burp).
"""
import logging
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List, Any
from pathlib import Path

from database import get_db_manager, Scan, Vulnerability

logger = logging.getLogger(__name__)


class ScannerIntegration:
    """Integrate with external vulnerability scanners."""
    
    def __init__(self, db_session=None):
        """Initialize scanner integration."""
        self.db = get_db_manager()
        self.db_session = db_session
    
    def _get_session(self):
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def import_nessus(self, nessus_file: Path, target_ip: str) -> int:
        """
        Import Nessus scan results.
        
        Args:
            nessus_file: Path to Nessus XML file
            target_ip: Target IP address
            
        Returns:
            Number of vulnerabilities imported
        """
        db = self._get_session()
        try:
            tree = ET.parse(nessus_file)
            root = tree.getroot()
            
            # Create scan record
            scan = Scan(
                target_ip=target_ip,
                scan_type="nessus_import",
                scan_label="Nessus Import",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            count = 0
            # Parse Nessus XML format
            for report in root.findall(".//Report"):
                for host in report.findall("ReportHost"):
                    for item in host.findall("ReportItem"):
                        plugin_name = item.get("pluginName", "")
                        severity = item.find("severity")
                        severity_text = severity.text if severity is not None else "0"
                        
                        # Convert severity number to text
                        severity_map = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
                        severity_level = severity_map.get(severity_text, "info")
                        
                        description = item.find("description")
                        description_text = description.text if description is not None else ""
                        
                        port = item.get("port", "0")
                        try:
                            port_num = int(port) if port else None
                        except ValueError:
                            port_num = None
                        
                        vuln = Vulnerability(
                            scan_id=scan.id,
                            port=port_num,
                            service=item.get("svc_name", ""),
                            description=description_text,
                            severity=severity_level,
                            script_id=plugin_name,
                        )
                        db.add(vuln)
                        count += 1
            
            db.commit()
            logger.info(f"Imported {count} vulnerabilities from Nessus scan")
            return count
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to import Nessus scan: {e}")
            return 0
    
    def import_openvas(self, openvas_file: Path, target_ip: str) -> int:
        """
        Import OpenVAS scan results.
        
        Args:
            openvas_file: Path to OpenVAS XML file
            target_ip: Target IP address
            
        Returns:
            Number of vulnerabilities imported
        """
        # Similar to Nessus import
        db = self._get_session()
        try:
            tree = ET.parse(openvas_file)
            root = tree.getroot()
            
            scan = Scan(
                target_ip=target_ip,
                scan_type="openvas_import",
                scan_label="OpenVAS Import",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            count = 0
            # Parse OpenVAS XML format
            for result in root.findall(".//result"):
                name = result.find("name")
                description = result.find("description")
                severity = result.find("severity")
                
                vuln = Vulnerability(
                    scan_id=scan.id,
                    description=(description.text if description is not None else "") or (name.text if name is not None else ""),
                    severity=self._parse_severity(severity.text if severity is not None else "0.0"),
                )
                db.add(vuln)
                count += 1
            
            db.commit()
            logger.info(f"Imported {count} vulnerabilities from OpenVAS scan")
            return count
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to import OpenVAS scan: {e}")
            return 0
    
    def import_burp(self, burp_file: Path, target_ip: str) -> int:
        """Import Burp Suite scan results."""
        # Burp Suite JSON format
        import json
        db = self._get_session()
        try:
            with open(burp_file, "r") as f:
                burp_data = json.load(f)
            
            scan = Scan(
                target_ip=target_ip,
                scan_type="burp_import",
                scan_label="Burp Suite Import",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            count = 0
            for issue in burp_data.get("issues", []):
                vuln = Vulnerability(
                    scan_id=scan.id,
                    port=issue.get("port"),
                    description=issue.get("name", ""),
                    severity=issue.get("severity", "info"),
                )
                db.add(vuln)
                count += 1
            
            db.commit()
            logger.info(f"Imported {count} vulnerabilities from Burp Suite scan")
            return count
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to import Burp Suite scan: {e}")
            return 0
    
    def _parse_severity(self, severity_str: str) -> str:
        """Parse severity string to level."""
        try:
            severity_float = float(severity_str)
            if severity_float >= 9.0:
                return "critical"
            elif severity_float >= 7.0:
                return "high"
            elif severity_float >= 4.0:
                return "medium"
            else:
                return "low"
        except ValueError:
            return "info"

