"""
Evidence collection system with screenshot capture and PoC storage.
"""
import logging
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from sqlalchemy.orm import Session

from database import get_db_manager, Evidence

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Collect and store evidence during assessments."""
    
    def __init__(self, db_session: Optional[Session] = None, evidence_dir: Optional[Path] = None):
        """
        Initialize evidence collector.
        
        Args:
            db_session: Optional database session
            evidence_dir: Directory for storing evidence files
        """
        self.db = get_db_manager()
        self.db_session = db_session
        
        if evidence_dir:
            self.evidence_dir = Path(evidence_dir)
        else:
            self.evidence_dir = Path.home() / ".netspear" / "evidence"
        
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_session(self) -> Session:
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def save_evidence(
        self,
        evidence_type: str,
        file_path: Path,
        scan_id: Optional[int] = None,
        vulnerability_id: Optional[int] = None,
        description: Optional[str] = None,
    ) -> Optional[Evidence]:
        """
        Save evidence file.
        
        Args:
            evidence_type: Type of evidence (screenshot, poc, file, log)
            file_path: Path to evidence file
            scan_id: Optional scan ID
            vulnerability_id: Optional vulnerability ID
            description: Optional description
            
        Returns:
            Created evidence record
        """
        if not file_path.exists():
            logger.error(f"Evidence file not found: {file_path}")
            return None
        
        db = self._get_session()
        try:
            # Copy file to evidence directory
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"{evidence_type}_{timestamp}_{file_path.name}"
            dest_path = self.evidence_dir / filename
            
            shutil.copy2(file_path, dest_path)
            
            # Calculate hash
            file_hash = self._calculate_hash(dest_path)
            
            # Create evidence record
            evidence = Evidence(
                scan_id=scan_id,
                vulnerability_id=vulnerability_id,
                evidence_type=evidence_type,
                filename=filename,
                file_path=str(dest_path),
                file_hash=file_hash,
                description=description,
                captured_at=datetime.now(timezone.utc),
            )
            
            db.add(evidence)
            db.commit()
            db.refresh(evidence)
            
            logger.info(f"Saved evidence: {filename} (hash: {file_hash[:16]}...)")
            return evidence
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save evidence: {e}")
            return None
    
    def capture_screenshot(
        self,
        url: str,
        scan_id: Optional[int] = None,
        description: Optional[str] = None,
    ) -> Optional[Evidence]:
        """
        Capture a screenshot of a webpage.
        
        Args:
            url: URL to capture
            scan_id: Optional scan ID
            description: Optional description
            
        Returns:
            Created evidence record
        """
        try:
            # Use selenium or playwright for screenshot
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            screenshot_path = self.evidence_dir / f"screenshot_{timestamp}.png"
            driver.save_screenshot(str(screenshot_path))
            driver.quit()
            
            return self.save_evidence(
                evidence_type="screenshot",
                file_path=screenshot_path,
                scan_id=scan_id,
                description=description or f"Screenshot of {url}",
            )
        except ImportError:
            logger.warning("Selenium not available for screenshot capture")
            return None
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
            return None
    
    def save_poc(
        self,
        poc_content: str,
        filename: str,
        scan_id: Optional[int] = None,
        vulnerability_id: Optional[int] = None,
        description: Optional[str] = None,
    ) -> Optional[Evidence]:
        """
        Save proof-of-concept file.
        
        Args:
            poc_content: PoC content (code, exploit, etc.)
            filename: Filename for PoC
            scan_id: Optional scan ID
            vulnerability_id: Optional vulnerability ID
            description: Optional description
            
        Returns:
            Created evidence record
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        poc_path = self.evidence_dir / f"poc_{timestamp}_{filename}"
        
        try:
            with open(poc_path, "w") as f:
                f.write(poc_content)
            
            return self.save_evidence(
                evidence_type="poc",
                file_path=poc_path,
                scan_id=scan_id,
                vulnerability_id=vulnerability_id,
                description=description,
            )
        except Exception as e:
            logger.error(f"Failed to save PoC: {e}")
            return None
    
    def get_evidence(self, evidence_id: int) -> Optional[Evidence]:
        """Get evidence by ID."""
        db = self._get_session()
        return db.query(Evidence).filter(Evidence.id == evidence_id).first()
    
    def list_evidence(
        self,
        scan_id: Optional[int] = None,
        vulnerability_id: Optional[int] = None,
        evidence_type: Optional[str] = None,
    ) -> List[Evidence]:
        """
        List evidence matching criteria.
        
        Args:
            scan_id: Filter by scan ID
            vulnerability_id: Filter by vulnerability ID
            evidence_type: Filter by evidence type
            
        Returns:
            List of evidence records
        """
        db = self._get_session()
        query = db.query(Evidence)
        
        if scan_id:
            query = query.filter(Evidence.scan_id == scan_id)
        if vulnerability_id:
            query = query.filter(Evidence.vulnerability_id == vulnerability_id)
        if evidence_type:
            query = query.filter(Evidence.evidence_type == evidence_type)
        
        return query.order_by(Evidence.captured_at.desc()).all()

