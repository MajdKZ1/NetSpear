"""
Database persistence layer for NetSpear Network Analyzer.

Supports both SQLite (default) and PostgreSQL for storing scans, vulnerabilities,
credentials, sessions, and historical data.
"""
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

logger = logging.getLogger(__name__)

Base = declarative_base()


class Scan(Base):
    """Store network scan results."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True)
    scan_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    target_ip = Column(String(45), nullable=False, index=True)
    target_hostname = Column(String(255))
    scan_type = Column(String(50), nullable=False)
    scan_label = Column(String(255))
    host_state = Column(String(20))
    mode = Column(String(20))
    proxy = Column(String(255))
    stealth = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    ports = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    web_enumerations = relationship("WebEnumeration", back_populates="scan", cascade="all, delete-orphan")
    recon_data = relationship("ReconData", back_populates="scan", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="scan", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_uuid": self.scan_uuid,
            "target_ip": self.target_ip,
            "target_hostname": self.target_hostname,
            "scan_type": self.scan_type,
            "scan_label": self.scan_label,
            "host_state": self.host_state,
            "mode": self.mode,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class Port(Base):
    """Store port scan results."""
    __tablename__ = "ports"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    state = Column(String(20))
    service = Column(String(100))
    version = Column(String(255))
    banner = Column(Text)
    extra_data = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    scan = relationship("Scan", back_populates="ports")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
        }


class Vulnerability(Base):
    """Store vulnerability information."""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    cve = Column(String(50), index=True)
    port = Column(Integer)
    protocol = Column(String(10))
    service = Column(String(100))
    version = Column(String(255))
    description = Column(Text)
    severity = Column(String(20), index=True)  # critical, high, medium, low, info
    cvss_score = Column(Float)
    cvss_vector = Column(String(255))
    exploit_available = Column(Boolean, default=False)
    exploit_path = Column(String(255))
    risk_score = Column(Float, index=True)
    asset_criticality = Column(String(20))  # critical, high, medium, low
    remediation_priority = Column(Integer, index=True)
    status = Column(String(20), default="open")  # open, verified, false_positive, remediated, accepted_risk
    script_id = Column(String(100))
    raw_output = Column(Text)
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    verified_at = Column(DateTime(timezone=True))
    remediated_at = Column(DateTime(timezone=True))
    
    scan = relationship("Scan", back_populates="vulnerabilities")
    evidence = relationship("Evidence", back_populates="vulnerability", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cve": self.cve,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "risk_score": self.risk_score,
            "status": self.status,
        }


class WebEnumeration(Base):
    """Store web enumeration results."""
    __tablename__ = "web_enumerations"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    base_url = Column(String(500))
    port = Column(Integer)
    technologies = Column(JSON)  # List of detected technologies
    directories = Column(JSON)  # List of discovered directories
    admin_endpoints = Column(JSON)  # List of admin panels
    waf_detected = Column(String(100))
    nuclei_findings = Column(JSON)
    sqlmap_findings = Column(JSON)
    errors = Column(JSON)
    raw_data = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    scan = relationship("Scan", back_populates="web_enumerations")


class ReconData(Base):
    """Store reconnaissance data."""
    __tablename__ = "recon_data"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    target = Column(String(255), nullable=False)
    target_type = Column(String(20))  # ip, domain, url
    geoip_data = Column(JSON)
    dns_records = Column(JSON)
    whois_data = Column(JSON)
    shodan_data = Column(JSON)
    subdomains = Column(JSON)
    certificates = Column(JSON)
    osint_data = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    scan = relationship("Scan", back_populates="recon_data")


class Credential(Base):
    """Store discovered credentials."""
    __tablename__ = "credentials"
    
    id = Column(Integer, primary_key=True)
    credential_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    target_ip = Column(String(45), index=True)
    target_hostname = Column(String(255))
    service = Column(String(50), nullable=False, index=True)  # ssh, ftp, smb, rdp, etc.
    port = Column(Integer)
    username = Column(String(255), nullable=False)
    password = Column(String(500))  # Encrypted in production
    password_hash = Column(String(255))
    domain = Column(String(255))
    realm = Column(String(255))
    source = Column(String(100))  # brute_force, found_in_file, etc.
    verified = Column(Boolean, default=False)
    tested_on = Column(JSON)  # List of IPs this credential was tested on
    last_used = Column(DateTime(timezone=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "service": self.service,
            "username": self.username,
            "verified": self.verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Session(Base):
    """Store active exploitation sessions."""
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True)
    session_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    session_type = Column(String(50), nullable=False)  # meterpreter, shell, ssh, etc.
    target_ip = Column(String(45), nullable=False, index=True)
    target_hostname = Column(String(255))
    port = Column(Integer)
    payload = Column(String(255))
    lhost = Column(String(45))
    lport = Column(Integer)
    user = Column(String(255))
    privileges = Column(String(20))  # root, admin, user, etc.
    os = Column(String(100))
    arch = Column(String(20))
    active = Column(Boolean, default=True, index=True)
    connection_info = Column(JSON)
    last_checkin = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    commands = relationship("SessionCommand", back_populates="session", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "session_uuid": self.session_uuid,
            "session_type": self.session_type,
            "target_ip": self.target_ip,
            "user": self.user,
            "privileges": self.privileges,
            "active": self.active,
            "last_checkin": self.last_checkin.isoformat() if self.last_checkin else None,
        }


class SessionCommand(Base):
    """Store commands executed in sessions."""
    __tablename__ = "session_commands"
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    command = Column(Text, nullable=False)
    output = Column(Text)
    exit_code = Column(Integer)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    
    session = relationship("Session", back_populates="commands")


class NetworkTopology(Base):
    """Store network topology information."""
    __tablename__ = "network_topology"
    
    id = Column(Integer, primary_key=True)
    source_ip = Column(String(45), nullable=False, index=True)
    target_ip = Column(String(45), nullable=False, index=True)
    relationship_type = Column(String(50))  # routes_to, depends_on, communicates_with
    protocol = Column(String(20))
    port = Column(Integer)
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "relationship_type": self.relationship_type,
            "protocol": self.protocol,
            "port": self.port,
        }


class Evidence(Base):
    """Store evidence and proof-of-concept files."""
    __tablename__ = "evidence"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    evidence_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    evidence_type = Column(String(50))  # screenshot, poc, file, log
    filename = Column(String(255))
    file_path = Column(String(500))
    file_hash = Column(String(64))  # SHA-256
    description = Column(Text)
    captured_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    scan = relationship("Scan", back_populates="evidence")
    vulnerability = relationship("Vulnerability", back_populates="evidence")


class Workflow(Base):
    """Store workflow definitions."""
    __tablename__ = "workflows"
    
    id = Column(Integer, primary_key=True)
    workflow_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    steps = Column(JSON, nullable=False)  # Array of workflow steps
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    executions = relationship("WorkflowExecution", back_populates="workflow", cascade="all, delete-orphan")


class WorkflowExecution(Base):
    """Store workflow execution history."""
    __tablename__ = "workflow_executions"
    
    id = Column(Integer, primary_key=True)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=False)
    execution_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    status = Column(String(20), default="running")  # running, completed, failed, cancelled
    target = Column(String(255))
    results = Column(JSON)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True))
    
    workflow = relationship("Workflow", back_populates="executions")


class Notification(Base):
    """Store notifications and alerts."""
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True)
    notification_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    channel = Column(String(50))  # email, slack, teams, webhook
    level = Column(String(20))  # critical, high, medium, low, info
    title = Column(String(255), nullable=False)
    message = Column(Text)
    target = Column(String(255))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    sent = Column(Boolean, default=False)
    sent_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class DatabaseManager:
    """Manage database connections and operations."""
    
    def __init__(self, db_url: Optional[str] = None, db_path: Optional[Path] = None):
        """
        Initialize database manager.
        
        Args:
            db_url: Full database URL (for PostgreSQL: postgresql://user:pass@host/db)
            db_path: Path to SQLite database file (default: ~/.netspear/netspear.db)
        """
        if db_url:
            self.db_url = db_url
        elif db_path:
            self.db_url = f"sqlite:///{db_path}"
        else:
            # Default SQLite location
            db_dir = Path.home() / ".netspear"
            db_dir.mkdir(exist_ok=True)
            db_file = db_dir / "netspear.db"
            self.db_url = f"sqlite:///{db_file}"
        
        # Create engine with connection pooling
        self.engine = create_engine(
            self.db_url,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False} if "sqlite" in self.db_url else {}
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Create all tables
        Base.metadata.create_all(bind=self.engine)
        
        logger.info(f"Database initialized at {self.db_url}")
    
    def get_session(self) -> Session:
        """Get a database session."""
        return self.SessionLocal()
    
    def close(self):
        """Close database connections."""
        self.engine.dispose()
        logger.info("Database connections closed")


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager(db_url: Optional[str] = None, db_path: Optional[Path] = None) -> DatabaseManager:
    """Get or create the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_url, db_path)
    return _db_manager


def init_database(db_url: Optional[str] = None, db_path: Optional[Path] = None) -> DatabaseManager:
    """Initialize the database."""
    return get_db_manager(db_url, db_path)

