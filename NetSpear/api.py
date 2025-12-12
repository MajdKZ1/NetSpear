"""
REST API for NetSpear Network Analyzer using FastAPI.

Provides endpoints for automation, integration, and remote access.
"""
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db_manager, Scan, Vulnerability, Credential, Session as DBSession
from session_manager import SessionManager
from credential_manager import CredentialManager
from workflow_engine import WorkflowEngine

logger = logging.getLogger(__name__)

app = FastAPI(
    title="NetSpear API",
    description="REST API for NetSpear Network Analyzer",
    version="2.0",
)

security = HTTPBearer()
_db_manager = None
_analyzer = None  # Will be set by set_analyzer()


def set_analyzer(analyzer):
    """Set the NetSpear analyzer instance."""
    global _analyzer
    _analyzer = analyzer


def get_db() -> Session:
    """Dependency to get database session."""
    global _db_manager
    if _db_manager is None:
        _db_manager = get_db_manager()
    return _db_manager.get_session()


# Pydantic models for API requests/responses
class ScanRequest(BaseModel):
    target_ip: str
    scan_type: str = "quick"
    stealth: bool = False
    proxy: Optional[str] = None
    mode: str = "SAFE"


class ScanResponse(BaseModel):
    scan_uuid: str
    target_ip: str
    scan_type: str
    status: str
    timestamp: str


class VulnerabilityResponse(BaseModel):
    id: int
    cve: Optional[str]
    port: Optional[int]
    severity: Optional[str]
    cvss_score: Optional[float]
    description: Optional[str]


class CredentialRequest(BaseModel):
    target_ip: str
    service: str
    username: str
    password: Optional[str] = None
    password_hash: Optional[str] = None
    verified: bool = False


class CredentialResponse(BaseModel):
    id: int
    target_ip: str
    service: str
    username: str
    verified: bool


class SessionResponse(BaseModel):
    session_uuid: str
    session_type: str
    target_ip: str
    active: bool
    user: Optional[str]
    privileges: Optional[str]


class WorkflowRequest(BaseModel):
    name: str
    description: str
    steps: List[Dict[str, Any]]
    enabled: bool = True


@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "name": "NetSpear API",
        "version": "2.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Scan endpoints
@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(scan_request: ScanRequest, db: Session = Depends(get_db)):
    """Create and execute a network scan."""
    if not _analyzer:
        raise HTTPException(status_code=500, detail="Analyzer not available")
    
    try:
        # Execute scan
        scan_result, vulnerabilities = _analyzer.scanner.run_nmap_scan(
            scan_request.target_ip,
            scan_request.scan_type,
            scan_request.stealth,
            scan_request.proxy,
            scan_request.mode,
        )
        
        # Store in database
        scan = Scan(
            target_ip=scan_request.target_ip,
            scan_type=scan_request.scan_type,
            scan_label=scan_request.scan_type,
            mode=scan_request.mode,
            stealth=scan_request.stealth,
            proxy=scan_request.proxy,
            host_state=scan_result.get("host_state", "unknown"),
        )
        
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Store ports
        from database import Port
        for port_data in scan_result.get("ports", []):
            port = Port(
                scan_id=scan.id,
                port_number=port_data.get("port"),
                protocol=port_data.get("protocol"),
                state=port_data.get("state"),
                service=port_data.get("service"),
                version=port_data.get("version"),
            )
            db.add(port)
        
        # Store vulnerabilities
        for vuln_data in vulnerabilities:
            vuln = Vulnerability(
                scan_id=scan.id,
                cve=vuln_data.get("cve"),
                port=vuln_data.get("port"),
                protocol=vuln_data.get("protocol"),
                service=vuln_data.get("service"),
                version=vuln_data.get("version"),
                description=vuln_data.get("description"),
                severity=vuln_data.get("severity"),
            )
            db.add(vuln)
        
        db.commit()
        
        return ScanResponse(
            scan_uuid=scan.scan_uuid,
            target_ip=scan.target_ip,
            scan_type=scan.scan_type,
            status="completed",
            timestamp=scan.timestamp.isoformat() if scan.timestamp else "",
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/scans")
async def list_scans(limit: int = 100, target_ip: Optional[str] = None, db: Session = Depends(get_db)):
    """List all scans."""
    query = db.query(Scan)
    if target_ip:
        query = query.filter(Scan.target_ip == target_ip)
    scans = query.order_by(Scan.timestamp.desc()).limit(limit).all()
    
    return [scan.to_dict() for scan in scans]


@app.get("/api/v1/scans/{scan_uuid}")
async def get_scan(scan_uuid: str, db: Session = Depends(get_db)):
    """Get scan details."""
    scan = db.query(Scan).filter(Scan.scan_uuid == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan.to_dict()
    
    # Include ports and vulnerabilities
    result["ports"] = [p.to_dict() for p in scan.ports]
    result["vulnerabilities"] = [v.to_dict() for v in scan.vulnerabilities]
    
    return result


# Vulnerability endpoints
@app.get("/api/v1/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    severity: Optional[str] = None,
    target_ip: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """List vulnerabilities."""
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if target_ip:
        query = query.join(Scan).filter(Scan.target_ip == target_ip)
    
    vulnerabilities = query.order_by(Vulnerability.discovered_at.desc()).limit(limit).all()
    return [v.to_dict() for v in vulnerabilities]


@app.get("/api/v1/vulnerabilities/{vuln_id}")
async def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Get vulnerability details."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln.to_dict()


# Credential endpoints
@app.post("/api/v1/credentials", response_model=CredentialResponse)
async def create_credential(cred_request: CredentialRequest, db: Session = Depends(get_db)):
    """Add a credential."""
    cred_manager = CredentialManager(db_session=db)
    cred = cred_manager.add_credential(
        target_ip=cred_request.target_ip,
        service=cred_request.service,
        username=cred_request.username,
        password=cred_request.password,
        password_hash=cred_request.password_hash,
        verified=cred_request.verified,
    )
    
    if not cred:
        raise HTTPException(status_code=500, detail="Failed to add credential")
    
    return CredentialResponse(
        id=cred.id,
        target_ip=cred.target_ip,
        service=cred.service,
        username=cred.username,
        verified=cred.verified,
    )


@app.get("/api/v1/credentials")
async def list_credentials(
    target_ip: Optional[str] = None,
    service: Optional[str] = None,
    verified_only: bool = False,
    db: Session = Depends(get_db),
):
    """List credentials."""
    cred_manager = CredentialManager(db_session=db)
    credentials = cred_manager.find_credentials(
        target_ip=target_ip,
        service=service,
        verified_only=verified_only,
    )
    return credentials


# Session endpoints
@app.get("/api/v1/sessions", response_model=List[SessionResponse])
async def list_sessions(active_only: bool = False, db: Session = Depends(get_db)):
    """List all sessions."""
    session_manager = SessionManager(db_session=db)
    sessions = session_manager.list_all_sessions(active_only=active_only)
    return [s.to_dict() for s in sessions]


@app.get("/api/v1/sessions/{session_uuid}", response_model=SessionResponse)
async def get_session(session_uuid: str, db: Session = Depends(get_db)):
    """Get session details."""
    session_manager = SessionManager(db_session=db)
    session = session_manager.get_session(session_uuid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.to_dict()


# Workflow endpoints
@app.post("/api/v1/workflows")
async def create_workflow(workflow_request: WorkflowRequest, db: Session = Depends(get_db)):
    """Create a workflow."""
    workflow_engine = WorkflowEngine(analyzer=_analyzer)
    workflow = workflow_engine.create_workflow(
        name=workflow_request.name,
        description=workflow_request.description,
        steps=workflow_request.steps,
        enabled=workflow_request.enabled,
    )
    
    if not workflow:
        raise HTTPException(status_code=500, detail="Failed to create workflow")
    
    return {
        "workflow_uuid": workflow.workflow_uuid,
        "name": workflow.name,
        "status": "created",
    }


@app.post("/api/v1/workflows/{workflow_uuid}/execute")
async def execute_workflow(
    workflow_uuid: str,
    target: Optional[str] = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
):
    """Execute a workflow."""
    workflow_engine = WorkflowEngine(analyzer=_analyzer)
    
    def run_workflow():
        execution = workflow_engine.execute_workflow(workflow_uuid, target=target)
        return execution
    
    # Execute in background
    background_tasks.add_task(run_workflow)
    
    return {
        "status": "started",
        "workflow_uuid": workflow_uuid,
        "message": "Workflow execution started",
    }


@app.get("/api/v1/workflows")
async def list_workflows(enabled_only: bool = False, db: Session = Depends(get_db)):
    """List all workflows."""
    workflow_engine = WorkflowEngine(analyzer=_analyzer)
    workflows = workflow_engine.list_workflows(enabled_only=enabled_only)
    return [
        {
            "workflow_uuid": w.workflow_uuid,
            "name": w.name,
            "description": w.description,
            "enabled": w.enabled,
        }
        for w in workflows
    ]


def run_api_server(host: str = "127.0.0.1", port: int = 8000, analyzer=None):
    """Run the API server."""
    import uvicorn
    set_analyzer(analyzer)
    uvicorn.run(app, host=host, port=port)

