"""
Session management system for tracking active shells, Meterpreter sessions, and connections.
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_

from database import get_db_manager, Session as DBSession, SessionCommand

logger = logging.getLogger(__name__)


class SessionManager:
    """Manage active exploitation sessions."""
    
    def __init__(self, db_session: Optional[Session] = None):
        """
        Initialize session manager.
        
        Args:
            db_session: Optional database session (creates new one if not provided)
        """
        self.db = get_db_manager()
        self.db_session = db_session
    
    def _get_session(self) -> Session:
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def create_session(
        self,
        session_type: str,
        target_ip: str,
        target_hostname: Optional[str] = None,
        port: Optional[int] = None,
        payload: Optional[str] = None,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        user: Optional[str] = None,
        privileges: Optional[str] = None,
        os: Optional[str] = None,
        arch: Optional[str] = None,
        connection_info: Optional[Dict[str, Any]] = None,
    ) -> DBSession:
        """
        Create a new session record.
        
        Args:
            session_type: Type of session (meterpreter, shell, ssh, etc.)
            target_ip: Target IP address
            target_hostname: Optional hostname
            port: Optional port number
            payload: Payload used
            lhost: Listener host
            lport: Listener port
            user: User account
            privileges: Privilege level (root, admin, user)
            os: Operating system
            arch: Architecture
            connection_info: Additional connection metadata
            
        Returns:
            Created session object
        """
        db = self._get_session()
        try:
            session = DBSession(
                session_type=session_type,
                target_ip=target_ip,
                target_hostname=target_hostname,
                port=port,
                payload=payload,
                lhost=lhost,
                lport=lport,
                user=user,
                privileges=privileges,
                os=os,
                arch=arch,
                connection_info=connection_info or {},
                active=True,
                last_checkin=datetime.now(timezone.utc),
            )
            db.add(session)
            db.commit()
            db.refresh(session)
            logger.info(f"Created session {session.session_uuid} on {target_ip}")
            return session
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create session: {e}")
            raise
    
    def update_session(self, session_uuid: str, **kwargs) -> Optional[DBSession]:
        """
        Update session information.
        
        Args:
            session_uuid: Session UUID
            **kwargs: Fields to update
            
        Returns:
            Updated session object or None
        """
        db = self._get_session()
        try:
            session = db.query(DBSession).filter(DBSession.session_uuid == session_uuid).first()
            if not session:
                return None
            
            for key, value in kwargs.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            
            session.last_checkin = datetime.now(timezone.utc)
            db.commit()
            db.refresh(session)
            return session
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to update session: {e}")
            return None
    
    def get_session(self, session_uuid: str) -> Optional[DBSession]:
        """Get session by UUID."""
        db = self._get_session()
        return db.query(DBSession).filter(DBSession.session_uuid == session_uuid).first()
    
    def get_active_sessions(self, target_ip: Optional[str] = None) -> List[DBSession]:
        """
        Get all active sessions.
        
        Args:
            target_ip: Optional filter by target IP
            
        Returns:
            List of active sessions
        """
        db = self._get_session()
        query = db.query(DBSession).filter(DBSession.active == True)
        if target_ip:
            query = query.filter(DBSession.target_ip == target_ip)
        return query.all()
    
    def deactivate_session(self, session_uuid: str) -> bool:
        """
        Deactivate a session.
        
        Args:
            session_uuid: Session UUID
            
        Returns:
            True if successful
        """
        session = self.update_session(session_uuid, active=False)
        return session is not None
    
    def add_command(
        self,
        session_uuid: str,
        command: str,
        output: Optional[str] = None,
        exit_code: Optional[int] = None,
    ) -> Optional[SessionCommand]:
        """
        Record a command executed in a session.
        
        Args:
            session_uuid: Session UUID
            command: Command executed
            output: Command output
            exit_code: Exit code
            
        Returns:
            Created command record
        """
        db = self._get_session()
        try:
            session = self.get_session(session_uuid)
            if not session:
                return None
            
            cmd = SessionCommand(
                session_id=session.id,
                command=command,
                output=output,
                exit_code=exit_code,
                timestamp=datetime.now(timezone.utc),
            )
            db.add(cmd)
            db.commit()
            db.refresh(cmd)
            return cmd
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to add command: {e}")
            return None
    
    def get_session_commands(self, session_uuid: str, limit: int = 100) -> List[SessionCommand]:
        """
        Get command history for a session.
        
        Args:
            session_uuid: Session UUID
            limit: Maximum number of commands to return
            
        Returns:
            List of command records
        """
        db = self._get_session()
        session = self.get_session(session_uuid)
        if not session:
            return []
        
        return (
            db.query(SessionCommand)
            .filter(SessionCommand.session_id == session.id)
            .order_by(SessionCommand.timestamp.desc())
            .limit(limit)
            .all()
        )
    
    def list_all_sessions(self, active_only: bool = False) -> List[DBSession]:
        """
        List all sessions.
        
        Args:
            active_only: Only return active sessions
            
        Returns:
            List of sessions
        """
        db = self._get_session()
        query = db.query(DBSession)
        if active_only:
            query = query.filter(DBSession.active == True)
        return query.order_by(DBSession.created_at.desc()).all()
    
    def cleanup_stale_sessions(self, hours: int = 24) -> int:
        """
        Deactivate sessions that haven't checked in recently.
        
        Args:
            hours: Hours of inactivity before considering stale
            
        Returns:
            Number of sessions deactivated
        """
        db = self._get_session()
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        try:
            sessions = db.query(DBSession).filter(
                and_(
                    DBSession.active == True,
                    DBSession.last_checkin < cutoff
                )
            ).all()
            
            count = 0
            for session in sessions:
                session.active = False
                count += 1
            
            db.commit()
            logger.info(f"Deactivated {count} stale sessions")
            return count
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to cleanup stale sessions: {e}")
            return 0

