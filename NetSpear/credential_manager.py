"""
Secure credential management system with encryption, reuse, and spraying capabilities.
"""
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from database import get_db_manager, Credential

logger = logging.getLogger(__name__)


class CredentialManager:
    """Manage credentials securely with encryption."""
    
    def __init__(self, db_session: Optional[Session] = None, encryption_key: Optional[bytes] = None):
        """
        Initialize credential manager.
        
        Args:
            db_session: Optional database session
            encryption_key: Optional encryption key (generates one if not provided)
        """
        self.db = get_db_manager()
        self.db_session = db_session
        
        # Generate or use provided encryption key
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            # Default key derivation from a fixed string (in production, use proper key management)
            key = self._derive_key("netspear_default_key_change_in_production")
            self.cipher = Fernet(key)
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from password."""
        if salt is None:
            salt = b"netspear_salt_v1"  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _encrypt(self, plaintext: str) -> str:
        """Encrypt a string."""
        if not plaintext:
            return ""
        return self.cipher.encrypt(plaintext.encode()).decode()
    
    def _decrypt(self, ciphertext: str) -> str:
        """Decrypt a string."""
        if not ciphertext:
            return ""
        try:
            return self.cipher.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return ""
    
    def _get_session(self) -> Session:
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def add_credential(
        self,
        target_ip: str,
        service: str,
        username: str,
        password: Optional[str] = None,
        password_hash: Optional[str] = None,
        target_hostname: Optional[str] = None,
        port: Optional[int] = None,
        domain: Optional[str] = None,
        realm: Optional[str] = None,
        source: str = "manual",
        verified: bool = False,
        notes: Optional[str] = None,
    ) -> Optional[Credential]:
        """
        Add a new credential.
        
        Args:
            target_ip: Target IP address
            service: Service type (ssh, ftp, smb, rdp, etc.)
            username: Username
            password: Plaintext password (will be encrypted)
            password_hash: Password hash (for hash-based auth)
            target_hostname: Optional hostname
            port: Optional port number
            domain: Optional domain
            realm: Optional realm
            source: Source of credential (brute_force, found_in_file, manual, etc.)
            verified: Whether credential has been verified
            notes: Optional notes
            
        Returns:
            Created credential object
        """
        db = self._get_session()
        try:
            # Encrypt password if provided
            encrypted_password = self._encrypt(password) if password else None
            
            credential = Credential(
                target_ip=target_ip,
                target_hostname=target_hostname,
                service=service,
                port=port,
                username=username,
                password=encrypted_password,
                password_hash=password_hash,
                domain=domain,
                realm=realm,
                source=source,
                verified=verified,
                notes=notes,
                tested_on=[],
            )
            db.add(credential)
            db.commit()
            db.refresh(credential)
            logger.info(f"Added credential for {username}@{target_ip}:{service}")
            return credential
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to add credential: {e}")
            return None
    
    def get_credential(self, credential_id: int, decrypt: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get credential by ID.
        
        Args:
            credential_id: Credential ID
            decrypt: Whether to decrypt password
            
        Returns:
            Credential dict with decrypted password if requested
        """
        db = self._get_session()
        cred = db.query(Credential).filter(Credential.id == credential_id).first()
        if not cred:
            return None
        
        result = cred.to_dict()
        if decrypt and cred.password:
            result["password"] = self._decrypt(cred.password)
        else:
            result["password"] = None
        
        result["password_hash"] = cred.password_hash
        result["domain"] = cred.domain
        result["notes"] = cred.notes
        return result
    
    def find_credentials(
        self,
        target_ip: Optional[str] = None,
        service: Optional[str] = None,
        username: Optional[str] = None,
        verified_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Find credentials matching criteria.
        
        Args:
            target_ip: Filter by target IP
            service: Filter by service
            username: Filter by username
            verified_only: Only return verified credentials
            
        Returns:
            List of matching credentials
        """
        db = self._get_session()
        query = db.query(Credential)
        
        if target_ip:
            query = query.filter(Credential.target_ip == target_ip)
        if service:
            query = query.filter(Credential.service == service)
        if username:
            query = query.filter(Credential.username == username)
        if verified_only:
            query = query.filter(Credential.verified == True)
        
        credentials = query.all()
        results = []
        for cred in credentials:
            result = cred.to_dict()
            result["password"] = self._decrypt(cred.password) if cred.password else None
            results.append(result)
        
        return results
    
    def verify_credential(self, credential_id: int, verified: bool = True) -> bool:
        """
        Mark credential as verified or unverified.
        
        Args:
            credential_id: Credential ID
            verified: Verification status
            
        Returns:
            True if successful
        """
        db = self._get_session()
        try:
            cred = db.query(Credential).filter(Credential.id == credential_id).first()
            if not cred:
                return False
            
            cred.verified = verified
            if verified:
                cred.last_used = datetime.now(timezone.utc)
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to verify credential: {e}")
            return False
    
    def mark_tested_on(self, credential_id: int, target_ip: str) -> bool:
        """
        Mark credential as tested on a target.
        
        Args:
            credential_id: Credential ID
            target_ip: Target IP where it was tested
            
        Returns:
            True if successful
        """
        db = self._get_session()
        try:
            cred = db.query(Credential).filter(Credential.id == credential_id).first()
            if not cred:
                return False
            
            tested_on = cred.tested_on or []
            if target_ip not in tested_on:
                tested_on.append(target_ip)
                cred.tested_on = tested_on
                cred.last_used = datetime.now(timezone.utc)
                db.commit()
            return True
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to mark tested: {e}")
            return False
    
    def get_credentials_for_spraying(
        self,
        service: str,
        username_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Get credentials formatted for credential spraying.
        
        Args:
            service: Service type to spray
            username_only: Only return usernames (for username enumeration)
            
        Returns:
            List of credentials formatted for spraying
        """
        db = self._get_session()
        query = db.query(Credential).filter(Credential.service == service)
        
        if username_only:
            # Return unique usernames
            credentials = query.distinct(Credential.username).all()
            return [{"username": c.username, "domain": c.domain} for c in credentials]
        else:
            # Return username:password pairs
            credentials = query.filter(Credential.verified == True).all()
            results = []
            for cred in credentials:
                results.append({
                    "username": cred.username,
                    "password": self._decrypt(cred.password) if cred.password else None,
                    "password_hash": cred.password_hash,
                    "domain": cred.domain,
                    "target_ip": cred.target_ip,
                })
            return results
    
    def analyze_passwords(self) -> Dict[str, Any]:
        """
        Analyze stored passwords for common patterns.
        
        Returns:
            Dictionary with password analysis statistics
        """
        db = self._get_session()
        credentials = db.query(Credential).filter(Credential.password.isnot(None)).all()
        
        if not credentials:
            return {"total": 0, "common_passwords": [], "password_lengths": {}}
        
        password_freq: Dict[str, int] = {}
        length_dist: Dict[int, int] = {}
        
        for cred in credentials:
            password = self._decrypt(cred.password)
            if password:
                # Count frequency
                password_freq[password] = password_freq.get(password, 0) + 1
                
                # Count length distribution
                length = len(password)
                length_dist[length] = length_dist.get(length, 0) + 1
        
        # Get most common passwords
        common_passwords = sorted(
            password_freq.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total": len(credentials),
            "unique_passwords": len(password_freq),
            "common_passwords": [{"password": pwd, "count": count} for pwd, count in common_passwords],
            "password_lengths": length_dist,
        }
    
    def export_credentials(self, format: str = "csv") -> str:
        """
        Export credentials to a string format.
        
        Args:
            format: Export format (csv, json)
            
        Returns:
            Exported credentials as string
        """
        db = self._get_session()
        credentials = db.query(Credential).all()
        
        if format == "csv":
            lines = ["target_ip,service,username,password,verified,created_at"]
            for cred in credentials:
                password = self._decrypt(cred.password) if cred.password else ""
                lines.append(
                    f"{cred.target_ip},{cred.service},{cred.username},{password},"
                    f"{cred.verified},{cred.created_at}"
                )
            return "\n".join(lines)
        elif format == "json":
            import json
            results = []
            for cred in credentials:
                results.append({
                    "target_ip": cred.target_ip,
                    "service": cred.service,
                    "username": cred.username,
                    "password": self._decrypt(cred.password) if cred.password else None,
                    "verified": cred.verified,
                    "created_at": cred.created_at.isoformat() if cred.created_at else None,
                })
            return json.dumps(results, indent=2)
        else:
            return ""

