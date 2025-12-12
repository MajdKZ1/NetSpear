"""
Notification and alerting system with multiple channels.
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from database import get_db_manager, Notification, Vulnerability

logger = logging.getLogger(__name__)


class NotificationManager:
    """Manage notifications and alerts."""
    
    def __init__(self, db_session: Optional[Session] = None):
        """
        Initialize notification manager.
        
        Args:
            db_session: Optional database session
        """
        self.db = get_db_manager()
        self.db_session = db_session
    
    def _get_session(self) -> Session:
        """Get or create database session."""
        return self.db_session or self.db.get_session()
    
    def send_notification(
        self,
        channel: str,
        level: str,
        title: str,
        message: str,
        target: Optional[str] = None,
        vulnerability_id: Optional[int] = None,
    ) -> Optional[Notification]:
        """
        Send a notification.
        
        Args:
            channel: Notification channel (email, slack, teams, webhook)
            level: Severity level (critical, high, medium, low, info)
            title: Notification title
            message: Notification message
            target: Optional target (IP, domain, etc.)
            vulnerability_id: Optional vulnerability ID
            
        Returns:
            Created notification record
        """
        db = self._get_session()
        try:
            notification = Notification(
                channel=channel,
                level=level,
                title=title,
                message=message,
                target=target,
                vulnerability_id=vulnerability_id,
                sent=False,
            )
            db.add(notification)
            db.commit()
            
            # Send via appropriate channel
            sent = False
            if channel == "email":
                sent = self._send_email(notification)
            elif channel == "slack":
                sent = self._send_slack(notification)
            elif channel == "teams":
                sent = self._send_teams(notification)
            elif channel == "webhook":
                sent = self._send_webhook(notification)
            
            notification.sent = sent
            notification.sent_at = datetime.now(timezone.utc) if sent else None
            db.commit()
            
            return notification
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to send notification: {e}")
            return None
    
    def _send_email(self, notification: Notification) -> bool:
        """Send email notification."""
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        email_to = os.getenv("NOTIFICATION_EMAIL")
        
        if not all([smtp_user, smtp_password, email_to]):
            logger.warning("Email configuration incomplete")
            return False
        
        try:
            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = email_to
            msg["Subject"] = f"[{notification.level.upper()}] {notification.title}"
            msg.attach(MIMEText(notification.message, "plain"))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent: {notification.title}")
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False
    
    def _send_slack(self, notification: Notification) -> bool:
        """Send Slack notification."""
        import requests
        
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False
        
        try:
            payload = {
                "text": f"[{notification.level.upper()}] {notification.title}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": notification.title,
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": notification.message,
                        },
                    },
                ],
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack notification sent: {notification.title}")
            return True
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False
    
    def _send_teams(self, notification: Notification) -> bool:
        """Send Microsoft Teams notification."""
        import requests
        
        webhook_url = os.getenv("TEAMS_WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False
        
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": notification.title,
                "themeColor": self._get_color_for_level(notification.level),
                "title": notification.title,
                "text": notification.message,
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Teams notification sent: {notification.title}")
            return True
        except Exception as e:
            logger.error(f"Teams send failed: {e}")
            return False
    
    def _send_webhook(self, notification: Notification) -> bool:
        """Send generic webhook notification."""
        import requests
        
        webhook_url = os.getenv("WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Webhook URL not configured")
            return False
        
        try:
            payload = {
                "level": notification.level,
                "title": notification.title,
                "message": notification.message,
                "target": notification.target,
                "timestamp": notification.created_at.isoformat() if notification.created_at else None,
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Webhook notification sent: {notification.title}")
            return True
        except Exception as e:
            logger.error(f"Webhook send failed: {e}")
            return False
    
    def _get_color_for_level(self, level: str) -> str:
        """Get color code for severity level."""
        colors = {
            "critical": "FF0000",
            "high": "FF6600",
            "medium": "FFAA00",
            "low": "FFFF00",
            "info": "0066FF",
        }
        return colors.get(level.lower(), "808080")
    
    def alert_on_vulnerability(
        self,
        vulnerability_id: int,
        threshold: str = "high",
    ) -> bool:
        """
        Send alert when a vulnerability is found above threshold.
        
        Args:
            vulnerability_id: Vulnerability ID
            threshold: Minimum severity to alert (critical, high, medium)
            
        Returns:
            True if alert sent
        """
        db = self._get_session()
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if not vuln:
            return False
        
        severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        vuln_level = severity_levels.get(vuln.severity or "low", 0)
        threshold_level = severity_levels.get(threshold.lower(), 2)
        
        if vuln_level >= threshold_level:
            from database import Scan
            scan = db.query(Scan).filter(Scan.id == vuln.scan_id).first()
            
            title = f"Vulnerability Found: {vuln.cve or 'Unknown CVE'}"
            message = f"""
Severity: {vuln.severity}
Target: {scan.target_ip if scan else 'Unknown'}
Port: {vuln.port}/{vuln.protocol}
Service: {vuln.service}
Description: {vuln.description or 'No description'}
            """.strip()
            
            self.send_notification(
                channel="email",  # Default channel
                level=vuln.severity or "medium",
                title=title,
                message=message,
                target=scan.target_ip if scan else None,
                vulnerability_id=vulnerability_id,
            )
            return True
        
        return False

