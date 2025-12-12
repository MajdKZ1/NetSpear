"""
Social Engineering Toolkit with phishing templates and attack vectors.
"""
import logging
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


class SocialEngineeringToolkit:
    """Social engineering toolkit with phishing templates."""
    
    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialize social engineering toolkit.
        
        Args:
            templates_dir: Directory for storing phishing templates
        """
        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            self.templates_dir = Path.home() / ".netspear" / "se_templates"
        
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self._initialize_templates()
    
    def _initialize_templates(self):
        """Initialize default phishing templates."""
        if not (self.templates_dir / "phishing").exists():
            (self.templates_dir / "phishing").mkdir(parents=True, exist_ok=True)
            self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default phishing email templates."""
        templates = {
            "office365_password_reset.html": self._office365_template(),
            "security_alert.html": self._security_alert_template(),
            "password_expiry.html": self._password_expiry_template(),
            "document_share.html": self._document_share_template(),
            "suspicious_activity.html": self._suspicious_activity_template(),
            "account_verification.html": self._account_verification_template(),
        }
        
        for filename, content in templates.items():
            template_path = self.templates_dir / "phishing" / filename
            if not template_path.exists():
                with open(template_path, "w", encoding="utf-8") as f:
                    f.write(content)
    
    def _office365_template(self) -> str:
        """Office 365 password reset phishing template."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Account Security</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #0078d4; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .button { display: inline-block; background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #eee; }
        .warning { background: #fff4e6; border-left: 4px solid #ff9800; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Microsoft Account</h1>
        </div>
        <div class="content">
            <h2>Action Required: Verify Your Account</h2>
            <p>We've detected unusual sign-in activity on your Microsoft account. For your security, we need to verify your identity.</p>
            
            <div class="warning">
                <strong>⚠️ Security Alert:</strong> Sign-in from a new device or location detected.
            </div>
            
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Location:</strong> {location}</p>
            <p><strong>Device:</strong> {device}</p>
            
            <p>If this was you, please verify your account to continue using Microsoft services. If not, please secure your account immediately.</p>
            
            <a href="{phishing_url}" class="button">Verify Account</a>
            
            <p style="margin-top: 30px; color: #666; font-size: 14px;">
                This email was sent to {email} because unusual activity was detected on your Microsoft account.
            </p>
        </div>
        <div class="footer">
            <p>Microsoft Corporation | One Microsoft Way, Redmond, WA 98052</p>
            <p>This is an automated security message. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>"""
    
    def _security_alert_template(self) -> str:
        """Security alert phishing template."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Alert - Action Required</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; }
        .header { background: #dc3545; color: white; padding: 20px; }
        .content { padding: 30px; }
        .alert-box { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .button { display: inline-block; background: #28a745; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: bold; }
        .footer { background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SECURITY ALERT</h1>
        </div>
        <div class="content">
            <h2>Immediate Action Required</h2>
            
            <div class="alert-box">
                <strong>⚠️ CRITICAL:</strong> We detected a security breach attempt on your account.
            </div>
            
            <p>Dear {user_name},</p>
            
            <p>Our security systems have detected multiple failed login attempts from an unauthorized location:</p>
            <ul>
                <li><strong>IP Address:</strong> {ip_address}</li>
                <li><strong>Location:</strong> {location}</li>
                <li><strong>Time:</strong> {timestamp}</li>
                <li><strong>Attempts:</strong> {attempt_count} failed login attempts</li>
            </ul>
            
            <p>To protect your account, we've temporarily restricted access. Please verify your identity to restore access.</p>
            
            <a href="{phishing_url}" class="button">Verify & Secure Account</a>
            
            <p style="color: #dc3545; font-weight: bold;">⏰ This security action must be completed within 24 hours or your account will be permanently locked.</p>
        </div>
        <div class="footer">
            <p>This is an automated security message from {company_name}</p>
            <p>If you did not attempt to access your account, please contact support immediately.</p>
        </div>
    </div>
</body>
</html>"""
    
    def _password_expiry_template(self) -> str:
        """Password expiry notification template."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Expiration Notice</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #e9ecef; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; text-align: center; }
        .content { padding: 30px; }
        .countdown { background: #fff3cd; border: 2px solid #ffc107; padding: 15px; margin: 20px 0; text-align: center; border-radius: 4px; }
        .button { display: inline-block; background: #28a745; color: white; padding: 14px 35px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #6c757d; border-top: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Expiration Notice</h1>
        </div>
        <div class="content">
            <p>Dear {user_name},</p>
            
            <p>Your password for {service_name} will expire in <strong>{days_remaining} days</strong>.</p>
            
            <div class="countdown">
                <h3>⏰ Expiration Date: {expiry_date}</h3>
                <p>Please update your password before this date to maintain uninterrupted access.</p>
            </div>
            
            <p>For security reasons, we require periodic password updates. You can update your password now by clicking the button below:</p>
            
            <div style="text-align: center;">
                <a href="{phishing_url}" class="button">Update Password Now</a>
            </div>
            
            <p style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6;">
                <strong>Security Requirements:</strong>
            </p>
            <ul>
                <li>Minimum 8 characters</li>
                <li>At least one uppercase letter</li>
                <li>At least one number</li>
                <li>At least one special character</li>
            </ul>
            
            <p style="color: #dc3545;"><strong>Note:</strong> Failure to update your password before expiration will result in account lockout.</p>
        </div>
        <div class="footer">
            <p>{company_name} IT Security Team</p>
            <p>This is an automated notification. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>"""
    
    def _document_share_template(self) -> str:
        """Document sharing phishing template."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Document Shared With You</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; }
        .header { background: #4285f4; color: white; padding: 20px; }
        .content { padding: 30px; }
        .document-box { background: #f8f9fa; border-left: 4px solid #4285f4; padding: 15px; margin: 20px 0; }
        .button { display: inline-block; background: #4285f4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; margin: 15px 0; }
        .footer { background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📄 Document Shared</h1>
        </div>
        <div class="content">
            <p>Hi {recipient_name},</p>
            
            <p><strong>{sender_name}</strong> has shared a document with you.</p>
            
            <div class="document-box">
                <strong>📎 {document_name}</strong><br>
                <span style="color: #666;">Shared on {timestamp}</span><br>
                <span style="color: #666;">File size: {file_size}</span>
            </div>
            
            <p>You can view and download the document using the link below:</p>
            
            <a href="{phishing_url}" class="button">View Document</a>
            
            <p style="margin-top: 30px; color: #666; font-size: 14px;">
                This document will be available until {expiry_date}. Please download it before then.
            </p>
            
            <p style="color: #666; font-size: 12px; margin-top: 20px;">
                This is an automated notification from {service_name}. If you weren't expecting this document, please ignore this email.
            </p>
        </div>
        <div class="footer">
            <p>{service_name} - Secure Document Sharing</p>
        </div>
    </div>
</body>
</html>"""
    
    def _suspicious_activity_template(self) -> str:
        """Suspicious activity alert template."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Unusual Activity Detected</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #2d2d2d; border-radius: 8px; overflow: hidden; border: 1px solid #444; }
        .header { background: #c82333; padding: 20px; text-align: center; }
        .content { padding: 30px; }
        .alert { background: #721c24; border: 2px solid #c82333; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .activity-box { background: #1a1a1a; padding: 15px; margin: 15px 0; border-radius: 4px; border: 1px solid #444; }
        .button { display: inline-block; background: #28a745; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: bold; }
        .footer { background: #1a1a1a; padding: 15px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #444; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 URGENT: Unusual Activity Detected</h1>
        </div>
        <div class="content">
            <div class="alert">
                <strong>⚠️ SECURITY ALERT:</strong> We've detected suspicious activity on your account that requires immediate attention.
            </div>
            
            <p>Dear {user_name},</p>
            
            <p>Our automated security system has flagged the following activity on your account:</p>
            
            <div class="activity-box">
                <p><strong>📍 Location:</strong> {location}</p>
                <p><strong>🌐 IP Address:</strong> {ip_address}</p>
                <p><strong>🕐 Time:</strong> {timestamp}</p>
                <p><strong>🔍 Activity:</strong> {activity_type}</p>
                <p><strong>📱 Device:</strong> {device_info}</p>
            </div>
            
            <p>If this activity was not authorized by you, your account may be compromised. We recommend taking immediate action to secure your account.</p>
            
            <a href="{phishing_url}" class="button">Secure My Account Now</a>
            
            <p style="color: #ffc107; font-weight: bold; margin-top: 30px;">
                ⏰ This is time-sensitive. Please verify your account within the next 2 hours.
            </p>
            
            <p style="font-size: 12px; color: #888; margin-top: 20px;">
                If you recognize this activity, you can safely ignore this message. If not, please secure your account immediately.
            </p>
        </div>
        <div class="footer">
            <p>{company_name} Security Team</p>
            <p>This is an automated security notification.</p>
        </div>
    </div>
</body>
</html>"""
    
    def _account_verification_template(self) -> str:
        """Account verification phishing template."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Account Verification Required</title>
    <style>
        body { font-family: 'Helvetica Neue', Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 35px; }
        .verification-box { background: #e7f3ff; border: 2px solid #2196F3; padding: 20px; margin: 25px 0; border-radius: 8px; text-align: center; }
        .button { display: inline-block; background: #4CAF50; color: white; padding: 16px 40px; text-decoration: none; border-radius: 6px; margin: 25px 0; font-weight: bold; font-size: 16px; }
        .info-list { background: #f9f9f9; padding: 20px; margin: 20px 0; border-radius: 6px; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #6c757d; border-top: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ Account Verification Required</h1>
        </div>
        <div class="content">
            <p>Hello {user_name},</p>
            
            <p>Thank you for using {service_name}. To ensure the security of your account and comply with our security policies, we need to verify your account information.</p>
            
            <div class="verification-box">
                <h2>🔐 Verify Your Account</h2>
                <p>Please complete the verification process to continue using all features of your account.</p>
            </div>
            
            <div class="info-list">
                <p><strong>What you need to verify:</strong></p>
                <ul style="text-align: left; margin: 15px 0;">
                    <li>Email address confirmation</li>
                    <li>Phone number verification</li>
                    <li>Security question update</li>
                    <li>Two-factor authentication setup</li>
                </ul>
            </div>
            
            <p>This verification process takes less than 2 minutes and helps protect your account from unauthorized access.</p>
            
            <div style="text-align: center;">
                <a href="{phishing_url}" class="button">Verify My Account</a>
            </div>
            
            <p style="margin-top: 30px; color: #666; font-size: 14px;">
                <strong>Why are we asking for verification?</strong><br>
                This is a routine security check to ensure your account remains secure. All accounts are periodically reviewed for security purposes.
            </p>
            
            <p style="color: #ff9800; font-weight: bold; margin-top: 20px;">
                ⏰ Please complete verification within 48 hours to avoid temporary account restrictions.
            </p>
        </div>
        <div class="footer">
            <p>{company_name} Customer Support</p>
            <p>If you didn't create an account with us, please ignore this email.</p>
        </div>
    </div>
</body>
</html>"""
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List available phishing templates."""
        templates = []
        phishing_dir = self.templates_dir / "phishing"
        
        if phishing_dir.exists():
            for template_file in phishing_dir.glob("*.html"):
                templates.append({
                    "name": template_file.stem,
                    "filename": template_file.name,
                    "path": str(template_file),
                })
        
        return templates
    
    def generate_phishing_email(
        self,
        template_name: str,
        phishing_url: str,
        recipient_email: str,
        **kwargs
    ) -> Optional[str]:
        """
        Generate a phishing email from a template.
        
        Args:
            template_name: Name of the template
            phishing_url: URL for the phishing page
            recipient_email: Recipient email address
            **kwargs: Template variables
            
        Returns:
            Generated HTML email content
        """
        template_path = self.templates_dir / "phishing" / f"{template_name}.html"
        
        if not template_path.exists():
            logger.error(f"Template not found: {template_name}")
            return None
        
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
            
            # Default variables
            defaults = {
                "email": recipient_email,
                "user_name": recipient_email.split("@")[0],
                "recipient_name": recipient_email.split("@")[0],
                "sender_name": "System Administrator",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "location": "Unknown Location",
                "device": "Unknown Device",
                "ip_address": "Unknown",
                "company_name": "Your Organization",
                "service_name": "Our Service",
                "phishing_url": phishing_url,
                "attempt_count": "5",
                "days_remaining": "3",
                "expiry_date": (datetime.now(timezone.utc).replace(day=1) + timedelta(days=32)).strftime("%Y-%m-%d"),
                "document_name": "Important_Document.pdf",
                "file_size": "2.4 MB",
                "activity_type": "Unusual login attempt",
                "device_info": "Windows 10 / Chrome Browser",
            }
            
            defaults.update(kwargs)
            
            # Replace template variables
            for key, value in defaults.items():
                template = template.replace(f"{{{key}}}", str(value))
            
            return template
        except Exception as e:
            logger.error(f"Failed to generate phishing email: {e}")
            return None
    
    def save_generated_email(self, content: str, filename: str) -> Optional[Path]:
        """
        Save generated email to file.
        
        Args:
            content: Email HTML content
            filename: Output filename
            
        Returns:
            Path to saved file
        """
        output_dir = self.templates_dir / "generated"
        output_dir.mkdir(exist_ok=True)
        
        output_path = output_dir / filename
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"Generated email saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save email: {e}")
            return None

