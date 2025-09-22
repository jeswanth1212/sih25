#!/usr/bin/env python3
"""
QuMail Email Integration Module
ISRO Smart India Hackathon 2025 - Task 34: Send Emails with smtplib

Email integration with hybrid encryption support:
- Level 1: Quantum Secure (OTP with QKD keys)
- Level 2: Quantum-aided AES (Hybrid key derivation)
- Level 3: Hybrid PQC (ML-KEM-768 + Double signatures)
- Level 4: No Quantum Security (Plaintext passthrough)

Features:
- Gmail SMTP integration with App Passwords
- Hybrid encryption before sending
- MIME multipart email construction
- Attachment encryption support
- Error handling and fallbacks
"""

import smtplib
import imaplib
import email
import ssl
import os
import json
import base64
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email import encoders
from dataclasses import dataclass, asdict

# Import QuMail encryption
from encryption import QuMailMultiLevelEncryption, SecurityLevel, EncryptedMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EmailCredentials:
    """Email account credentials"""
    email: str
    password: str  # App Password for Gmail
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    imap_server: str = "imap.gmail.com"
    imap_port: int = 993

@dataclass
class EmailMessage:
    """Email message structure"""
    sender: str
    recipient: str
    subject: str
    content: str
    attachments: List[Dict[str, Any]] = None
    security_level: SecurityLevel = SecurityLevel.QUANTUM_AIDED
    
    def __post_init__(self):
        if self.attachments is None:
            self.attachments = []

@dataclass
class EmailSendResult:
    """Result of email sending operation"""
    success: bool
    message_id: str = ""
    error: str = ""
    encryption_metadata: Dict[str, Any] = None
    sent_at: str = ""

class QuMailEmailSender:
    """
    QuMail Email Sender with Hybrid Encryption
    Integrates multi-level encryption with Gmail SMTP
    """
    
    def __init__(self, credentials: EmailCredentials):
        """
        Initialize email sender
        
        Args:
            credentials: Email account credentials
        """
        self.credentials = credentials
        self.encryptor = QuMailMultiLevelEncryption()
        self.smtp_server = None
        
    def connect_smtp(self) -> bool:
        """
        Connect to Gmail SMTP server
        
        Returns:
            bool: True if connection successful
        """
        try:
            logger.info(f"🔄 Connecting to Gmail SMTP: {self.credentials.smtp_server}:{self.credentials.smtp_port}")
            
            # Create SMTP connection with TLS
            self.smtp_server = smtplib.SMTP(self.credentials.smtp_server, self.credentials.smtp_port)
            self.smtp_server.starttls()  # Enable TLS encryption
            
            # Login with App Password
            self.smtp_server.login(self.credentials.email, self.credentials.password)
            
            logger.info("✅ Gmail SMTP connection established")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ SMTP Authentication failed: {e}")
            logger.error("💡 Tip: Use Gmail App Password, not regular password")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected SMTP error: {e}")
            return False
    
    def disconnect_smtp(self):
        """Disconnect from SMTP server"""
        if self.smtp_server:
            try:
                self.smtp_server.quit()
                logger.info("✅ SMTP connection closed")
            except Exception as e:
                logger.warning(f"⚠️ Error closing SMTP: {e}")
            finally:
                self.smtp_server = None
    
    def encrypt_email_content(self, email_msg: EmailMessage) -> Tuple[str, Dict[str, Any]]:
        """
        Encrypt email content using specified security level
        
        Args:
            email_msg: Email message to encrypt
            
        Returns:
            Tuple of (encrypted_content, encryption_metadata)
        """
        try:
            logger.info(f"🔐 Encrypting email with Security Level {email_msg.security_level.value}")
            
            # Encrypt the email content
            encrypted_message = self.encryptor.encrypt_message(
                plaintext=email_msg.content,
                security_level=email_msg.security_level,
                sender=email_msg.sender,
                recipient=email_msg.recipient,
                subject=email_msg.subject,
                attachments=email_msg.attachments
            )
            
            # Extract encryption metadata
            metadata = {
                "security_level": encrypted_message.metadata.security_level,
                "algorithm": encrypted_message.metadata.algorithm,
                "key_source": encrypted_message.metadata.key_source,
                "timestamp": encrypted_message.metadata.timestamp,
                "message_id": encrypted_message.metadata.message_id,
                "key_ids": encrypted_message.metadata.key_ids,
                "quantum_resistant": encrypted_message.metadata.quantum_resistant,
                "etsi_compliant": encrypted_message.metadata.etsi_compliant
            }
            
            logger.info(f"✅ Email encrypted: {encrypted_message.metadata.algorithm}")
            logger.info(f"🔑 Key Source: {encrypted_message.metadata.key_source}")
            logger.info(f"🛡️ Quantum Resistant: {encrypted_message.metadata.quantum_resistant}")
            
            return encrypted_message.ciphertext, metadata
            
        except Exception as e:
            logger.error(f"❌ Encryption error: {e}")
            raise
    
    def create_mime_message(self, email_msg: EmailMessage, encrypted_content: str, 
                           encryption_metadata: Dict[str, Any]) -> MIMEMultipart:
        """
        Create MIME multipart message with encrypted content
        
        Args:
            email_msg: Original email message
            encrypted_content: Encrypted email content
            encryption_metadata: Encryption metadata
            
        Returns:
            MIMEMultipart: Constructed email message
        """
        try:
            # Create multipart message
            mime_msg = MIMEMultipart('alternative')
            
            # Set headers
            mime_msg['From'] = email_msg.sender
            mime_msg['To'] = email_msg.recipient
            mime_msg['Subject'] = f"[QuMail-L{email_msg.security_level.value}] {email_msg.subject}"
            
            # Add QuMail headers for identification
            mime_msg['X-QuMail-Version'] = "1.0.0"
            mime_msg['X-QuMail-Security-Level'] = str(email_msg.security_level.value)
            mime_msg['X-QuMail-Algorithm'] = encryption_metadata['algorithm']
            mime_msg['X-QuMail-Quantum-Resistant'] = str(encryption_metadata['quantum_resistant'])
            mime_msg['X-QuMail-ETSI-Compliant'] = str(encryption_metadata['etsi_compliant'])
            
            # Create encrypted content part
            if email_msg.security_level == SecurityLevel.NO_QUANTUM:
                # Level 4: Send as plaintext
                content_part = MIMEText(email_msg.content, 'plain', 'utf-8')
            else:
                # Levels 1-3: Send encrypted content with metadata
                encrypted_body = {
                    "qumail_version": "1.0.0",
                    "encrypted_content": encrypted_content,
                    "encryption_metadata": encryption_metadata,
                    "instructions": "This email was encrypted with QuMail. Use QuMail client to decrypt."
                }
                
                # Create both plain text and JSON parts
                plain_text = f"""
🔐 QuMail Encrypted Message 🔐

This email was encrypted using QuMail's hybrid quantum-classical encryption.

Security Level: {email_msg.security_level.value} ({encryption_metadata['algorithm']})
Quantum Resistant: {encryption_metadata['quantum_resistant']}
ETSI Compliant: {encryption_metadata['etsi_compliant']}

To decrypt this message, please use the QuMail client.

---
Encrypted Content:
{encrypted_content[:100]}...

Encryption Metadata:
{json.dumps(encryption_metadata, indent=2)[:300]}...

---
QuMail - Quantum Secure Email for ISRO
Smart India Hackathon 2025
                """.strip()
                
                # Add plain text part for non-QuMail clients
                plain_part = MIMEText(plain_text, 'plain', 'utf-8')
                mime_msg.attach(plain_part)
                
                # Add JSON part for QuMail clients
                json_part = MIMEApplication(
                    json.dumps(encrypted_body, indent=2).encode('utf-8'),
                    _subtype='json',
                    name='qumail_encrypted.json'
                )
                json_part.add_header('Content-Disposition', 'attachment', filename='qumail_encrypted.json')
                mime_msg.attach(json_part)
            
            # Handle attachments (if any)
            for attachment in email_msg.attachments:
                try:
                    att_part = MIMEBase('application', 'octet-stream')
                    att_part.set_payload(attachment.get('data', b''))
                    encoders.encode_base64(att_part)
                    att_part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment.get("filename", "attachment")}'
                    )
                    mime_msg.attach(att_part)
                    logger.info(f"📎 Attached: {attachment.get('filename', 'attachment')}")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to attach {attachment.get('filename', 'file')}: {e}")
            
            return mime_msg
            
        except Exception as e:
            logger.error(f"❌ MIME construction error: {e}")
            raise
    
    def send_email(self, email_msg: EmailMessage) -> EmailSendResult:
        """
        Send encrypted email via Gmail SMTP
        
        Args:
            email_msg: Email message to send
            
        Returns:
            EmailSendResult: Result of send operation
        """
        try:
            logger.info(f"📧 Sending email from {email_msg.sender} to {email_msg.recipient}")
            logger.info(f"🔒 Security Level: {email_msg.security_level.value}")
            
            # Connect to SMTP if not already connected
            if not self.smtp_server:
                if not self.connect_smtp():
                    return EmailSendResult(
                        success=False,
                        error="Failed to connect to SMTP server"
                    )
            
            # Encrypt email content
            encrypted_content, encryption_metadata = self.encrypt_email_content(email_msg)
            
            # Create MIME message
            mime_msg = self.create_mime_message(email_msg, encrypted_content, encryption_metadata)
            
            # Send email
            result = self.smtp_server.send_message(mime_msg)
            
            # Generate message ID
            message_id = f"qumail_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
            
            logger.info(f"✅ Email sent successfully!")
            logger.info(f"📨 Message ID: {message_id}")
            logger.info(f"🔐 Algorithm: {encryption_metadata['algorithm']}")
            
            return EmailSendResult(
                success=True,
                message_id=message_id,
                encryption_metadata=encryption_metadata,
                sent_at=datetime.now(timezone.utc).isoformat()
            )
            
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP send error: {e}")
            return EmailSendResult(
                success=False,
                error=f"SMTP error: {str(e)}"
            )
        except Exception as e:
            logger.error(f"❌ Send email error: {e}")
            return EmailSendResult(
                success=False,
                error=f"Send error: {str(e)}"
            )
    
    def send_test_email(self, recipient: str, security_level: SecurityLevel = SecurityLevel.QUANTUM_AIDED) -> EmailSendResult:
        """
        Send a test email with specified security level
        
        Args:
            recipient: Email address to send to
            security_level: Security level to use
            
        Returns:
            EmailSendResult: Result of send operation
        """
        test_content = f"""
🔐 QuMail Test Email - Security Level {security_level.value} 🔐

This is a test email from QuMail's hybrid quantum-classical encryption system.

Security Level: {security_level.value}
Timestamp: {datetime.now(timezone.utc).isoformat()}

Test Message Content:
- Quantum Key Distribution (QKD) simulation using BB84 protocol
- Post-Quantum Cryptography with ML-KEM-768 and ML-DSA-65
- Classical cryptography with X25519 ECDH and EdDSA
- Hybrid key derivation using HKDF-SHA256

This email demonstrates the integration of multiple cryptographic layers 
for quantum-resistant email security.

---
QuMail - Quantum Secure Email for ISRO
Smart India Hackathon 2025
        """.strip()
        
        test_email = EmailMessage(
            sender=self.credentials.email,
            recipient=recipient,
            subject=f"QuMail Test - Level {security_level.value} Encryption",
            content=test_content,
            security_level=security_level
        )
        
        return self.send_email(test_email)
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect_smtp()

# Factory function for easy integration
def create_email_sender(email: str, password: str) -> QuMailEmailSender:
    """
    Create QuMail email sender instance
    
    Args:
        email: Gmail address
        password: Gmail App Password
        
    Returns:
        QuMailEmailSender: Configured email sender
    """
    credentials = EmailCredentials(email=email, password=password)
    return QuMailEmailSender(credentials)

# Demo function
def demo_email_sending():
    """Demonstrate email sending with different security levels"""
    print("🔐 QuMail Email Integration Demo")
    print("=" * 50)
    
    # Note: Replace with actual credentials for testing
    demo_email = "your_email@gmail.com"
    demo_password = "your_app_password"
    recipient = "recipient@gmail.com"
    
    print("⚠️ Demo requires actual Gmail credentials")
    print("1. Enable 2-Factor Authentication on Gmail")
    print("2. Generate App Password for QuMail")
    print("3. Update demo_email and demo_password variables")
    print("4. Set recipient email address")
    
    # Uncomment below for actual testing:
    """
    try:
        with create_email_sender(demo_email, demo_password) as sender:
            # Test different security levels
            for level in [SecurityLevel.QUANTUM_SECURE, SecurityLevel.QUANTUM_AIDED, SecurityLevel.HYBRID_PQC]:
                print(f"\n📧 Testing Security Level {level.value}...")
                result = sender.send_test_email(recipient, level)
                
                if result.success:
                    print(f"✅ Email sent: {result.message_id}")
                    print(f"🔐 Algorithm: {result.encryption_metadata['algorithm']}")
                else:
                    print(f"❌ Failed: {result.error}")
                    
        print("\n✅ Email integration demo completed!")
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
    """

if __name__ == "__main__":
    demo_email_sending()
