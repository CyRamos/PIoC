"""
Utility functions and classes for the CTI application.
Includes security validators, rate limiters, and audit logging.
"""

import asyncio
import time
import hashlib
import hmac
import logging
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from collections import defaultdict, deque
import mimetypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.config import security_config
from src.pioc.models import SessionLocal, AuditLog

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Security validation utilities."""
    
    def __init__(self):
        """Initialize security validator."""
        self.max_file_size = security_config.MAX_FILE_SIZE_MB * 1024 * 1024
        self.allowed_extensions = security_config.ALLOWED_FILE_EXTENSIONS
        
        # Dangerous file signatures (magic numbers)
        self.dangerous_signatures = {
            b'\x4D\x5A': 'PE executable',  # PE/EXE
            b'\x7F\x45\x4C\x46': 'ELF executable',  # ELF
            b'\xFE\xED\xFA': 'Mach-O executable',  # Mach-O
            b'\xCF\xFA\xED\xFE': 'Mach-O executable',  # Mach-O (reverse)
            b'\x50\x4B\x03\x04': 'ZIP archive',  # ZIP
            b'\x50\x4B\x05\x06': 'ZIP archive',  # ZIP (empty)
            b'\x50\x4B\x07\x08': 'ZIP archive',  # ZIP (spanned)
        }
        
        # Malicious patterns
        self.malicious_patterns = [
            rb'<script[^>]*>',  # JavaScript
            rb'javascript:',  # JavaScript URL
            rb'vbscript:',  # VBScript URL
            rb'data:text/html',  # Data URLs with HTML
            rb'<%.*%>',  # Server-side includes
            rb'\x00',  # Null bytes
        ]
    
    def validate_file_content(self, file_path: Path) -> bool:
        """
        Validate file content for security threats.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            True if file is safe, False otherwise
        """
        try:
            # Check file size
            if file_path.stat().st_size > self.max_file_size:
                logger.warning(f"File too large: {file_path}")
                return False
            
            # Read first few bytes to check file signature
            with open(file_path, 'rb') as f:
                header = f.read(1024)  # Read first 1KB
            
            # Check for dangerous file signatures
            for signature, description in self.dangerous_signatures.items():
                if header.startswith(signature):
                    logger.warning(f"Dangerous file signature detected: {description} in {file_path}")
                    return False
            
            # Check for malicious patterns
            for pattern in self.malicious_patterns:
                if re.search(pattern, header, re.IGNORECASE):
                    logger.warning(f"Malicious pattern detected in {file_path}")
                    return False
            
            # Validate MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and 'executable' in mime_type.lower():
                logger.warning(f"Executable MIME type detected: {mime_type} for {file_path}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating file content {file_path}: {str(e)}")
            return False
    
    def validate_input_string(self, input_string: str, max_length: int = 1000) -> bool:
        """
        Validate input string for security threats.
        
        Args:
            input_string: String to validate
            max_length: Maximum allowed length
            
        Returns:
            True if input is safe, False otherwise
        """
        try:
            # Check length
            if len(input_string) > max_length:
                return False
            
            # Check for null bytes
            if '\x00' in input_string:
                return False
            
            # Check for potential script injection
            dangerous_patterns = [
                r'<script[^>]*>',
                r'javascript:',
                r'vbscript:',
                r'data:text/html',
                r'<%.*%>',
                r'{{.*}}',  # Template injection
                r'\$\{.*\}',  # Expression language injection
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, input_string, re.IGNORECASE):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating input string: {str(e)}")
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and other attacks.
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        
        # Limit length
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            sanitized = name[:250] + ('.' + ext if ext else '')
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = f"file_{int(time.time())}"
        
        return sanitized
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            Base64-encoded secure token
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8')

class RateLimiter:
    """Rate limiter for controlling API request frequency."""
    
    def __init__(self, max_requests: int, time_window: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(deque)
        self._lock = asyncio.Lock()
    
    async def acquire(self, identifier: str = "global") -> bool:
        """
        Acquire permission to make a request.
        
        Args:
            identifier: Unique identifier for the requester
            
        Returns:
            True if request is allowed, False otherwise
        """
        async with self._lock:
            now = time.time()
            
            # Clean old requests
            while (self.requests[identifier] and 
                   self.requests[identifier][0] < now - self.time_window):
                self.requests[identifier].popleft()
            
            # Check if we can make a new request
            if len(self.requests[identifier]) < self.max_requests:
                self.requests[identifier].append(now)
                return True
            
            # Wait until we can make a request
            if self.requests[identifier]:
                wait_time = self.requests[identifier][0] + self.time_window - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    return await self.acquire(identifier)
            
            return False
    
    def get_remaining_requests(self, identifier: str = "global") -> int:
        """
        Get number of remaining requests for an identifier.
        
        Args:
            identifier: Unique identifier for the requester
            
        Returns:
            Number of remaining requests
        """
        now = time.time()
        
        # Clean old requests
        while (self.requests[identifier] and 
               self.requests[identifier][0] < now - self.time_window):
            self.requests[identifier].popleft()
        
        return max(0, self.max_requests - len(self.requests[identifier]))

class DataEncryption:
    """Data encryption utilities."""
    
    def __init__(self, password: Optional[str] = None):
        """
        Initialize encryption with password.
        
        Args:
            password: Password for encryption key derivation
        """
        if password is None:
            password = security_config.SECRET_KEY
            
        # Derive key from password
        salt = b'stable_salt_for_cti'  # In production, use random salt per encryption
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher = Fernet(key)
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Base64-encoded encrypted data
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted = self.cipher.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            
        Returns:
            Decrypted data as string
        """
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')

class AuditLogger:
    """Audit logging for compliance and security monitoring."""
    
    def __init__(self):
        """Initialize audit logger."""
        self.encrypt_logs = security_config.ENCRYPT_SENSITIVE_DATA
        self.encryptor = DataEncryption() if self.encrypt_logs else None
    
    def log_event(self, user_id: str, action: str, resource_type: str,
                  resource_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None,
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> None:
        """
        Log an audit event.
        
        Args:
            user_id: ID of the user performing the action
            action: Action being performed
            resource_type: Type of resource being acted upon
            resource_id: ID of the specific resource
            details: Additional details about the action
            ip_address: IP address of the user
            user_agent: User agent string
        """
        try:
            # Prepare details
            details_json = json.dumps(details) if details else None
            if self.encrypt_logs and details_json:
                details_json = self.encryptor.encrypt(details_json)
            
            # Create audit log entry
            with SessionLocal() as session:
                audit_log = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    details=details_json,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                session.add(audit_log)
                session.commit()
                
            logger.info(f"Audit log created: {user_id} performed {action} on {resource_type}")
            
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")
    
    def get_audit_logs(self, user_id: Optional[str] = None, action: Optional[str] = None,
                      resource_type: Optional[str] = None, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs with optional filtering.
        
        Args:
            user_id: Filter by user ID
            action: Filter by action
            resource_type: Filter by resource type
            hours: Number of hours to look back
            
        Returns:
            List of audit log dictionaries
        """
        try:
            with SessionLocal() as session:
                query = session.query(AuditLog)
                
                # Apply filters
                if user_id:
                    query = query.filter(AuditLog.user_id == user_id)
                if action:
                    query = query.filter(AuditLog.action == action)
                if resource_type:
                    query = query.filter(AuditLog.resource_type == resource_type)
                
                # Time filter
                cutoff_time = datetime.now() - timedelta(hours=hours)
                query = query.filter(AuditLog.timestamp >= cutoff_time)
                
                # Order by timestamp
                audit_logs = query.order_by(AuditLog.timestamp.desc()).all()
                
                # Convert to dictionaries and decrypt if needed
                result = []
                for log in audit_logs:
                    log_dict = {
                        'id': log.id,
                        'user_id': log.user_id,
                        'action': log.action,
                        'resource_type': log.resource_type,
                        'resource_id': log.resource_id,
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent,
                        'timestamp': log.timestamp.isoformat()
                    }
                    
                    # Decrypt details if encrypted
                    if log.details:
                        if self.encrypt_logs and self.encryptor:
                            try:
                                decrypted_details = self.encryptor.decrypt(log.details)
                                log_dict['details'] = json.loads(decrypted_details)
                            except Exception:
                                log_dict['details'] = {"error": "Failed to decrypt details"}
                        else:
                            try:
                                log_dict['details'] = json.loads(log.details)
                            except Exception:
                                log_dict['details'] = {"error": "Invalid JSON in details"}
                    else:
                        log_dict['details'] = None
                    
                    result.append(log_dict)
                
                return result
                
        except Exception as e:
            logger.error(f"Error retrieving audit logs: {str(e)}")
            return []

class DataRetentionManager:
    """Manages data retention policies."""
    
    def __init__(self):
        """Initialize data retention manager."""
        self.retention_days = security_config.DATA_RETENTION_DAYS
    
    def cleanup_old_data(self) -> Dict[str, int]:
        """
        Clean up old data based on retention policy.
        
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            with SessionLocal() as session:
                cutoff_date = datetime.now() - timedelta(days=self.retention_days)
                
                # Clean up old audit logs
                audit_deleted = session.query(AuditLog).filter(
                    AuditLog.timestamp < cutoff_date
                ).delete()
                
                # Clean up old health checks
                from models import HealthCheck
                health_checks_deleted = session.query(HealthCheck).filter(
                    HealthCheck.checked_at < cutoff_date
                ).delete()
                
                session.commit()
                
                cleanup_stats = {
                    'audit_logs_deleted': audit_deleted,
                    'health_checks_deleted': health_checks_deleted,
                    'cutoff_date': cutoff_date.isoformat()
                }
                
                logger.info(f"Data cleanup completed: {cleanup_stats}")
                return cleanup_stats
                
        except Exception as e:
            logger.error(f"Error during data cleanup: {str(e)}")
            return {'error': str(e)}

class ConfigValidator:
    """Validates configuration settings."""
    
    @staticmethod
    def validate_security_config() -> List[str]:
        """
        Validate security configuration.
        
        Returns:
            List of validation warnings/errors
        """
        warnings = []
        
        # Check secret key strength
        if len(security_config.SECRET_KEY) < 32:
            warnings.append("SECRET_KEY should be at least 32 characters long")
        
        # Check rate limiting settings
        if security_config.MAX_REQUESTS_PER_MINUTE > 1000:
            warnings.append("MAX_REQUESTS_PER_MINUTE is very high, consider lowering")
        
        # Check file size limits
        if security_config.MAX_FILE_SIZE_MB > 100:
            warnings.append("MAX_FILE_SIZE_MB is very high, consider lowering")
        
        # Check data retention
        if security_config.DATA_RETENTION_DAYS > 2555:  # 7 years
            warnings.append("DATA_RETENTION_DAYS is very high")
        
        return warnings

class HashCalculator:
    """Calculate various hashes for data integrity."""
    
    @staticmethod
    def calculate_sha256(data: Union[str, bytes]) -> str:
        """Calculate SHA256 hash."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def calculate_md5(data: Union[str, bytes]) -> str:
        """Calculate MD5 hash."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.md5(data).hexdigest()
    
    @staticmethod
    def calculate_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use
            
        Returns:
            Hexadecimal hash string
        """
        hash_func = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()

# Global utility instances
security_validator = SecurityValidator()
audit_logger = AuditLogger()
data_retention_manager = DataRetentionManager()
hash_calculator = HashCalculator() 