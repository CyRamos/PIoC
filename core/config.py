"""
Configuration module for the CTI (Cyber Threat Intelligence) application.
Implements R.A.I.L.G.U.A.R.D security principles.
"""

import os
from typing import Dict, Any, Optional, List
from pathlib import Path
from dotenv import load_dotenv
import secrets

# Load environment variables
load_dotenv()

class SecurityConfig:
    """Security configuration following R.A.I.L.G.U.A.R.D principles."""
    
    # Rate limiting (R - Rate Limiting)
    MAX_REQUESTS_PER_MINUTE: int = 60
    MAX_FILE_SIZE_MB: int = 50
    
    # Authentication (A - Authentication)
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Input validation (I - Input Validation)
    MAX_INDICATORS_PER_BATCH: int = 10000
    ALLOWED_FILE_EXTENSIONS: set = {".csv", ".json", ".txt", ".xml"}
    
    # Logging (L - Logging)
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = "cti_application.log"
    
    # General security (G - General Security)
    HASH_ALGORITHM: str = "sha256"
    ENCRYPTION_KEY_SIZE: int = 32
    
    # User access control (U - User Access Control)
    DEFAULT_USER_ROLE: str = "analyst"
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@cti.local")
    
    # Audit and monitoring (A - Audit)
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_FILE: str = "audit.log"
    
    # Risk management (R - Risk Management)
    MALWARE_SCAN_ENABLED: bool = True
    QUARANTINE_SUSPICIOUS_FILES: bool = True
    
    # Data protection (D - Data Protection)
    ENCRYPT_SENSITIVE_DATA: bool = True
    DATA_RETENTION_DAYS: int = 365

class DatabaseConfig:
    """Database configuration."""
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///cti_database.db")
    DATABASE_ECHO: bool = os.getenv("DATABASE_ECHO", "False").lower() == "true"
    CONNECTION_POOL_SIZE: int = 20
    CONNECTION_POOL_OVERFLOW: int = 30

class ApplicationConfig:
    """Main application configuration."""
    
    APP_NAME: str = "CTI Threat Intelligence Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    
    # File processing
    UPLOAD_DIR: Path = Path("uploads")
    TEMP_DIR: Path = Path("temp")
    EXPORT_DIR: Path = Path("exports")
    
    # API configuration
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    
    # GUI configuration
    GUI_HOST: str = os.getenv("GUI_HOST", "127.0.0.1")
    GUI_PORT: int = int(os.getenv("GUI_PORT", "8501"))
    
    def __init__(self):
        """Initialize application configuration and create necessary directories."""
        self._create_directories()
    
    def _create_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        for directory in [self.UPLOAD_DIR, self.TEMP_DIR, self.EXPORT_DIR]:
            directory.mkdir(exist_ok=True)

class AuthConfig:
    """Authentication configuration."""
    
    # Authentication settings
    REQUIRE_AUTH: bool = os.getenv("CTI_REQUIRE_AUTH", "true").lower() == "true"
    AUTH_METHOD: str = "email"  # "email", "token", "oauth"
    
    # Email authentication
    ALLOWED_DOMAINS: List[str] = ["cyterous.com", "gmail.com"]  # Add your domain
    ADMIN_EMAILS: List[str] = ["admin@cyterous.com"]  # Add admin emails
    
    # Session settings
    SESSION_TIMEOUT_MINUTES: int = 480  # 8 hours
    REMEMBER_ME_DAYS: int = 30
    
    # Integration with cyterous.com
    CYTEROUS_API_URL: str = "https://cyterous.com/api"  # Your website API
    CYTEROUS_AUTH_ENDPOINT: str = "/auth/verify"
    CYTEROUS_API_KEY: str = os.getenv("CYTEROUS_API_KEY", "")
    
    # OAuth settings (if using OAuth)
    OAUTH_CLIENT_ID: str = os.getenv("OAUTH_CLIENT_ID", "")
    OAUTH_CLIENT_SECRET: str = os.getenv("OAUTH_CLIENT_SECRET", "")
    OAUTH_REDIRECT_URI: str = "http://localhost:8501/auth/callback"

# Global configuration instances
security_config = SecurityConfig()
db_config = DatabaseConfig()
app_config = ApplicationConfig()
auth_config = AuthConfig()

# Health check endpoints configuration
HEALTH_CHECK_ENDPOINTS = {
    "virus_total": "https://www.virustotal.com/vtapi/v2/url/report",
    "abuse_ipdb": "https://api.abuseipdb.com/api/v2/check",
    "shodan": "https://api.shodan.io/shodan/host",
}

# Indicator type mappings
INDICATOR_TYPES = {
    "ip": "IP Address",
    "domain": "Domain",
    "url": "URL", 
    "hash": "File Hash",
    "email": "Email Address",
}

# Normalization patterns for defanged indicators
NORMALIZATION_PATTERNS = {
    "defang_url": [
        (r"hxxp://", "http://"),
        (r"hxxps://", "https://"),
        (r"hxxp", "http"),
        (r"hxxps", "https"),
        (r"\[.\]", "."),
        (r"\[\.\]", "."),
        (r"\|\.\|", "."),
        (r"\(\.\)", "."),
        (r"\[:\]", ":"),
        (r"\[/\]", "/"),
    ],
    "defang_ip": [
        (r"\[.\]", "."),
        (r"\[\.\]", "."),
        (r"\|\.\|", "."),
        (r"\,", "."),
        (r"\[(\d+)\]", r"\1"),  # Remove brackets around numbers
    ],
    "defang_domain": [
        (r"\[.\]", "."),
        (r"\[\.\]", "."),
        (r"\|\.\|", "."),
        (r"\(\.\)", "."),
        (r"\[:\]", ":"),
        (r"\[/\]", "/"),
    ]
} 