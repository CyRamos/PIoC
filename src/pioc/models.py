"""
Database models for the CTI (Cyber Threat Intelligence) application.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, ForeignKey, 
    Index, UniqueConstraint, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel, Field, validator
import hashlib
import json

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.config import db_config

Base = declarative_base()

class Indicator(Base):
    """Indicator model for storing normalized indicators."""
    
    __tablename__ = "indicators"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(50), nullable=False, index=True)
    value = Column(String(500), nullable=False, index=True)
    normalized_value = Column(String(500), nullable=False, index=True)
    hash_value = Column(String(64), unique=True, nullable=False, index=True)
    confidence_score = Column(Integer, default=50)  # 0-100
    tlp_level = Column(String(20), default="WHITE", index=True)  # WHITE, GREEN, AMBER, RED
    source_file = Column(String(255))
    first_seen = Column(DateTime, default=func.now(), nullable=False)
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True, index=True)
    created_by = Column(String(100), default="system")
    
    # Relationships
    health_checks = relationship("HealthCheck", back_populates="indicator", cascade="all, delete-orphan")
    tags = relationship("IndicatorTag", back_populates="indicator", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_indicator_type_value', 'indicator_type', 'normalized_value'),
        Index('idx_first_seen_active', 'first_seen', 'is_active'),
        UniqueConstraint('indicator_type', 'normalized_value', name='uq_indicator_type_value'),
    )
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.hash_value:
            self.hash_value = self._generate_hash()
    
    def _generate_hash(self) -> str:
        """Generate a unique hash for the indicator."""
        content = f"{self.indicator_type}:{self.normalized_value}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> dict:
        """Convert indicator to dictionary."""
        return {
            'id': self.id,
            'indicator_type': self.indicator_type,
            'value': self.value,
            'normalized_value': self.normalized_value,
            'confidence_score': self.confidence_score,
            'tlp_level': self.tlp_level,
            'source_file': self.source_file,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_active': self.is_active,
            'created_by': self.created_by
        }

class HealthCheck(Base):
    """Health check results for indicators."""
    
    __tablename__ = "health_checks"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(Integer, ForeignKey('indicators.id'), nullable=False, index=True)
    check_type = Column(String(50), nullable=False)  # reputation, availability, etc.
    check_source = Column(String(100), nullable=False)  # VirusTotal, AbuseIPDB, etc.
    result = Column(Text)  # JSON result from the check
    status = Column(String(20), nullable=False, index=True)  # healthy, suspicious, malicious, error
    checked_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Relationships
    indicator = relationship("Indicator", back_populates="health_checks")
    
    # Indexes
    __table_args__ = (
        Index('idx_indicator_check_type', 'indicator_id', 'check_type'),
        Index('idx_checked_at_status', 'checked_at', 'status'),
    )
    
    def to_dict(self) -> dict:
        """Convert health check to dictionary."""
        return {
            'id': self.id,
            'indicator_id': self.indicator_id,
            'check_type': self.check_type,
            'check_source': self.check_source,
            'result': json.loads(self.result) if self.result else None,
            'status': self.status,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None
        }

class IndicatorTag(Base):
    """Tags for categorizing indicators."""
    
    __tablename__ = "indicator_tags"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(Integer, ForeignKey('indicators.id'), nullable=False, index=True)
    tag_name = Column(String(100), nullable=False, index=True)
    tag_value = Column(String(255))
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Relationships
    indicator = relationship("Indicator", back_populates="tags")
    
    # Indexes
    __table_args__ = (
        Index('idx_tag_name_value', 'tag_name', 'tag_value'),
        UniqueConstraint('indicator_id', 'tag_name', name='uq_indicator_tag'),
    )

class AuditLog(Base):
    """Audit log for tracking user actions."""
    
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(100), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100))
    details = Column(Text)  # JSON details of the action
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(String(500))
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_user_action_timestamp', 'user_id', 'action', 'timestamp'),
        Index('idx_resource_type_id', 'resource_type', 'resource_id'),
    )

# Pydantic models for API validation
class IndicatorCreate(BaseModel):
    """Pydantic model for creating indicators."""
    
    indicator_type: str = Field(..., description="Type of indicator (ip, domain, url, hash, email)")
    value: str = Field(..., min_length=1, max_length=500, description="Original indicator value")
    confidence_score: Optional[int] = Field(50, ge=0, le=100, description="Confidence score (0-100)")
    tlp_level: Optional[str] = Field("WHITE", description="TLP classification level")
    source_file: Optional[str] = Field(None, max_length=255, description="Source file name")
    created_by: Optional[str] = Field("system", max_length=100, description="Creator identifier")
    
    @validator('indicator_type')
    def validate_indicator_type(cls, v):
        """Validate indicator type."""
        allowed_types = {'ip', 'domain', 'url', 'hash', 'email'}
        if v.lower() not in allowed_types:
            raise ValueError(f'indicator_type must be one of {allowed_types}')
        return v.lower()
    
    @validator('tlp_level')
    def validate_tlp_level(cls, v):
        """Validate TLP level."""
        allowed_levels = {'WHITE', 'GREEN', 'AMBER', 'RED'}
        if v.upper() not in allowed_levels:
            raise ValueError(f'tlp_level must be one of {allowed_levels}')
        return v.upper()

class IndicatorResponse(BaseModel):
    """Pydantic model for indicator responses."""
    
    id: int
    indicator_type: str
    value: str
    normalized_value: str
    confidence_score: int
    tlp_level: str
    source_file: Optional[str]
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    created_by: str
    
    class Config:
        from_attributes = True

class HealthCheckCreate(BaseModel):
    """Pydantic model for creating health checks."""
    
    indicator_id: int
    check_type: str = Field(..., max_length=50)
    check_source: str = Field(..., max_length=100)
    result: Optional[dict] = None
    status: str = Field(..., description="Health check status")
    
    @validator('status')
    def validate_status(cls, v):
        """Validate health check status."""
        allowed_statuses = {'healthy', 'suspicious', 'malicious', 'error', 'unknown'}
        if v.lower() not in allowed_statuses:
            raise ValueError(f'status must be one of {allowed_statuses}')
        return v.lower()

class HealthCheckResponse(BaseModel):
    """Pydantic model for health check responses."""
    
    id: int
    indicator_id: int
    check_type: str
    check_source: str
    result: Optional[dict]
    status: str
    checked_at: datetime
    
    class Config:
        from_attributes = True

# Database setup
def create_database_engine():
    """Create database engine with proper configuration."""
    return create_engine(
        db_config.DATABASE_URL,
        echo=db_config.DATABASE_ECHO,
        pool_size=db_config.CONNECTION_POOL_SIZE,
        max_overflow=db_config.CONNECTION_POOL_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=3600  # Recycle connections after 1 hour
    )

def create_tables(engine):
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)

def get_session_factory():
    """Get SQLAlchemy session factory."""
    engine = create_database_engine()
    create_tables(engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Global session factory
SessionLocal = get_session_factory() 