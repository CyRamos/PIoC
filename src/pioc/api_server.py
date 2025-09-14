"""
FastAPI backend server for the CTI (Cyber Threat Intelligence) platform.
Provides REST API endpoints for managing indicators and operations.
"""

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, BackgroundTasks, Security
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field
import uvicorn
import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import time

# Import our CTI modules
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.config import app_config, security_config, INDICATOR_TYPES
from src.pioc.models import (
    SessionLocal, Indicator, HealthCheck, AuditLog,
    IndicatorCreate, IndicatorResponse, HealthCheckResponse
)
from src.pioc.indicator_processor import IndicatorProcessor
from src.pioc.health_checker import HealthCheckManager
from src.pioc.utils import security_validator, audit_logger, RateLimiter

# Configure logging
logging.basicConfig(
    level=getattr(logging, security_config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(security_config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=app_config.APP_NAME,
    version=app_config.APP_VERSION,
    description="Secure CTI platform with R.A.I.L.G.U.A.R.D security features. Use Bearer token 'demo-token' for testing.",
    docs_url=None,  # We serve custom docs at /docs
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],  # Streamlit
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
rate_limiter = RateLimiter(
    max_requests=security_config.MAX_REQUESTS_PER_MINUTE,
    time_window=60
)

# Global instances
processor = IndicatorProcessor()
health_manager = HealthCheckManager()

# Request/response models specific to API endpoints
class IndicatorExistsRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=500)

class IndicatorBulkItem(BaseModel):
    value: str = Field(..., min_length=1, max_length=500)
    confidence_score: Optional[int] = Field(50, ge=0, le=100)
    tlp_level: Optional[str] = Field("WHITE")
    source_file: Optional[str] = None

class IndicatorBulkRequest(BaseModel):
    items: List[IndicatorBulkItem] = Field(..., min_items=1)
    source_name: Optional[str] = Field("manual_bulk_api")

# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Validate user authentication."""
    # In a real implementation, validate the JWT token
    # For now, we'll use a simple approach
    token = credentials.credentials
    if token == "demo-token":
        return {"user_id": "api_user", "role": "analyst"}
    
    raise HTTPException(status_code=401, detail="Invalid authentication token")

async def rate_limit_check(request_id: str = "global"):
    """Check rate limiting."""
    allowed = await rate_limiter.acquire(request_id)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later."
        )

def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Middleware for audit logging
@app.middleware("http")
async def audit_middleware(request, call_next):
    """Middleware for audit logging."""
    start_time = time.time()
    
    # Get client IP
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    response = await call_next(request)
    
    # Log request
    process_time = time.time() - start_time
    
    audit_logger.log_event(
        user_id="system",
        action="api_request",
        resource_type="endpoint",
        resource_id=str(request.url.path),
        details={
            "method": request.method,
            "status_code": response.status_code,
            "process_time": process_time,
            "client_ip": client_ip
        },
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    return response

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Test database connection
        with SessionLocal() as session:
            from sqlalchemy import text
            session.execute(text("SELECT 1"))
        
        # Test file system access
        app_config.UPLOAD_DIR.touch(exist_ok=True)
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": app_config.APP_VERSION,
            "database": "connected",
            "filesystem": "accessible"
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
        )

# Indicator endpoints
@app.get("/api/v1/indicators", response_model=List[IndicatorResponse])
async def list_indicators(
    skip: int = 0,
    limit: int = 100,
    indicator_type: Optional[str] = None,
    tlp_level: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """List indicators with optional filtering."""
    try:
        query = db.query(Indicator)
        
        # Apply filters
        if indicator_type and indicator_type in INDICATOR_TYPES:
            query = query.filter(Indicator.indicator_type == indicator_type)
        
        if tlp_level and tlp_level in ['WHITE', 'GREEN', 'AMBER', 'RED']:
            query = query.filter(Indicator.tlp_level == tlp_level)
        
        if search:
            query = query.filter(
                Indicator.normalized_value.contains(search) |
                Indicator.source_file.contains(search)
            )
        
        # Apply pagination
        indicators = query.order_by(Indicator.first_seen.desc()).offset(skip).limit(limit).all()
        
        return indicators
        
    except Exception as e:
        logger.error(f"Error listing indicators: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/indicators/{indicator_id}", response_model=IndicatorResponse)
async def get_indicator(
    indicator_id: int,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Get a specific indicator by ID."""
    try:
        indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
        
        if not indicator:
            raise HTTPException(status_code=404, detail="Indicator not found")
        
        return indicator
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting indicator {indicator_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/indicators", response_model=IndicatorResponse)
async def create_indicator(
    indicator: IndicatorCreate,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Create a new indicator."""
    try:
        # Validate and normalize the indicator
        normalized_indicator = processor._process_single_indicator(
            indicator.value,
            "manual_api"
        )
        
        if not normalized_indicator:
            raise HTTPException(status_code=400, detail="Invalid indicator format")
        
        # Check if indicator already exists
        existing = db.query(Indicator).filter(
            Indicator.indicator_type == normalized_indicator['indicator_type'],
            Indicator.normalized_value == normalized_indicator['normalized_value']
        ).first()
        
        if existing:
            # Update last seen
            existing.last_seen = datetime.now()
            db.commit()
            return existing
        
        # Create new indicator
        db_indicator = Indicator(
            indicator_type=normalized_indicator['indicator_type'],
            value=indicator.value,
            normalized_value=normalized_indicator['normalized_value'],
            confidence_score=indicator.confidence_score,
            tlp_level=indicator.tlp_level,
            source_file=indicator.source_file,
            created_by=current_user['user_id']
        )
        
        db.add(db_indicator)
        db.commit()
        db.refresh(db_indicator)
        
        # Log audit event
        audit_logger.log_event(
            user_id=current_user['user_id'],
            action="indicator_created",
            resource_type="indicator",
            resource_id=str(db_indicator.id),
            details={"indicator_type": db_indicator.indicator_type, "value": db_indicator.normalized_value}
        )
        
        return db_indicator
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating indicator: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/indicators/exists")
async def indicator_exists(
    payload: IndicatorExistsRequest,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Check if an indicator already exists (by normalized value and type)."""
    try:
        processed = processor._process_single_indicator(payload.value, "exists_api")
        if not processed.get("success"):
            raise HTTPException(status_code=400, detail=processed.get("error_reason") or "Invalid indicator")

        indicator_type = processed["indicator_type"]
        normalized_value = processed["normalized_value"]

        existing = db.query(Indicator).filter(
            Indicator.indicator_type == indicator_type,
            Indicator.normalized_value == normalized_value
        ).first()

        return {
            "exists": existing is not None,
            "indicator_type": indicator_type,
            "normalized_value": normalized_value,
            "id": existing.id if existing else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking indicator existence: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/indicators/bulk")
async def bulk_upsert_indicators(
    payload: IndicatorBulkRequest,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Bulk insert/upsert indicators. Skips duplicates, updates last_seen for existing."""
    try:
        items = payload.items
        if len(items) > security_config.MAX_INDICATORS_PER_BATCH:
            raise HTTPException(status_code=400, detail=f"Batch limit exceeded: max {security_config.MAX_INDICATORS_PER_BATCH}")

        summary = {
            "received": len(items),
            "inserted": 0,
            "updated": 0,
            "invalid": 0,
            "errors": [],
            "details": []
        }

        now_ts = datetime.now()

        for item in items:
            try:
                processed = processor._process_single_indicator(item.value, payload.source_name or "manual_bulk_api")
                if not processed.get("success"):
                    summary["invalid"] += 1
                    summary["errors"].append({"value": item.value, "reason": processed.get("error_reason")})
                    continue

                indicator_type = processed["indicator_type"]
                normalized_value = processed["normalized_value"]

                existing = db.query(Indicator).filter(
                    Indicator.indicator_type == indicator_type,
                    Indicator.normalized_value == normalized_value
                ).first()

                if existing:
                    existing.last_seen = now_ts
                    if item.confidence_score is not None:
                        existing.confidence_score = item.confidence_score
                    if item.tlp_level:
                        existing.tlp_level = item.tlp_level.upper()
                    db.add(existing)
                    summary["updated"] += 1
                    summary["details"].append({"action": "updated", "id": existing.id, "value": normalized_value, "type": indicator_type})
                else:
                    db_indicator = Indicator(
                        indicator_type=indicator_type,
                        value=item.value,
                        normalized_value=normalized_value,
                        confidence_score=item.confidence_score if item.confidence_score is not None else 50,
                        tlp_level=(item.tlp_level.upper() if item.tlp_level else "WHITE"),
                        source_file=item.source_file or payload.source_name,
                        created_by=current_user['user_id']
                    )
                    db.add(db_indicator)
                    db.flush()  # get id
                    summary["inserted"] += 1
                    summary["details"].append({"action": "inserted", "id": db_indicator.id, "value": normalized_value, "type": indicator_type})

            except Exception as e_item:
                summary["invalid"] += 1
                summary["errors"].append({"value": getattr(item, 'value', None), "reason": str(e_item)})

        db.commit()

        audit_logger.log_event(
            user_id=current_user['user_id'],
            action="bulk_upsert",
            resource_type="indicator",
            resource_id="bulk",
            details={"summary": {k: v for k, v in summary.items() if k not in ["details", "errors"]}}
        )

        return summary

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during bulk upsert: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.delete("/api/v1/indicators/{indicator_id}")
async def delete_indicator(
    indicator_id: int,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Delete an indicator."""
    try:
        indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
        
        if not indicator:
            raise HTTPException(status_code=404, detail="Indicator not found")
        
        # Check permissions (admin or creator)
        if current_user['role'] != 'admin' and indicator.created_by != current_user['user_id']:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        db.delete(indicator)
        db.commit()
        
        # Log audit event
        audit_logger.log_event(
            user_id=current_user['user_id'],
            action="indicator_deleted",
            resource_type="indicator",
            resource_id=str(indicator_id),
            details={"indicator_type": indicator.indicator_type, "value": indicator.normalized_value}
        )
        
        return {"message": "Indicator deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting indicator {indicator_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# File upload endpoint
@app.post("/api/v1/indicators/upload")
async def upload_indicators_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source_name: Optional[str] = None,
    run_health_checks: bool = True,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check)
):
    """Upload and process indicators file."""
    try:
        # Validate file
        if file.size > security_config.MAX_FILE_SIZE_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large")
        
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in security_config.ALLOWED_FILE_EXTENSIONS:
            raise HTTPException(status_code=400, detail="File type not allowed")
        
        # Save file temporarily
        sanitized_filename = security_validator.sanitize_filename(file.filename)
        temp_path = app_config.TEMP_DIR / f"{int(time.time())}_{sanitized_filename}"
        
        with open(temp_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        
        # Validate file content
        if not security_validator.validate_file_content(temp_path):
            temp_path.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="File content validation failed")
        
        # Process file in background
        background_tasks.add_task(
            process_file_background,
            temp_path,
            source_name or file.filename,
            run_health_checks,
            current_user['user_id']
        )
        
        # Log audit event
        audit_logger.log_event(
            user_id=current_user['user_id'],
            action="file_uploaded",
            resource_type="file",
            resource_id=file.filename,
            details={"file_size": file.size, "source_name": source_name}
        )
        
        return {
            "message": "File uploaded and processing started",
            "filename": file.filename,
            "size": file.size,
            "status": "processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

async def process_file_background(
    file_path: Path,
    source_name: str,
    run_health_checks: bool,
    user_id: str
):
    """Background task to process uploaded file."""
    try:
        # Process file
        result = processor.process_file(file_path, source_name)
        
        # Run health checks if requested
        if run_health_checks and result.get('success', False):
            # Get recently added indicators
            with SessionLocal() as session:
                cutoff_time = datetime.now() - timedelta(minutes=5)
                recent_indicators = session.query(Indicator).filter(
                    Indicator.first_seen >= cutoff_time,
                    Indicator.source_file == source_name
                ).all()
                
                if recent_indicators:
                    await health_manager.check_multiple_indicators(recent_indicators)
        
        # Log processing result
        audit_logger.log_event(
            user_id=user_id,
            action="file_processed",
            resource_type="file",
            resource_id=str(file_path),
            details=result
        )
        
        logger.info(f"Background processing completed for {file_path}: {result}")
        
    except Exception as e:
        logger.error(f"Error in background file processing: {str(e)}")
    finally:
        # Clean up temporary file
        file_path.unlink(missing_ok=True)

# Health check endpoints
@app.get("/api/v1/health-checks", response_model=List[HealthCheckResponse])
async def list_health_checks(
    skip: int = 0,
    limit: int = 100,
    indicator_id: Optional[int] = None,
    status: Optional[str] = None,
    hours: int = 24,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """List health checks with optional filtering."""
    try:
        query = db.query(HealthCheck)
        
        # Time filter
        cutoff_time = datetime.now() - timedelta(hours=hours)
        query = query.filter(HealthCheck.checked_at >= cutoff_time)
        
        # Apply filters
        if indicator_id:
            query = query.filter(HealthCheck.indicator_id == indicator_id)
        
        if status and status in ['healthy', 'suspicious', 'malicious', 'error', 'unknown']:
            query = query.filter(HealthCheck.status == status)
        
        # Apply pagination
        health_checks = query.order_by(HealthCheck.checked_at.desc()).offset(skip).limit(limit).all()
        
        return health_checks
        
    except Exception as e:
        logger.error(f"Error listing health checks: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/health-checks/run")
async def run_health_checks(
    background_tasks: BackgroundTasks,
    indicator_ids: List[int],
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Run health checks for specific indicators."""
    try:
        # Get indicators
        indicators = db.query(Indicator).filter(Indicator.id.in_(indicator_ids)).all()
        
        if not indicators:
            raise HTTPException(status_code=404, detail="No indicators found")
        
        # Run health checks in background
        background_tasks.add_task(
            run_health_checks_background,
            indicators,
            current_user['user_id']
        )
        
        return {
            "message": f"Health checks initiated for {len(indicators)} indicators",
            "indicator_count": len(indicators),
            "status": "running"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running health checks: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

async def run_health_checks_background(indicators: List[Indicator], user_id: str):
    """Background task to run health checks."""
    try:
        results = await health_manager.check_multiple_indicators(indicators)
        
        # Log audit event
        audit_logger.log_event(
            user_id=user_id,
            action="health_checks_run",
            resource_type="health_check",
            resource_id="bulk",
            details={"indicator_count": len(indicators), "results_count": len(results)}
        )
        
        logger.info(f"Background health checks completed for {len(indicators)} indicators")
        
    except Exception as e:
        logger.error(f"Error in background health checks: {str(e)}")

# Statistics endpoints
@app.get("/api/v1/statistics")
async def get_statistics(
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check),
    db = Depends(get_db)
):
    """Get platform statistics."""
    try:
        # Get basic counts
        total_indicators = db.query(Indicator).count()
        active_indicators = db.query(Indicator).filter(Indicator.is_active == True).count()
        
        # Get indicator type distribution
        type_distribution = {}
        for indicator_type in INDICATOR_TYPES.keys():
            count = db.query(Indicator).filter(Indicator.indicator_type == indicator_type).count()
            if count > 0:
                type_distribution[indicator_type] = count
        
        # Get recent health checks
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_health_checks = db.query(HealthCheck).filter(
            HealthCheck.checked_at >= cutoff_time
        ).count()
        
        # Get health status distribution
        status_distribution = {}
        statuses = ['healthy', 'suspicious', 'malicious', 'error', 'unknown']
        for status in statuses:
            count = db.query(HealthCheck).filter(
                HealthCheck.checked_at >= cutoff_time,
                HealthCheck.status == status
            ).count()
            if count > 0:
                status_distribution[status] = count
        
        # Get new indicators today
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        new_today = db.query(Indicator).filter(Indicator.first_seen >= today).count()
        
        return {
            "total_indicators": total_indicators,
            "active_indicators": active_indicators,
            "new_today": new_today,
            "recent_health_checks": recent_health_checks,
            "type_distribution": type_distribution,
            "status_distribution": status_distribution,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Audit log endpoints
@app.get("/api/v1/audit-logs")
async def get_audit_logs(
    hours: int = 24,
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check)
):
    """Get audit logs."""
    try:
        # Check permissions
        if current_user['role'] != 'admin' and user_id != current_user['user_id']:
            # Non-admin users can only see their own logs
            user_id = current_user['user_id']
        
        filters = {}
        if action:
            filters['action'] = action
        if user_id:
            filters['user_id'] = user_id
        
        logs = audit_logger.get_audit_logs(hours=hours, **filters)
        
        return {
            "logs": logs,
            "count": len(logs),
            "hours": hours,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# System maintenance endpoints
@app.post("/api/v1/system/cleanup")
async def cleanup_old_data(
    current_user: dict = Depends(get_current_user),
    _rate_limit: None = Depends(rate_limit_check)
):
    """Clean up old data based on retention policy."""
    try:
        # Check admin permissions
        if current_user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        
        from utils import data_retention_manager
        result = data_retention_manager.cleanup_old_data()
        
        # Log audit event
        audit_logger.log_event(
            user_id=current_user['user_id'],
            action="system_cleanup",
            resource_type="system",
            resource_id="cleanup",
            details=result
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# Custom Swagger UI with tabs and live URL updates
@app.get("/docs", response_class=HTMLResponse)
async def custom_swagger_ui():
    """Custom Swagger UI with tabs for code examples."""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html>
<head>
    <title>CTI Platform API</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <style>
        .code-tabs {
            margin-top: 10px;
            border: 1px solid #e1e5e9;
            border-radius: 6px;
            overflow: hidden;
        }
        .tab-buttons {
            display: flex;
            background: #f7f7f7;
            border-bottom: 1px solid #e1e5e9;
        }
        .tab-button {
            padding: 10px 16px;
            border: none;
            background: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            border-right: 1px solid #e1e5e9;
            transition: all 0.2s;
        }
        .tab-button:last-child {
            border-right: none;
        }
        .tab-button.active {
            background: #61affe;
            color: white;
        }
        .tab-button:hover:not(.active) {
            background: #e8f4fd;
        }
        .tab-content {
            display: none;
            padding: 16px;
            background: #41444e;
            color: #f8f8f2;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            line-height: 1.4;
            overflow-x: auto;
        }
        .tab-content.active {
            display: block;
        }
        .code-url {
            background: #272822;
            padding: 8px 12px;
            border-radius: 4px;
            margin: 8px 0;
            word-break: break-all;
            border-left: 3px solid #61affe;
        }
        .live-url {
            color: #a6e22e;
            font-weight: bold;
        }
        #swagger-ui .swagger-ui .opblock .opblock-summary {
            padding: 10px 20px;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                onComplete: function() {
                    // Wait for Swagger UI to fully render
                    setTimeout(() => {
                        initializeCodeTabs();
                    }, 1000);
                }
            });
        };
        
        function initializeCodeTabs() {
            console.log('Initializing code tabs...');
            
            // Add click listeners to all operation summaries
            document.addEventListener('click', function(event) {
                const opblockSummary = event.target.closest('.opblock-summary');
                if (opblockSummary) {
                    setTimeout(() => {
                        addTabsToExpandedOperation(opblockSummary);
                    }, 300);
                }
            });
            
            // Also try to add tabs to any already expanded operations
            setTimeout(() => {
                document.querySelectorAll('.opblock.is-open').forEach(addTabsToExpandedOperation);
            }, 500);
        }
        
        function addTabsToExpandedOperation(operationElement) {
            const operation = operationElement.closest ? operationElement.closest('.opblock') : operationElement;
            if (!operation) return;
            
            // Check if tabs already exist
            if (operation.querySelector('.code-tabs')) return;
            
            // Get the endpoint path
            const pathSpan = operation.querySelector('.opblock-summary-path span');
            const path = pathSpan ? pathSpan.textContent.trim() : '';
            
            console.log('Checking path:', path);
            
            // Only add tabs to indicator/statistics endpoints
            if (!path.includes('/indicators') && !path.includes('/statistics')) return;
            
            // Find the operation body where we'll insert tabs
            const opblockBody = operation.querySelector('.opblock-body');
            if (!opblockBody) return;
            
            // Create and insert the tabs
            const tabsContainer = document.createElement('div');
            tabsContainer.innerHTML = createTabsHTML(path, operation);
            
            // Insert tabs at the beginning of the operation body
            opblockBody.insertBefore(tabsContainer.firstElementChild, opblockBody.firstChild);
            
            // Initialize tab functionality
            initializeTabBehavior(operation, path);
            
            console.log('Tabs added to:', path);
        }
        
        function createTabsHTML(path, operation) {
            const operationId = 'tab_' + Math.random().toString(36).substr(2, 9);
            const baseUrl = window.location.origin;
            
            return `
                <div class="code-tabs" style="margin: 16px 0;">
                    <div class="tab-buttons">
                        <button class="tab-button active" data-tab="unix-${operationId}">Unix/Linux</button>
                        <button class="tab-button" data-tab="ps-${operationId}">PowerShell</button>
                        <button class="tab-button" data-tab="py-${operationId}">Python</button>
                    </div>
                    <div class="tab-content active" id="unix-${operationId}">
                        <div class="code-url">Live URL: <span class="live-url" data-path="${path}">${baseUrl}${path}</span></div>
                        <pre>${getUnixExample(path, baseUrl)}</pre>
                    </div>
                    <div class="tab-content" id="ps-${operationId}">
                        <div class="code-url">Live URL: <span class="live-url" data-path="${path}">${baseUrl}${path}</span></div>
                        <pre>${getPowerShellExample(path, baseUrl)}</pre>
                    </div>
                    <div class="tab-content" id="py-${operationId}">
                        <div class="code-url">Live URL: <span class="live-url" data-path="${path}">${baseUrl}${path}</span></div>
                        <pre>${getPythonExample(path, baseUrl)}</pre>
                    </div>
                </div>
            `;
        }
        
        function initializeTabBehavior(operation, path) {
            const tabButtons = operation.querySelectorAll('.tab-button');
            
            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const targetTabId = button.getAttribute('data-tab');
                    
                    // Remove active class from all buttons and contents in this operation
                    operation.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                    operation.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                    
                    // Add active class to clicked button and corresponding content
                    button.classList.add('active');
                    const targetContent = operation.querySelector('#' + targetTabId);
                    if (targetContent) {
                        targetContent.classList.add('active');
                    }
                });
            });
            
            // Set up live URL updates for this operation
            setupLiveUrlUpdates(operation, path);
        }
        
        function setupLiveUrlUpdates(operation, basePath) {
            // Watch for parameter changes in this specific operation
            const parameterInputs = operation.querySelectorAll('input, select, textarea');
            
            parameterInputs.forEach(input => {
                input.addEventListener('input', () => updateUrls(operation, basePath));
                input.addEventListener('change', () => updateUrls(operation, basePath));
            });
            
            // Also watch for dynamic content changes
            const observer = new MutationObserver(() => {
                setTimeout(() => updateUrls(operation, basePath), 100);
            });
            
            observer.observe(operation, {
                childList: true,
                subtree: true,
                attributes: true
            });
        }
        
        function updateUrls(operation, basePath) {
            const baseUrl = window.location.origin;
            let fullUrl = baseUrl + basePath;
            
            // Collect parameters from the operation
            const params = [];
            const paramInputs = operation.querySelectorAll('.parameters-col input, .parameters-col select');
            
            paramInputs.forEach(input => {
                const paramName = input.getAttribute('placeholder') || input.name || '';
                const value = input.value;
                
                if (value && value.trim() !== '' && paramName) {
                    // Extract actual parameter name from placeholder or nearby label
                    let cleanParamName = paramName.replace(/\s*\*?\s*$/, ''); // Remove asterisks
                    const label = input.closest('tr')?.querySelector('td:first-child .parameter__name');
                    if (label) {
                        cleanParamName = label.textContent.trim();
                    }
                    
                    if (cleanParamName && cleanParamName !== 'undefined') {
                        params.push(encodeURIComponent(cleanParamName) + '=' + encodeURIComponent(value));
                    }
                }
            });
            
            if (params.length > 0) {
                fullUrl += '?' + params.join('&');
            }
            
            // Update all live URL spans in this operation
            operation.querySelectorAll('.live-url').forEach(urlSpan => {
                urlSpan.textContent = fullUrl;
            });
        }
        
        function getUnixExample(path, baseUrl) {
            const examples = {
                '/api/v1/indicators': `curl -X GET "${baseUrl}${path}" \\
  -H "Authorization: Bearer demo-token"`,
                '/api/v1/indicators/exists': `curl -X POST "${baseUrl}${path}" \\
  -H "Authorization: Bearer demo-token" \\
  -H "Content-Type: application/json" \\
  -d '{"value": "192.168.1.1"}'`,
                '/api/v1/indicators/bulk': `curl -X POST "${baseUrl}${path}" \\
  -H "Authorization: Bearer demo-token" \\
  -H "Content-Type: application/json" \\
  -d '{
    "items": [
      {"value": "192.168.1.1", "confidence_score": 80},
      {"value": "malware.com", "tlp_level": "RED"}
    ],
    "source_name": "api_test"
  }'`,
                '/api/v1/statistics': `curl -X GET "${baseUrl}${path}" \\
  -H "Authorization: Bearer demo-token"`
            };
            return examples[path] || `curl -X GET "${baseUrl}${path}" \\
  -H "Authorization: Bearer demo-token"`;
        }
        
        function getPowerShellExample(path, baseUrl) {
            const examples = {
                '/api/v1/indicators': `curl -Uri '${baseUrl}${path}' \`
  -Headers @{'Authorization' = 'Bearer demo-token'}`,
                '/api/v1/indicators/exists': `curl -Uri '${baseUrl}${path}' \`
  -Method POST \`
  -Headers @{
    'Authorization' = 'Bearer demo-token'
    'Content-Type' = 'application/json'
  } \`
  -Body '{"value": "192.168.1.1"}'`,
                '/api/v1/indicators/bulk': `curl -Uri '${baseUrl}${path}' \`
  -Method POST \`
  -Headers @{
    'Authorization' = 'Bearer demo-token'
    'Content-Type' = 'application/json'
  } \`
  -Body '{
    "items": [
      {"value": "192.168.1.1", "confidence_score": 80},
      {"value": "malware.com", "tlp_level": "RED"}
    ],
    "source_name": "api_test"
  }'`,
                '/api/v1/statistics': `curl -Uri '${baseUrl}${path}' \`
  -Headers @{'Authorization' = 'Bearer demo-token'}`
            };
            return examples[path] || `curl -Uri '${baseUrl}${path}' \`
  -Headers @{'Authorization' = 'Bearer demo-token'}`;
        }
        
        function getPythonExample(path, baseUrl) {
            const examples = {
                '/api/v1/indicators': `import requests
headers = {"Authorization": "Bearer demo-token"}
response = requests.get("${baseUrl}${path}", headers=headers)
print(response.json())`,
                '/api/v1/indicators/exists': `import requests
headers = {"Authorization": "Bearer demo-token"}
data = {"value": "192.168.1.1"}
response = requests.post("${baseUrl}${path}", headers=headers, json=data)
print(response.json())`,
                '/api/v1/indicators/bulk': `import requests
headers = {"Authorization": "Bearer demo-token"}
data = {
    "items": [
        {"value": "192.168.1.1", "confidence_score": 80},
        {"value": "malware.com", "tlp_level": "RED"}
    ],
    "source_name": "api_test"
}
response = requests.post("${baseUrl}${path}", headers=headers, json=data)
print(response.json())`,
                '/api/v1/statistics': `import requests
headers = {"Authorization": "Bearer demo-token"}
response = requests.get("${baseUrl}${path}", headers=headers)
print(response.json())`
            };
            return examples[path] || `import requests
headers = {"Authorization": "Bearer demo-token"}
response = requests.get("${baseUrl}${path}", headers=headers)
print(response.json())`;
        }
        
    </script>
</body>
</html>
    """)

# Main function to run the server
def main():
    """Run the FastAPI server."""
    uvicorn.run(
        "api_server:app",
        host=app_config.API_HOST,
        port=app_config.API_PORT,
        reload=app_config.DEBUG,
        log_level=security_config.LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    main() 