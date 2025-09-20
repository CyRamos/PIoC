"""
Database utilities for connectivity testing and configuration management.
"""

import logging
import time
from typing import Dict, Any, Optional, Tuple
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from pathlib import Path
import json
import os

logger = logging.getLogger(__name__)

class DatabaseConnectivityTester:
    """Utility class for testing database connectivity and configuration."""
    
    @staticmethod
    def test_connection(database_url: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Test database connectivity.
        
        Args:
            database_url: Database URL to test
            timeout: Connection timeout in seconds
            
        Returns:
            Dict with connection status and details
        """
        start_time = time.time()
        result = {
            "status": "unknown",
            "connected": False,
            "response_time_ms": 0,
            "error": None,
            "database_type": "unknown",
            "database_file_exists": None,
            "details": {}
        }
        
        try:
            # Determine database type from URL
            if database_url.startswith("sqlite:"):
                result["database_type"] = "SQLite"
                # Check if SQLite file exists for file-based SQLite
                if ":///" in database_url:
                    db_file = database_url.split(":///")[-1]
                    result["database_file_exists"] = Path(db_file).exists()
                    result["details"]["file_path"] = db_file
            elif database_url.startswith("postgresql:"):
                result["database_type"] = "PostgreSQL"
            elif database_url.startswith("mysql:"):
                result["database_type"] = "MySQL"
            else:
                result["database_type"] = "Other"
            
            # Create engine with timeout
            engine = create_engine(
                database_url,
                pool_pre_ping=True,
                pool_timeout=timeout,
                connect_args={"timeout": timeout} if "sqlite" in database_url.lower() else {}
            )
            
            # Test connection
            with engine.connect() as connection:
                # Execute a simple query
                connection.execute(text("SELECT 1"))
                result["connected"] = True
                result["status"] = "connected"
                
                # Get additional database info
                try:
                    if result["database_type"] == "SQLite":
                        # Get SQLite version and database info
                        version_result = connection.execute(text("SELECT sqlite_version()")).fetchone()
                        if version_result:
                            result["details"]["version"] = version_result[0]
                        
                        # Get database size
                        if result["database_file_exists"]:
                            db_file = database_url.split(":///")[-1]
                            file_size = Path(db_file).stat().st_size
                            result["details"]["file_size_bytes"] = file_size
                            result["details"]["file_size_mb"] = round(file_size / (1024 * 1024), 2)
                    
                    # Get table count
                    if result["database_type"] == "SQLite":
                        table_count_result = connection.execute(
                            text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                        ).fetchone()
                    else:
                        # For other databases, use information_schema
                        table_count_result = connection.execute(
                            text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()")
                        ).fetchone()
                    
                    if table_count_result:
                        result["details"]["table_count"] = table_count_result[0]
                        
                except Exception as detail_error:
                    logger.warning(f"Could not get database details: {detail_error}")
                    result["details"]["detail_error"] = str(detail_error)
            
            engine.dispose()
            
        except SQLAlchemyError as e:
            result["status"] = "error"
            result["connected"] = False
            result["error"] = str(e)
            logger.error(f"Database connection failed: {e}")
            
        except Exception as e:
            result["status"] = "error"
            result["connected"] = False
            result["error"] = f"Unexpected error: {str(e)}"
            logger.error(f"Unexpected database connection error: {e}")
        
        finally:
            end_time = time.time()
            result["response_time_ms"] = round((end_time - start_time) * 1000, 2)
        
        return result
    
    @staticmethod
    def validate_database_url(database_url: str) -> Tuple[bool, str]:
        """
        Validate database URL format.
        
        Args:
            database_url: Database URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not database_url:
            return False, "Database URL cannot be empty"
        
        if not database_url.strip():
            return False, "Database URL cannot be only whitespace"
        
        # Basic URL format validation
        supported_schemes = ["sqlite", "postgresql", "mysql", "mariadb", "oracle", "mssql"]
        
        if "://" not in database_url:
            return False, "Database URL must include a scheme (e.g., sqlite://, postgresql://)"
        
        scheme = database_url.split("://")[0].lower()
        if scheme not in supported_schemes:
            return False, f"Unsupported database scheme: {scheme}. Supported: {', '.join(supported_schemes)}"
        
        # SQLite-specific validation
        if scheme == "sqlite":
            if not database_url.startswith("sqlite:///"):
                return False, "SQLite URLs should use format: sqlite:///path/to/database.db"
        
        return True, ""


class DatabaseConfigManager:
    """Manages database configuration persistence."""
    
    CONFIG_FILE = "db_config.json"
    
    @classmethod
    def save_custom_config(cls, database_url: str, description: str = "") -> bool:
        """
        Save custom database configuration.
        
        Args:
            database_url: Database URL to save
            description: Optional description
            
        Returns:
            Success status
        """
        try:
            config = {
                "custom_database_url": database_url,
                "description": description,
                "created_at": time.time(),
                "last_updated": time.time()
            }
            
            with open(cls.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Saved custom database configuration to {cls.CONFIG_FILE}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save database configuration: {e}")
            return False
    
    @classmethod
    def load_custom_config(cls) -> Optional[Dict[str, Any]]:
        """
        Load custom database configuration.
        
        Returns:
            Configuration dict or None if not found
        """
        try:
            if Path(cls.CONFIG_FILE).exists():
                with open(cls.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded custom database configuration from {cls.CONFIG_FILE}")
                return config
            return None
            
        except Exception as e:
            logger.error(f"Failed to load database configuration: {e}")
            return None
    
    @classmethod
    def delete_custom_config(cls) -> bool:
        """
        Delete custom database configuration.
        
        Returns:
            Success status
        """
        try:
            if Path(cls.CONFIG_FILE).exists():
                Path(cls.CONFIG_FILE).unlink()
                logger.info(f"Deleted custom database configuration file")
                return True
            return True  # Already doesn't exist
            
        except Exception as e:
            logger.error(f"Failed to delete database configuration: {e}")
            return False
    
    @classmethod
    def get_effective_database_url(cls) -> str:
        """
        Get the effective database URL (custom if exists, otherwise default).
        
        Returns:
            Database URL to use
        """
        custom_config = cls.load_custom_config()
        if custom_config and custom_config.get("custom_database_url"):
            return custom_config["custom_database_url"]
        
        # Fall back to environment or default
        from core.config import db_config
        return db_config.DATABASE_URL


def get_database_info_summary(database_url: str) -> Dict[str, Any]:
    """
    Get a summary of database information including connectivity status.
    
    Args:
        database_url: Database URL to check
        
    Returns:
        Summary information dict
    """
    tester = DatabaseConnectivityTester()
    connectivity = tester.test_connection(database_url)
    
    summary = {
        "url": database_url,
        "connectivity": connectivity,
        "is_custom": DatabaseConfigManager.load_custom_config() is not None,
        "config_file_exists": Path(DatabaseConfigManager.CONFIG_FILE).exists()
    }
    
    return summary
