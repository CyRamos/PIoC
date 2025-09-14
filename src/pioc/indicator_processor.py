"""
Indicator processing module for the CTI application.
Handles file parsing, normalization, and validation with security measures.
"""

import re
import json
import csv
import xml.etree.ElementTree as ET
import hashlib
import logging
import ipaddress
import validators
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urlparse, urlunparse
import pandas as pd
from datetime import datetime

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.config import security_config, NORMALIZATION_PATTERNS, INDICATOR_TYPES
from src.pioc.models import SessionLocal, Indicator, IndicatorCreate
from src.pioc.utils import SecurityValidator, AuditLogger

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

class IndicatorNormalizer:
    """Handles indicator normalization and defanging."""
    
    def __init__(self):
        """Initialize the normalizer with patterns."""
        self.patterns = NORMALIZATION_PATTERNS
        
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL indicators by removing defanging.
        
        Args:
            url: Raw URL string
            
        Returns:
            Normalized URL string
            
        Raises:
            ValueError: If URL is invalid after normalization
        """
        try:
            # Apply defanging patterns
            normalized = url.lower().strip()
            for pattern, replacement in self.patterns["defang_url"]:
                normalized = re.sub(pattern, replacement, normalized)
            
            # Ensure URL has a scheme
            if not normalized.startswith(('http://', 'https://')):
                normalized = 'http://' + normalized
            
            # Parse and reconstruct URL for consistency
            parsed = urlparse(normalized)
            if not parsed.netloc:
                raise ValueError(f"Invalid URL structure: {url}")
            
            # Normalize domain part
            normalized_netloc = parsed.netloc.lower()
            reconstructed = urlunparse(parsed._replace(netloc=normalized_netloc))
            
            logger.debug(f"Normalized URL: {url} -> {reconstructed}")
            return reconstructed
            
        except Exception as e:
            logger.error(f"Error normalizing URL {url}: {str(e)}")
            raise ValueError(f"Failed to normalize URL: {url}")
    
    def normalize_ip(self, ip: str) -> str:
        """
        Normalize IP address indicators.
        
        Args:
            ip: Raw IP string
            
        Returns:
            Normalized IP string
            
        Raises:
            ValueError: If IP is invalid
        """
        try:
            # Apply defanging patterns
            normalized = ip.strip()
            for pattern, replacement in self.patterns["defang_ip"]:
                normalized = re.sub(pattern, replacement, normalized)
            
            # Validate IP address
            ip_obj = ipaddress.ip_address(normalized)
            result = str(ip_obj)
            
            logger.debug(f"Normalized IP: {ip} -> {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error normalizing IP {ip}: {str(e)}")
            raise ValueError(f"Invalid IP address: {ip}")
    
    def normalize_domain(self, domain: str) -> str:
        """
        Normalize domain indicators.
        
        Args:
            domain: Raw domain string
            
        Returns:
            Normalized domain string
            
        Raises:
            ValueError: If domain is invalid
        """
        try:
            # Apply defanging patterns
            normalized = domain.lower().strip()
            for pattern, replacement in self.patterns["defang_domain"]:
                normalized = re.sub(pattern, replacement, normalized)
            
            # Remove protocol if present
            if normalized.startswith(('http://', 'https://')):
                normalized = urlparse(normalized).netloc
            
            # Basic domain validation
            if not validators.domain(normalized):
                raise ValueError(f"Invalid domain format: {domain}")
            
            logger.debug(f"Normalized domain: {domain} -> {normalized}")
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing domain {domain}: {str(e)}")
            raise ValueError(f"Invalid domain: {domain}")
    
    def normalize_hash(self, hash_value: str) -> str:
        """
        Normalize hash indicators.
        
        Args:
            hash_value: Raw hash string
            
        Returns:
            Normalized hash string
            
        Raises:
            ValueError: If hash is invalid
        """
        try:
            normalized = hash_value.lower().strip()
            
            # Validate hash length and format
            if len(normalized) not in [32, 40, 64]:  # MD5, SHA1, SHA256
                raise ValueError(f"Invalid hash length: {len(normalized)}")
            
            if not re.match(r'^[a-f0-9]+$', normalized):
                raise ValueError(f"Invalid hash format: {hash_value}")
            
            logger.debug(f"Normalized hash: {hash_value} -> {normalized}")
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing hash {hash_value}: {str(e)}")
            raise ValueError(f"Invalid hash: {hash_value}")
    
    def normalize_email(self, email: str) -> str:
        """
        Normalize email indicators.
        
        Args:
            email: Raw email string
            
        Returns:
            Normalized email string
            
        Raises:
            ValueError: If email is invalid
        """
        try:
            normalized = email.lower().strip()
            
            # Apply defanging patterns for domain part
            if '@' in normalized:
                local, domain = normalized.split('@', 1)
                for pattern, replacement in self.patterns["defang_domain"]:
                    domain = re.sub(pattern, replacement, domain)
                normalized = f"{local}@{domain}"
            
            # Validate email format
            if not validators.email(normalized):
                raise ValueError(f"Invalid email format: {email}")
            
            logger.debug(f"Normalized email: {email} -> {normalized}")
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing email {email}: {str(e)}")
            raise ValueError(f"Invalid email: {email}")

class IndicatorClassifier:
    """Classifies and validates indicators."""
    
    def __init__(self):
        """Initialize the classifier with patterns."""
        self.url_pattern = re.compile(
            r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$',
            re.IGNORECASE
        )
        self.ip_pattern = re.compile(
            r'^(\d{1,3}[.,|\[\]]\d{1,3}[.,|\[\]]\d{1,3}[.,|\[\]]\d{1,3})$'
        )
        self.hash_pattern = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        self.domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
    
    def classify_indicator(self, value: str) -> Optional[str]:
        """
        Classify an indicator based on its pattern.
        Handles both normal and defanged indicators.
        
        Args:
            value: Indicator value to classify
            
        Returns:
            Indicator type string or None if unrecognized
        """
        value = value.strip()
        
        # Check for hash first (most specific)
        if self.hash_pattern.match(value):
            return 'hash'
        
        # Check for defanged/normal URLs first (most complex)
        if (value.startswith(('http://', 'https://', 'hxxp://', 'hxxps://')) or 
            'hxxp://' in value or 'hxxps://' in value or
            re.search(r'https?://.*\[.\].*', value) or
            re.search(r'hxxps?://.*\[.\].*', value)):
            return 'url'
        
        # Check for defanged IP addresses
        if (re.search(r'\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}', value) or
            re.search(r'\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}', value) or
            self.ip_pattern.match(value)):
            return 'ip'
        
        # Check for defanged domains
        if (re.search(r'[a-zA-Z0-9-]+\[.\][a-zA-Z0-9.-]+\[.\][a-zA-Z]{2,}', value) or
            re.search(r'[a-zA-Z0-9-]+\[\.\][a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,}', value) or
            self.domain_pattern.match(value)):
            return 'domain'
        
        # Check for defanged emails
        if (re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*\[.\][a-zA-Z0-9.-]*\[.\][a-zA-Z]{2,}', value) or
            re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*\[\.\][a-zA-Z0-9.-]*\[\.\][a-zA-Z]{2,}', value) or
            self.email_pattern.match(value)):
            return 'email'
        
        return None

class FileProcessor:
    """Handles secure file processing with validation."""
    
    def __init__(self):
        """Initialize the file processor with security validator."""
        self.security_validator = SecurityValidator()
        self.max_file_size = security_config.MAX_FILE_SIZE_MB * 1024 * 1024
        self.allowed_extensions = security_config.ALLOWED_FILE_EXTENSIONS
    
    def validate_file(self, file_path: Path) -> bool:
        """
        Validate file for security and size constraints.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            True if file is valid
            
        Raises:
            ValueError: If file validation fails
        """
        # Check file existence
        if not file_path.exists():
            raise ValueError(f"File does not exist: {file_path}")
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(f"File too large: {file_size} bytes (max: {self.max_file_size})")
        
        # Check file extension
        if file_path.suffix.lower() not in self.allowed_extensions:
            raise ValueError(f"File extension not allowed: {file_path.suffix}")
        
        # Basic content validation
        if not self.security_validator.validate_file_content(file_path):
            raise ValueError(f"File content validation failed: {file_path}")
        
        return True
    
    def read_csv(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Read and parse CSV file securely.
        
        Args:
            file_path: Path to CSV file
            
        Returns:
            List of dictionaries containing row data
        """
        self.validate_file(file_path)
        
        try:
            # Use pandas for robust CSV parsing
            df = pd.read_csv(file_path, encoding='utf-8')
            
            # Convert to list of dictionaries
            return df.to_dict('records')
            
        except Exception as e:
            logger.error(f"Error reading CSV file {file_path}: {str(e)}")
            raise ValueError(f"Failed to read CSV file: {str(e)}")
    
    def read_json(self, file_path: Path) -> Dict[str, Any]:
        """
        Read and parse JSON file securely.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Dictionary containing JSON data
        """
        self.validate_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Validate JSON content size
            if len(content) > self.max_file_size:
                raise ValueError("JSON content too large")
            
            return json.loads(content)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path}: {str(e)}")
            raise ValueError(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            logger.error(f"Error reading JSON file {file_path}: {str(e)}")
            raise ValueError(f"Failed to read JSON file: {str(e)}")
    
    def read_text(self, file_path: Path) -> str:
        """
        Read text file securely.
        
        Args:
            file_path: Path to text file
            
        Returns:
            File content as string
        """
        self.validate_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Validate content size
            if len(content) > self.max_file_size:
                raise ValueError("Text content too large")
            
            return content
            
        except Exception as e:
            logger.error(f"Error reading text file {file_path}: {str(e)}")
            raise ValueError(f"Failed to read text file: {str(e)}")

class IndicatorProcessor:
    """Main indicator processing class."""
    
    def __init__(self):
        """Initialize the indicator processor."""
        self.normalizer = IndicatorNormalizer()
        self.classifier = IndicatorClassifier()
        self.file_processor = FileProcessor()
        self.audit_logger = AuditLogger()
    
    def process_file(self, file_path: Path, source_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a file containing indicators with diff functionality.
        
        Args:
            file_path: Path to the file to process
            source_name: Optional source name for tracking
            
        Returns:
            Dictionary containing processing results with diff information
        """
        try:
            start_time = datetime.now()
            file_extension = file_path.suffix.lower()
            
            # Read file based on extension
            if file_extension == '.csv':
                raw_data = self.file_processor.read_csv(file_path)
                indicators = self._extract_indicators_from_csv(raw_data)
            elif file_extension == '.json':
                raw_data = self.file_processor.read_json(file_path)
                indicators = self._extract_indicators_from_json(raw_data)
            elif file_extension in ['.txt', '.xml']:
                raw_content = self.file_processor.read_text(file_path)
                indicators = self._extract_indicators_from_text(raw_content)
            else:
                raise ValueError(f"Unsupported file type: {file_extension}")
            
            # Process and normalize indicators with diff tracking
            processed_results = self._process_indicators_with_diff(
                indicators, source_name or file_path.name
            )
            
            # Store new indicators in database
            stored_count = self._store_new_indicators(processed_results['new_indicators'])
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            result = {
                'file_path': str(file_path),
                'source_name': source_name or file_path.name,
                'total_indicators': len(indicators),
                'processed_indicators': len(processed_results['all_processed']),
                'new_indicators': processed_results['new_indicators'],
                'existing_indicators': processed_results['existing_indicators'],
                'duplicate_indicators': processed_results['duplicate_indicators'],
                'invalid_indicators': processed_results['invalid_indicators'],
                'stored_indicators': stored_count,
                'processing_time_seconds': processing_time,
                'diff_summary': {
                    'total_found': len(indicators),
                    'new_count': len(processed_results['new_indicators']),
                    'existing_count': len(processed_results['existing_indicators']),
                    'duplicate_count': len(processed_results['duplicate_indicators']),
                    'invalid_count': len(processed_results['invalid_indicators'])
                },
                'success': True
            }
            
            # Log audit event
            self.audit_logger.log_event(
                user_id="system",
                action="file_processed",
                resource_type="file",
                resource_id=str(file_path),
                details={
                    'source': source_name or file_path.name,
                    'diff_summary': result['diff_summary']
                }
            )
            
            logger.info(f"Successfully processed file {file_path}: {result['diff_summary']}")
            return result
            
        except Exception as e:
            error_result = {
                'file_path': str(file_path),
                'error': str(e),
                'success': False
            }
            logger.error(f"Error processing file {file_path}: {str(e)}")
            return error_result
    
    def _extract_indicators_from_csv(self, data: List[Dict[str, Any]]) -> List[str]:
        """Extract indicators from CSV data."""
        indicators = []
        
        for row in data:
            for key, value in row.items():
                if value and isinstance(value, str):
                    value = value.strip()
                    if not value:
                        continue
                        
                    # Skip obvious non-indicator columns
                    skip_columns = ['reportby', 'reportid', 'title', 'tlp', 'publishdate', 
                                  'email(s)', 'filename', 'fileidentifier', 'reliability', 
                                  'description', 'version', 'confidence', 'source']
                    
                    if key.lower() in skip_columns:
                        continue
                    
                    # Extract from all potential indicator columns
                    # This includes: IP, domain, url, hash, registry, filePath, md5, sha1, sha256, etc.
                    if (len(value) > 3 and  # Skip very short values
                        not value.lower() in ['suspected', 'confirmed', 'unknown', 'high', 'medium', 'low']):
                        indicators.append(value)
        
        return indicators
    
    def _extract_indicators_from_json(self, data: Dict[str, Any]) -> List[str]:
        """Extract indicators from JSON data."""
        indicators = []
        
        def extract_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, str) and value.strip():
                        # Look for common IoC keys
                        if any(term in key.lower() for term in ['ip', 'domain', 'url', 'hash', 'email', 'ioc', 'indicator']):
                            indicators.append(value.strip())
                    elif isinstance(value, (dict, list)):
                        extract_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_recursive(item)
        
        extract_recursive(data)
        return indicators
    
    def _extract_indicators_from_text(self, content: str) -> List[str]:
        """Extract indicators from text content."""
        indicators = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):  # Skip comments
                # Split line by common delimiters
                potential_indicators = re.split(r'[,;\s\t]+', line)
                for indicator in potential_indicators:
                    indicator = indicator.strip()
                    if indicator:
                        indicators.append(indicator)
        
        return indicators
    
    def _process_indicators_with_diff(self, indicators: List[str], source_name: str) -> Dict[str, List]:
        """
        Process indicators and categorize them as new, existing, duplicate, or invalid.
        
        Args:
            indicators: List of raw indicator strings
            source_name: Source name for tracking
            
        Returns:
            Dictionary with categorized indicators
        """
        results = {
            'all_processed': [],
            'new_indicators': [],
            'existing_indicators': [],
            'duplicate_indicators': [],
            'invalid_indicators': []
        }
        
        seen_in_file = set()  # Track duplicates within the same file
        
        with SessionLocal() as session:
            for raw_indicator in indicators:
                try:
                    # Process single indicator
                    processed = self._process_single_indicator(raw_indicator, source_name)
                    
                    if not processed['success']:
                        results['invalid_indicators'].append({
                            'value': raw_indicator,
                            'reason': processed['error_reason']
                        })
                        continue
                    
                    normalized_value = processed['normalized_value']
                    indicator_type = processed['indicator_type']
                    
                    # Check for duplicates within the same file
                    file_key = f"{indicator_type}:{normalized_value}"
                    if file_key in seen_in_file:
                        results['duplicate_indicators'].append({
                            'value': raw_indicator,
                            'normalized_value': normalized_value,
                            'type': indicator_type,
                            'reason': 'Duplicate in file'
                        })
                        continue
                    
                    seen_in_file.add(file_key)
                    
                    # Check if indicator exists in database
                    existing = session.query(Indicator).filter_by(
                        indicator_type=indicator_type,
                        normalized_value=normalized_value
                    ).first()
                    
                    processed_indicator = {
                        'value': raw_indicator,
                        'normalized_value': normalized_value,
                        'type': indicator_type,
                        'source_file': source_name,
                        'processed_data': {
                            'indicator_type': indicator_type,
                            'value': raw_indicator,
                            'normalized_value': normalized_value,
                            'source_file': source_name
                        }
                    }
                    
                    if existing:
                        processed_indicator.update({
                            'existing_id': existing.id,
                            'first_seen': existing.first_seen.isoformat(),
                            'last_seen': existing.last_seen.isoformat(),
                            'existing_source': existing.source_file,
                            'confidence_score': existing.confidence_score
                        })
                        results['existing_indicators'].append(processed_indicator)
                    else:
                        results['new_indicators'].append(processed_indicator)
                    
                    results['all_processed'].append(processed_indicator)
                    
                except Exception as e:
                    logger.warning(f"Failed to process indicator {raw_indicator}: {str(e)}")
                    results['invalid_indicators'].append({
                        'value': raw_indicator,
                        'reason': str(e)
                    })
                    continue
        
        return results
    
    def _store_new_indicators(self, new_indicators: List[Dict[str, Any]]) -> int:
        """Store only new indicators in database."""
        stored_count = 0
        
        with SessionLocal() as session:
            try:
                for indicator_data in new_indicators:
                    processed = indicator_data['processed_data']
                    
                    new_indicator = Indicator(
                        indicator_type=processed['indicator_type'],
                        value=processed['value'],
                        normalized_value=processed['normalized_value'],
                        source_file=processed['source_file']
                    )
                    session.add(new_indicator)
                    stored_count += 1
                    logger.debug(f"Added new indicator: {processed['normalized_value']}")
                
                session.commit()
                logger.info(f"Successfully stored {stored_count} new indicators")
                
            except Exception as e:
                session.rollback()
                logger.error(f"Error storing indicators: {str(e)}")
                raise
        
        return stored_count
    
    def get_indicators_by_source(self, source_names: List[str] = None, 
                                only_new: bool = False, 
                                date_from: datetime = None) -> List[Dict[str, Any]]:
        """
        Get indicators filtered by source with optional filtering.
        
        Args:
            source_names: List of source names to filter by
            only_new: If True, only return indicators added after date_from
            date_from: Date threshold for 'new' indicators
            
        Returns:
            List of indicator dictionaries
        """
        with SessionLocal() as session:
            query = session.query(Indicator)
            
            if source_names:
                query = query.filter(Indicator.source_file.in_(source_names))
            
            if only_new and date_from:
                query = query.filter(Indicator.first_seen >= date_from)
            
            indicators = query.all()
            
            result = []
            for indicator in indicators:
                result.append({
                    'id': indicator.id,
                    'type': indicator.indicator_type,
                    'value': indicator.value,
                    'normalized_value': indicator.normalized_value,
                    'source_file': indicator.source_file,
                    'first_seen': indicator.first_seen.isoformat(),
                    'last_seen': indicator.last_seen.isoformat(),
                    'confidence_score': indicator.confidence_score,
                    'tlp_level': indicator.tlp_level,
                    'is_active': indicator.is_active
                })
            
            return result
    
    def export_indicators_to_csv(self, indicators: List[Dict[str, Any]], 
                                export_path: Path) -> str:
        """
        Export indicators to CSV format.
        
        Args:
            indicators: List of indicator dictionaries
            export_path: Path to save the CSV file
            
        Returns:
            Path to the exported file
        """
        import csv
        
        if not indicators:
            raise ValueError("No indicators to export")
        
        # Ensure export directory exists
        export_path.parent.mkdir(exist_ok=True)
        
        with open(export_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'type', 'value', 'normalized_value', 'source_file',
                'first_seen', 'last_seen', 'confidence_score', 'tlp_level'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for indicator in indicators:
                writer.writerow({
                    'type': indicator.get('type', ''),
                    'value': indicator.get('value', ''),
                    'normalized_value': indicator.get('normalized_value', ''),
                    'source_file': indicator.get('source_file', ''),
                    'first_seen': indicator.get('first_seen', ''),
                    'last_seen': indicator.get('last_seen', ''),
                    'confidence_score': indicator.get('confidence_score', ''),
                    'tlp_level': indicator.get('tlp_level', '')
                })
        
        logger.info(f"Exported {len(indicators)} indicators to {export_path}")
        return str(export_path)
    
    def export_indicators_to_json(self, indicators: List[Dict[str, Any]], 
                                 export_path: Path) -> str:
        """
        Export indicators to JSON format.
        
        Args:
            indicators: List of indicator dictionaries
            export_path: Path to save the JSON file
            
        Returns:
            Path to the exported file
        """
        if not indicators:
            raise ValueError("No indicators to export")
        
        # Ensure export directory exists
        export_path.parent.mkdir(exist_ok=True)
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'total_indicators': len(indicators),
                'format': 'PloC Platform Export'
            },
            'indicators': indicators
        }
        
        with open(export_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(indicators)} indicators to {export_path}")
        return str(export_path)
    
    def _process_single_indicator(self, value: str, source_name: str) -> Dict[str, Any]:
        """Process a single indicator and return result with detailed error info."""
        result = {
            'indicator_type': None,
            'value': value,
            'normalized_value': None,
            'source_file': source_name,
            'success': False,
            'error_reason': None
        }
        
        # Input validation
        if not value or not value.strip():
            result['error_reason'] = "Empty or whitespace-only value"
            return result
            
        cleaned_value = value.strip()
        
        # Check for suspicious patterns that might indicate metadata
        if any(keyword in cleaned_value.lower() for keyword in ['header', 'column', 'field', 'type', 'name']):
            result['error_reason'] = "Appears to be metadata/header rather than indicator"
            return result
        
        # Classify indicator
        indicator_type = self.classifier.classify_indicator(cleaned_value)
        if not indicator_type:
            # Provide specific classification failure reasons
            if len(cleaned_value) < 3:
                result['error_reason'] = "Value too short to be a valid indicator"
            elif len(cleaned_value) > 500:
                result['error_reason'] = "Value too long to be a valid indicator"
            elif cleaned_value.isdigit():
                result['error_reason'] = "Pure numeric value - not a recognized indicator type"
            elif '://' in cleaned_value and not cleaned_value.startswith(('http', 'https', 'ftp')):
                result['error_reason'] = "Unrecognized URL protocol"
            elif '@' in cleaned_value and cleaned_value.count('@') > 1:
                result['error_reason'] = "Invalid email format - multiple @ symbols"
            elif '.' in cleaned_value and cleaned_value.count('.') > 10:
                result['error_reason'] = "Too many dots - likely not a valid domain or IP"
            elif any(char in cleaned_value for char in '<>|"\'`'):
                result['error_reason'] = "Contains invalid characters for any indicator type"
            else:
                result['error_reason'] = "Could not match to any known indicator type (IP, domain, URL, hash, email)"
            
            logger.debug(f"Could not classify indicator: {cleaned_value} - {result['error_reason']}")
            return result
        
        result['indicator_type'] = indicator_type
        
        # Normalize indicator with specific error handling
        try:
            if indicator_type == 'url':
                normalized_value = self.normalizer.normalize_url(cleaned_value)
            elif indicator_type == 'ip':
                normalized_value = self.normalizer.normalize_ip(cleaned_value)
            elif indicator_type == 'domain':
                normalized_value = self.normalizer.normalize_domain(cleaned_value)
            elif indicator_type == 'hash':
                normalized_value = self.normalizer.normalize_hash(cleaned_value)
            elif indicator_type == 'email':
                normalized_value = self.normalizer.normalize_email(cleaned_value)
            else:
                result['error_reason'] = f"Unsupported indicator type: {indicator_type}"
                return result
                
            result['normalized_value'] = normalized_value
            result['success'] = True
            return result
                
        except ValueError as e:
            # Enhanced error reporting for normalization failures
            error_msg = str(e).lower()
            if 'invalid ip' in error_msg or 'invalid address' in error_msg:
                result['error_reason'] = f"Invalid IP address format: {str(e)}"
            elif 'invalid domain' in error_msg or 'invalid hostname' in error_msg:
                result['error_reason'] = f"Invalid domain format: {str(e)}"
            elif 'invalid url' in error_msg or 'invalid scheme' in error_msg:
                result['error_reason'] = f"Invalid URL format: {str(e)}"
            elif 'invalid hash' in error_msg:
                result['error_reason'] = f"Invalid hash format: {str(e)}"
            elif 'invalid email' in error_msg:
                result['error_reason'] = f"Invalid email format: {str(e)}"
            else:
                result['error_reason'] = f"Normalization failed: {str(e)}"
            
            logger.warning(f"Failed to normalize {indicator_type} indicator {cleaned_value}: {result['error_reason']}")
            return result
        
        except Exception as e:
            result['error_reason'] = f"Unexpected error during normalization: {str(e)}"
            logger.error(f"Unexpected error processing indicator {cleaned_value}: {str(e)}")
            return result 