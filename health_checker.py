"""
Health checker module for validating indicators against threat intelligence sources.
Implements secure API interactions and rate limiting.
"""

import asyncio
import aiohttp
import logging
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from urllib.parse import urljoin
import dns.resolver
import ipaddress
from dataclasses import dataclass

from config import security_config, HEALTH_CHECK_ENDPOINTS
from models import SessionLocal, Indicator, HealthCheck
from utils import RateLimiter, SecurityValidator

logger = logging.getLogger(__name__)

@dataclass
class HealthCheckResult:
    """Data class for health check results."""
    indicator_id: int
    check_type: str
    check_source: str
    status: str  # healthy, suspicious, malicious, error, unknown
    result: Dict[str, Any]
    confidence_score: int = 50

class IPHealthChecker:
    """Health checker for IP addresses."""
    
    def __init__(self, rate_limiter: RateLimiter):
        """Initialize IP health checker."""
        self.rate_limiter = rate_limiter
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
    
    async def check_ip_reputation(self, ip: str, api_key: Optional[str] = None) -> HealthCheckResult:
        """
        Check IP reputation using multiple sources.
        
        Args:
            ip: IP address to check
            api_key: Optional API key for enhanced checks
            
        Returns:
            HealthCheckResult object
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is private
            if ip_obj.is_private:
                return HealthCheckResult(
                    indicator_id=0,
                    check_type="reputation",
                    check_source="internal",
                    status="healthy",
                    result={"message": "Private IP address"},
                    confidence_score=100
                )
            
            # Perform DNS-based checks
            dns_results = await self._check_dns_reputation(ip)
            
            # Perform geolocation check
            geo_results = await self._check_ip_geolocation(ip)
            
            # Combine results
            combined_result = {
                "dns_checks": dns_results,
                "geolocation": geo_results,
                "timestamp": datetime.now().isoformat()
            }
            
            # Determine overall status
            status = self._determine_ip_status(dns_results, geo_results)
            confidence = self._calculate_confidence(dns_results, geo_results)
            
            return HealthCheckResult(
                indicator_id=0,
                check_type="reputation",
                check_source="multiple",
                status=status,
                result=combined_result,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"Error checking IP reputation for {ip}: {str(e)}")
            return HealthCheckResult(
                indicator_id=0,
                check_type="reputation",
                check_source="error",
                status="error",
                result={"error": str(e)},
                confidence_score=0
            )
    
    async def _check_dns_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP against DNS-based reputation lists."""
        reputation_lists = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "b.barracudacentral.org"
        ]
        
        results = {}
        
        # Reverse IP for DNS lookup
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
        except Exception:
            return {"error": "Invalid IP format"}
        
        for reputation_list in reputation_lists:
            try:
                query_host = f"{reversed_ip}.{reputation_list}"
                
                # Apply rate limiting
                await self.rate_limiter.acquire()
                
                # Perform DNS query
                try:
                    response = self.resolver.resolve(query_host, 'A')
                    results[reputation_list] = {
                        "listed": True,
                        "responses": [str(r) for r in response]
                    }
                except dns.resolver.NXDOMAIN:
                    results[reputation_list] = {"listed": False}
                except Exception as e:
                    results[reputation_list] = {"error": str(e)}
                    
            except Exception as e:
                results[reputation_list] = {"error": str(e)}
        
        return results
    
    async def _check_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Check IP geolocation for suspicious patterns."""
        try:
            # Simple geolocation check (in production, use a proper service)
            # This is a placeholder implementation
            return {
                "country": "unknown",
                "region": "unknown", 
                "city": "unknown",
                "suspicious_location": False
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _determine_ip_status(self, dns_results: Dict[str, Any], geo_results: Dict[str, Any]) -> str:
        """Determine overall IP status based on checks."""
        # Check if IP is listed in any reputation list
        listed_count = sum(1 for result in dns_results.values() 
                          if isinstance(result, dict) and result.get("listed", False))
        
        if listed_count >= 2:
            return "malicious"
        elif listed_count == 1:
            return "suspicious"
        else:
            return "healthy"
    
    def _calculate_confidence(self, dns_results: Dict[str, Any], geo_results: Dict[str, Any]) -> int:
        """Calculate confidence score based on available data."""
        # Simple confidence calculation
        total_checks = len(dns_results)
        successful_checks = sum(1 for result in dns_results.values() 
                               if isinstance(result, dict) and "error" not in result)
        
        if total_checks == 0:
            return 0
        
        return int((successful_checks / total_checks) * 100)

class DomainHealthChecker:
    """Health checker for domains."""
    
    def __init__(self, rate_limiter: RateLimiter):
        """Initialize domain health checker."""
        self.rate_limiter = rate_limiter
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
    
    async def check_domain_health(self, domain: str) -> HealthCheckResult:
        """
        Check domain health and reputation.
        
        Args:
            domain: Domain to check
            
        Returns:
            HealthCheckResult object
        """
        try:
            # Perform DNS resolution check
            dns_results = await self._check_dns_resolution(domain)
            
            # Check domain age and registration
            whois_results = await self._check_domain_registration(domain)
            
            # Check for suspicious patterns
            pattern_results = self._check_suspicious_patterns(domain)
            
            # Combine results
            combined_result = {
                "dns_resolution": dns_results,
                "registration": whois_results,
                "pattern_analysis": pattern_results,
                "timestamp": datetime.now().isoformat()
            }
            
            # Determine overall status
            status = self._determine_domain_status(dns_results, whois_results, pattern_results)
            confidence = self._calculate_domain_confidence(dns_results, whois_results, pattern_results)
            
            return HealthCheckResult(
                indicator_id=0,
                check_type="health",
                check_source="multiple",
                status=status,
                result=combined_result,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"Error checking domain health for {domain}: {str(e)}")
            return HealthCheckResult(
                indicator_id=0,
                check_type="health",
                check_source="error",
                status="error",
                result={"error": str(e)},
                confidence_score=0
            )
    
    async def _check_dns_resolution(self, domain: str) -> Dict[str, Any]:
        """Check if domain resolves and get DNS records."""
        results = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                await self.rate_limiter.acquire()
                
                response = self.resolver.resolve(domain, record_type)
                results[record_type] = [str(r) for r in response]
                
            except dns.resolver.NXDOMAIN:
                results[record_type] = None
            except Exception as e:
                results[record_type] = {"error": str(e)}
        
        # Check if domain is accessible
        results["resolvable"] = any(results.get(rt) for rt in ['A', 'AAAA'])
        
        return results
    
    async def _check_domain_registration(self, domain: str) -> Dict[str, Any]:
        """Check domain registration information."""
        # Placeholder for WHOIS functionality
        # In production, implement proper WHOIS lookup
        return {
            "age_days": "unknown",
            "registrar": "unknown",
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "recently_registered": False
        }
    
    def _check_suspicious_patterns(self, domain: str) -> Dict[str, Any]:
        """Check for suspicious patterns in domain name."""
        suspicious_indicators = []
        
        # Check for long domain names
        if len(domain) > 50:
            suspicious_indicators.append("long_domain_name")
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            suspicious_indicators.append("excessive_subdomains")
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'secure', 'update', 'verify', 'account', 'suspend',
            'confirm', 'login', 'bank', 'paypal', 'microsoft'
        ]
        
        domain_lower = domain.lower()
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                suspicious_indicators.append(f"suspicious_keyword_{keyword}")
        
        # Check for homograph attacks (basic check)
        suspicious_chars = ['xn--', 'ο', 'о', 'а', 'е', 'р', 'у']  # Common homograph chars
        for char in suspicious_chars:
            if char in domain_lower:
                suspicious_indicators.append("potential_homograph")
                break
        
        return {
            "suspicious_indicators": suspicious_indicators,
            "risk_score": len(suspicious_indicators)
        }
    
    def _determine_domain_status(self, dns_results: Dict[str, Any], 
                                whois_results: Dict[str, Any],
                                pattern_results: Dict[str, Any]) -> str:
        """Determine overall domain status."""
        risk_score = pattern_results.get("risk_score", 0)
        
        # If domain doesn't resolve, it might be suspicious
        if not dns_results.get("resolvable", False):
            return "suspicious"
        
        # High risk score indicates suspicious domain
        if risk_score >= 3:
            return "suspicious"
        elif risk_score >= 1:
            return "unknown"
        else:
            return "healthy"
    
    def _calculate_domain_confidence(self, dns_results: Dict[str, Any],
                                   whois_results: Dict[str, Any],
                                   pattern_results: Dict[str, Any]) -> int:
        """Calculate confidence score for domain check."""
        confidence = 50  # Base confidence
        
        # Increase confidence if DNS resolves successfully
        if dns_results.get("resolvable", False):
            confidence += 20
        
        # Adjust confidence based on pattern analysis
        risk_score = pattern_results.get("risk_score", 0)
        confidence -= (risk_score * 10)
        
        return max(0, min(100, confidence))

class UrlHealthChecker:
    """Health checker for URLs."""
    
    def __init__(self, rate_limiter: RateLimiter):
        """Initialize URL health checker."""
        self.rate_limiter = rate_limiter
        self.session_timeout = aiohttp.ClientTimeout(total=10)
    
    async def check_url_health(self, url: str) -> HealthCheckResult:
        """
        Check URL health and accessibility.
        
        Args:
            url: URL to check
            
        Returns:
            HealthCheckResult object
        """
        try:
            # Check URL accessibility
            accessibility_results = await self._check_url_accessibility(url)
            
            # Check for suspicious patterns
            pattern_results = self._check_url_patterns(url)
            
            # Combine results
            combined_result = {
                "accessibility": accessibility_results,
                "pattern_analysis": pattern_results,
                "timestamp": datetime.now().isoformat()
            }
            
            # Determine overall status
            status = self._determine_url_status(accessibility_results, pattern_results)
            confidence = self._calculate_url_confidence(accessibility_results, pattern_results)
            
            return HealthCheckResult(
                indicator_id=0,
                check_type="health",
                check_source="multiple",
                status=status,
                result=combined_result,
                confidence_score=confidence
            )
            
        except Exception as e:
            logger.error(f"Error checking URL health for {url}: {str(e)}")
            return HealthCheckResult(
                indicator_id=0,
                check_type="health",
                check_source="error",
                status="error",
                result={"error": str(e)},
                confidence_score=0
            )
    
    async def _check_url_accessibility(self, url: str) -> Dict[str, Any]:
        """Check if URL is accessible."""
        try:
            await self.rate_limiter.acquire()
            
            async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                async with session.head(url, allow_redirects=True) as response:
                    return {
                        "accessible": True,
                        "status_code": response.status,
                        "final_url": str(response.url),
                        "redirects": len(response.history),
                        "content_type": response.headers.get('content-type', 'unknown')
                    }
                    
        except Exception as e:
            return {
                "accessible": False,
                "error": str(e)
            }
    
    def _check_url_patterns(self, url: str) -> Dict[str, Any]:
        """Check for suspicious patterns in URL."""
        suspicious_indicators = []
        
        # Check for suspicious URL patterns
        suspicious_patterns = [
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Suspicious TLDs
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP-based URLs
            r'[a-zA-Z0-9]{20,}',  # Very long random strings
            r'bit\.ly|tinyurl|short',  # URL shorteners
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_indicators.append(f"pattern_{pattern}")
        
        # Check URL length
        if len(url) > 200:
            suspicious_indicators.append("excessive_length")
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'secure', 'update', 'verify', 'urgent', 'suspend',
            'confirm', 'login', 'download', 'free'
        ]
        
        url_lower = url.lower()
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                suspicious_indicators.append(f"suspicious_keyword_{keyword}")
        
        return {
            "suspicious_indicators": suspicious_indicators,
            "risk_score": len(suspicious_indicators)
        }
    
    def _determine_url_status(self, accessibility_results: Dict[str, Any],
                             pattern_results: Dict[str, Any]) -> str:
        """Determine overall URL status."""
        risk_score = pattern_results.get("risk_score", 0)
        
        # If URL is not accessible, it might be taken down
        if not accessibility_results.get("accessible", False):
            return "unknown"
        
        # High risk score indicates suspicious URL
        if risk_score >= 4:
            return "suspicious"
        elif risk_score >= 2:
            return "unknown"
        else:
            return "healthy"
    
    def _calculate_url_confidence(self, accessibility_results: Dict[str, Any],
                                 pattern_results: Dict[str, Any]) -> int:
        """Calculate confidence score for URL check."""
        confidence = 50  # Base confidence
        
        # Increase confidence if URL is accessible
        if accessibility_results.get("accessible", False):
            confidence += 20
        
        # Adjust confidence based on pattern analysis
        risk_score = pattern_results.get("risk_score", 0)
        confidence -= (risk_score * 5)
        
        return max(0, min(100, confidence))

class HealthCheckManager:
    """Main health check manager."""
    
    def __init__(self):
        """Initialize the health check manager."""
        self.rate_limiter = RateLimiter(
            max_requests=security_config.MAX_REQUESTS_PER_MINUTE,
            time_window=60
        )
        
        # Initialize checkers
        self.ip_checker = IPHealthChecker(self.rate_limiter)
        self.domain_checker = DomainHealthChecker(self.rate_limiter)
        self.url_checker = UrlHealthChecker(self.rate_limiter)
    
    async def check_indicator_health(self, indicator: Indicator) -> HealthCheckResult:
        """
        Check health of a single indicator.
        
        Args:
            indicator: Indicator object to check
            
        Returns:
            HealthCheckResult object
        """
        try:
            if indicator.indicator_type == 'ip':
                result = await self.ip_checker.check_ip_reputation(indicator.normalized_value)
            elif indicator.indicator_type == 'domain':
                result = await self.domain_checker.check_domain_health(indicator.normalized_value)
            elif indicator.indicator_type == 'url':
                result = await self.url_checker.check_url_health(indicator.normalized_value)
            else:
                # For hash and email, return a basic health check
                result = HealthCheckResult(
                    indicator_id=indicator.id,
                    check_type="basic",
                    check_source="internal",
                    status="healthy",
                    result={"message": f"No health check available for {indicator.indicator_type}"},
                    confidence_score=50
                )
            
            # Set the indicator ID
            result.indicator_id = indicator.id
            
            # Store health check result in database
            await self._store_health_check(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking indicator health {indicator.id}: {str(e)}")
            return HealthCheckResult(
                indicator_id=indicator.id,
                check_type="error",
                check_source="system",
                status="error",
                result={"error": str(e)},
                confidence_score=0
            )
    
    async def check_multiple_indicators(self, indicators: List[Indicator]) -> List[HealthCheckResult]:
        """
        Check health of multiple indicators concurrently.
        
        Args:
            indicators: List of Indicator objects to check
            
        Returns:
            List of HealthCheckResult objects
        """
        # Limit concurrency to prevent overwhelming external services
        semaphore = asyncio.Semaphore(5)
        
        async def check_with_semaphore(indicator):
            async with semaphore:
                return await self.check_indicator_health(indicator)
        
        # Run health checks concurrently
        tasks = [check_with_semaphore(indicator) for indicator in indicators]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log them
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Health check failed for indicator {indicators[i].id}: {str(result)}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    async def _store_health_check(self, result: HealthCheckResult) -> None:
        """Store health check result in database."""
        try:
            with SessionLocal() as session:
                health_check = HealthCheck(
                    indicator_id=result.indicator_id,
                    check_type=result.check_type,
                    check_source=result.check_source,
                    result=json.dumps(result.result),
                    status=result.status
                )
                
                session.add(health_check)
                session.commit()
                
                logger.debug(f"Stored health check result for indicator {result.indicator_id}")
                
        except Exception as e:
            logger.error(f"Error storing health check result: {str(e)}")
    
    def get_recent_health_checks(self, indicator_id: int, hours: int = 24) -> List[HealthCheck]:
        """
        Get recent health checks for an indicator.
        
        Args:
            indicator_id: ID of the indicator
            hours: Number of hours to look back
            
        Returns:
            List of recent HealthCheck objects
        """
        try:
            with SessionLocal() as session:
                cutoff_time = datetime.now() - timedelta(hours=hours)
                
                health_checks = session.query(HealthCheck).filter(
                    HealthCheck.indicator_id == indicator_id,
                    HealthCheck.checked_at >= cutoff_time
                ).order_by(HealthCheck.checked_at.desc()).all()
                
                return health_checks
                
        except Exception as e:
            logger.error(f"Error retrieving health checks: {str(e)}")
            return [] 