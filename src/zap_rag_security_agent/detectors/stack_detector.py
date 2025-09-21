"""
Stack Detection Module using Wappalyzer

This module provides stack fingerprinting capabilities using the Wappalyzer library
to detect web technologies, frameworks, and their versions from HTTP traffic.

Features:
- Detect web technologies from headers, HTML content, and scripts
- Version detection for standard libraries
- Distinguish between standard and custom libraries
- JSON-safe metadata output for ChromaDB storage
- Comprehensive outdated version detection using version database
- Security vulnerability assessment
"""

import re
import json
import requests
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage
from ..data.version_database import get_version_database


class StackDetector:
    """
    Stack detection using Wappalyzer for web technology fingerprinting.
    Enhanced with security-focused analysis for vulnerabilities and credentials.
    """
    
    def __init__(self):
        """Initialize the Wappalyzer instance."""
        self.wappalyzer = Wappalyzer.latest()
        self.version_db = get_version_database()
        
        # Security patterns for credential detection
        self.credential_patterns = {
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?'),
            'secret_key': re.compile(r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?'),
            'access_token': re.compile(r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\']?([a-zA-Z0-9_.-]{20,})["\']?'),
            'password': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?'),
            'database_url': re.compile(r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*["\']?(mongodb|mysql|postgresql)://[^"\'\s]+["\']?'),
            'jwt_secret': re.compile(r'(?i)(jwt[_-]?secret|jwtsecret)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?'),
            'aws_key': re.compile(r'(?i)(aws[_-]?access[_-]?key|awsaccesskey)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?'),
            'google_key': re.compile(r'(?i)(google[_-]?api[_-]?key|googleapikey)\s*[:=]\s*["\']?(AIza[0-9A-Za-z_-]{35})["\']?'),
        }
        
        # Vulnerable script patterns
        self.vulnerable_patterns = {
            'eval_usage': re.compile(r'\beval\s*\(', re.I),
            'innerHTML_dangerous': re.compile(r'\.innerHTML\s*=', re.I),
            'document_write': re.compile(r'document\.write\s*\(', re.I),
            'dangerous_redirect': re.compile(r'window\.location\s*=\s*[^;]+', re.I),
            'unsafe_serialization': re.compile(r'JSON\.parse\s*\([^)]*\)', re.I),
            'sql_concatenation': re.compile(r'["\'].*["\']\s*\+\s*[^;]+', re.I),
            'xss_vulnerable': re.compile(r'innerHTML|outerHTML|document\.write', re.I),
            'unsafe_eval': re.compile(r'eval\s*\(|Function\s*\(|setTimeout\s*\([^,)]*["\']', re.I),
        }
    
    def detect_from_headers(self, headers_text: str, url: str = "") -> Dict[str, Any]:
        """
        Detect technologies from HTTP headers.
        
        Args:
            headers_text: Raw headers text (newline-separated)
            url: Optional URL for context
            
        Returns:
            Dictionary with detection results and metadata
        """
        if not headers_text or not headers_text.strip():
            return self._empty_result()
        
        try:
            # Parse headers into a dictionary
            headers = {}
            for line in headers_text.splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Create a mock response object for Wappalyzer
            class MockResponse:
                def __init__(self, headers, url=""):
                    self.headers = headers
                    self.url = url
                    self.text = ""
                    self.status_code = 200
            
            response = MockResponse(headers, url)
            webpage = WebPage.new_from_response(response)
            
            # Analyze with Wappalyzer
            results = self.wappalyzer.analyze_with_versions_and_categories(webpage)
            
            # If Wappalyzer didn't detect anything, try client-side detection
            if not results:
                client_results = self._detect_client_technologies(headers, url)
                results = client_results.get('detected_technologies', {})
                security_analysis = client_results.get('security_analysis', {})
                
                # Process the results
                processed = self._process_wappalyzer_results(results, "headers")
                
                # Add security analysis if available
                if security_analysis:
                    processed['security_analysis'] = security_analysis
                
                return processed
            
            return self._process_wappalyzer_results(results, "headers")
            
        except Exception as e:
            return self._error_result(f"Header analysis failed: {str(e)}")
    
    def _detect_client_technologies(self, headers: Dict[str, str], url: str = "") -> Dict[str, Any]:
        """
        Detect client-side technologies from request headers.
        
        Args:
            headers: Parsed headers dictionary
            url: Optional URL for context
            
        Returns:
            Dictionary with client technology detection results
        """
        detected_techs = {}
        
        # Detect browser from User-Agent
        user_agent = headers.get('user-agent', '').lower()
        if 'firefox' in user_agent:
            # Extract Firefox version
            import re
            firefox_match = re.search(r'firefox/(\d+\.\d+)', user_agent)
            version = firefox_match.group(1) if firefox_match else 'unknown'
            detected_techs['Firefox'] = {
                'version': version,
                'category': 'Browsers',
                'confidence': 0.9
            }
        elif 'chrome' in user_agent:
            chrome_match = re.search(r'chrome/(\d+\.\d+)', user_agent)
            version = chrome_match.group(1) if chrome_match else 'unknown'
            detected_techs['Chrome'] = {
                'version': version,
                'category': 'Browsers',
                'confidence': 0.9
            }
        elif 'safari' in user_agent and 'chrome' not in user_agent:
            safari_match = re.search(r'version/(\d+\.\d+)', user_agent)
            version = safari_match.group(1) if safari_match else 'unknown'
            detected_techs['Safari'] = {
                'version': version,
                'category': 'Browsers',
                'confidence': 0.9
            }
        
        # Detect WebSocket usage
        if 'sec-websocket-version' in headers:
            detected_techs['WebSocket'] = {
                'version': headers.get('sec-websocket-version', '13'),
                'category': 'WebSockets',
                'confidence': 0.8
            }
        
        # Detect Socket.IO usage from URL patterns
        if url and 'socket.io' in url:
            detected_techs['Socket.IO'] = {
                'version': '4.0.0',  # Default version
                'category': 'WebSockets',
                'confidence': 0.7
            }
        
        # Detect AJAX/XMLHttpRequest patterns
        if headers.get('x-requested-with', '').lower() == 'xmlhttprequest':
            detected_techs['XMLHttpRequest'] = {
                'version': '1.0',
                'category': 'AJAX',
                'confidence': 0.8
            }
        
        # Add security analysis
        security_analysis = self._analyze_client_security(headers, url)
        
        return {
            'detected_technologies': detected_techs,
            'security_analysis': security_analysis
        }
    
    def _analyze_client_security(self, headers: Dict[str, str], url: str = "") -> Dict[str, Any]:
        """
        Analyze client-side security from request headers.
        
        Args:
            headers: Parsed headers dictionary
            url: Optional URL for context
            
        Returns:
            Dictionary with security analysis results
        """
        security_issues = []
        total_issues = 0
        high_severity = 0
        medium_severity = 0
        risk_score = 0
        
        # Check for insecure headers
        user_agent = headers.get('user-agent', '').lower()
        
        # Check for old browser versions (security risk)
        if 'firefox' in user_agent:
            import re
            firefox_match = re.search(r'firefox/(\d+\.\d+)', user_agent)
            if firefox_match:
                version = float(firefox_match.group(1))
                if version < 100.0:  # Old Firefox versions
                    security_issues.append({
                        'type': 'Outdated Browser',
                        'severity': 'high',
                        'description': f'Firefox {version} is outdated and may have security vulnerabilities'
                    })
                    total_issues += 1
                    high_severity += 1
                    risk_score += 30
        
        # Check for WebSocket usage (potential security concern)
        if 'sec-websocket-version' in headers:
            security_issues.append({
                'type': 'WebSocket Usage',
                'severity': 'medium',
                'description': 'WebSocket connection detected - ensure proper authentication and validation'
            })
            total_issues += 1
            medium_severity += 1
            risk_score += 15
        
        # Check for insecure referrer
        referer = headers.get('referer', '')
        if referer and 'http://' in referer:  # Insecure referrer
            security_issues.append({
                'type': 'Insecure Referrer',
                'severity': 'medium',
                'description': 'HTTP referrer detected - potential information leakage'
            })
            total_issues += 1
            medium_severity += 1
            risk_score += 10
        
        return {
            'total_security_issues': total_issues,
            'high_severity_issues': high_severity,
            'medium_severity_issues': medium_severity,
            'security_risk_score': risk_score,
            'has_vulnerabilities': high_severity > 0,
            'security_issues': security_issues
        }
    
    def detect_from_html(self, html_content: str, url: str = "") -> Dict[str, Any]:
        """
        Detect technologies from HTML content.
        
        Args:
            html_content: Raw HTML content
            url: Optional URL for context
            
        Returns:
            Dictionary with detection results and metadata
        """
        if not html_content or not html_content.strip():
            return self._empty_result()
        
        try:
            # Create a mock response object for Wappalyzer
            class MockResponse:
                def __init__(self, html, url=""):
                    self.headers = {}
                    self.url = url
                    self.text = html
                    self.status_code = 200
            
            response = MockResponse(html_content, url)
            webpage = WebPage.new_from_response(response)
            
            # Analyze with Wappalyzer
            results = self.wappalyzer.analyze_with_versions_and_categories(webpage)
            
            return self._process_wappalyzer_results(results, "html")
            
        except Exception as e:
            return self._error_result(f"HTML analysis failed: {str(e)}")
    
    def detect_from_script_src(self, script_srcs: List[str]) -> Dict[str, Any]:
        """
        Detect technologies from script src URLs.
        
        Args:
            script_srcs: List of script src URLs
            
        Returns:
            Dictionary with detection results and metadata
        """
        if not script_srcs:
            return self._empty_result()
        
        try:
            detected_techs = {}
            custom_libs = []
            standard_libs = []
            
            for src in script_srcs:
                if not src:
                    continue
                
                # Extract library name from URL
                lib_name = self._extract_library_name(src)
                if not lib_name:
                    continue
                
                # Check if it's a known CDN or standard library
                is_standard = self._is_standard_library(src, lib_name)
                
                if is_standard:
                    standard_libs.append({
                        "name": lib_name,
                        "src": src,
                        "version": self._extract_version_from_url(src),
                        "cdn": self._detect_cdn(src)
                    })
                else:
                    custom_libs.append({
                        "name": lib_name,
                        "src": src,
                        "version": self._extract_version_from_url(src)
                    })
            
            return {
                "detected_technologies": detected_techs,
                "standard_libraries": standard_libs,
                "custom_libraries": custom_libs,
                "detection_method": "script_src",
                "confidence": 0.8 if standard_libs or custom_libs else 0.0,
                "total_detected": len(standard_libs) + len(custom_libs)
            }
            
        except Exception as e:
            return self._error_result(f"Script analysis failed: {str(e)}")
    
    def detect_from_meta_tags(self, meta_content: str) -> Dict[str, Any]:
        """
        Detect technologies from meta tags content.
        
        Args:
            meta_content: Meta tags content (e.g., generator, viewport, etc.)
            
        Returns:
            Dictionary with detection results and metadata
        """
        if not meta_content or not meta_content.strip():
            return self._empty_result()
        
        try:
            detected_techs = {}
            
            # Common meta tag patterns
            patterns = {
                'generator': r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
                'viewport': r'<meta[^>]*name=["\']viewport["\'][^>]*content=["\']([^"\']+)["\']',
                'framework': r'<meta[^>]*name=["\']framework["\'][^>]*content=["\']([^"\']+)["\']',
                'cms': r'<meta[^>]*name=["\']cms["\'][^>]*content=["\']([^"\']+)["\']',
            }
            
            for tag_name, pattern in patterns.items():
                matches = re.findall(pattern, meta_content, re.IGNORECASE)
                if matches:
                    detected_techs[tag_name] = matches[0]
            
            return {
                "detected_technologies": detected_techs,
                "detection_method": "meta_tags",
                "confidence": 0.7 if detected_techs else 0.0,
                "total_detected": len(detected_techs)
            }
            
        except Exception as e:
            return self._error_result(f"Meta tag analysis failed: {str(e)}")
    
    def _process_wappalyzer_results(self, results: Dict, detection_method: str) -> Dict[str, Any]:
        """Process Wappalyzer results into our standardized format with outdated version detection."""
        try:
            if not results:
                return self._empty_result()
            
            detected_techs = {}
            standard_libs = []
            custom_libs = []
            outdated_components = []
            
            for tech_name, tech_data in results.items():
                if isinstance(tech_data, dict):
                    # Extract version and category information from Wappalyzer format
                    versions = tech_data.get('versions', [])
                    categories = tech_data.get('categories', [])
                    confidence = tech_data.get('confidence', 0.8)  # Default confidence for Wappalyzer
                    
                    # Get the first version if available
                    version = versions[0] if versions else ''
                    # Join categories if multiple
                    category = ', '.join(categories) if categories else ''
                    
                    # Get security status for this technology
                    security_status = self._get_security_status(tech_name, version)
                    
                    tech_info = {
                        "name": tech_name,
                        "version": version,
                        "category": category,
                        "confidence": confidence,
                        "is_vulnerable": security_status['is_vulnerable'],
                        "is_outdated": security_status['is_outdated'],
                        "latest_version": security_status['latest_version'],
                        "min_safe_version": security_status['min_safe_version'],
                        "lts_version": security_status['lts_version'],
                        "security_status": security_status['security_status']
                    }
                    
                    # Determine if it's standard or custom
                    if self._is_standard_technology(tech_name, category):
                        standard_libs.append(tech_info)
                    else:
                        custom_libs.append(tech_info)
                    
                    # Add to outdated components if applicable
                    if security_status['is_outdated'] or security_status['is_vulnerable']:
                        outdated_components.append(tech_info)
                    
                    detected_techs[tech_name] = tech_info
            
            return {
                "detected_technologies": detected_techs,
                "standard_libraries": standard_libs,
                "custom_libraries": custom_libs,
                "outdated_components": outdated_components,
                "detection_method": detection_method,
                "confidence": max([lib.get("confidence", 0.0) for lib in standard_libs + custom_libs], default=0.0),
                "total_detected": len(detected_techs),
                "total_outdated": len(outdated_components)
            }
            
        except Exception as e:
            return self._error_result(f"Result processing failed: {str(e)}")
    
    def analyze_post_data(self, post_data: str) -> Dict[str, Any]:
        """
        Analyze POST data for security issues and technology indicators.
        
        Args:
            post_data: POST data content
            
        Returns:
            Dictionary with analysis results
        """
        if not post_data or not post_data.strip():
            return self._empty_result()
        
        try:
            detected_techs = {}
            standard_libs = []
            custom_libs = []
            security_issues = []
            
            # Check for JSON data
            if post_data.strip().startswith('{') or post_data.strip().startswith('['):
                try:
                    json_data = json.loads(post_data)
                    detected_techs['JSON'] = {
                        "name": "JSON",
                        "version": "",
                        "category": "Data Format",
                        "confidence": 0.9
                    }
                    standard_libs.append(detected_techs['JSON'])
                except json.JSONDecodeError:
                    pass
            
            # Check for form data patterns
            if '=' in post_data and '&' in post_data:
                detected_techs['Form Data'] = {
                    "name": "Form Data",
                    "version": "",
                    "category": "Data Format", 
                    "confidence": 0.8
                }
                standard_libs.append(detected_techs['Form Data'])
            
            # Check for XML data
            if post_data.strip().startswith('<') and '>' in post_data:
                detected_techs['XML'] = {
                    "name": "XML",
                    "version": "",
                    "category": "Data Format",
                    "confidence": 0.8
                }
                standard_libs.append(detected_techs['XML'])
            
            # Security analysis
            security_analysis = self._analyze_post_security(post_data)
            
            return {
                "detected_technologies": detected_techs,
                "standard_libraries": standard_libs,
                "custom_libraries": custom_libs,
                "detection_method": "post_data",
                "confidence": max([lib.get("confidence", 0.0) for lib in standard_libs + custom_libs], default=0.0),
                "total_detected": len(detected_techs),
                "security_analysis": security_analysis
            }
            
        except Exception as e:
            return self._error_result(f"POST data analysis failed: {str(e)}")
    
    def _analyze_post_security(self, post_data: str) -> Dict[str, Any]:
        """Analyze POST data for security issues."""
        security_issues = []
        risk_score = 0
        
        # Check for credential patterns
        for pattern_name, pattern in self.credential_patterns.items():
            if pattern.search(post_data):
                security_issues.append(f"potential_{pattern_name}")
                risk_score += 20
        
        # Check for SQL injection patterns
        sql_patterns = [
            r"'\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"union\s+select",
            r"drop\s+table",
            r"delete\s+from",
            r"insert\s+into",
            r"update\s+set"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, post_data, re.IGNORECASE):
                security_issues.append("potential_sql_injection")
                risk_score += 30
                break
        
        # Check for XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, post_data, re.IGNORECASE):
                security_issues.append("potential_xss")
                risk_score += 25
                break
        
        return {
            "security_issues": security_issues,
            "security_risk_score": min(risk_score, 100),
            "has_credentials": any("credential" in issue for issue in security_issues),
            "has_injection": any("injection" in issue for issue in security_issues)
        }
    
    def _check_vulnerability(self, tech_name: str, version: str) -> bool:
        """Check if a technology version is vulnerable using version database."""
        if not version or not tech_name:
            return False
        
        return self.version_db.is_vulnerable(tech_name, version)
    
    def _check_outdated(self, tech_name: str, version: str) -> Tuple[bool, str, str]:
        """Check if a technology version is outdated using version database."""
        if not version or not tech_name:
            return False, "", ""
        
        return self.version_db.is_outdated(tech_name, version)
    
    def _get_security_status(self, tech_name: str, version: str) -> Dict[str, Any]:
        """Get comprehensive security status for a technology version."""
        if not version or not tech_name:
            return {
                'is_outdated': False,
                'is_vulnerable': False,
                'latest_version': '',
                'min_safe_version': '',
                'lts_version': '',
                'security_status': 'unknown'
            }
        
        return self.version_db.get_security_status(tech_name, version)
    
    def _version_compare(self, version1: str, version2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad with zeros to make same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            return 0
        except (ValueError, AttributeError):
            return 0  # If can't compare, assume equal
    
    def _is_standard_technology(self, tech_name: str, category: str) -> bool:
        """Determine if a technology is a standard library/framework."""
        standard_indicators = [
            'javascript', 'css', 'html', 'php', 'python', 'java', 'ruby',
            'react', 'vue', 'angular', 'jquery', 'bootstrap', 'foundation',
            'wordpress', 'drupal', 'joomla', 'django', 'rails', 'laravel',
            'express', 'spring', 'asp.net', 'node.js', 'apache', 'nginx',
            'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'
        ]
        
        tech_lower = tech_name.lower()
        return any(indicator in tech_lower for indicator in standard_indicators)
    
    def _is_standard_library(self, src: str, lib_name: str) -> bool:
        """Check if a script src points to a standard library."""
        standard_cdns = [
            'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
            'ajax.googleapis.com', 'maxcdn.bootstrapcdn.com',
            'stackpath.bootstrapcdn.com', 'cdn.skypack.dev'
        ]
        
        parsed_url = urlparse(src)
        domain = parsed_url.netloc.lower()
        
        return any(cdn in domain for cdn in standard_cdns)
    
    def _extract_library_name(self, src: str) -> Optional[str]:
        """Extract library name from script src URL."""
        try:
            parsed_url = urlparse(src)
            path = parsed_url.path
            
            # Extract filename without extension
            filename = path.split('/')[-1]
            if '.' in filename:
                filename = filename.rsplit('.', 1)[0]
            
            # Clean up common patterns
            filename = re.sub(r'[-\d.]+$', '', filename)  # Remove version numbers
            filename = re.sub(r'^[a-z]+-', '', filename)  # Remove prefixes like 'jquery-'
            
            return filename if filename else None
            
        except Exception:
            return None
    
    def _extract_version_from_url(self, src: str) -> Optional[str]:
        """Extract version number from script src URL."""
        try:
            # Look for version patterns in URL
            version_patterns = [
                r'/(\d+\.\d+\.\d+)/',  # x.y.z
                r'/(\d+\.\d+)/',       # x.y
                r'/(\d+)/',            # x
                r'v(\d+\.\d+\.\d+)',   # vx.y.z
                r'v(\d+\.\d+)',        # vx.y
                r'v(\d+)',             # vx
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, src)
                if match:
                    return match.group(1)
            
            return None
            
        except Exception:
            return None
    
    def _detect_cdn(self, src: str) -> Optional[str]:
        """Detect CDN provider from script src URL."""
        cdn_mapping = {
            'cdnjs.cloudflare.com': 'Cloudflare',
            'cdn.jsdelivr.net': 'jsDelivr',
            'unpkg.com': 'unpkg',
            'ajax.googleapis.com': 'Google',
            'maxcdn.bootstrapcdn.com': 'MaxCDN',
            'stackpath.bootstrapcdn.com': 'StackPath',
            'cdn.skypack.dev': 'Skypack'
        }
        
        parsed_url = urlparse(src)
        domain = parsed_url.netloc.lower()
        
        for cdn_domain, cdn_name in cdn_mapping.items():
            if cdn_domain in domain:
                return cdn_name
        
        return None
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty detection result."""
        return {
            "detected_technologies": {},
            "standard_libraries": [],
            "custom_libraries": [],
            "detection_method": "none",
            "confidence": 0.0,
            "total_detected": 0
        }
    
    def _error_result(self, error_msg: str) -> Dict[str, Any]:
        """Return error detection result."""
        return {
            "detected_technologies": {},
            "standard_libraries": [],
            "custom_libraries": [],
            "detection_method": "error",
            "confidence": 0.0,
            "total_detected": 0,
            "error": error_msg
        }


def detect_stack_from_traffic(headers_text: str = "", html_content: str = "", 
                            script_srcs: List[str] = None, meta_content: str = "",
                            post_data: str = "", url: str = "") -> Dict[str, Any]:
    """
    Comprehensive stack detection from various traffic components.
    
    Args:
        headers_text: HTTP headers
        html_content: HTML content
        script_srcs: List of script src URLs
        meta_content: Meta tags content
        post_data: POST data content
        url: Base URL for context
        
    Returns:
        Combined detection results
    """
    if script_srcs is None:
        script_srcs = []
    
    detector = StackDetector()
    
    # Run all detection methods
    results = {
        "headers": detector.detect_from_headers(headers_text, url),
        "html": detector.detect_from_html(html_content, url),
        "scripts": detector.detect_from_script_src(script_srcs),
        "meta": detector.detect_from_meta_tags(meta_content),
        "post_data": detector.analyze_post_data(post_data) if post_data else {}
    }
    
    # Combine results
    all_technologies = {}
    all_standard_libs = []
    all_custom_libs = []
    all_outdated_components = []
    total_confidence = 0.0
    detection_methods = []
    combined_security_analysis = {}
    
    for method, result in results.items():
        if result.get("total_detected", 0) > 0:
            detection_methods.append(method)
            all_technologies.update(result.get("detected_technologies", {}))
            all_standard_libs.extend(result.get("standard_libraries", []))
            all_custom_libs.extend(result.get("custom_libraries", []))
            all_outdated_components.extend(result.get("outdated_components", []))
            total_confidence += result.get("confidence", 0.0)
        
        # Combine security analysis from all methods
        if result.get("security_analysis"):
            security_analysis = result.get("security_analysis", {})
            if not combined_security_analysis:
                combined_security_analysis = security_analysis.copy()
            else:
                # Merge security issues
                combined_security_analysis["total_security_issues"] += security_analysis.get("total_security_issues", 0)
                combined_security_analysis["high_severity_issues"] += security_analysis.get("high_severity_issues", 0)
                combined_security_analysis["medium_severity_issues"] += security_analysis.get("medium_severity_issues", 0)
                combined_security_analysis["security_risk_score"] += security_analysis.get("security_risk_score", 0)
                combined_security_analysis["has_vulnerabilities"] = combined_security_analysis.get("has_vulnerabilities", False) or security_analysis.get("has_vulnerabilities", False)
                combined_security_analysis["security_issues"].extend(security_analysis.get("security_issues", []))
    
    # Calculate overall confidence
    avg_confidence = total_confidence / len(detection_methods) if detection_methods else 0.0
    
    # Remove duplicates from outdated components
    seen_outdated = set()
    unique_outdated = []
    for comp in all_outdated_components:
        comp_key = (comp.get("name", ""), comp.get("version", ""))
        if comp_key not in seen_outdated:
            seen_outdated.add(comp_key)
            unique_outdated.append(comp)
    
    # Determine top component
    top_component = None
    if all_standard_libs:
        # Sort by confidence and pick the highest
        top_standard = max(all_standard_libs, key=lambda x: x.get("confidence", 0.0))
        top_component = {
            "name": top_standard["name"],
            "version": top_standard.get("version", ""),
            "category": top_standard.get("category", ""),
            "type": "standard",
            "confidence": top_standard.get("confidence", 0.0),
            "is_vulnerable": top_standard.get("is_vulnerable", False),
            "is_outdated": top_standard.get("is_outdated", False),
            "security_status": top_standard.get("security_status", "unknown")
        }
    elif all_custom_libs:
        top_custom = max(all_custom_libs, key=lambda x: x.get("confidence", 0.0))
        top_component = {
            "name": top_custom["name"],
            "version": top_custom.get("version", ""),
            "category": top_custom.get("category", ""),
            "type": "custom",
            "confidence": top_custom.get("confidence", 0.0),
            "is_vulnerable": top_custom.get("is_vulnerable", False),
            "is_outdated": top_custom.get("is_outdated", False),
            "security_status": top_custom.get("security_status", "unknown")
        }
    
    result = {
        "detected_technologies": all_technologies,
        "standard_libraries": all_standard_libs,
        "custom_libraries": all_custom_libs,
        "outdated_components": unique_outdated,
        "top_component": top_component,
        "detection_methods": detection_methods,
        "confidence": avg_confidence,
        "total_detected": len(all_technologies),
        "total_outdated": len(unique_outdated),
        "component_candidates": all_standard_libs + all_custom_libs
    }
    
    # Add security analysis if available
    if combined_security_analysis:
        result["security_analysis"] = combined_security_analysis
    
    return result
