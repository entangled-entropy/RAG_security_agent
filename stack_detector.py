"""
Stack Detection Module using Wappalyzer

This module provides stack fingerprinting capabilities using the Wappalyzer library
to detect web technologies, frameworks, and their versions from HTTP traffic.

Features:
- Detect web technologies from headers, HTML content, and scripts
- Version detection for standard libraries
- Distinguish between standard and custom libraries
- JSON-safe metadata output for ChromaDB storage
"""

import re
import json
import requests
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage


class StackDetector:
    """
    Stack detection using Wappalyzer for web technology fingerprinting.
    Enhanced with security-focused analysis for vulnerabilities and credentials.
    """
    
    def __init__(self):
        """Initialize the Wappalyzer instance."""
        self.wappalyzer = Wappalyzer.latest()
        
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
        
        # Known vulnerable versions (simplified - in production, use CVE databases)
        self.vulnerable_versions = {
            'jquery': {
                'vulnerable': ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0', '1.7.0', '1.8.0', '1.9.0', '1.10.0', '1.11.0', '1.12.0'],
                'min_safe': '3.0.0'
            },
            'bootstrap': {
                'vulnerable': ['3.0.0', '3.1.0', '3.2.0', '3.3.0', '3.4.0', '4.0.0', '4.1.0', '4.2.0', '4.3.0', '4.4.0', '4.5.0', '4.6.0'],
                'min_safe': '5.0.0'
            },
            'angular': {
                'vulnerable': ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0', '1.7.0', '1.8.0'],
                'min_safe': '2.0.0'
            },
            'vue': {
                'vulnerable': ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0', '1.7.0', '1.8.0', '1.9.0', '1.10.0'],
                'min_safe': '2.0.0'
            }
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
            
            return self._process_wappalyzer_results(results, "headers")
            
        except Exception as e:
            return self._error_result(f"Header analysis failed: {str(e)}")
    
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
        Detect technologies from script src URLs with security analysis.
        
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
            security_issues = []
            
            for src in script_srcs:
                if not src:
                    continue
                
                # Extract library name from URL
                lib_name = self._extract_library_name(src)
                if not lib_name:
                    continue
                
                version = self._extract_version_from_url(src)
                
                # Check if it's a known CDN or standard library
                is_standard = self._is_standard_library(src, lib_name)
                
                # Check for version vulnerabilities
                vuln_check = self.check_version_vulnerability(lib_name, version)
                
                lib_info = {
                    "name": lib_name,
                    "src": src,
                    "version": version,
                    "vulnerability_check": vuln_check
                }
                
                if is_standard:
                    lib_info["cdn"] = self._detect_cdn(src)
                    standard_libs.append(lib_info)
                else:
                    custom_libs.append(lib_info)
                
                # Add security issues if vulnerable
                if vuln_check.get("is_vulnerable", False):
                    security_issues.append({
                        "type": "vulnerable_version",
                        "library": lib_name,
                        "version": version,
                        "reason": vuln_check.get("reason", "Unknown vulnerability"),
                        "severity": vuln_check.get("severity", "medium"),
                        "min_safe_version": vuln_check.get("min_safe_version", "Unknown")
                    })
            
            return {
                "detected_technologies": detected_techs,
                "standard_libraries": standard_libs,
                "custom_libraries": custom_libs,
                "security_issues": security_issues,
                "detection_method": "script_src",
                "confidence": 0.8 if standard_libs or custom_libs else 0.0,
                "total_detected": len(standard_libs) + len(custom_libs),
                "has_vulnerabilities": len(security_issues) > 0
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
        """Process Wappalyzer results into our standardized format with security analysis."""
        try:
            if not results:
                return self._empty_result()
            
            detected_techs = {}
            standard_libs = []
            custom_libs = []
            security_issues = []
            
            for tech_name, tech_data in results.items():
                if isinstance(tech_data, dict):
                    # Extract version and category information
                    version = tech_data.get('version', '')
                    category = tech_data.get('category', '')
                    confidence = tech_data.get('confidence', 0.0)
                    
                    # Check for version vulnerabilities
                    vuln_check = self.check_version_vulnerability(tech_name, version)
                    
                    tech_info = {
                        "name": tech_name,
                        "version": version,
                        "category": category,
                        "confidence": confidence,
                        "vulnerability_check": vuln_check
                    }
                    
                    # Add security issues if vulnerable
                    if vuln_check.get("is_vulnerable", False):
                        security_issues.append({
                            "type": "vulnerable_version",
                            "library": tech_name,
                            "version": version,
                            "reason": vuln_check.get("reason", "Unknown vulnerability"),
                            "severity": vuln_check.get("severity", "medium"),
                            "min_safe_version": vuln_check.get("min_safe_version", "Unknown")
                        })
                    
                    # Determine if it's standard or custom
                    if self._is_standard_technology(tech_name, category):
                        standard_libs.append(tech_info)
                    else:
                        custom_libs.append(tech_info)
                    
                    detected_techs[tech_name] = tech_info
            
            return {
                "detected_technologies": detected_techs,
                "standard_libraries": standard_libs,
                "custom_libraries": custom_libs,
                "security_issues": security_issues,
                "detection_method": detection_method,
                "confidence": max([lib.get("confidence", 0.0) for lib in standard_libs + custom_libs], default=0.0),
                "total_detected": len(detected_techs),
                "has_vulnerabilities": len(security_issues) > 0
            }
            
        except Exception as e:
            return self._error_result(f"Result processing failed: {str(e)}")
    
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
    
    def check_version_vulnerability(self, lib_name: str, version: str) -> Dict[str, Any]:
        """
        Check if a library version is vulnerable.
        
        Args:
            lib_name: Name of the library
            version: Version string
            
        Returns:
            Dictionary with vulnerability information
        """
        if not version or not lib_name:
            return {"is_vulnerable": False, "reason": "No version or library name"}
        
        lib_key = lib_name.lower().replace('-', '').replace('_', '').replace('.', '')
        
        # Check against known vulnerable versions
        for lib, vuln_info in self.vulnerable_versions.items():
            if lib in lib_key or lib_key in lib:
                if version in vuln_info['vulnerable']:
                    return {
                        "is_vulnerable": True,
                        "reason": f"Known vulnerable version {version}",
                        "min_safe_version": vuln_info['min_safe'],
                        "severity": "high"
                    }
                elif self._compare_versions(version, vuln_info['min_safe']) < 0:
                    return {
                        "is_vulnerable": True,
                        "reason": f"Version {version} below minimum safe version {vuln_info['min_safe']}",
                        "min_safe_version": vuln_info['min_safe'],
                        "severity": "medium"
                    }
        
        return {"is_vulnerable": False, "reason": "Version appears safe"}
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        def version_tuple(v):
            return tuple(map(int, (v.split("."))))
        
        try:
            t1 = version_tuple(v1)
            t2 = version_tuple(v2)
            if t1 < t2:
                return -1
            elif t1 > t2:
                return 1
            else:
                return 0
        except ValueError:
            return 0  # If parsing fails, assume equal
    
    def detect_credentials_in_content(self, content: str) -> Dict[str, Any]:
        """
        Detect hardcoded credentials and sensitive data in content.
        
        Args:
            content: Content to analyze (HTML, JS, etc.)
            
        Returns:
            Dictionary with credential detection results
        """
        found_credentials = []
        security_issues = []
        
        for cred_type, pattern in self.credential_patterns.items():
            matches = pattern.findall(content)
            for match in matches:
                if len(match) == 2:
                    key, value = match
                    found_credentials.append({
                        "type": cred_type,
                        "key": key.strip(),
                        "value": value[:20] + "..." if len(value) > 20 else value,
                        "severity": "high" if cred_type in ['api_key', 'secret_key', 'aws_key'] else "medium"
                    })
        
        # Check for other security issues
        if self.vulnerable_patterns['eval_usage'].search(content):
            security_issues.append({
                "type": "dangerous_eval",
                "description": "Use of eval() function detected",
                "severity": "high"
            })
        
        if self.vulnerable_patterns['innerHTML_dangerous'].search(content):
            security_issues.append({
                "type": "xss_risk",
                "description": "Direct innerHTML assignment detected",
                "severity": "medium"
            })
        
        if self.vulnerable_patterns['document_write'].search(content):
            security_issues.append({
                "type": "xss_risk",
                "description": "document.write() usage detected",
                "severity": "medium"
            })
        
        return {
            "credentials_found": found_credentials,
            "security_issues": security_issues,
            "total_issues": len(found_credentials) + len(security_issues),
            "has_credentials": len(found_credentials) > 0,
            "has_security_issues": len(security_issues) > 0
        }
    
    def analyze_post_data(self, post_data: str) -> Dict[str, Any]:
        """
        Analyze POST data for security vulnerabilities.
        
        Args:
            post_data: POST request body data
            
        Returns:
            Dictionary with POST data analysis results
        """
        if not post_data or not post_data.strip():
            return {"analysis": "No POST data", "issues": []}
        
        issues = []
        sensitive_fields = []
        
        # Check for sensitive data in POST
        try:
            # Try to parse as JSON
            if post_data.strip().startswith('{'):
                data = json.loads(post_data)
                if isinstance(data, dict):
                    for key, value in data.items():
                        key_lower = key.lower()
                        if any(sensitive in key_lower for sensitive in ['password', 'secret', 'token', 'key', 'auth']):
                            sensitive_fields.append({
                                "field": key,
                                "type": "sensitive_field",
                                "severity": "high"
                            })
        except json.JSONDecodeError:
            # Try to parse as form data
            if '=' in post_data and '&' in post_data:
                for pair in post_data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        key_lower = key.lower()
                        if any(sensitive in key_lower for sensitive in ['password', 'secret', 'token', 'key', 'auth']):
                            sensitive_fields.append({
                                "field": key,
                                "type": "sensitive_field",
                                "severity": "high"
                            })
        
        # Check for SQL injection patterns
        sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table", r"delete\s+from",
            r"insert\s+into", r"update\s+set", r"exec\s*\(", r"xp_cmdshell"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, post_data, re.I):
                issues.append({
                    "type": "sql_injection_attempt",
                    "description": f"Potential SQL injection pattern: {pattern}",
                    "severity": "high"
                })
        
        # Check for XSS patterns
        xss_patterns = [
            r"<script[^>]*>", r"javascript:", r"onerror\s*=", r"onload\s*=",
            r"onclick\s*=", r"onmouseover\s*="
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, post_data, re.I):
                issues.append({
                    "type": "xss_attempt",
                    "description": f"Potential XSS pattern: {pattern}",
                    "severity": "high"
                })
        
        return {
            "analysis": "POST data analyzed",
            "sensitive_fields": sensitive_fields,
            "issues": issues,
            "total_issues": len(sensitive_fields) + len(issues),
            "has_sensitive_data": len(sensitive_fields) > 0,
            "has_attacks": len(issues) > 0
        }
    
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
    Comprehensive stack detection from various traffic components with security analysis.
    
    Args:
        headers_text: HTTP headers
        html_content: HTML content
        script_srcs: List of script src URLs
        meta_content: Meta tags content
        post_data: POST request body data
        url: Base URL for context
        
    Returns:
        Combined detection results with security analysis
    """
    if script_srcs is None:
        script_srcs = []
    
    detector = StackDetector()
    
    # Run all detection methods
    results = {
        "headers": detector.detect_from_headers(headers_text, url),
        "html": detector.detect_from_html(html_content, url),
        "scripts": detector.detect_from_script_src(script_srcs),
        "meta": detector.detect_from_meta_tags(meta_content)
    }
    
    # Analyze POST data for security issues
    post_analysis = detector.analyze_post_data(post_data) if post_data else {}
    
    # Analyze content for credentials
    credential_analysis = {}
    if html_content:
        credential_analysis = detector.detect_credentials_in_content(html_content)
    
    # Combine results
    all_technologies = {}
    all_standard_libs = []
    all_custom_libs = []
    all_security_issues = []
    total_confidence = 0.0
    detection_methods = []
    
    for method, result in results.items():
        if result.get("total_detected", 0) > 0:
            detection_methods.append(method)
            all_technologies.update(result.get("detected_technologies", {}))
            all_standard_libs.extend(result.get("standard_libraries", []))
            all_custom_libs.extend(result.get("custom_libraries", []))
            all_security_issues.extend(result.get("security_issues", []))
            total_confidence += result.get("confidence", 0.0)
    
    # Add POST data security issues
    if post_analysis.get("issues"):
        all_security_issues.extend(post_analysis["issues"])
    
    # Add credential analysis issues
    if credential_analysis.get("security_issues"):
        all_security_issues.extend(credential_analysis["security_issues"])
    
    # Calculate overall confidence
    avg_confidence = total_confidence / len(detection_methods) if detection_methods else 0.0
    
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
            "vulnerability_check": top_standard.get("vulnerability_check", {})
        }
    elif all_custom_libs:
        top_custom = max(all_custom_libs, key=lambda x: x.get("confidence", 0.0))
        top_component = {
            "name": top_custom["name"],
            "version": top_custom.get("version", ""),
            "category": top_custom.get("category", ""),
            "type": "custom",
            "confidence": top_custom.get("confidence", 0.0),
            "vulnerability_check": top_custom.get("vulnerability_check", {})
        }
    
    # Calculate security risk score
    high_severity_issues = len([issue for issue in all_security_issues if issue.get("severity") == "high"])
    medium_severity_issues = len([issue for issue in all_security_issues if issue.get("severity") == "medium"])
    security_risk_score = (high_severity_issues * 3) + (medium_severity_issues * 1)
    
    return {
        "detected_technologies": all_technologies,
        "standard_libraries": all_standard_libs,
        "custom_libraries": all_custom_libs,
        "top_component": top_component,
        "detection_methods": detection_methods,
        "confidence": avg_confidence,
        "total_detected": len(all_technologies),
        "component_candidates": all_standard_libs + all_custom_libs,
        "security_analysis": {
            "security_issues": all_security_issues,
            "total_security_issues": len(all_security_issues),
            "high_severity_issues": high_severity_issues,
            "medium_severity_issues": medium_severity_issues,
            "security_risk_score": security_risk_score,
            "has_vulnerabilities": len(all_security_issues) > 0,
            "post_data_analysis": post_analysis,
            "credential_analysis": credential_analysis
        }
    }
