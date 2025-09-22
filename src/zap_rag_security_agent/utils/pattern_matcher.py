"""
Pattern matching utilities for JavaScript vulnerability detection.
Low-level pattern matching with configurable thresholds.
"""

import re
from typing import Dict, List, Any, Tuple

class PatternMatcher:
    def __init__(self):
        self.patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize vulnerability patterns with weights and descriptions"""
        return {
            "eval_usage": {
                "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
                "weight": 10,
                "description": "Direct eval() usage - high risk",
                "category": "code_injection"
            },
            "innerHTML_dangerous": {
                "pattern": re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
                "weight": 8,
                "description": "innerHTML assignment - potential XSS",
                "category": "xss"
            },
            "document_write": {
                "pattern": re.compile(r'document\.write\s*\(', re.IGNORECASE),
                "weight": 7,
                "description": "document.write usage - potential XSS",
                "category": "xss"
            },
            "function_constructor": {
                "pattern": re.compile(r'Function\s*\(', re.IGNORECASE),
                "weight": 9,
                "description": "Function constructor - code injection risk",
                "category": "code_injection"
            },
            "setTimeout_string": {
                "pattern": re.compile(r'setTimeout\s*\([^,)]*["\'][^"\']*["\']', re.IGNORECASE),
                "weight": 6,
                "description": "setTimeout with string - code injection risk",
                "category": "code_injection"
            },
            "prototype_pollution": {
                "pattern": re.compile(r'__proto__|constructor\.prototype', re.IGNORECASE),
                "weight": 8,
                "description": "Prototype pollution - object manipulation",
                "category": "prototype_pollution"
            },
            "localStorage_unsafe": {
                "pattern": re.compile(r'localStorage\.setItem\s*\([^,)]*["\'](?:password|token|secret|key)["\']', re.IGNORECASE),
                "weight": 5,
                "description": "Unsafe localStorage usage with sensitive data",
                "category": "data_exposure"
            },
            "crypto_weak": {
                "pattern": re.compile(r'Math\.random|Date\.now', re.IGNORECASE),
                "weight": 4,
                "description": "Weak cryptographic practices",
                "category": "crypto"
            },
            "xss_sinks": {
                "pattern": re.compile(r'(innerHTML|outerHTML|document\.write|eval)\s*\(', re.IGNORECASE),
                "weight": 7,
                "description": "XSS sink functions",
                "category": "xss"
            },
            "unsafe_jquery": {
                "pattern": re.compile(r'\$\([^)]*\)\.html\s*\(', re.IGNORECASE),
                "weight": 6,
                "description": "Unsafe jQuery HTML manipulation",
                "category": "xss"
            }
        }
    
    def calculate_suspicion_density(self, script_content: str) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate suspicion density and return detailed matches.
        
        Returns:
            (density_score, detailed_matches)
        """
        lines = [line.strip() for line in script_content.split('\n') if line.strip()]
        total_lines = len(lines)
        
        if total_lines == 0:
            return 0.0, []
        
        matches = []
        total_weight = 0
        
        for pattern_name, pattern_info in self.patterns.items():
            pattern = pattern_info["pattern"]
            weight = pattern_info["weight"]
            
            for match in pattern.finditer(script_content):
                line_number = script_content[:match.start()].count('\n') + 1
                matches.append({
                    "pattern": pattern_name,
                    "description": pattern_info["description"],
                    "category": pattern_info["category"],
                    "weight": weight,
                    "line": line_number,
                    "match": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
                })
                total_weight += weight
        
        density_score = total_weight / total_lines
        return density_score, matches
    
    def is_custom_script(self, script_url: str, script_content: str) -> Dict[str, Any]:
        """Determine if script is custom vs third-party"""
        
        # Third-party indicators (high confidence)
        third_party_indicators = [
            'cdnjs.cloudflare.com', 'unpkg.com', 'cdn.jsdelivr.net',
            'googleapis.com', 'ajax.googleapis.com', 'code.jquery.com',
            'maxcdn.bootstrapcdn.com', 'cdnjs.com', 'jsdelivr.net'
        ]
        
        # Common library names in URLs
        library_names = [
            'jquery', 'react', 'vue', 'angular', 'bootstrap', 'lodash',
            'moment', 'chart.js', 'd3', 'three.js', 'socket.io',
            'axios', 'underscore', 'backbone', 'ember', 'knockout'
        ]
        
        # Custom script indicators
        custom_indicators = [
            '/static/js/', '/assets/js/', '/js/', '/scripts/',
            'custom', 'app', 'main', 'script', 'bundle'
        ]
        
        url_lower = script_url.lower()
        content_lower = script_content.lower()
        
        # Check for third-party indicators
        is_third_party = any(indicator in url_lower for indicator in third_party_indicators)
        is_library = any(lib in url_lower or lib in content_lower[:200] for lib in library_names)
        
        # Check for custom indicators
        is_custom = any(indicator in url_lower for indicator in custom_indicators)
        
        # Content analysis for custom code indicators
        custom_content_indicators = [
            'function ', 'var ', 'let ', 'const ', 'class ',
            'document.getElementById', 'addEventListener',
            'XMLHttpRequest', 'fetch('
        ]
        
        has_custom_content = any(indicator in content_lower for indicator in custom_content_indicators)
        
        # Calculate confidence
        confidence = 0.0
        if is_third_party or is_library:
            confidence = 0.1  # Low confidence it's custom
        elif is_custom and has_custom_content:
            confidence = 0.9  # High confidence it's custom
        elif is_custom:
            confidence = 0.7  # Medium confidence
        elif has_custom_content:
            confidence = 0.6  # Medium confidence
        else:
            confidence = 0.5  # Unknown
        
        # For inline scripts, be more lenient - assume custom unless clearly third-party
        if script_url.startswith('inline:'):
            if not is_third_party and not is_library:
                confidence = max(confidence, 0.7)  # Assume custom for inline scripts
        
        return {
            "is_custom": confidence > 0.6,
            "confidence": confidence,
            "indicators": {
                "third_party": is_third_party,
                "library": is_library,
                "custom_url": is_custom,
                "custom_content": has_custom_content
            }
        }
