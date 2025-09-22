"""
Entropy calculation and obfuscation detection utilities.
Detects obfuscated, minified, or potentially malicious JavaScript.
"""

import math
import re
from typing import Dict, Any, List

class EntropyCalculator:
    def __init__(self):
        self.obfuscation_patterns = self._initialize_obfuscation_patterns()
    
    def _initialize_obfuscation_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for detecting obfuscated code"""
        return [
            {
                "name": "variable_concatenation",
                "pattern": re.compile(r'[a-zA-Z]{1,2}\s*=\s*[a-zA-Z]{1,2}\s*\+\s*[a-zA-Z]{1,2}'),
                "weight": 2
            },
            {
                "name": "string_from_charcode",
                "pattern": re.compile(r'String\.fromCharCode'),
                "weight": 3
            },
            {
                "name": "hex_encoding",
                "pattern": re.compile(r'\\x[0-9a-fA-F]{2}'),
                "weight": 2
            },
            {
                "name": "unicode_encoding",
                "pattern": re.compile(r'\\u[0-9a-fA-F]{4}'),
                "weight": 2
            },
            {
                "name": "array_like_access",
                "pattern": re.compile(r'[a-zA-Z]{1,2}\['),
                "weight": 1
            },
            {
                "name": "iife_patterns",
                "pattern": re.compile(r'\([^)]*\)\s*\([^)]*\)'),
                "weight": 1
            },
            {
                "name": "base64_like",
                "pattern": re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
                "weight": 2
            },
            {
                "name": "excessive_whitespace",
                "pattern": re.compile(r'\s{20,}'),
                "weight": 1
            }
        ]
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_obfuscation(self, script_content: str) -> Dict[str, Any]:
        """Comprehensive obfuscation analysis"""
        
        # Calculate entropy
        entropy = self.calculate_entropy(script_content)
        
        # Check for obfuscation patterns
        pattern_matches = []
        total_pattern_weight = 0
        
        for pattern_info in self.obfuscation_patterns:
            pattern = pattern_info["pattern"]
            weight = pattern_info["weight"]
            
            matches = list(pattern.finditer(script_content))
            if matches:
                pattern_matches.append({
                    "name": pattern_info["name"],
                    "count": len(matches),
                    "weight": weight,
                    "total_weight": len(matches) * weight
                })
                total_pattern_weight += len(matches) * weight
        
        # Calculate obfuscation score
        content_length = len(script_content)
        pattern_density = total_pattern_weight / max(content_length, 1) * 1000  # per 1000 chars
        
        # Determine if obfuscated
        is_obfuscated = (
            entropy > 4.8 or  # High entropy
            pattern_density > 10 or  # High pattern density
            (entropy > 4.5 and pattern_density > 5)  # Combined threshold
        )
        
        # Calculate confidence
        confidence = 0.0
        if entropy > 5.0 and pattern_density > 10:
            confidence = 0.9  # Very high confidence
        elif entropy > 4.5 or pattern_density > 5:
            confidence = 0.7  # High confidence
        elif entropy > 4.0 or pattern_density > 2:
            confidence = 0.5  # Medium confidence
        else:
            confidence = 0.1  # Low confidence
        
        return {
            "is_obfuscated": is_obfuscated,
            "confidence": confidence,
            "entropy": entropy,
            "pattern_density": pattern_density,
            "pattern_matches": pattern_matches,
            "total_pattern_weight": total_pattern_weight
        }
    
    def is_minified(self, script_content: str) -> bool:
        """Detect if script is minified (not obfuscated)"""
        
        lines = script_content.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        if not non_empty_lines:
            return False
        
        # Check for minification indicators
        avg_line_length = sum(len(line) for line in non_empty_lines) / len(non_empty_lines)
        long_lines = sum(1 for line in non_empty_lines if len(line) > 100)
        long_line_ratio = long_lines / len(non_empty_lines)
        
        # Minified code typically has very long lines and few line breaks
        return avg_line_length > 200 and long_line_ratio > 0.8
