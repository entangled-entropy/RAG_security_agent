"""
Test cases for entropy calculator functionality.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from zap_rag_security_agent.utils.entropy_calculator import EntropyCalculator

class TestEntropyCalculator:
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        calculator = EntropyCalculator()
        
        # Low entropy (repetitive)
        low_entropy = "aaaaaaaaaa"
        assert calculator.calculate_entropy(low_entropy) < 1.0
        
        # High entropy (random)
        high_entropy = "a1b2c3d4e5f6g7h8i9j0"
        assert calculator.calculate_entropy(high_entropy) > 3.0
    
    def test_obfuscation_detection(self):
        """Test obfuscation detection"""
        calculator = EntropyCalculator()
        
        # Normal code
        normal_code = """
        function hello() {
            console.log('Hello World');
            return true;
        }
        """
        normal_result = calculator.analyze_obfuscation(normal_code)
        assert not normal_result['is_obfuscated']
        assert normal_result['confidence'] < 0.5
        
        # Obfuscated code
        obfuscated_code = """
        var a='H',b='e',c='l',d='o';
        var e=a+b+c+c+d;
        eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103));
        """
        obfuscated_result = calculator.analyze_obfuscation(obfuscated_code)
        assert obfuscated_result['is_obfuscated']
        assert obfuscated_result['confidence'] > 0.5
    
    def test_minification_detection(self):
        """Test minification detection"""
        calculator = EntropyCalculator()
        
        # Minified code - make it longer to meet the threshold
        minified_code = "function a(b,c){return b+c;}var d=1,e=2;console.log(a(d,e));" * 10
        assert calculator.is_minified(minified_code)
        
        # Normal code
        normal_code = """
        function add(a, b) {
            return a + b;
        }
        var x = 1;
        var y = 2;
        console.log(add(x, y));
        """
        assert not calculator.is_minified(normal_code)
    
    def test_obfuscation_patterns(self):
        """Test detection of specific obfuscation patterns"""
        calculator = EntropyCalculator()
        
        # String concatenation obfuscation
        concat_code = "var a='H',b='e',c='l',d='o';var e=a+b+c+c+d;"
        result = calculator.analyze_obfuscation(concat_code)
        assert result['pattern_density'] > 0
        assert any(p['name'] == 'variable_concatenation' for p in result['pattern_matches'])
        
        # String.fromCharCode obfuscation
        charcode_code = "String.fromCharCode(72,101,108,108,111)"
        result = calculator.analyze_obfuscation(charcode_code)
        assert any(p['name'] == 'string_from_charcode' for p in result['pattern_matches'])
        
        # Hex encoding
        hex_code = "var x = '\\x48\\x65\\x6c\\x6c\\x6f';"
        result = calculator.analyze_obfuscation(hex_code)
        assert any(p['name'] == 'hex_encoding' for p in result['pattern_matches'])
        
        # Unicode encoding
        unicode_code = "var x = '\\u0048\\u0065\\u006c\\u006c\\u006f';"
        result = calculator.analyze_obfuscation(unicode_code)
        assert any(p['name'] == 'unicode_encoding' for p in result['pattern_matches'])
    
    def test_entropy_edge_cases(self):
        """Test entropy calculation edge cases"""
        calculator = EntropyCalculator()
        
        # Empty string
        assert calculator.calculate_entropy("") == 0.0
        
        # Single character
        assert calculator.calculate_entropy("a") == 0.0
        
        # Two different characters
        assert calculator.calculate_entropy("ab") == 1.0
        
        # All different characters
        unique_chars = "abcdefghijklmnopqrstuvwxyz"
        entropy = calculator.calculate_entropy(unique_chars)
        assert entropy > 4.0  # High entropy for unique characters
    
    def test_confidence_calculation(self):
        """Test confidence calculation for obfuscation detection"""
        calculator = EntropyCalculator()
        
        # Very high entropy and pattern density
        high_entropy_code = "a" + "b" * 100 + "c" * 100 + "d" * 100
        high_entropy_code += "String.fromCharCode(1,2,3,4,5);" * 20
        result = calculator.analyze_obfuscation(high_entropy_code)
        assert result['confidence'] >= 0.7
        
        # Medium entropy
        medium_code = "var a='test';var b='data';var c=a+b;"
        result = calculator.analyze_obfuscation(medium_code)
        assert 0.1 <= result['confidence'] <= 0.7
        
        # Low entropy
        low_code = "console.log('hello');"
        result = calculator.analyze_obfuscation(low_code)
        assert result['confidence'] < 0.5
