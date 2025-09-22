"""
Test cases for pattern matcher functionality.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from zap_rag_security_agent.utils.pattern_matcher import PatternMatcher

class TestPatternMatcher:
    def test_suspicion_density_calculation(self):
        """Test suspicion density calculation"""
        matcher = PatternMatcher()
        
        # High suspicion script
        high_suspicion_script = """
        eval(userInput);
        document.getElementById('content').innerHTML = data;
        localStorage.setItem('password', userPassword);
        """
        
        density, matches = matcher.calculate_suspicion_density(high_suspicion_script)
        
        assert density > 0.5  # High density
        assert len(matches) > 0
        assert any(m['pattern'] == 'eval_usage' for m in matches)
        assert any(m['pattern'] == 'innerHTML_dangerous' for m in matches)
    
    def test_custom_script_detection(self):
        """Test custom vs third-party script detection"""
        matcher = PatternMatcher()
        
        # Third-party script
        third_party_result = matcher.is_custom_script(
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
            "jQuery library code..."
        )
        assert not third_party_result['is_custom']
        assert third_party_result['confidence'] < 0.5
        
        # Custom script
        custom_result = matcher.is_custom_script(
            "https://example.com/static/js/app.js",
            "function myFunction() { console.log('custom code'); }"
        )
        assert custom_result['is_custom']
        assert custom_result['confidence'] > 0.6
    
    def test_pattern_weights(self):
        """Test that different patterns have appropriate weights"""
        matcher = PatternMatcher()
        
        # Test eval vs innerHTML weights
        eval_script = "eval('malicious code');"
        innerHTML_script = "element.innerHTML = data;"
        
        eval_density, _ = matcher.calculate_suspicion_density(eval_script)
        innerHTML_density, _ = matcher.calculate_suspicion_density(innerHTML_script)
        
        # Eval should have higher weight (10) than innerHTML (8)
        assert eval_density > innerHTML_density
    
    def test_xss_patterns(self):
        """Test XSS-related pattern detection"""
        matcher = PatternMatcher()
        
        xss_script = """
        document.getElementById('content').innerHTML = userInput;
        document.write('<script>alert("xss")</script>');
        element.outerHTML = '<div>' + data + '</div>';
        """
        
        density, matches = matcher.calculate_suspicion_density(xss_script)
        
        assert density > 0.3
        assert any(m['category'] == 'xss' for m in matches)
        assert any(m['pattern'] == 'innerHTML_dangerous' for m in matches)
        assert any(m['pattern'] == 'document_write' for m in matches)
    
    def test_code_injection_patterns(self):
        """Test code injection pattern detection"""
        matcher = PatternMatcher()
        
        injection_script = """
        eval(userCode);
        new Function('return ' + userInput)();
        setTimeout('alert("injection")', 1000);
        """
        
        density, matches = matcher.calculate_suspicion_density(injection_script)
        
        assert density > 0.4
        assert any(m['category'] == 'code_injection' for m in matches)
        assert any(m['pattern'] == 'eval_usage' for m in matches)
        assert any(m['pattern'] == 'function_constructor' for m in matches)
        assert any(m['pattern'] == 'setTimeout_string' for m in matches)
    
    def test_prototype_pollution_patterns(self):
        """Test prototype pollution pattern detection"""
        matcher = PatternMatcher()
        
        pollution_script = """
        obj.__proto__.isAdmin = true;
        obj.constructor.prototype.polluted = 'value';
        """
        
        density, matches = matcher.calculate_suspicion_density(pollution_script)
        
        assert density > 0.2
        assert any(m['category'] == 'prototype_pollution' for m in matches)
        assert any(m['pattern'] == 'prototype_pollution' for m in matches)
    
    def test_data_exposure_patterns(self):
        """Test data exposure pattern detection"""
        matcher = PatternMatcher()
        
        exposure_script = """
        localStorage.setItem('password', userPassword);
        localStorage.setItem('token', authToken);
        sessionStorage.setItem('secret', secretKey);
        """
        
        density, matches = matcher.calculate_suspicion_density(exposure_script)
        
        assert density > 0.1
        assert any(m['category'] == 'data_exposure' for m in matches)
        assert any(m['pattern'] == 'localStorage_unsafe' for m in matches)
    
    def test_third_party_library_detection(self):
        """Test detection of various third-party libraries"""
        matcher = PatternMatcher()
        
        libraries = [
            ("https://unpkg.com/react@17/umd/react.production.min.js", "React library"),
            ("https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js", "Vue library"),
            ("https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js", "Angular library"),
            ("https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js", "Bootstrap library"),
            ("https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js", "Lodash library")
        ]
        
        for url, description in libraries:
            result = matcher.is_custom_script(url, description)
            assert not result['is_custom'], f"Should detect {description} as third-party"
            assert result['confidence'] < 0.5
    
    def test_custom_script_indicators(self):
        """Test detection of custom script indicators"""
        matcher = PatternMatcher()
        
        custom_scripts = [
            ("https://example.com/static/js/app.js", "function myApp() { return true; }"),
            ("https://mysite.com/assets/js/main.js", "var config = { api: 'test' };"),
            ("https://app.example.com/js/custom.js", "class MyClass { constructor() {} }"),
            ("https://example.com/scripts/bundle.js", "const utils = { process: function() {} };")
        ]
        
        for url, content in custom_scripts:
            result = matcher.is_custom_script(url, content)
            assert result['is_custom'], f"Should detect {url} as custom"
            assert result['confidence'] > 0.6
    
    def test_mixed_content_analysis(self):
        """Test analysis of scripts with mixed custom and library content"""
        matcher = PatternMatcher()
        
        # Script that includes both custom code and library usage
        mixed_script = """
        // Custom application code
        function processUserData(data) {
            var result = JSON.parse(data);  // Using native JSON
            return result;
        }
        
        // More custom code
        document.getElementById('submit').addEventListener('click', function() {
            var input = document.getElementById('userInput').value;
            processUserData(input);
        });
        """
        
        result = matcher.is_custom_script("https://example.com/app.js", mixed_script)
        # Should be detected as custom
        assert result['is_custom']
        assert result['indicators']['custom_content']
    
    def test_empty_script_handling(self):
        """Test handling of empty or minimal scripts"""
        matcher = PatternMatcher()
        
        empty_script = ""
        density, matches = matcher.calculate_suspicion_density(empty_script)
        
        assert density == 0.0
        assert len(matches) == 0
        
        # Test with whitespace only
        whitespace_script = "   \n\t  \n  "
        density, matches = matcher.calculate_suspicion_density(whitespace_script)
        
        assert density == 0.0
        assert len(matches) == 0
    
    def test_case_insensitive_matching(self):
        """Test that pattern matching is case insensitive"""
        matcher = PatternMatcher()
        
        case_variations = [
            "EVAL(userInput);",
            "Eval(userInput);",
            "eval(userInput);",
            "document.InnerHTML = data;",
            "document.innerHTML = data;",
            "document.innerhtml = data;"
        ]
        
        for script in case_variations:
            density, matches = matcher.calculate_suspicion_density(script)
            assert density > 0.0, f"Should detect pattern in {script}"
            assert len(matches) > 0
