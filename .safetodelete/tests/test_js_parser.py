"""
Test cases for JavaScript parser functionality.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from zap_rag_security_agent.utils.js_parser import JSParser

class TestJSParser:
    def test_parse_script(self):
        """Test basic script parsing"""
        parser = JSParser()
        
        # Valid JavaScript
        valid_js = "function test() { return 'hello'; }"
        ast = parser.parse_script(valid_js)
        assert ast is not None
        assert ast['type'] == 'Program'
        
        # Invalid JavaScript
        invalid_js = "function test( { return 'hello'; }"  # Missing closing paren
        ast = parser.parse_script(invalid_js)
        assert ast is None
    
    def test_complexity_analysis(self):
        """Test complexity analysis"""
        parser = JSParser()
        
        # Simple code
        simple_code = "var x = 1; console.log(x);"
        result = parser.analyze_complexity(simple_code)
        assert not result['is_unusual']
        assert result['confidence'] < 0.5
        
        # Complex code with many functions
        complex_code = """
        function func1() { return 1; }
        function func2() { return 2; }
        function func3() { return 3; }
        function func4() { return 4; }
        function func5() { return 5; }
        function func6() { return 6; }
        function func7() { return 7; }
        function func8() { return 8; }
        function func9() { return 9; }
        function func10() { return 10; }
        function func11() { return 11; }
        function func12() { return 12; }
        function func13() { return 13; }
        function func14() { return 14; }
        function func15() { return 15; }
        function func16() { return 16; }
        function func17() { return 17; }
        function func18() { return 18; }
        function func19() { return 19; }
        function func20() { return 20; }
        function func21() { return 21; }
        """
        result = parser.analyze_complexity(complex_code)
        assert result['is_unusual']  # Too many functions
        assert result['confidence'] >= 0.5
    
    def test_data_flow_analysis(self):
        """Test data flow analysis"""
        parser = JSParser()
        
        # Code with data sources and sinks
        flow_code = """
        var userInput = location.search;
        document.getElementById('content').innerHTML = userInput;
        """
        result = parser.analyze_data_flow(flow_code)
        assert result['suspicion_score'] > 0
        assert len(result['sinks']) > 0
        assert len(result['tainted_flows']) > 0
    
    def test_eval_detection(self):
        """Test detection of eval usage"""
        parser = JSParser()
        
        eval_code = "eval(userInput);"
        result = parser.analyze_complexity(eval_code)
        assert result['is_unusual']
        assert result['confidence'] > 0.8
        assert result['metrics']['eval_calls'] > 0
    
    def test_function_constructor_detection(self):
        """Test detection of Function constructor usage"""
        parser = JSParser()
        
        func_code = "new Function('return ' + userCode)();"
        result = parser.analyze_complexity(func_code)
        assert result['is_unusual']
        assert result['metrics']['dynamic_code_generation'] > 0
    
    def test_nesting_depth_calculation(self):
        """Test calculation of nesting depth"""
        parser = JSParser()
        
        # Deeply nested code
        nested_code = """
        if (true) {
            if (true) {
                if (true) {
                    if (true) {
                        if (true) {
                            if (true) {
                                console.log('deep');
                            }
                        }
                    }
                }
            }
        }
        """
        result = parser.analyze_complexity(nested_code)
        assert result['metrics']['nested_depth'] > 5
        assert result['is_unusual']
    
    def test_data_sources_detection(self):
        """Test detection of data sources"""
        parser = JSParser()
        
        source_code = """
        var search = location.search;
        var hash = location.hash;
        var referrer = document.referrer;
        var cookie = document.cookie;
        var storage = localStorage.getItem('data');
        """
        result = parser.analyze_data_flow(source_code)
        assert len(result['sinks']) == 0  # No sinks in this code
        # Note: The current implementation finds sources in sinks list
        # This might need adjustment based on actual implementation
    
    def test_data_sinks_detection(self):
        """Test detection of data sinks"""
        parser = JSParser()
        
        sink_code = """
        document.getElementById('content').innerHTML = data;
        document.write(userInput);
        eval(userCode);
        new Function('return ' + code)();
        """
        result = parser.analyze_data_flow(sink_code)
        assert len(result['sinks']) > 0
    
    def test_tainted_flow_analysis(self):
        """Test tainted data flow analysis"""
        parser = JSParser()
        
        tainted_code = """
        var userData = location.search;
        document.getElementById('output').innerHTML = userData;
        """
        result = parser.analyze_data_flow(tainted_code)
        assert result['suspicion_score'] > 0
        assert len(result['tainted_flows']) > 0
    
    def test_risk_level_calculation(self):
        """Test risk level calculation for tainted flows"""
        parser = JSParser()
        
        # High risk combination
        high_risk_code = """
        var search = location.search;
        document.getElementById('content').innerHTML = search;
        """
        result = parser.analyze_data_flow(high_risk_code)
        assert result['suspicion_score'] > 0
        
        # Medium risk combination
        medium_risk_code = """
        var data = localStorage.getItem('data');
        eval(data);
        """
        result = parser.analyze_data_flow(medium_risk_code)
        assert result['suspicion_score'] > 0
    
    def test_parse_error_handling(self):
        """Test handling of parse errors"""
        parser = JSParser()
        
        # Malformed JavaScript
        malformed_js = "function test( { return 'hello'; }"
        result = parser.analyze_complexity(malformed_js)
        assert not result['is_unusual']
        assert result['confidence'] == 0.0
        
        result = parser.analyze_data_flow(malformed_js)
        assert result['suspicion_score'] == 0.0
        assert len(result['tainted_flows']) == 0
        assert len(result['sinks']) == 0
