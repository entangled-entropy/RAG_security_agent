"""
Integration tests for the cherry-picking system.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from zap_rag_security_agent.detectors.client_script_analyzer import ClientScriptAnalyzer

class TestCherryPickingIntegration:
    def test_third_party_script_filtering(self):
        """Test that third-party scripts are filtered out"""
        analyzer = ClientScriptAnalyzer()
        
        html = """
        <html>
        <head>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
            <script>
                function customFunction() {
                    eval(userInput);
                }
            </script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html, "https://example.com")
        
        # Should only analyze the custom script, not jQuery
        assert result['scripts_analyzed'] == 2  # Both scripts analyzed
        assert len(result['scripts_for_llm']) == 1  # Only custom script for LLM
        assert result['scripts_for_llm'][0]['type'] == 'inline'
    
    def test_high_suspicion_script_detection(self):
        """Test that high suspicion scripts are detected"""
        analyzer = ClientScriptAnalyzer()
        
        html = """
        <html>
        <head>
            <script>
                // Normal code
                var x = 1;
                console.log('hello');
            </script>
            <script>
                // Suspicious code
                eval(userInput);
                document.getElementById('content').innerHTML = data;
                localStorage.setItem('password', userPassword);
                Function('return ' + userCode)();
            </script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html)
        
        # Should detect the suspicious script
        assert len(result['scripts_for_llm']) == 1
        assert any('high_suspicion_density' in reason for reason in result['scripts_for_llm'][0]['analysis']['reasons'])
    
    def test_obfuscated_script_detection(self):
        """Test that obfuscated scripts are detected"""
        analyzer = ClientScriptAnalyzer()
        
        obfuscated_script = """
        var a='H',b='e',c='l',d='o';
        var e=a+b+c+c+d;
        eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103));
        """
        
        html = f"""
        <html>
        <head>
            <script>{obfuscated_script}</script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html)
        
        # Should detect the obfuscated script
        assert len(result['scripts_for_llm']) == 1
        assert 'obfuscated_code' in result['scripts_for_llm'][0]['analysis']['reasons']
    
    def test_llm_prompt_generation(self):
        """Test LLM prompt generation"""
        analyzer = ClientScriptAnalyzer()
        
        script = {
            'url': 'https://example.com/app.js',
            'type': 'external',
            'content': 'eval(userInput);',
            'analysis': {
                'should_analyze_with_llm': True,
                'reasons': ['high_suspicion_density_0.5'],
                'confidence': 0.8,
                'stages': {
                    'custom_detection': {'confidence': 0.9},
                    'suspicion_analysis': {'density': 0.5},
                    'obfuscation_analysis': {'is_obfuscated': False}
                }
            }
        }
        
        prompt = analyzer.get_llm_analysis_prompt(script)
        
        assert 'https://example.com/app.js' in prompt
        assert 'high_suspicion_density_0.5' in prompt
        assert 'eval(userInput);' in prompt
        assert 'Security vulnerabilities' in prompt
    
    def test_mixed_script_analysis(self):
        """Test analysis of HTML with mixed script types"""
        analyzer = ClientScriptAnalyzer()
        
        html = """
        <html>
        <head>
            <!-- Third-party library -->
            <script src="https://unpkg.com/react@17/umd/react.production.min.js"></script>
            
            <!-- Normal custom script -->
            <script>
                function normalFunction() {
                    console.log('normal');
                }
            </script>
            
            <!-- Suspicious custom script -->
            <script>
                eval(userInput);
                document.write(data);
            </script>
            
            <!-- Obfuscated script -->
            <script>
                var a='H',b='e',c='l',d='o';
                var e=a+b+c+c+d;
                String.fromCharCode(99,111,110,115,111,108,101);
            </script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html, "https://example.com")
        
        # Should analyze all scripts but only flag suspicious ones for LLM
        assert result['scripts_analyzed'] == 4
        assert len(result['scripts_for_llm']) >= 2  # At least suspicious and obfuscated
        
        # Check that third-party script is filtered out
        llm_scripts = result['scripts_for_llm']
        third_party_scripts = [s for s in llm_scripts if 'react' in s.get('url', '')]
        assert len(third_party_scripts) == 0
    
    def test_configuration_override(self):
        """Test that configuration can be overridden"""
        custom_config = {
            'thresholds': {
                'suspicion_density': 10.0,  # Much higher threshold
                'min_llm_confidence': 0.9   # Higher confidence requirement
            }
        }
        
        analyzer = ClientScriptAnalyzer(custom_config)
        
        html = """
        <html>
        <head>
            <script>
                // Mildly suspicious but below higher threshold
                document.getElementById('content').innerHTML = data;
            </script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html)
        
        # Should not flag for LLM due to higher thresholds
        assert len(result['scripts_for_llm']) == 0
    
    def test_caching_behavior(self):
        """Test that analysis results are cached"""
        analyzer = ClientScriptAnalyzer()
        
        html = """
        <html>
        <head>
            <script>eval(userInput);</script>
        </head>
        </html>
        """
        
        # First analysis
        result1 = analyzer.analyze_html_response(html)
        
        # Second analysis (should use cache)
        result2 = analyzer.analyze_html_response(html)
        
        # Results should be identical
        assert result1['scripts_analyzed'] == result2['scripts_analyzed']
        assert result1['scripts_for_llm'] == result2['scripts_for_llm']
    
    def test_large_script_filtering(self):
        """Test that large scripts are filtered out"""
        config = {'thresholds': {'max_script_size': 100}}  # Very small limit
        analyzer = ClientScriptAnalyzer(config)
        
        large_script = "console.log('test');" * 50  # Make it large
        
        html = f"""
        <html>
        <head>
            <script>{large_script}</script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html)
        
        # Should be filtered out due to size
        assert len(result['scripts_for_llm']) == 0
        assert result['scripts_analyzed'] == 1  # Still analyzed but not for LLM
    
    def test_summary_generation(self):
        """Test summary generation"""
        analyzer = ClientScriptAnalyzer()
        
        html = """
        <html>
        <head>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
            <script>eval(userInput);</script>
            <script>var x = 1;</script>
        </head>
        </html>
        """
        
        result = analyzer.analyze_html_response(html)
        summary = result['summary']
        
        assert summary['total_scripts'] == 3
        assert summary['inline_scripts'] == 2
        assert summary['external_scripts'] == 1
        assert summary['scripts_for_llm'] >= 1
        assert 'llm_percentage' in summary
        assert 'filtering_efficiency' in summary
