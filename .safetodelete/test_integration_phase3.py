"""
Integration tests for Phase 3: ZAP Collector and Agent integration with client-side script analysis.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

# Test only the collector integration since agent requires autogen dependencies
# Import directly to avoid package init issues
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'zap_rag_security_agent', 'collectors'))

from zap_collector import ZAPCollector


class TestPhase3Integration:
    def test_zap_collector_initialization_with_script_analysis(self):
        """Test that ZAP collector initializes with script analysis enabled"""
        collector = ZAPCollector(
            enable_script_analysis=True,
            script_analysis_config={
                'thresholds': {
                    'suspicion_density': 5.0,
                    'min_llm_confidence': 0.7
                }
            }
        )
        
        assert collector.enable_script_analysis is True
        assert collector.script_analysis_config['thresholds']['suspicion_density'] == 5.0
        assert collector.script_analysis_config['thresholds']['min_llm_confidence'] == 0.7
        assert collector.script_analyzer is None  # Not initialized yet

    def test_zap_collector_initialization_without_script_analysis(self):
        """Test that ZAP collector initializes with script analysis disabled"""
        collector = ZAPCollector(enable_script_analysis=False)
        
        assert collector.enable_script_analysis is False
        assert collector.script_analysis_config == {}
        assert collector.script_analyzer is None

    @pytest.mark.asyncio
    async def test_script_analysis_integration(self):
        """Test that script analysis is integrated into message processing"""
        collector = ZAPCollector(enable_script_analysis=True)
        
        # Mock the script analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze_html_response.return_value = {
            'scripts_for_llm': [
                {
                    'id': 'test-script-1',
                    'url': 'inline:test',
                    'type': 'inline',
                    'content': 'console.log("test");',
                    'analysis': {
                        'confidence': 0.8,
                        'is_suspicious': False,
                        'is_obfuscated': False,
                        'is_custom': True,
                        'complexity_score': 0.3,
                        'suspicion_density': 2.0,
                        'reasons': ['custom_code_detected']
                    }
                }
            ],
            'scripts_analyzed': 1
        }
        
        collector.script_analyzer = mock_analyzer
        
        # Test script analysis method
        resp_text = """
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
<script>
console.log("test");
</script>
</head>
<body>Test</body>
</html>
"""
        
        script_entries = await collector._analyze_client_scripts(resp_text, "test-group-1")
        
        assert len(script_entries) == 1
        assert script_entries[0].metadata['type'] == 'client_script_analysis'
        assert script_entries[0].metadata['group_id'] == 'test-group-1'
        assert script_entries[0].metadata['script_id'] == 'test-script-1'
        assert script_entries[0].metadata['is_custom'] is True
        assert script_entries[0].metadata['analysis_confidence'] == 0.8


    def test_script_analysis_error_handling(self):
        """Test error handling in script analysis"""
        collector = ZAPCollector(enable_script_analysis=True)
        
        # Mock the script analyzer to raise an exception
        mock_analyzer = Mock()
        mock_analyzer.analyze_html_response.side_effect = Exception("Test error")
        collector.script_analyzer = mock_analyzer
        
        # Test that errors are handled gracefully
        result = asyncio.run(collector._analyze_client_scripts("test", "test-group"))
        
        assert result == []  # Should return empty list on error

    def test_configuration_merging(self):
        """Test that custom configuration is properly merged with defaults"""
        custom_config = {
            'thresholds': {
                'suspicion_density': 10.0,
                'min_llm_confidence': 0.9
            },
            'max_script_size': 50000
        }
        
        collector = ZAPCollector(
            enable_script_analysis=True,
            script_analysis_config=custom_config
        )
        
        # The configuration should be passed to the script analyzer
        # We can't easily test the internal merging without initializing,
        # but we can verify the config is stored correctly
        assert collector.script_analysis_config == custom_config


if __name__ == "__main__":
    pytest.main([__file__])
