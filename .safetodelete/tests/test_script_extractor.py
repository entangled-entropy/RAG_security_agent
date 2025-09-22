"""
Test cases for script extractor functionality.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from zap_rag_security_agent.preprocessing.script_extractor import ScriptExtractor

class TestScriptExtractor:
    def test_extract_inline_scripts(self):
        """Test inline script extraction"""
        html = """
        <html>
        <head>
            <script>console.log('test');</script>
            <script>var x = 1;</script>
        </head>
        <body>
            <script>
                function test() {
                    return 'hello';
                }
            </script>
        </body>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html)
        
        assert len(result['inline_scripts']) == 3
        assert result['inline_scripts'][0]['content'] == "console.log('test');"
        assert result['inline_scripts'][1]['content'] == "var x = 1;"
        assert 'function test()' in result['inline_scripts'][2]['content']
    
    def test_extract_external_scripts(self):
        """Test external script URL extraction"""
        html = """
        <html>
        <head>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
            <script src="/static/js/app.js"></script>
        </head>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html, "https://example.com")
        
        assert len(result['external_scripts']) == 2
        assert 'jquery' in result['external_scripts'][0]['url']
        assert result['external_scripts'][1]['url'] == "https://example.com/static/js/app.js"
    
    def test_empty_scripts_ignored(self):
        """Test that empty scripts are ignored"""
        html = """
        <html>
        <head>
            <script></script>
            <script>   </script>
            <script>console.log('test');</script>
        </head>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html)
        
        assert len(result['inline_scripts']) == 1
        assert result['inline_scripts'][0]['content'] == "console.log('test');"
    
    def test_multiline_scripts(self):
        """Test extraction of multiline scripts"""
        html = """
        <html>
        <head>
            <script>
                function complexFunction() {
                    var data = {
                        name: 'test',
                        value: 123
                    };
                    return data;
                }
            </script>
        </head>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html)
        
        assert len(result['inline_scripts']) == 1
        script_content = result['inline_scripts'][0]['content']
        assert 'function complexFunction()' in script_content
        assert 'var data = {' in script_content
        assert 'return data;' in script_content
    
    def test_script_attributes(self):
        """Test that script attributes are handled correctly"""
        html = """
        <html>
        <head>
            <script type="text/javascript" async>console.log('async');</script>
            <script defer>console.log('defer');</script>
            <script type="module">console.log('module');</script>
        </head>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html)
        
        assert len(result['inline_scripts']) == 3
        assert result['inline_scripts'][0]['content'] == "console.log('async');"
        assert result['inline_scripts'][1]['content'] == "console.log('defer');"
        assert result['inline_scripts'][2]['content'] == "console.log('module');"
    
    def test_url_resolution(self):
        """Test URL resolution for relative paths"""
        html = """
        <html>
        <head>
            <script src="js/app.js"></script>
            <script src="./lib/utils.js"></script>
            <script src="../shared/common.js"></script>
        </head>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html, "https://example.com/path/to/page")
        
        assert len(result['external_scripts']) == 3
        assert result['external_scripts'][0]['url'] == "https://example.com/path/to/js/app.js"
        assert result['external_scripts'][1]['url'] == "https://example.com/path/to/lib/utils.js"
        assert result['external_scripts'][2]['url'] == "https://example.com/path/shared/common.js"
    
    def test_line_number_calculation(self):
        """Test line number calculation for scripts"""
        html = """
        <html>
        <head>
            <title>Test</title>
            <script>console.log('first');</script>
            <meta charset="utf-8">
            <script>
                console.log('second');
                var x = 1;
            </script>
        </head>
        </html>
        """
        
        extractor = ScriptExtractor()
        result = extractor.extract_scripts_from_html(html)
        
        assert len(result['inline_scripts']) == 2
        assert result['inline_scripts'][0]['line'] == 5  # After title
        assert result['inline_scripts'][1]['line'] == 7  # After meta
