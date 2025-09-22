#!/usr/bin/env python3
"""
No longer needed
Test cases for version detection with ATTACK markers.
This specifically tests the issue where ATTACK markers interfere with version detection.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text
from zap_rag_security_agent.detectors.stack_detector import detect_stack_from_traffic


class TestVersionDetectionWithAttackMarkers(unittest.TestCase):
    """Test version detection with ATTACK markers from real traffic samples."""
    
    def setUp(self):
        """Set up test fixtures with real traffic samples."""
        self.version_detection_samples = [
            {
                "name": "User-Agent with Firefox version and ATTACK markers",
                "content": """GET https://portswigger.net HTTP/1.1
host: portswigger.net
User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml[ATTACK:[ATTACK:;]]q=0.9,*/*[ATTACK:[ATTACK:;]]q=0.8
Accept-Language: en-US,en[ATTACK:[ATTACK:;]]q=0.5""",
                "type": "headers",
                "expected_versions": {
                    "Firefox": "142.0",
                    "Gecko": "20100101"
                },
                "should_not_detect": [
                    "[ATTACK:(]X11",
                    "[ATTACK:[ATTACK:;]",
                    "[ATTACK:) ]"
                ]
            },
            {
                "name": "Headers with multiple versions and ATTACK markers",
                "content": """GET /api/users HTTP/1.1
Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0
X-Framework: Laravel/9.0.0
X-Application: MyApp/2.3.1
Content-Type: application/json; charset=utf-8""",
                "type": "headers",
                "expected_versions": {
                    "PHP": "8.1.2",
                    "nginx": "1.20.2",
                    "Laravel": "9.0.0",
                    "MyApp": "2.3.1",
                    "Firefox": "142.0"
                },
                "should_not_detect": [
                    "[ATTACK:(]X11",
                    "[ATTACK:[ATTACK:;]",
                    "[ATTACK:) ]"
                ]
            },
            {
                "name": "HTML with library versions and ATTACK markers",
                "content": """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/js/bootstrap.bundle.min.js"></script>
    <script>
        // Some JavaScript with ATTACK markers
        var user = "admin[ATTACK:[ATTACK:;] ]";
        var version = "1.0.0[ATTACK:[ATTACK:;] ]";
        console.log("Version: " + version);
    </script>
</head>
<body>
    <h1>Test Page</h1>
    <div class="container">
        <p>Content with [ATTACK:test] markers</p>
    </div>
</body>
</html>""",
                "type": "body",
                "expected_versions": {
                    "jQuery": "3.6.0",
                    "Bootstrap": "5.2.3"
                },
                "should_not_detect": [
                    "[ATTACK:[ATTACK:;]",
                    "[ATTACK:test]"
                ]
            },
            {
                "name": "POST data with version info and ATTACK markers",
                "content": """username=admin[ATTACK:[ATTACK:;] ]&password=secret123[ATTACK:[ATTACK:;] ]&version=2.1.0[ATTACK:[ATTACK:;] ]&framework=laravel[ATTACK:[ATTACK:;] ]&app_version=1.5.2[ATTACK:[ATTACK:;] ]&action=login""",
                "type": "body",
                "expected_versions": {
                    "version": "2.1.0",
                    "app_version": "1.5.2"
                },
                "should_not_detect": [
                    "[ATTACK:[ATTACK:;]"
                ]
            },
            {
                "name": "JSON with version info and ATTACK markers",
                "content": """{"username": "admin[ATTACK:[ATTACK:;] ]", "password": "secret123[ATTACK:[ATTACK:;] ]", "version": "1.0.0[ATTACK:[ATTACK:;] ]", "framework": "laravel[ATTACK:[ATTACK:;] ]", "app_version": "2.3.1[ATTACK:[ATTACK:;] ]", "dependencies": {"react": "18.2.0[ATTACK:[ATTACK:;] ]", "vue": "3.2.0[ATTACK:[ATTACK:;] ]"}}""",
                "type": "body",
                "expected_versions": {
                    "version": "1.0.0",
                    "app_version": "2.3.1",
                    "react": "18.2.0",
                    "vue": "3.2.0"
                },
                "should_not_detect": [
                    "[ATTACK:[ATTACK:;]"
                ]
            }
        ]
    
    def test_version_detection_with_attack_markers(self):
        """Test that version detection works correctly despite ATTACK markers."""
        for sample in self.version_detection_samples:
            with self.subTest(sample=sample['name']):
                print(f"\n[TEST] {sample['name']}")
                
                # Test normalization
                normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
                
                # Check that ATTACK markers are preserved in normalized text
                self.assertIn('[ATTACK:', normalized, "ATTACK markers should be preserved")
                
                # Check that the original content contains expected versions
                for version_name, expected_version in sample['expected_versions'].items():
                    # Check if the version appears in the original content
                    version_found = False
                    for line in sample['content'].split('\n'):
                        if expected_version in line:
                            version_found = True
                            break
                    
                    if version_found:
                        print(f"  ✓ Found expected version: {version_name} = {expected_version}")
                    else:
                        print(f"  ⚠ Expected version not found in content: {version_name} = {expected_version}")
                
                # Check that ATTACK markers are not treated as versions
                for should_not_detect in sample['should_not_detect']:
                    # The ATTACK markers should not appear as standalone version strings
                    # in the normalized text (they should be part of larger strings)
                    if should_not_detect in normalized:
                        # Check if it's part of a larger string (which is OK)
                        # or if it's treated as a standalone version (which is NOT OK)
                        lines = normalized.split('\n')
                        for line in lines:
                            if should_not_detect in line:
                                # Check if it's the only content on the line (bad)
                                if line.strip() == should_not_detect:
                                    self.fail(f"ATTACK marker '{should_not_detect}' should not be treated as standalone version")
                                else:
                                    print(f"  ✓ ATTACK marker '{should_not_detect}' properly embedded in larger string")
                
                print(f"  Normalized length: {len(normalized)} chars")
                print(f"  Suspicion score: {metadata.get('suspicion_score', 0)}")
    
    def test_stack_detection_with_attack_markers(self):
        """Test that stack detection works correctly with ATTACK markers."""
        # Mock the stack detector to avoid actual detection
        with patch('zap_rag_security_agent.preprocessing.normalizer.detect_stack_from_traffic') as mock_detect:
            # Mock return value
            mock_detect.return_value = {
                "total_detected": 3,
                "confidence": 0.85,
                "detection_methods": ["headers", "user_agent"],
                "top_component": {
                    "name": "Firefox",
                    "version": "142.0",
                    "type": "browser",
                    "confidence": 0.9,
                    "vulnerability_check": {"is_vulnerable": False}
                },
                "component_candidates": [
                    {
                        "name": "Firefox",
                        "version": "142.0",
                        "category": "browser",
                        "confidence": 0.9,
                        "vulnerability_check": {"is_vulnerable": False}
                    },
                    {
                        "name": "PHP",
                        "version": "8.1.2",
                        "category": "server",
                        "confidence": 0.8,
                        "vulnerability_check": {"is_vulnerable": False}
                    }
                ]
            }
            
            sample = self.version_detection_samples[1]  # Headers with multiple versions
            
            # Test normalization
            normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
            
            # Check that stack detection was called
            mock_detect.assert_called_once()
            
            # Check that stack detection results are in metadata
            self.assertIn('stack_detection', metadata, "Stack detection results should be in metadata")
            
            stack_info = metadata['stack_detection']
            self.assertEqual(stack_info['total_detected'], 3, "Should detect 3 technologies")
            self.assertEqual(stack_info['confidence'], 0.85, "Should have confidence 0.85")
            
            # Check top component
            self.assertIn('top_component', metadata, "Top component should be in metadata")
            top_comp = metadata['top_component']
            self.assertEqual(top_comp['name'], 'Firefox', "Top component should be Firefox")
            self.assertEqual(top_comp['version'], '142.0', "Top component version should be 142.0")
            
            print(f"\n[TEST] Stack detection with ATTACK markers")
            print(f"  Total detected: {stack_info['total_detected']}")
            print(f"  Top component: {top_comp['name']} v{top_comp['version']}")
            print(f"  Confidence: {stack_info['confidence']}")
    
    def test_version_extraction_accuracy(self):
        """Test that version extraction is accurate despite ATTACK markers."""
        # Test specific version patterns that should be detected
        version_patterns = [
            {
                "content": "Firefox/142.0",
                "expected": "142.0",
                "name": "Firefox"
            },
            {
                "content": "PHP/8.1.2",
                "expected": "8.1.2", 
                "name": "PHP"
            },
            {
                "content": "nginx/1.20.2",
                "expected": "1.20.2",
                "name": "nginx"
            },
            {
                "content": "Laravel/9.0.0",
                "expected": "9.0.0",
                "name": "Laravel"
            }
        ]
        
        for pattern in version_patterns:
            with self.subTest(pattern=pattern['name']):
                # Test with ATTACK markers around the version
                content_with_attack = f"User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 {pattern['content']}"
                
                # Test normalization
                normalized, metadata = normalize_chunk_text(content_with_attack, "headers")
                
                # The version should still be detectable in the original content
                self.assertIn(pattern['content'], content_with_attack, 
                            f"Original content should contain {pattern['name']} version")
                
                # The ATTACK markers should not interfere with version detection
                self.assertIn('[ATTACK:', normalized, "ATTACK markers should be preserved")
                
                print(f"\n[TEST] Version extraction: {pattern['name']}")
                print(f"  Expected version: {pattern['expected']}")
                print(f"  Content: {content_with_attack}")
                print(f"  Normalized: {normalized[:100]}...")
    
    def test_attack_marker_interference(self):
        """Test that ATTACK markers don't interfere with version detection."""
        # Test the specific problematic pattern from the user's issue
        problematic_content = """User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0"""
        
        # Test normalization
        normalized, metadata = normalize_chunk_text(problematic_content, "headers")
        
        # Check that the problematic pattern is handled correctly
        self.assertIn('[ATTACK:', normalized, "ATTACK markers should be preserved")
        
        # Check that the original version information is still present
        self.assertIn('Firefox/142.0', problematic_content, "Original should contain Firefox version")
        self.assertIn('rv:142.0', problematic_content, "Original should contain rv version")
        
        # The normalized text should not contain the malformed ATTACK pattern as a standalone version
        lines = normalized.split('\n')
        for line in lines:
            if '[ATTACK:(]X11[ATTACK:[ATTACK:;]' in line:
                # This should be part of a larger string, not standalone
                self.assertNotEqual(line.strip(), '[ATTACK:(]X11[ATTACK:[ATTACK:;]', 
                                  "Malformed ATTACK pattern should not be standalone")
        
        print(f"\n[TEST] ATTACK marker interference")
        print(f"  Original: {problematic_content}")
        print(f"  Normalized: {normalized}")
        print(f"  Suspicion score: {metadata.get('suspicion_score', 0)}")
    
    def test_version_detection_robustness(self):
        """Test that version detection is robust against various ATTACK marker patterns."""
        # Test various ATTACK marker patterns that might interfere
        attack_patterns = [
            "[ATTACK:(]",
            "[ATTACK:[ATTACK:;]",
            "[ATTACK:) ]",
            "[ATTACK:test]",
            "[ATTACK:malicious]",
            "[ATTACK:injection]"
        ]
        
        base_content = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
        
        for attack_pattern in attack_patterns:
            with self.subTest(attack_pattern=attack_pattern):
                # Insert ATTACK pattern into the content
                content_with_attack = base_content.replace("(", f"{attack_pattern}(")
                
                # Test normalization
                normalized, metadata = normalize_chunk_text(content_with_attack, "headers")
                
                # Should handle the ATTACK pattern without crashing
                self.assertIsInstance(normalized, str, "Should normalize without crashing")
                self.assertIsInstance(metadata, dict, "Should return metadata")
                
                # The original version should still be detectable
                self.assertIn('Firefox/142.0', content_with_attack, "Original version should be preserved")
                
                print(f"\n[TEST] Robustness test: {attack_pattern}")
                print(f"  Content: {content_with_attack}")
                print(f"  Normalized: {normalized[:100]}...")
                print(f"  Suspicion score: {metadata.get('suspicion_score', 0)}")


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)
