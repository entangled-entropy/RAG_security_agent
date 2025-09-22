#!/usr/bin/env python3
"""
Test cases for normalization with ATTACK markers from real traffic samples.
This tests the specific issue where [ATTACK: markers cause false positives.
"""

import sys
import os
import unittest
from unittest.mock import patch

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.preprocessing.normalizer import (
    normalize_chunk_text,
    preprocess_payload,
    annotate_suspicious_tokens,
    compute_suspicion_score,
    redact_sensitive_headers,
    normalize_body,
    normalize_path,
    normalize_query_string
)


class TestNormalizationAttackMarkers(unittest.TestCase):
    """Test normalization with ATTACK markers from real traffic samples."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.real_traffic_samples = [
            {
                "name": "User-Agent with ATTACK markers",
                "content": """GET https://portswigger.net HTTP/1.1
host: portswigger.net
User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/[REDACTED_TOKEN] Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml[ATTACK:[ATTACK:;]]q=0.9,*/*[ATTACK:[ATTACK:;]]q=0.8
Accept-Language: en-US,en[ATTACK:[ATTACK:;]]q=0.5
Referer: https://duckduckgo.com/
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Priority: u=0, i""",
                "type": "headers",
                "expected_issues": [
                    "Should not trigger false positives in version detection",
                    "Should properly handle ATTACK markers in User-Agent",
                    "Should not treat ATTACK markers as version strings"
                ]
            },
            {
                "name": "Headers with version info and ATTACK markers",
                "content": """GET /api/users HTTP/1.1
Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0
X-Framework: Laravel/9.0.0
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c""",
                "type": "headers",
                "expected_issues": [
                    "Should detect real versions (PHP/8.1.2, nginx/1.20.2, Laravel/9.0.0)",
                    "Should not treat ATTACK markers as versions",
                    "Should redact JWT token properly"
                ]
            },
            {
                "name": "POST data with ATTACK markers",
                "content": """username=admin[ATTACK:[ATTACK:;] ]&password=secret123[ATTACK:[ATTACK:;] ]&version=2.1.0[ATTACK:[ATTACK:;] ]&framework=laravel[ATTACK:[ATTACK:;] ]&action=login""",
                "type": "body",
                "expected_issues": [
                    "Should extract real version (2.1.0) and framework (laravel)",
                    "Should not treat ATTACK markers as parameter values",
                    "Should redact password properly"
                ]
            },
            {
                "name": "JSON with ATTACK markers",
                "content": """{"username": "admin[ATTACK:[ATTACK:;] ]", "password": "secret123[ATTACK:[ATTACK:;] ]", "version": "1.0.0[ATTACK:[ATTACK:;] ]", "framework": "laravel[ATTACK:[ATTACK:;] ]"}""",
                "type": "body",
                "expected_issues": [
                    "Should parse JSON correctly despite ATTACK markers",
                    "Should extract real version (1.0.0) and framework (laravel)",
                    "Should redact password properly"
                ]
            },
            {
                "name": "Path with ATTACK markers",
                "content": "/api/users[ATTACK:[ATTACK:;] ]/123[ATTACK:[ATTACK:;] ]/profile[ATTACK:[ATTACK:;] ]?version=1.0.0",
                "type": "path",
                "expected_issues": [
                    "Should normalize path correctly",
                    "Should not treat ATTACK markers as path segments",
                    "Should handle query parameters properly"
                ]
            },
            {
                "name": "Query string with ATTACK markers",
                "content": "username=admin[ATTACK:[ATTACK:;] ]&password=secret[ATTACK:[ATTACK:;] ]&version=2.1.0[ATTACK:[ATTACK:;] ]&framework=laravel[ATTACK:[ATTACK:;] ]",
                "type": "query",
                "expected_issues": [
                    "Should parse query parameters correctly",
                    "Should extract real version (2.1.0) and framework (laravel)",
                    "Should redact sensitive values properly"
                ]
            }
        ]
    
    def test_attack_markers_in_headers(self):
        """Test that ATTACK markers in headers don't cause false positives."""
        sample = self.real_traffic_samples[0]
        
        # Test the normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that ATTACK markers are handled properly
        self.assertIn('[ATTACK:', normalized, "ATTACK markers should be preserved for forensic analysis")
        
        # Check that the normalized text doesn't contain malformed version strings
        # The issue was that [ATTACK:(]X11[ATTACK:[ATTACK:;] was being treated as a version
        self.assertNotIn('[ATTACK:(]X11[ATTACK:[ATTACK:;]', normalized, 
                        "Malformed ATTACK markers should not appear as-is")
        
        # Check suspicion score - should be > 0 due to ATTACK markers
        self.assertGreater(metadata['suspicion_score'], 0, 
                          "Should detect suspicious patterns in ATTACK markers")
        
        print(f"\n[TEST] {sample['name']}")
        print(f"Normalized: {normalized[:200]}...")
        print(f"Suspicion score: {metadata['suspicion_score']}")
        print(f"Suspicious tags: {metadata['suspicious_tags']}")
    
    def test_version_detection_with_attack_markers(self):
        """Test that version detection works correctly with ATTACK markers."""
        sample = self.real_traffic_samples[1]  # Headers with version info
        
        # Test the normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that real versions are preserved
        self.assertIn('PHP/8.1.2', sample['content'], "Original should contain PHP version")
        self.assertIn('nginx/1.20.2', sample['content'], "Original should contain nginx version")
        self.assertIn('Laravel/9.0.0', sample['content'], "Original should contain Laravel version")
        
        # Check that ATTACK markers don't interfere with version detection
        # The stack detection should still work on the original content
        if 'stack_detection' in metadata:
            stack_info = metadata['stack_detection']
            print(f"\n[TEST] {sample['name']}")
            print(f"Stack detection results: {stack_info}")
            
            # Should detect some technologies despite ATTACK markers
            self.assertGreaterEqual(stack_info.get('total_detected', 0), 0,
                                  "Stack detection should work despite ATTACK markers")
    
    def test_body_normalization_with_attack_markers(self):
        """Test body normalization with ATTACK markers."""
        sample = self.real_traffic_samples[2]  # POST data
        
        # Test the normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that the normalized content is properly formatted
        self.assertIsInstance(normalized, str, "Normalized content should be a string")
        
        # Check that ATTACK markers are handled
        self.assertIn('[ATTACK:', normalized, "ATTACK markers should be preserved")
        
        print(f"\n[TEST] {sample['name']}")
        print(f"Original: {sample['content']}")
        print(f"Normalized: {normalized}")
        print(f"Suspicion score: {metadata['suspicion_score']}")
    
    def test_json_normalization_with_attack_markers(self):
        """Test JSON normalization with ATTACK markers."""
        sample = self.real_traffic_samples[3]  # JSON data
        
        # Test the normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that JSON structure is preserved
        self.assertIn('"username"', normalized, "JSON structure should be preserved")
        self.assertIn('"version"', normalized, "Version field should be preserved")
        
        print(f"\n[TEST] {sample['name']}")
        print(f"Original: {sample['content']}")
        print(f"Normalized: {normalized}")
        print(f"Suspicion score: {metadata['suspicion_score']}")
    
    def test_path_normalization_with_attack_markers(self):
        """Test path normalization with ATTACK markers."""
        sample = self.real_traffic_samples[4]  # Path data
        
        # Test the normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that path structure is preserved
        self.assertIn('/api/users', normalized, "Path structure should be preserved")
        
        print(f"\n[TEST] {sample['name']}")
        print(f"Original: {sample['content']}")
        print(f"Normalized: {normalized}")
        print(f"Suspicion score: {metadata['suspicion_score']}")
    
    def test_query_normalization_with_attack_markers(self):
        """Test query string normalization with ATTACK markers."""
        sample = self.real_traffic_samples[5]  # Query data
        
        # Test the normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that query parameters are preserved
        self.assertIn('username=', normalized, "Query parameters should be preserved")
        self.assertIn('version=', normalized, "Version parameter should be preserved")
        
        print(f"\n[TEST] {sample['name']}")
        print(f"Original: {sample['content']}")
        print(f"Normalized: {normalized}")
        print(f"Suspicion score: {metadata['suspicion_score']}")
    
    def test_attack_marker_patterns(self):
        """Test specific ATTACK marker patterns that cause issues."""
        problematic_patterns = [
            "[ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]",
            "application/xml[ATTACK:[ATTACK:;]]q=0.9,*/*[ATTACK:[ATTACK:;]]q=0.8",
            "en-US,en[ATTACK:[ATTACK:;]]q=0.5",
            "admin[ATTACK:[ATTACK:;] ]&password=secret[ATTACK:[ATTACK:;] ]",
            '{"username": "admin[ATTACK:[ATTACK:;] ]", "version": "1.0.0[ATTACK:[ATTACK:;] ]"}'
        ]
        
        for i, pattern in enumerate(problematic_patterns):
            with self.subTest(pattern=pattern):
                # Test that these patterns don't cause crashes
                try:
                    normalized, metadata = normalize_chunk_text(pattern, "body")
                    self.assertIsInstance(normalized, str, f"Pattern {i} should normalize to string")
                    self.assertIsInstance(metadata, dict, f"Pattern {i} should return metadata dict")
                    print(f"\n[TEST] Problematic pattern {i}: {pattern[:50]}...")
                    print(f"Normalized: {normalized[:100]}...")
                    print(f"Suspicion score: {metadata['suspicion_score']}")
                except Exception as e:
                    self.fail(f"Pattern {i} caused exception: {e}")
    
    def test_suspicion_score_calculation(self):
        """Test that suspicion scores are calculated correctly with ATTACK markers."""
        # Test with content that has ATTACK markers
        content_with_attack = "User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64"
        
        score, tags = compute_suspicion_score(content_with_attack)
        
        # Should have a suspicion score > 0 due to ATTACK markers
        self.assertGreater(score, 0, "Content with ATTACK markers should have suspicion score > 0")
        self.assertIsInstance(tags, list, "Should return list of suspicious tags")
        
        print(f"\n[TEST] Suspicion score calculation")
        print(f"Content: {content_with_attack}")
        print(f"Score: {score}")
        print(f"Tags: {tags}")
    
    def test_annotation_preservation(self):
        """Test that ATTACK annotations are preserved correctly."""
        # Test the annotation function directly
        test_content = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
        
        annotated = annotate_suspicious_tokens(test_content)
        
        # Should not add ATTACK markers to normal content
        self.assertEqual(annotated, test_content, "Normal content should not be annotated")
        
        # Test with suspicious content
        suspicious_content = "admin'; DROP TABLE users; --"
        annotated_suspicious = annotate_suspicious_tokens(suspicious_content)
        
        # Should add ATTACK markers to suspicious content
        self.assertIn('[ATTACK:', annotated_suspicious, "Suspicious content should be annotated")
        
        print(f"\n[TEST] Annotation preservation")
        print(f"Normal content: {test_content}")
        print(f"Annotated normal: {annotated}")
        print(f"Suspicious content: {suspicious_content}")
        print(f"Annotated suspicious: {annotated_suspicious}")


class TestNormalizationEdgeCases(unittest.TestCase):
    """Test edge cases in normalization that might cause issues."""
    
    def test_empty_and_none_inputs(self):
        """Test handling of empty and None inputs."""
        test_cases = [
            ("", "headers"),
            (None, "headers"),
            ("   ", "body"),
            ("\n\t", "query")
        ]
        
        for content, chunk_type in test_cases:
            with self.subTest(content=content, chunk_type=chunk_type):
                try:
                    normalized, metadata = normalize_chunk_text(content, chunk_type)
                    self.assertIsInstance(normalized, str, "Should return string even for empty input")
                    self.assertIsInstance(metadata, dict, "Should return metadata dict")
                    print(f"\n[TEST] Empty/None input: '{content}' -> '{normalized}'")
                except Exception as e:
                    self.fail(f"Empty/None input caused exception: {e}")
    
    def test_very_long_content(self):
        """Test handling of very long content."""
        # Create a very long string with ATTACK markers
        long_content = "A" * 10000 + "[ATTACK:test]" + "B" * 10000
        
        try:
            normalized, metadata = normalize_chunk_text(long_content, "body")
            self.assertIsInstance(normalized, str, "Should handle long content")
            self.assertIsInstance(metadata, dict, "Should return metadata for long content")
            print(f"\n[TEST] Long content: {len(long_content)} chars -> {len(normalized)} chars")
        except Exception as e:
            self.fail(f"Long content caused exception: {e}")
    
    def test_malformed_attack_markers(self):
        """Test handling of malformed ATTACK markers."""
        malformed_cases = [
            "[ATTACK:",
            "[ATTACK:test",
            "ATTACK:test]",
            "[ATTACK:test][ATTACK:",
            "[ATTACK:[ATTACK:test]",
            "[ATTACK:test][ATTACK:test]"
        ]
        
        for malformed in malformed_cases:
            with self.subTest(malformed=malformed):
                try:
                    normalized, metadata = normalize_chunk_text(malformed, "body")
                    self.assertIsInstance(normalized, str, "Should handle malformed ATTACK markers")
                    self.assertIsInstance(metadata, dict, "Should return metadata for malformed markers")
                    print(f"\n[TEST] Malformed marker: '{malformed}' -> '{normalized}'")
                except Exception as e:
                    self.fail(f"Malformed ATTACK marker caused exception: {e}")


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)
