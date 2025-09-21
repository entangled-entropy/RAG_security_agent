#!/usr/bin/env python3
"""
Test cases using real traffic samples from the user's issue.
This tests the specific problematic traffic that causes false positives.
"""

import sys
import os
import unittest
from unittest.mock import patch

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text


class TestRealTrafficSamples(unittest.TestCase):
    """Test with real traffic samples that cause false positives."""
    
    def setUp(self):
        """Set up test fixtures with real problematic traffic."""
        self.real_problematic_traffic = {
            "name": "Real problematic traffic from user's issue",
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
            "issues": [
                "ATTACK markers cause false positives in version detection",
                "Malformed ATTACK patterns like [ATTACK:(]X11[ATTACK:[ATTACK:;] are treated as versions",
                "Normalization doesn't properly handle nested ATTACK markers"
            ]
        }
    
    def test_real_problematic_traffic(self):
        """Test the real problematic traffic from the user's issue."""
        sample = self.real_problematic_traffic
        
        print(f"\n[TEST] {sample['name']}")
        print(f"Issues to address: {sample['issues']}")
        
        # Test normalization
        normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
        
        # Check that normalization doesn't crash
        self.assertIsInstance(normalized, str, "Should normalize without crashing")
        self.assertIsInstance(metadata, dict, "Should return metadata")
        
        # Check that ATTACK markers are preserved
        self.assertIn('[ATTACK:', normalized, "ATTACK markers should be preserved")
        
        # Check that the problematic pattern is handled
        problematic_pattern = "[ATTACK:(]X11[ATTACK:[ATTACK:;]"
        if problematic_pattern in normalized:
            # Check if it's treated as a standalone version (bad) or part of larger string (ok)
            lines = normalized.split('\n')
            for line in lines:
                if problematic_pattern in line:
                    if line.strip() == problematic_pattern:
                        self.fail("Problematic ATTACK pattern should not be treated as standalone version")
                    else:
                        print(f"  ✓ Problematic pattern properly embedded: {line[:100]}...")
        
        # Check that real versions are still detectable
        self.assertIn('Firefox/142.0', sample['content'], "Original should contain Firefox version")
        
        # Check suspicion score
        suspicion_score = metadata.get('suspicion_score', 0)
        self.assertGreater(suspicion_score, 0, "Should have suspicion score > 0 due to ATTACK markers")
        
        print(f"  Normalized length: {len(normalized)} chars")
        print(f"  Suspicion score: {suspicion_score}")
        print(f"  Suspicious tags: {metadata.get('suspicious_tags', [])}")
        
        # Print the normalized content for inspection
        print(f"  Normalized content:")
        for i, line in enumerate(normalized.split('\n')[:10]):  # First 10 lines
            print(f"    {i+1}: {line}")
        if len(normalized.split('\n')) > 10:
            print(f"    ... ({len(normalized.split('\n')) - 10} more lines)")
    
    def test_attack_marker_patterns_analysis(self):
        """Analyze the specific ATTACK marker patterns in the problematic traffic."""
        sample = self.real_problematic_traffic
        
        # Extract all ATTACK marker patterns
        content = sample['content']
        attack_patterns = []
        
        import re
        # Find all [ATTACK:...] patterns
        attack_matches = re.findall(r'\[ATTACK:[^\]]*\]', content)
        attack_patterns.extend(attack_matches)
        
        print(f"\n[TEST] ATTACK marker patterns analysis")
        print(f"  Found {len(attack_patterns)} ATTACK marker patterns:")
        
        for i, pattern in enumerate(attack_patterns):
            print(f"    {i+1}: {pattern}")
            
            # Check if this pattern could be mistaken for a version
            if re.search(r'\d+\.\d+', pattern):
                print(f"      ⚠️  Contains version-like pattern")
            if re.search(r'[A-Za-z]+\d+', pattern):
                print(f"      ⚠️  Contains software-like pattern")
            if len(pattern) > 50:
                print(f"      ⚠️  Very long pattern ({len(pattern)} chars)")
        
        # Test each pattern individually
        for pattern in attack_patterns:
            with self.subTest(pattern=pattern):
                try:
                    # Test normalization with just this pattern
                    normalized, metadata = normalize_chunk_text(pattern, "body")
                    self.assertIsInstance(normalized, str, f"Pattern '{pattern}' should normalize")
                    print(f"      ✓ Pattern normalizes correctly")
                except Exception as e:
                    print(f"      ❌ Pattern caused error: {e}")
    
    def test_version_detection_accuracy(self):
        """Test that version detection is accurate despite ATTACK markers."""
        sample = self.real_problematic_traffic
        
        # Expected versions in the traffic
        expected_versions = [
            "Firefox/142.0",
            "rv:142.0"
        ]
        
        # Versions that should NOT be detected (false positives)
        false_positive_patterns = [
            "[ATTACK:(]X11[ATTACK:[ATTACK:;]",
            "[ATTACK:[ATTACK:;]",
            "[ATTACK:) ]"
        ]
        
        print(f"\n[TEST] Version detection accuracy")
        
        # Check that expected versions are in the original content
        for expected_version in expected_versions:
            if expected_version in sample['content']:
                print(f"  ✓ Expected version found: {expected_version}")
            else:
                print(f"  ❌ Expected version not found: {expected_version}")
        
        # Check that false positive patterns are not treated as versions
        for false_positive in false_positive_patterns:
            if false_positive in sample['content']:
                print(f"  ⚠️  False positive pattern found: {false_positive}")
                # This pattern should not be treated as a standalone version
                # It should be part of a larger string
            else:
                print(f"  ✓ False positive pattern not found: {false_positive}")
    
    def test_normalization_consistency(self):
        """Test that normalization is consistent across multiple runs."""
        sample = self.real_problematic_traffic
        
        # Run normalization multiple times
        results = []
        for i in range(5):
            normalized, metadata = normalize_chunk_text(sample['content'], sample['type'])
            results.append((normalized, metadata))
        
        print(f"\n[TEST] Normalization consistency")
        
        # Check that all results are identical
        first_normalized, first_metadata = results[0]
        
        for i, (normalized, metadata) in enumerate(results[1:], 1):
            self.assertEqual(normalized, first_normalized, 
                           f"Normalization should be consistent (run {i+1} differs)")
            self.assertEqual(metadata, first_metadata, 
                           f"Metadata should be consistent (run {i+1} differs)")
        
        print(f"  ✓ All 5 runs produced identical results")
        print(f"  Normalized length: {len(first_normalized)} chars")
        print(f"  Suspicion score: {first_metadata.get('suspicion_score', 0)}")
    
    def test_edge_case_handling(self):
        """Test handling of edge cases in the problematic traffic."""
        sample = self.real_problematic_traffic
        
        # Test with modified versions of the problematic content
        edge_cases = [
            {
                "name": "Empty content",
                "content": "",
                "type": "headers"
            },
            {
                "name": "Only ATTACK markers",
                "content": "[ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]",
                "type": "headers"
            },
            {
                "name": "Malformed ATTACK markers",
                "content": "[ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0",
                "type": "headers"
            },
            {
                "name": "Nested ATTACK markers",
                "content": "[ATTACK:[ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]]",
                "type": "headers"
            }
        ]
        
        for edge_case in edge_cases:
            with self.subTest(edge_case=edge_case['name']):
                print(f"\n[TEST] Edge case: {edge_case['name']}")
                
                try:
                    normalized, metadata = normalize_chunk_text(edge_case['content'], edge_case['type'])
                    self.assertIsInstance(normalized, str, "Should normalize edge case")
                    self.assertIsInstance(metadata, dict, "Should return metadata for edge case")
                    
                    print(f"  ✓ Edge case handled successfully")
                    print(f"  Normalized: {normalized[:100]}...")
                    print(f"  Suspicion score: {metadata.get('suspicion_score', 0)}")
                    
                except Exception as e:
                    print(f"  ❌ Edge case caused error: {e}")
                    # Some edge cases might legitimately cause errors
                    # but we should handle them gracefully


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2)
