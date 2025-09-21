#!/usr/bin/env python3
"""
Test the fix for ATTACK markers - should return clean normalized text instead of annotated version.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Direct import of the normalizer module
import importlib.util
spec = importlib.util.spec_from_file_location(
    "normalizer", 
    os.path.join(os.path.dirname(__file__), '..', 'src', 'zap_rag_security_agent', 'preprocessing', 'normalizer.py')
)
normalizer = importlib.util.module_from_spec(spec)

# Mock the stack detector to avoid import issues
class MockStackDetector:
    @staticmethod
    def detect_stack_from_traffic(**kwargs):
        return {
            "total_detected": 0,
            "confidence": 0.0,
            "detection_methods": [],
            "standard_libraries": [],
            "custom_libraries": [],
            "component_candidates": [],
            "security_analysis": {
                "total_security_issues": 0,
                "high_severity_issues": 0,
                "medium_severity_issues": 0,
                "security_risk_score": 0,
                "has_vulnerabilities": False,
                "credential_analysis": {"has_credentials": False},
                "post_data_analysis": {"has_attacks": False}
            }
        }

# Mock the stack detector import
normalizer.detect_stack_from_traffic = MockStackDetector.detect_stack_from_traffic

# Now load the module
spec.loader.exec_module(normalizer)


def test_attack_markers_fix():
    """Test that the fix returns clean normalized text instead of annotated version."""
    
    print("[TEST] ATTACK markers fix - should return clean text")
    print("=" * 60)
    
    # Real problematic traffic from the user's issue
    problematic_content = """GET https://portswigger.net HTTP/1.1
host: portswigger.net
User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/[REDACTED_TOKEN] Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml[ATTACK:[ATTACK:;]]q=0.9,*/*[ATTACK:[ATTACK:;]]q=0.8
Accept-Language: en-US,en[ATTACK:[ATTACK:;]]q=0.5"""
    
    print("Original content:")
    for i, line in enumerate(problematic_content.split('\n')):
        print(f"  {i+1}: {line}")
    
    # Test normalization
    try:
        normalized, metadata = normalizer.normalize_chunk_text(problematic_content, "headers")
        
        print(f"\n✅ Normalization successful")
        print(f"Normalized length: {len(normalized)} chars")
        print(f"Suspicion score: {metadata.get('suspicion_score', 0)}")
        print(f"Suspicious tags: {metadata.get('suspicious_tags', [])}")
        
        # Check that the returned text is clean (no ATTACK markers)
        if '[ATTACK:' in normalized:
            print("❌ FAIL: Normalized text still contains ATTACK markers")
            print("This means the fix didn't work properly")
        else:
            print("✅ SUCCESS: Normalized text is clean (no ATTACK markers)")
        
        # Check that ATTACK markers are preserved in metadata for forensic analysis
        if 'annotated_text' in metadata and '[ATTACK:' in metadata['annotated_text']:
            print("✅ SUCCESS: ATTACK markers preserved in metadata for forensic analysis")
        else:
            print("⚠️  WARNING: ATTACK markers not preserved in metadata")
        
        # Print the clean normalized content
        print(f"\nClean normalized content:")
        for i, line in enumerate(normalized.split('\n')):
            print(f"  {i+1}: {line}")
        
        # Print the annotated version from metadata (for forensic analysis)
        if 'annotated_text' in metadata:
            print(f"\nAnnotated version (for forensic analysis):")
            annotated_lines = metadata['annotated_text'].split('\n')
            for i, line in enumerate(annotated_lines[:5]):  # First 5 lines only
                print(f"  {i+1}: {line}")
            if len(annotated_lines) > 5:
                print(f"  ... ({len(annotated_lines) - 5} more lines)")
            
    except Exception as e:
        print(f"❌ Error during normalization: {e}")
        import traceback
        traceback.print_exc()


def test_version_detection_after_fix():
    """Test that version detection works correctly after the fix."""
    
    print("\n[TEST] Version detection after ATTACK markers fix")
    print("=" * 60)
    
    # Test content with real versions and ATTACK markers
    test_content = """User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel/9.0.0"""
    
    print("Test content:")
    for line in test_content.split('\n'):
        print(f"  {line}")
    
    # Expected versions that should be detectable
    expected_versions = ["Firefox/142.0", "PHP/8.1.2", "nginx/1.20.2", "Laravel/9.0.0"]
    
    try:
        normalized, metadata = normalizer.normalize_chunk_text(test_content, "headers")
        
        print(f"\n✅ Normalization successful")
        print(f"Suspicion score: {metadata.get('suspicion_score', 0)}")
        
        # Check that the normalized text is clean
        if '[ATTACK:' in normalized:
            print("❌ FAIL: Normalized text contains ATTACK markers")
        else:
            print("✅ SUCCESS: Normalized text is clean")
        
        # Check that real versions are still in the normalized text
        print(f"\nVersion detection check:")
        for version in expected_versions:
            if version in normalized:
                print(f"  ✅ Found: {version}")
            else:
                print(f"  ❌ Missing: {version}")
        
        # Check that ATTACK markers are not treated as versions
        attack_patterns = ["[ATTACK:(]X11", "[ATTACK:[ATTACK:;]", "[ATTACK:) ]"]
        print(f"\nFalse positive check:")
        for pattern in attack_patterns:
            if pattern in normalized:
                print(f"  ❌ False positive: {pattern} found in normalized text")
            else:
                print(f"  ✅ No false positive: {pattern} not in normalized text")
        
        # Print the clean normalized content
        print(f"\nClean normalized content:")
        for i, line in enumerate(normalized.split('\n')):
            print(f"  {i+1}: {line}")
            
    except Exception as e:
        print(f"❌ Error during normalization: {e}")
        import traceback
        traceback.print_exc()


def test_suspicion_score_still_works():
    """Test that suspicion score calculation still works after the fix."""
    
    print("\n[TEST] Suspicion score calculation after fix")
    print("=" * 60)
    
    test_cases = [
        {
            "name": "Normal content",
            "content": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0",
            "expected_score": 0
        },
        {
            "name": "Content with ATTACK markers",
            "content": "User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0",
            "expected_score": "> 0"
        },
        {
            "name": "Suspicious content",
            "content": "admin'; DROP TABLE users; --",
            "expected_score": "> 0"
        }
    ]
    
    for test_case in test_cases:
        print(f"\n{test_case['name']}:")
        print(f"  Content: {test_case['content'][:50]}...")
        
        try:
            normalized, metadata = normalizer.normalize_chunk_text(test_case['content'], "headers")
            score = metadata.get('suspicion_score', 0)
            tags = metadata.get('suspicious_tags', [])
            
            print(f"  Score: {score}")
            print(f"  Tags: {tags}")
            print(f"  Normalized: {normalized[:100]}...")
            
            # Check that normalized text is clean
            if '[ATTACK:' in normalized:
                print("  ❌ Normalized text contains ATTACK markers")
            else:
                print("  ✅ Normalized text is clean")
            
            # Check score expectations
            if test_case['expected_score'] == 0:
                if score == 0:
                    print("  ✅ Expected score 0")
                else:
                    print(f"  ❌ Expected score 0, got {score}")
            elif test_case['expected_score'] == "> 0":
                if score > 0:
                    print("  ✅ Expected score > 0")
                else:
                    print(f"  ❌ Expected score > 0, got {score}")
                    
        except Exception as e:
            print(f"  ❌ Error: {e}")


if __name__ == "__main__":
    print("Testing ATTACK markers fix")
    print("=" * 60)
    
    test_attack_markers_fix()
    test_version_detection_after_fix()
    test_suspicion_score_still_works()
    
    print("\n" + "=" * 60)
    print("Testing completed!")
