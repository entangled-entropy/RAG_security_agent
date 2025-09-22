#!/usr/bin/env python3
"""
Simple test for normalization with ATTACK markers.
This directly imports the normalizer to avoid dependency issues.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Direct import to avoid dependency issues
from zap_rag_security_agent.preprocessing.normalizer import (
    normalize_chunk_text,
    preprocess_payload,
    annotate_suspicious_tokens,
    compute_suspicion_score
)


def test_real_problematic_traffic():
    """Test the real problematic traffic from the user's issue."""
    
    # Real problematic traffic from the user's issue
    problematic_content = """GET https://portswigger.net HTTP/1.1
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
Priority: u=0, i"""
    
    print("[TEST] Real problematic traffic from user's issue")
    print("=" * 60)
    
    # Test normalization
    try:
        normalized, metadata = normalize_chunk_text(problematic_content, "headers")
        
        print("✅ Normalization successful")
        print(f"Normalized length: {len(normalized)} chars")
        print(f"Suspicion score: {metadata.get('suspicion_score', 0)}")
        print(f"Suspicious tags: {metadata.get('suspicious_tags', [])}")
        
        # Check that ATTACK markers are preserved
        if '[ATTACK:' in normalized:
            print("✅ ATTACK markers are preserved")
        else:
            print("❌ ATTACK markers are missing")
        
        # Check for the specific problematic pattern
        problematic_pattern = "[ATTACK:(]X11[ATTACK:[ATTACK:;]"
        if problematic_pattern in normalized:
            print(f"⚠️  Problematic pattern found: {problematic_pattern}")
            
            # Check if it's treated as standalone (bad) or embedded (ok)
            lines = normalized.split('\n')
            for line in lines:
                if problematic_pattern in line:
                    if line.strip() == problematic_pattern:
                        print("❌ Problematic pattern treated as standalone version (BAD)")
                    else:
                        print("✅ Problematic pattern properly embedded in larger string (OK)")
                        print(f"   Line: {line[:100]}...")
        else:
            print("✅ Problematic pattern not found as-is")
        
        # Check that real versions are still detectable
        if 'Firefox/142.0' in problematic_content:
            print("✅ Real Firefox version found in original content")
        else:
            print("❌ Real Firefox version not found in original content")
        
        # Print first few lines of normalized content
        print("\nNormalized content (first 10 lines):")
        for i, line in enumerate(normalized.split('\n')[:10]):
            print(f"  {i+1}: {line}")
        
        if len(normalized.split('\n')) > 10:
            print(f"  ... ({len(normalized.split('\n')) - 10} more lines)")
            
    except Exception as e:
        print(f"❌ Error during normalization: {e}")
        import traceback
        traceback.print_exc()


def test_attack_marker_patterns():
    """Test specific ATTACK marker patterns."""
    
    print("\n[TEST] ATTACK marker patterns analysis")
    print("=" * 60)
    
    # Test various ATTACK marker patterns
    test_patterns = [
        "[ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]",
        "application/xml[ATTACK:[ATTACK:;]]q=0.9,*/*[ATTACK:[ATTACK:;]]q=0.8",
        "en-US,en[ATTACK:[ATTACK:;]]q=0.5",
        "admin[ATTACK:[ATTACK:;] ]&password=secret[ATTACK:[ATTACK:;] ]",
        '{"username": "admin[ATTACK:[ATTACK:;] ]", "version": "1.0.0[ATTACK:[ATTACK:;] ]"}'
    ]
    
    for i, pattern in enumerate(test_patterns):
        print(f"\nPattern {i+1}: {pattern[:50]}...")
        
        try:
            normalized, metadata = normalize_chunk_text(pattern, "body")
            print(f"  ✅ Normalized successfully")
            print(f"  Length: {len(normalized)} chars")
            print(f"  Suspicion score: {metadata.get('suspicion_score', 0)}")
            print(f"  Normalized: {normalized[:100]}...")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")


def test_version_detection_accuracy():
    """Test version detection accuracy with ATTACK markers."""
    
    print("\n[TEST] Version detection accuracy")
    print("=" * 60)
    
    # Test content with real versions and ATTACK markers
    test_content = """User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel/9.0.0"""
    
    print("Test content:")
    for line in test_content.split('\n'):
        print(f"  {line}")
    
    # Expected versions
    expected_versions = ["Firefox/142.0", "PHP/8.1.2", "nginx/1.20.2", "Laravel/9.0.0"]
    
    print(f"\nExpected versions: {expected_versions}")
    
    # Check which versions are in the original content
    for version in expected_versions:
        if version in test_content:
            print(f"  ✅ Found: {version}")
        else:
            print(f"  ❌ Missing: {version}")
    
    # Test normalization
    try:
        normalized, metadata = normalize_chunk_text(test_content, "headers")
        print(f"\n✅ Normalization successful")
        print(f"Suspicion score: {metadata.get('suspicion_score', 0)}")
        
        # Check that ATTACK markers are preserved
        if '[ATTACK:' in normalized:
            print("✅ ATTACK markers preserved")
        else:
            print("❌ ATTACK markers missing")
            
    except Exception as e:
        print(f"❌ Error during normalization: {e}")


def test_suspicion_score_calculation():
    """Test suspicion score calculation with ATTACK markers."""
    
    print("\n[TEST] Suspicion score calculation")
    print("=" * 60)
    
    # Test various content types
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
            score, tags = compute_suspicion_score(test_case['content'])
            print(f"  Score: {score}")
            print(f"  Tags: {tags}")
            
            if test_case['expected_score'] == 0:
                if score == 0:
                    print("  ✅ Expected score 0")
                else:
                    print("  ❌ Expected score 0, got {score}")
            elif test_case['expected_score'] == "> 0":
                if score > 0:
                    print("  ✅ Expected score > 0")
                else:
                    print("  ❌ Expected score > 0, got {score}")
                    
        except Exception as e:
            print(f"  ❌ Error: {e}")


if __name__ == "__main__":
    print("Testing normalization with ATTACK markers")
    print("=" * 60)
    
    test_real_problematic_traffic()
    test_attack_marker_patterns()
    test_version_detection_accuracy()
    test_suspicion_score_calculation()
    
    print("\n" + "=" * 60)
    print("Testing completed!")
