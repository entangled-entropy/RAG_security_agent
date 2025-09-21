#!/usr/bin/env python3
"""
Direct test for normalization with ATTACK markers.
This directly imports the normalizer module to avoid dependency issues.
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
spec.loader.exec_module(normalizer)


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
        normalized, metadata = normalizer.normalize_chunk_text(problematic_content, "headers")
        
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
            normalized, metadata = normalizer.normalize_chunk_text(pattern, "body")
            print(f"  ✅ Normalized successfully")
            print(f"  Length: {len(normalized)} chars")
            print(f"  Suspicion score: {metadata.get('suspicion_score', 0)}")
            print(f"  Normalized: {normalized[:100]}...")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")


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
            score, tags = normalizer.compute_suspicion_score(test_case['content'])
            print(f"  Score: {score}")
            print(f"  Tags: {tags}")
            
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


def test_annotation_function():
    """Test the annotation function directly."""
    
    print("\n[TEST] Annotation function")
    print("=" * 60)
    
    # Test the annotation function directly
    test_cases = [
        {
            "name": "Normal content",
            "content": "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0",
            "should_annotate": False
        },
        {
            "name": "Suspicious content",
            "content": "admin'; DROP TABLE users; --",
            "should_annotate": True
        },
        {
            "name": "Content with ATTACK markers",
            "content": "User-Agent: Mozilla/5.0 [ATTACK:(]X11[ATTACK:[ATTACK:;] ]Linux x86_64[ATTACK:[ATTACK:;] ]rv:142.0[ATTACK:) ]Gecko/20100101 Firefox/142.0",
            "should_annotate": False  # Already has ATTACK markers
        }
    ]
    
    for test_case in test_cases:
        print(f"\n{test_case['name']}:")
        print(f"  Content: {test_case['content'][:50]}...")
        
        try:
            annotated = normalizer.annotate_suspicious_tokens(test_case['content'])
            print(f"  Annotated: {annotated[:100]}...")
            
            if test_case['should_annotate']:
                if '[ATTACK:' in annotated:
                    print("  ✅ Content was annotated as expected")
                else:
                    print("  ❌ Content should have been annotated but wasn't")
            else:
                if '[ATTACK:' in annotated:
                    print("  ⚠️  Content was annotated but shouldn't have been")
                else:
                    print("  ✅ Content was not annotated as expected")
                    
        except Exception as e:
            print(f"  ❌ Error: {e}")


if __name__ == "__main__":
    print("Testing normalization with ATTACK markers")
    print("=" * 60)
    
    test_real_problematic_traffic()
    test_attack_marker_patterns()
    test_suspicion_score_calculation()
    test_annotation_function()
    
    print("\n" + "=" * 60)
    print("Testing completed!")
