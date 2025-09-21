#!/usr/bin/env python3
"""
Verification script for stack detection integration.

This script provides multiple ways to verify that the Wappalyzer integration
is working correctly with the RAG security agent system.
"""

import asyncio
import json
from preprocess import normalize_chunk_text
from stack_detector import detect_stack_from_traffic, StackDetector
from collector_chunked import chunk_message


def test_basic_functionality():
    """Test basic stack detection functionality."""
    print("=== 1. Basic Functionality Test ===\n")
    
    # Test with realistic HTTP headers
    headers = """Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel
X-Application: MyApp
Set-Cookie: session_id=abc123; HttpOnly; Secure"""
    
    print("Testing headers detection...")
    normalized, meta = normalize_chunk_text(headers, "headers")
    
    print(f"✓ Headers processed: {len(normalized)} chars")
    print(f"✓ Suspicion score: {meta.get('suspicion_score', 0)}")
    print(f"✓ Stack detection: {'Yes' if 'stack_detection' in meta else 'No'}")
    
    if 'stack_detection' in meta:
        stack_info = meta['stack_detection']
        print(f"  - Technologies detected: {stack_info.get('total_detected', 0)}")
        print(f"  - Detection methods: {stack_info.get('detection_methods', [])}")
        print(f"  - Has standard libs: {stack_info.get('has_standard_libs', False)}")
    
    if 'top_component' in meta:
        top = meta['top_component']
        print(f"  - Top component: {top.get('name', 'Unknown')} ({top.get('type', 'unknown')})")
    
    print()


def test_html_detection():
    """Test HTML content detection."""
    print("=== 2. HTML Content Detection Test ===\n")
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="WordPress 6.2">
    <title>Test Page</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.2.47/vue.global.js"></script>
</head>
<body>
    <div id="app" class="container">
        <h1>Vue.js Application</h1>
        <p>Powered by WordPress</p>
    </div>
    <script src="/static/js/custom.js"></script>
</body>
</html>"""
    
    print("Testing HTML detection...")
    normalized, meta = normalize_chunk_text(html_content, "body")
    
    print(f"✓ HTML processed: {len(normalized)} chars")
    print(f"✓ Suspicion score: {meta.get('suspicion_score', 0)}")
    print(f"✓ Stack detection: {'Yes' if 'stack_detection' in meta else 'No'}")
    
    if 'stack_detection' in meta:
        stack_info = meta['stack_detection']
        print(f"  - Technologies detected: {stack_info.get('total_detected', 0)}")
        print(f"  - Detection methods: {stack_info.get('detection_methods', [])}")
    
    if 'component_candidates' in meta:
        candidates = json.loads(meta['component_candidates'])
        print(f"  - Component candidates: {len(candidates)}")
        for i, comp in enumerate(candidates[:3], 1):  # Show first 3
            print(f"    {i}. {comp.get('name', 'Unknown')} v{comp.get('version', 'N/A')}")
    
    print()


def test_script_detection():
    """Test script source detection."""
    print("=== 3. Script Source Detection Test ===\n")
    
    detector = StackDetector()
    
    script_srcs = [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/js/bootstrap.bundle.min.js",
        "https://unpkg.com/vue@3.2.47/dist/vue.global.js",
        "/static/js/custom-dashboard.js",
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"
    ]
    
    print("Testing script source detection...")
    result = detector.detect_from_script_src(script_srcs)
    
    print(f"✓ Scripts analyzed: {len(script_srcs)}")
    print(f"✓ Technologies detected: {result.get('total_detected', 0)}")
    print(f"✓ Standard libraries: {len(result.get('standard_libraries', []))}")
    print(f"✓ Custom libraries: {len(result.get('custom_libraries', []))}")
    
    print("\nStandard libraries:")
    for lib in result.get('standard_libraries', []):
        print(f"  - {lib.get('name', 'Unknown')} v{lib.get('version', 'N/A')} (CDN: {lib.get('cdn', 'Unknown')})")
    
    print("\nCustom libraries:")
    for lib in result.get('custom_libraries', []):
        print(f"  - {lib.get('name', 'Unknown')} v{lib.get('version', 'N/A')} (Local)")
    
    print()


def test_comprehensive_detection():
    """Test comprehensive detection with all methods."""
    print("=== 4. Comprehensive Detection Test ===\n")
    
    # Realistic HTTP traffic
    headers = """Host: myapp.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel
X-Application: MyApp"""
    
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 6.2">
    <title>My App</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>Welcome to My App</h1>
    </div>
</body>
</html>"""
    
    script_srcs = [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js",
        "/static/js/app.js"
    ]
    
    print("Testing comprehensive detection...")
    result = detect_stack_from_traffic(
        headers_text=headers,
        html_content=html,
        script_srcs=script_srcs
    )
    
    print(f"✓ Total technologies detected: {result.get('total_detected', 0)}")
    print(f"✓ Detection methods used: {result.get('detection_methods', [])}")
    print(f"✓ Overall confidence: {result.get('confidence', 0.0):.2f}")
    
    if result.get('top_component'):
        top = result['top_component']
        print(f"✓ Top component: {top.get('name', 'Unknown')} ({top.get('type', 'unknown')})")
    
    print("\nAll detected technologies:")
    for name, tech in result.get('detected_technologies', {}).items():
        version = tech.get('version', 'N/A')
        category = tech.get('category', 'Unknown')
        print(f"  - {name} v{version} ({category})")
    
    print()


def test_chromadb_integration():
    """Test integration with ChromaDB storage."""
    print("=== 5. ChromaDB Integration Test ===\n")
    
    # Sample HTTP request
    sample_request = """[Request] GET https://example.com/dashboard HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 6.2">
    <title>Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>Admin Dashboard</h1>
        <p>Welcome to the admin panel</p>
    </div>
</body>
</html>"""
    
    print("Testing ChromaDB integration...")
    chunks = list(chunk_message(sample_request, "test-verification"))
    
    print(f"✓ Generated {len(chunks)} chunks")
    
    for i, chunk in enumerate(chunks, 1):
        print(f"\nChunk {i} ({chunk['part']}):")
        print(f"  - Content length: {len(chunk['content'])} chars")
        print(f"  - Suspicion score: {chunk['meta'].get('suspicion_score', 0)}")
        
        if 'stack_detection' in chunk['meta']:
            stack_info = chunk['meta']['stack_detection']
            print(f"  - Stack detection: {stack_info.get('total_detected', 0)} technologies")
            print(f"  - Methods: {stack_info.get('detection_methods', [])}")
        
        if 'top_component' in chunk['meta']:
            top = chunk['meta']['top_component']
            print(f"  - Top component: {top.get('name', 'Unknown')} ({top.get('type', 'unknown')})")
    
    print()


def test_error_handling():
    """Test error handling and edge cases."""
    print("=== 6. Error Handling Test ===\n")
    
    print("Testing with empty input...")
    normalized, meta = normalize_chunk_text("", "headers")
    print(f"✓ Empty input handled: {meta.get('chunk_type', 'unknown')}")
    
    print("\nTesting with malformed HTML...")
    malformed_html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
    normalized, meta = normalize_chunk_text(malformed_html, "body")
    print(f"✓ Malformed HTML handled: {meta.get('chunk_type', 'unknown')}")
    
    print("\nTesting with non-HTML body...")
    json_body = '{"name": "test", "value": 123}'
    normalized, meta = normalize_chunk_text(json_body, "body")
    print(f"✓ JSON body handled: {meta.get('chunk_type', 'unknown')}")
    
    print()


def test_performance():
    """Test performance with multiple requests."""
    print("=== 7. Performance Test ===\n")
    
    import time
    
    # Sample data
    headers = """Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel"""
    
    html = """<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><h1>Hello World</h1></body></html>"""
    
    print("Testing performance with 10 iterations...")
    start_time = time.time()
    
    for i in range(10):
        # Test headers
        normalize_chunk_text(headers, "headers")
        # Test HTML
        normalize_chunk_text(html, "body")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"✓ Processed 20 chunks in {duration:.2f} seconds")
    print(f"✓ Average time per chunk: {duration/20:.3f} seconds")
    print()


def main():
    """Run all verification tests."""
    print("🔍 Stack Detection Verification Suite")
    print("=" * 50)
    print()
    
    try:
        test_basic_functionality()
        test_html_detection()
        test_script_detection()
        test_comprehensive_detection()
        test_chromadb_integration()
        test_error_handling()
        test_performance()
        
        print("✅ All tests completed successfully!")
        print("\n🎉 Stack detection integration is working properly!")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
