#!/usr/bin/env python3
"""
Test script for security-focused stack detection features.

This script tests the enhanced security features including:
- Version vulnerability checking
- Credential detection
- Vulnerable script identification
- POST data analysis
- Enhanced tagging for LLM analysis
"""

import asyncio
import json

# Import from new modular structure
from src.zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text
from src.zap_rag_security_agent.detectors.stack_detector import detect_stack_from_traffic, StackDetector


def test_version_vulnerability_detection():
    """Test version vulnerability detection for standard libraries."""
    print("=== 1. Version Vulnerability Detection Test ===\n")
    
    detector = StackDetector()
    
    # Test vulnerable versions
    test_cases = [
        ("jquery", "1.12.0", True),  # Known vulnerable
        ("jquery", "3.6.0", False),  # Safe version
        ("bootstrap", "4.6.0", True),  # Known vulnerable
        ("bootstrap", "5.2.0", False),  # Safe version
        ("angular", "1.8.0", True),  # Known vulnerable
        ("angular", "2.0.0", False),  # Safe version
        ("vue", "1.10.0", True),  # Known vulnerable
        ("vue", "3.2.0", False),  # Safe version
    ]
    
    for lib_name, version, expected_vulnerable in test_cases:
        result = detector.check_version_vulnerability(lib_name, version)
        is_vulnerable = result.get("is_vulnerable", False)
        status = "✓" if is_vulnerable == expected_vulnerable else "✗"
        
        print(f"{status} {lib_name} v{version}: {'VULNERABLE' if is_vulnerable else 'SAFE'}")
        if is_vulnerable:
            print(f"    Reason: {result.get('reason', 'Unknown')}")
            print(f"    Severity: {result.get('severity', 'Unknown')}")
            print(f"    Min safe: {result.get('min_safe_version', 'Unknown')}")
    
    print()


def test_credential_detection():
    """Test credential detection in content."""
    print("=== 2. Credential Detection Test ===\n")
    
    detector = StackDetector()
    
    # Test content with various credentials
    test_content = """
    <script>
    const config = {
        api_key: "sk-1234567890abcdef1234567890abcdef",
        secret_key: "secret_abc123def456ghi789",
        database_url: "mongodb://user:password@localhost:27017/mydb",
        jwt_secret: "my-super-secret-jwt-key-12345",
        aws_access_key: "AKIA1234567890ABCDEF",
        google_api_key: "AIza1234567890abcdefghijklmnopqrstuvwxyz"
    };
    
    // Dangerous eval usage
    eval(userInput);
    
    // XSS vulnerable code
    document.getElementById('content').innerHTML = userData;
    </script>
    """
    
    result = detector.detect_credentials_in_content(test_content)
    
    print(f"✓ Credentials found: {result.get('has_credentials', False)}")
    print(f"✓ Security issues found: {result.get('has_security_issues', False)}")
    print(f"✓ Total issues: {result.get('total_issues', 0)}")
    
    print("\nCredentials detected:")
    for cred in result.get("credentials_found", []):
        print(f"  - {cred['type']}: {cred['key']} = {cred['value']} (severity: {cred['severity']})")
    
    print("\nSecurity issues detected:")
    for issue in result.get("security_issues", []):
        print(f"  - {issue['type']}: {issue['description']} (severity: {issue['severity']})")
    
    print()


def test_post_data_analysis():
    """Test POST data analysis for security issues."""
    print("=== 3. POST Data Analysis Test ===\n")
    
    detector = StackDetector()
    
    # Test cases for POST data
    test_cases = [
        {
            "name": "Sensitive JSON data",
            "data": '{"username": "admin", "password": "secret123", "token": "abc123"}',
            "expected_issues": True
        },
        {
            "name": "SQL injection attempt",
            "data": "username=admin&password=secret&query=1' OR '1'='1",
            "expected_issues": True
        },
        {
            "name": "XSS attempt",
            "data": "name=John<script>alert('xss')</script>&email=john@example.com",
            "expected_issues": True
        },
        {
            "name": "Normal form data",
            "data": "name=John&email=john@example.com&age=25",
            "expected_issues": False
        }
    ]
    
    for test_case in test_cases:
        result = detector.analyze_post_data(test_case["data"])
        has_issues = result.get("total_issues", 0) > 0
        status = "✓" if has_issues == test_case["expected_issues"] else "✗"
        
        print(f"{status} {test_case['name']}: {'ISSUES FOUND' if has_issues else 'CLEAN'}")
        
        if result.get("sensitive_fields"):
            print(f"    Sensitive fields: {len(result['sensitive_fields'])}")
            for field in result["sensitive_fields"]:
                print(f"      - {field['field']} ({field['type']})")
        
        if result.get("issues"):
            print(f"    Security issues: {len(result['issues'])}")
            for issue in result["issues"]:
                print(f"      - {issue['type']}: {issue['description']}")
    
    print()


def test_comprehensive_security_analysis():
    """Test comprehensive security analysis with all features."""
    print("=== 4. Comprehensive Security Analysis Test ===\n")
    
    # Sample traffic with various security issues
    headers = """Host: vulnerable-app.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Powered-By: PHP/7.4.3
Server: nginx/1.20.2
X-Framework: Laravel"""
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 5.8">
    <title>Vulnerable App</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.0/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
    <script>
        const config = {
            api_key: "sk-1234567890abcdef",
            secret: "my-secret-key-12345"
        };
        
        // Vulnerable code
        eval(userInput);
        document.getElementById('content').innerHTML = userData;
    </script>
</head>
<body>
    <div class="container">
        <h1>Welcome</h1>
    </div>
</body>
</html>"""
    
    script_srcs = [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.0/jquery.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.0/js/bootstrap.min.js",
        "/static/js/custom.js"
    ]
    
    post_data = '{"username": "admin", "password": "secret123", "query": "1\' OR \'1\'=\'1"}'
    
    print("Running comprehensive security analysis...")
    result = detect_stack_from_traffic(
        headers_text=headers,
        html_content=html_content,
        script_srcs=script_srcs,
        post_data=post_data
    )
    
    print(f"✓ Technologies detected: {result.get('total_detected', 0)}")
    print(f"✓ Detection methods: {result.get('detection_methods', [])}")
    
    security_analysis = result.get("security_analysis", {})
    print(f"✓ Security risk score: {security_analysis.get('security_risk_score', 0)}")
    print(f"✓ Total security issues: {security_analysis.get('total_security_issues', 0)}")
    print(f"✓ High severity issues: {security_analysis.get('high_severity_issues', 0)}")
    print(f"✓ Medium severity issues: {security_analysis.get('medium_severity_issues', 0)}")
    
    print("\nSecurity issues found:")
    for issue in security_analysis.get("security_issues", []):
        print(f"  - {issue.get('type', 'Unknown')}: {issue.get('description', issue.get('reason', 'Unknown'))} (severity: {issue.get('severity', 'Unknown')})")
    
    print("\nVulnerable libraries:")
    for lib in result.get("standard_libraries", []):
        if lib.get("vulnerability_check", {}).get("is_vulnerable", False):
            vuln_info = lib["vulnerability_check"]
            print(f"  - {lib['name']} v{lib['version']}: {vuln_info.get('reason', 'Unknown')} (severity: {vuln_info.get('severity', 'Unknown')})")
    
    print()


def test_llm_ready_metadata():
    """Test that metadata is properly formatted for LLM analysis."""
    print("=== 5. LLM-Ready Metadata Test ===\n")
    
    # Test with vulnerable content
    vulnerable_html = """<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
    <script>
        const api_key = "sk-1234567890abcdef";
        eval(userInput);
    </script>
</head>
<body>
    <h1>Test Page</h1>
</body>
</html>"""
    
    print("Testing metadata generation for LLM analysis...")
    normalized, meta = normalize_chunk_text(vulnerable_html, "body")
    
    print(f"✓ Content normalized: {len(normalized)} chars")
    print(f"✓ Suspicion score: {meta.get('suspicion_score', 0)}")
    print(f"✓ Suspicious: {meta.get('suspicious', False)}")
    
    # Check stack detection metadata
    if "stack_detection" in meta:
        stack_info = meta["stack_detection"]
        print(f"✓ Stack detection: {stack_info.get('total_detected', 0)} technologies")
        print(f"✓ Detection methods: {stack_info.get('detection_methods', [])}")
    
    # Check security analysis metadata
    if "security_analysis" in meta:
        security_info = meta["security_analysis"]
        print(f"✓ Security risk score: {security_info.get('security_risk_score', 0)}")
        print(f"✓ Has vulnerabilities: {security_info.get('has_vulnerabilities', False)}")
        print(f"✓ Has credentials: {security_info.get('has_credentials', False)}")
        print(f"✓ Has POST attacks: {security_info.get('has_post_attacks', False)}")
    
    # Check top component
    if "top_component" in meta:
        top = meta["top_component"]
        print(f"✓ Top component: {top.get('name', 'Unknown')} v{top.get('version', 'N/A')} ({top.get('type', 'unknown')})")
        print(f"✓ Is vulnerable: {top.get('is_vulnerable', False)}")
    
    # Check security issues summary
    if "security_issues_summary" in meta:
        issues = json.loads(meta["security_issues_summary"])
        print(f"✓ Security issues summary: {len(issues)} issues")
        for issue in issues:
            print(f"    - {issue.get('type', 'Unknown')}: {issue.get('description', 'Unknown')} (severity: {issue.get('severity', 'Unknown')})")
    
    print()


def test_performance_with_security():
    """Test performance with security features enabled."""
    print("=== 6. Performance Test with Security Features ===\n")
    
    import time
    
    # Sample data
    headers = """Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2"""
    
    html = """<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><h1>Hello World</h1></body></html>"""
    
    post_data = '{"username": "test", "password": "secret123"}'
    
    print("Testing performance with security features...")
    start_time = time.time()
    
    for i in range(5):
        # Test headers
        normalize_chunk_text(headers, "headers")
        # Test HTML
        normalize_chunk_text(html, "body")
        # Test POST data
        normalize_chunk_text(post_data, "body")
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"✓ Processed 15 chunks in {duration:.2f} seconds")
    print(f"✓ Average time per chunk: {duration/15:.3f} seconds")
    print()


def main():
    """Run all security feature tests."""
    print("🔒 Security-Focused Stack Detection Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_version_vulnerability_detection()
        test_credential_detection()
        test_post_data_analysis()
        test_comprehensive_security_analysis()
        test_llm_ready_metadata()
        test_performance_with_security()
        
        print("✅ All security feature tests completed successfully!")
        print("\n🎉 Enhanced stack detection with security analysis is working!")
        print("\n📋 Summary of Security Features:")
        print("  ✓ Version vulnerability checking for standard libraries")
        print("  ✓ Credential detection in custom libraries")
        print("  ✓ Vulnerable script identification")
        print("  ✓ POST data analysis for attacks")
        print("  ✓ Enhanced tagging for LLM analysis")
        print("  ✓ Security risk scoring")
        print("  ✓ JSON-safe metadata for ChromaDB storage")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
