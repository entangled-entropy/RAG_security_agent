#!/usr/bin/env python3
"""
Quick test script for the new version management system.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from zap_rag_security_agent.data.version_database import get_version_database
from zap_rag_security_agent.detectors.stack_detector import detect_stack_from_traffic


def test_version_database():
    """Test the version database."""
    print("🔍 Testing Version Database")
    print("=" * 40)
    
    version_db = get_version_database()
    
    # Test some technologies
    test_techs = ['jquery', 'bootstrap', 'react', 'vue', 'django', 'nginx']
    
    for tech in test_techs:
        info = version_db.get_version_info(tech)
        print(f"\n{tech.upper()}:")
        print(f"  Latest: {info.get('latest', 'N/A')}")
        print(f"  LTS: {info.get('lts', 'N/A')}")
        print(f"  Min Safe: {info.get('min_safe', 'N/A')}")
    
    # Test outdated detection
    print(f"\n🔄 Testing Outdated Detection")
    print("-" * 40)
    
    test_cases = [
        ('jquery', '1.12.4', True, True),  # Old jQuery
        ('jquery', '3.7.1', False, False),  # Latest jQuery
        ('bootstrap', '3.4.1', True, True),  # Old Bootstrap
        ('bootstrap', '5.3.2', False, False),  # Latest Bootstrap
    ]
    
    for tech, version, expected_outdated, expected_vulnerable in test_cases:
        is_outdated, latest, min_safe = version_db.is_outdated(tech, version)
        is_vulnerable = version_db.is_vulnerable(tech, version)
        
        print(f"\n{tech} v{version}:")
        print(f"  Outdated: {is_outdated} (expected: {expected_outdated})")
        print(f"  Vulnerable: {is_vulnerable} (expected: {expected_vulnerable})")
        print(f"  Latest: {latest}, Min Safe: {min_safe}")


def test_stack_detection():
    """Test stack detection with outdated versions."""
    print(f"\n🔍 Testing Stack Detection with Outdated Versions")
    print("=" * 40)
    
    # Test HTML with outdated jQuery and Bootstrap
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
        <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1>Test Page with Outdated Libraries</h1>
            <p>This page uses outdated jQuery 1.12.4 and Bootstrap 3.4.1</p>
        </div>
    </body>
    </html>
    """
    
    # Test headers with outdated server
    headers_text = """
    Server: nginx/1.18.0
    X-Powered-By: PHP/7.4.0
    Content-Type: text/html; charset=UTF-8
    """
    
    # Test script sources
    script_srcs = [
        "https://code.jquery.com/jquery-1.12.4.min.js",
        "https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"
    ]
    
    print("Testing with outdated technologies:")
    print("- jQuery 1.12.4 (should be outdated and vulnerable)")
    print("- Bootstrap 3.4.1 (should be outdated and vulnerable)")
    print("- nginx 1.18.0 (should be outdated and vulnerable)")
    print("- PHP 7.4.0 (should be outdated and vulnerable)")
    
    # Run stack detection
    result = detect_stack_from_traffic(
        headers_text=headers_text,
        html_content=html_content,
        script_srcs=script_srcs,
        url="https://example.com"
    )
    
    print(f"\nDetection Results:")
    print(f"Total detected: {result.get('total_detected', 0)}")
    print(f"Total outdated: {result.get('total_outdated', 0)}")
    print(f"Detection methods: {', '.join(result.get('detection_methods', []))}")
    
    # Show detected technologies
    if result.get('detected_technologies'):
        print(f"\nDetected Technologies:")
        for tech_name, tech_info in result['detected_technologies'].items():
            if isinstance(tech_info, dict):
                version = tech_info.get('version', 'N/A')
                is_outdated = tech_info.get('is_outdated', False)
                is_vulnerable = tech_info.get('is_vulnerable', False)
                security_status = tech_info.get('security_status', 'unknown')
                latest_version = tech_info.get('latest_version', 'N/A')
                
                status_icon = "⚠️ VULNERABLE" if is_vulnerable else "🔄 OUTDATED" if is_outdated else "✅ CURRENT"
                print(f"  - {tech_name} v{version} → v{latest_version} {status_icon}")
    
    # Show outdated components
    if result.get('outdated_components'):
        print(f"\nOutdated Components:")
        for comp in result['outdated_components']:
            name = comp.get('name', 'Unknown')
            version = comp.get('version', 'N/A')
            latest_version = comp.get('latest_version', 'N/A')
            is_vulnerable = comp.get('is_vulnerable', False)
            security_status = comp.get('security_status', 'unknown')
            
            status_icon = "⚠️ VULNERABLE" if is_vulnerable else "🔄 OUTDATED"
            print(f"  - {name} v{version} → v{latest_version} {status_icon}")


def main():
    """Main function."""
    print("🚀 Testing Version Management System")
    print("=" * 50)
    
    try:
        test_version_database()
        test_stack_detection()
        
        print("\n" + "=" * 50)
        print("✅ ALL TESTS COMPLETED SUCCESSFULLY")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
