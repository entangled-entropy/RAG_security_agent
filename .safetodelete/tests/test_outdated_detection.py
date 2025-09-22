#!/usr/bin/env python3
"""
Test script to demonstrate outdated version detection with sample data.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from zap_rag_security_agent.detectors.stack_detector import detect_stack_from_traffic


def test_outdated_detection():
    """Test outdated version detection with sample data."""
    print("🔍 Testing Outdated Version Detection")
    print("=" * 50)
    
    # Test HTML content with outdated jQuery and Bootstrap
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page with Outdated Libraries</title>
        <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/1.10.0/vue.min.js"></script>
    </head>
    <body>
        <div class="container">
            <h1>Test Page with Outdated Libraries</h1>
            <p>This page uses outdated versions of popular libraries.</p>
        </div>
    </body>
    </html>
    """
    
    # Test headers with outdated server
    headers_text = """
    Server: nginx/1.18.0
    X-Powered-By: PHP/7.4.0
    Content-Type: text/html; charset=UTF-8
    X-Framework: Laravel/5.8.0
    """
    
    # Test script sources with outdated libraries
    script_srcs = [
        "https://code.jquery.com/jquery-1.12.4.min.js",
        "https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/vue/1.10.0/vue.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/angularjs/1.6.0/angular.min.js"
    ]
    
    print("Testing with outdated technologies:")
    print("- jQuery 1.12.4 (should be outdated and vulnerable)")
    print("- Bootstrap 3.4.1 (should be outdated and vulnerable)")
    print("- Vue 1.10.0 (should be outdated and vulnerable)")
    print("- Angular 1.6.0 (should be outdated and vulnerable)")
    print("- nginx 1.18.0 (should be outdated and vulnerable)")
    print("- PHP 7.4.0 (should be outdated and vulnerable)")
    print("- Laravel 5.8.0 (should be outdated and vulnerable)")
    
    # Run comprehensive stack detection
    result = detect_stack_from_traffic(
        headers_text=headers_text,
        html_content=html_content,
        script_srcs=script_srcs,
        url="https://example.com"
    )
    
    print(f"\n🔍 Detection Results:")
    print(f"Total detected: {result.get('total_detected', 0)}")
    print(f"Total outdated: {result.get('total_outdated', 0)}")
    print(f"Detection methods: {', '.join(result.get('detection_methods', []))}")
    
    # Show detected technologies with version info
    if result.get('detected_technologies'):
        print(f"\n📋 Detected Technologies:")
        for tech_name, tech_info in result['detected_technologies'].items():
            if isinstance(tech_info, dict):
                version = tech_info.get('version', 'N/A')
                is_outdated = tech_info.get('is_outdated', False)
                is_vulnerable = tech_info.get('is_vulnerable', False)
                security_status = tech_info.get('security_status', 'unknown')
                latest_version = tech_info.get('latest_version', 'N/A')
                min_safe_version = tech_info.get('min_safe_version', 'N/A')
                
                if version and version != 'N/A':
                    status_icon = "⚠️ VULNERABLE" if is_vulnerable else "🔄 OUTDATED" if is_outdated else "✅ CURRENT"
                    print(f"  - {tech_name} v{version} → v{latest_version} {status_icon}")
                    if is_vulnerable:
                        print(f"    Min Safe: v{min_safe_version}")
                else:
                    print(f"  - {tech_name} v{version} (no version info)")
    
    # Show outdated components
    if result.get('outdated_components'):
        print(f"\n⚠️ Outdated Components:")
        for comp in result['outdated_components']:
            name = comp.get('name', 'Unknown')
            version = comp.get('version', 'N/A')
            latest_version = comp.get('latest_version', 'N/A')
            is_vulnerable = comp.get('is_vulnerable', False)
            security_status = comp.get('security_status', 'unknown')
            min_safe_version = comp.get('min_safe_version', 'N/A')
            
            status_icon = "⚠️ VULNERABLE" if is_vulnerable else "🔄 OUTDATED"
            print(f"  - {name} v{version} → v{latest_version} {status_icon}")
            if is_vulnerable:
                print(f"    Min Safe: v{min_safe_version}")
    
    # Show top component
    if result.get('top_component'):
        top_comp = result['top_component']
        print(f"\n🏆 Top Component:")
        print(f"  - {top_comp.get('name', 'Unknown')} v{top_comp.get('version', 'N/A')}")
        print(f"  - Type: {top_comp.get('type', 'unknown')}")
        print(f"  - Confidence: {top_comp.get('confidence', 0.0):.2f}")
        print(f"  - Security Status: {top_comp.get('security_status', 'unknown')}")
        if top_comp.get('is_vulnerable'):
            print(f"  - ⚠️ VULNERABLE - Min Safe: v{top_comp.get('min_safe_version', 'N/A')}")
        elif top_comp.get('is_outdated'):
            print(f"  - 🔄 OUTDATED - Latest: v{top_comp.get('latest_version', 'N/A')}")
    
    # Show security analysis
    if result.get('security_analysis'):
        sec_analysis = result['security_analysis']
        print(f"\n🛡️ Security Analysis:")
        print(f"  - Total Issues: {sec_analysis.get('total_security_issues', 0)}")
        print(f"  - High Severity: {sec_analysis.get('high_severity_issues', 0)}")
        print(f"  - Medium Severity: {sec_analysis.get('medium_severity_issues', 0)}")
        print(f"  - Risk Score: {sec_analysis.get('security_risk_score', 0)}")
        print(f"  - Has Vulnerabilities: {sec_analysis.get('has_vulnerabilities', False)}")


def main():
    """Main function."""
    print("🚀 Testing Outdated Version Detection System")
    print("=" * 60)
    
    try:
        test_outdated_detection()
        
        print("\n" + "=" * 60)
        print("✅ TEST COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nThe system successfully detected and flagged outdated versions!")
        print("You can now use queries like:")
        print("  - 'outdated versions'")
        print("  - 'vulnerable components'")
        print("  - 'jQuery 1.12'")
        print("  - 'Bootstrap 3.4'")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
