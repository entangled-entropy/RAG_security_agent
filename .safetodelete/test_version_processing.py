#!/usr/bin/env python3
"""
Test version processing with sample data
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text

def test_version_processing():
    """Test version processing with sample data."""
    
    print("[*] Testing version processing with sample data...")
    
    # Sample traffic with version information
    test_cases = [
        {
            "name": "Headers with version info",
            "content": """GET /test HTTP/1.1
Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel/9.0.0""",
            "type": "headers"
        },
        {
            "name": "HTML with jQuery version",
            "content": """<!DOCTYPE html>
<html>
<head>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/js/bootstrap.bundle.min.js"></script>
</head>
<body>
    <h1>Test Page</h1>
</body>
</html>""",
            "type": "body"
        },
        {
            "name": "POST data with credentials",
            "content": '{"username": "admin", "password": "secret123", "version": "1.0.0"}',
            "type": "body"
        },
        {
            "name": "Form data with version",
            "content": "username=admin&password=secret&version=2.1.0&framework=laravel",
            "type": "body"
        }
    ]
    
    for test_case in test_cases:
        print(f"\n[TEST] {test_case['name']}")
        print(f"Content: {test_case['content'][:100]}...")
        
        try:
            normalized, metadata = normalize_chunk_text(
                test_case['content'], 
                test_case['type']
            )
            
            print(f"✅ Processing successful")
            print(f"Normalized length: {len(normalized)} chars")
            
            # Check for stack detection results
            if 'stack_detection' in metadata:
                stack_info = metadata['stack_detection']
                print(f"Stack detection: {stack_info.get('total_detected', 0)} technologies")
                
                # Check for top component
                if 'top_component' in metadata:
                    top_comp = metadata['top_component']
                    print(f"Top component: {top_comp.get('name', 'Unknown')} v{top_comp.get('version', 'N/A')} (confidence: {top_comp.get('confidence', 0.0)})")
                    if top_comp.get('is_vulnerable'):
                        print("  ⚠️  VULNERABLE VERSION DETECTED!")
                
                # Check for component candidates (detailed version info)
                if 'component_candidates' in metadata:
                    import json
                    try:
                        candidates = json.loads(metadata['component_candidates'])
                        print(f"Component candidates ({len(candidates)}):")
                        for comp in candidates:
                            name = comp.get('name', 'Unknown')
                            version = comp.get('version', 'N/A')
                            confidence = comp.get('confidence', 0.0)
                            is_vuln = comp.get('is_vulnerable', False)
                            vuln_marker = " ⚠️ VULNERABLE" if is_vuln else ""
                            print(f"  - {name}: {version} (confidence: {confidence}){vuln_marker}")
                    except json.JSONDecodeError:
                        print("  Error parsing component candidates")
                
                # Check for security analysis
                if 'security_analysis' in metadata:
                    sec_analysis = metadata['security_analysis']
                    print(f"Security analysis:")
                    print(f"  - Total issues: {sec_analysis.get('total_security_issues', 0)}")
                    print(f"  - High severity: {sec_analysis.get('high_severity_issues', 0)}")
                    print(f"  - Medium severity: {sec_analysis.get('medium_severity_issues', 0)}")
                    print(f"  - Risk score: {sec_analysis.get('security_risk_score', 0)}")
            else:
                print("❌ No stack detection results found")
            
            # Check for suspicion score
            print(f"Suspicion score: {metadata.get('suspicion_score', 0)}")
            print(f"Suspicious: {metadata.get('suspicious', False)}")
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n[*] Version processing test completed!")

if __name__ == "__main__":
    test_version_processing()
