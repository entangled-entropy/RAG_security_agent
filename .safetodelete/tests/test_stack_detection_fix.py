#!/usr/bin/env python3
"""
Test the stack detection fix
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from zap_rag_security_agent.detectors.stack_detector import detect_stack_from_traffic

def test_stack_detection():
    """Test if the stack detection function works with post_data parameter."""
    
    print("[*] Testing stack detection function...")
    
    # Test with different parameters
    test_cases = [
        {
            "name": "Headers only",
            "params": {"headers_text": "X-Powered-By: PHP/8.1.2\nServer: nginx/1.20.2"}
        },
        {
            "name": "HTML content",
            "params": {"html_content": "<script src='jquery-3.6.0.min.js'></script>"}
        },
        {
            "name": "Script sources",
            "params": {"script_srcs": ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"]}
        },
        {
            "name": "POST data",
            "params": {"post_data": '{"username": "admin", "password": "secret"}'}
        },
        {
            "name": "Combined",
            "params": {
                "headers_text": "X-Powered-By: PHP/8.1.2",
                "html_content": "<script src='bootstrap-5.2.3.min.js'></script>",
                "script_srcs": ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"],
                "post_data": '{"action": "login"}'
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n[TEST] {test_case['name']}")
        try:
            result = detect_stack_from_traffic(**test_case['params'])
            
            print(f"  ✅ Success: {result.get('total_detected', 0)} technologies detected")
            
            if result.get('detected_technologies'):
                print("  Technologies found:")
                for tech, info in result['detected_technologies'].items():
                    version = info.get('version', 'N/A')
                    print(f"    - {tech}: {version}")
            
            if result.get('standard_libraries'):
                print("  Standard libraries:")
                for lib in result['standard_libraries']:
                    print(f"    - {lib.get('name', 'Unknown')}: {lib.get('version', 'N/A')}")
            
            if result.get('security_analysis', {}).get('security_risk_score', 0) > 0:
                print(f"  Security risk score: {result['security_analysis']['security_risk_score']}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print("\n[*] Stack detection test completed!")

if __name__ == "__main__":
    test_stack_detection()
