#!/usr/bin/env python3
"""
Test script for version detection and outdated component identification.

This script tests the new version management system to ensure it properly
identifies outdated and vulnerable technology versions.
"""

import sys
import os
import asyncio
from typing import Dict, Any

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.data.version_database import get_version_database
from zap_rag_security_agent.detectors.stack_detector import StackDetector, detect_stack_from_traffic


class VersionDetectionTester:
    """Test version detection and outdated component identification."""
    
    def __init__(self):
        self.version_db = get_version_database()
        self.stack_detector = StackDetector()
    
    def test_version_database(self):
        """Test the version database functionality."""
        print("=" * 60)
        print("🔍 TESTING VERSION DATABASE")
        print("=" * 60)
        
        # Test getting version info for various technologies
        test_technologies = ['jquery', 'react', 'vue', 'bootstrap', 'django', 'flask', 'nginx', 'mysql']
        
        for tech in test_technologies:
            version_info = self.version_db.get_version_info(tech)
            print(f"\n{tech.upper()}:")
            print(f"  Latest: {version_info.get('latest', 'N/A')}")
            print(f"  LTS: {version_info.get('lts', 'N/A')}")
            print(f"  Min Safe: {version_info.get('min_safe', 'N/A')}")
    
    def test_outdated_detection(self):
        """Test outdated version detection."""
        print("\n" + "=" * 60)
        print("🔄 TESTING OUTDATED VERSION DETECTION")
        print("=" * 60)
        
        # Test cases: (technology, version, expected_outdated, expected_vulnerable)
        test_cases = [
            ('jquery', '1.12.4', True, True),  # Old jQuery - should be outdated and vulnerable
            ('jquery', '3.7.1', False, False),  # Latest jQuery - should be current
            ('bootstrap', '3.4.1', True, True),  # Old Bootstrap - should be outdated and vulnerable
            ('bootstrap', '5.3.2', False, False),  # Latest Bootstrap - should be current
            ('react', '16.8.0', True, False),  # Old React - should be outdated but not vulnerable
            ('react', '18.2.0', False, False),  # Latest React - should be current
            ('vue', '1.10.0', True, True),  # Old Vue - should be outdated and vulnerable
            ('vue', '3.4.0', False, False),  # Latest Vue - should be current
            ('django', '2.2.0', True, True),  # Old Django - should be outdated and vulnerable
            ('django', '5.0.0', False, False),  # Latest Django - should be current
            ('nginx', '1.18.0', True, True),  # Old nginx - should be outdated and vulnerable
            ('nginx', '1.25.0', False, False),  # Latest nginx - should be current
        ]
        
        for tech, version, expected_outdated, expected_vulnerable in test_cases:
            is_outdated, latest, min_safe = self.version_db.is_outdated(tech, version)
            is_vulnerable = self.version_db.is_vulnerable(tech, version)
            security_status = self.version_db.get_security_status(tech, version)
            
            print(f"\n{tech.upper()} v{version}:")
            print(f"  Expected: Outdated={expected_outdated}, Vulnerable={expected_vulnerable}")
            print(f"  Actual: Outdated={is_outdated}, Vulnerable={is_vulnerable}")
            print(f"  Latest: {latest}, Min Safe: {min_safe}")
            print(f"  Security Status: {security_status['security_status']}")
            
            # Check if results match expectations
            outdated_match = is_outdated == expected_outdated
            vulnerable_match = is_vulnerable == expected_vulnerable
            
            if outdated_match and vulnerable_match:
                print(f"  ✅ PASS")
            else:
                print(f"  ❌ FAIL - Expected outdated={expected_outdated}, vulnerable={expected_vulnerable}")
    
    def run_all_tests(self):
        """Run all version detection tests."""
        print("🚀 STARTING VERSION DETECTION TESTS")
        print("=" * 60)
        
        try:
            # Run synchronous tests
            self.test_version_database()
            self.test_outdated_detection()
            
            print("\n" + "=" * 60)
            print("✅ ALL TESTS COMPLETED")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n❌ TEST FAILED: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Main function."""
    tester = VersionDetectionTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()