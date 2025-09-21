#!/usr/bin/env python3
"""
Integration Test Suite for ZAP RAG Security Agent

This script provides comprehensive integration testing for all components
of the ZAP RAG Security Agent system.
"""

import asyncio
import json
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.zap_rag_security_agent.core.agent import SecurityAnalysisAgent
from src.zap_rag_security_agent.collectors.zap_collector import ZAPCollector
from src.zap_rag_security_agent.detectors.stack_detector import StackDetector, detect_stack_from_traffic
from src.zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text, preprocess_payload
from src.zap_rag_security_agent.data.baseline_docs import BASELINE_DOCS


class IntegrationTestSuite:
    """Comprehensive integration test suite."""
    
    def __init__(self):
        self.test_results = []
        self.passed_tests = 0
        self.failed_tests = 0
    
    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """Log test result."""
        status = "PASS" if passed else "FAIL"
        self.test_results.append({
            "test": test_name,
            "status": status,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
        
        if passed:
            self.passed_tests += 1
            print(f"✅ {test_name}: {message}")
        else:
            self.failed_tests += 1
            print(f"❌ {test_name}: {message}")
    
    async def test_core_agent_initialization(self):
        """Test core agent initialization."""
        try:
            agent = SecurityAnalysisAgent()
            await agent.initialize()
            await agent.close()
            self.log_test("Core Agent Initialization", True, "Agent initialized successfully")
        except Exception as e:
            self.log_test("Core Agent Initialization", False, f"Failed: {e}")
    
    async def test_zap_collector_initialization(self):
        """Test ZAP collector initialization."""
        try:
            collector = ZAPCollector()
            # Don't actually initialize to avoid ZAP dependency
            self.log_test("ZAP Collector Initialization", True, "Collector created successfully")
        except Exception as e:
            self.log_test("ZAP Collector Initialization", False, f"Failed: {e}")
    
    def test_stack_detector_initialization(self):
        """Test stack detector initialization."""
        try:
            detector = StackDetector()
            self.log_test("Stack Detector Initialization", True, "Detector initialized successfully")
        except Exception as e:
            self.log_test("Stack Detector Initialization", False, f"Failed: {e}")
    
    def test_preprocessing_functions(self):
        """Test preprocessing functions."""
        try:
            # Test normalize_chunk_text
            test_content = "Test content for normalization"
            normalized, meta = normalize_chunk_text(test_content, "body")
            
            if normalized and isinstance(meta, dict):
                self.log_test("Preprocessing Functions", True, "Normalization working correctly")
            else:
                self.log_test("Preprocessing Functions", False, "Normalization returned invalid results")
        except Exception as e:
            self.log_test("Preprocessing Functions", False, f"Failed: {e}")
    
    def test_baseline_data_loading(self):
        """Test baseline data loading."""
        try:
            if BASELINE_DOCS and len(BASELINE_DOCS) > 0:
                self.log_test("Baseline Data Loading", True, f"Loaded {len(BASELINE_DOCS)} baseline documents")
            else:
                self.log_test("Baseline Data Loading", False, "No baseline documents found")
        except Exception as e:
            self.log_test("Baseline Data Loading", False, f"Failed: {e}")
    
    def test_stack_detection_functionality(self):
        """Test stack detection functionality."""
        try:
            detector = StackDetector()
            
            # Test with sample headers
            headers = """Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel"""
            
            result = detector.detect_from_headers(headers)
            
            if result and 'total_detected' in result:
                self.log_test("Stack Detection Functionality", True, f"Detected {result['total_detected']} technologies")
            else:
                self.log_test("Stack Detection Functionality", False, "Detection returned invalid results")
        except Exception as e:
            self.log_test("Stack Detection Functionality", False, f"Failed: {e}")
    
    def test_suspicious_content_detection(self):
        """Test suspicious content detection."""
        try:
            # Test with suspicious content
            suspicious_content = "1' OR '1'='1' --"
            normalized, meta = normalize_chunk_text(suspicious_content, "query")
            
            if meta.get('suspicious', False) and meta.get('suspicion_score', 0) > 0:
                self.log_test("Suspicious Content Detection", True, f"Detected suspicious content (score: {meta['suspicion_score']})")
            else:
                self.log_test("Suspicious Content Detection", False, "Failed to detect suspicious content")
        except Exception as e:
            self.log_test("Suspicious Content Detection", False, f"Failed: {e}")
    
    def test_html_content_analysis(self):
        """Test HTML content analysis."""
        try:
            html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
</head>
<body>
    <h1>Test Page</h1>
</body>
</html>"""
            
            normalized, meta = normalize_chunk_text(html_content, "body")
            
            if normalized and 'stack_detection' in meta:
                self.log_test("HTML Content Analysis", True, "HTML analysis completed successfully")
            else:
                self.log_test("HTML Content Analysis", False, "HTML analysis failed")
        except Exception as e:
            self.log_test("HTML Content Analysis", False, f"Failed: {e}")
    
    def test_comprehensive_stack_detection(self):
        """Test comprehensive stack detection."""
        try:
            headers = """Host: example.com
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2"""
            
            html = """<!DOCTYPE html>
<html>
<head>
    <title>Test</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
</head>
<body>
    <h1>Test Page</h1>
</body>
</html>"""
            
            script_srcs = [
                "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"
            ]
            
            result = detect_stack_from_traffic(
                headers_text=headers,
                html_content=html,
                script_srcs=script_srcs
            )
            
            if result and result.get('total_detected', 0) > 0:
                self.log_test("Comprehensive Stack Detection", True, f"Detected {result['total_detected']} technologies")
            else:
                self.log_test("Comprehensive Stack Detection", False, "No technologies detected")
        except Exception as e:
            self.log_test("Comprehensive Stack Detection", False, f"Failed: {e}")
    
    def test_metadata_generation(self):
        """Test metadata generation for ChromaDB."""
        try:
            test_content = "Test content with suspicious patterns: 1' OR '1'='1"
            normalized, meta = normalize_chunk_text(test_content, "query")
            
            # Check if metadata contains required fields
            required_fields = ['suspicion_score', 'suspicious', 'chunk_type']
            if all(field in meta for field in required_fields):
                self.log_test("Metadata Generation", True, "Metadata generated correctly")
            else:
                self.log_test("Metadata Generation", False, "Missing required metadata fields")
        except Exception as e:
            self.log_test("Metadata Generation", False, f"Failed: {e}")
    
    def test_error_handling(self):
        """Test error handling with invalid inputs."""
        try:
            # Test with empty content
            normalized, meta = normalize_chunk_text("", "body")
            
            # Test with None content (should be handled gracefully)
            try:
                normalized2, meta2 = normalize_chunk_text(None, "body")
                if normalized == "" and normalized2 == "":
                    self.log_test("Error Handling", True, "Handled empty/None inputs correctly")
                else:
                    self.log_test("Error Handling", False, "Failed to handle empty/None inputs")
            except Exception:
                # If None handling throws an exception, that's also acceptable
                if normalized == "":
                    self.log_test("Error Handling", True, "Handled empty input correctly, None input properly rejected")
                else:
                    self.log_test("Error Handling", False, "Failed to handle empty input")
        except Exception as e:
            self.log_test("Error Handling", False, f"Failed: {e}")
    
    def test_performance(self):
        """Test performance with multiple operations."""
        try:
            import time
            
            start_time = time.time()
            
            # Process multiple chunks
            for i in range(10):
                content = f"Test content {i} with some suspicious patterns: 1' OR '1'='1"
                normalized, meta = normalize_chunk_text(content, "query")
            
            end_time = time.time()
            duration = end_time - start_time
            
            if duration < 5.0:  # Should complete in under 5 seconds
                self.log_test("Performance Test", True, f"Processed 10 chunks in {duration:.2f} seconds")
            else:
                self.log_test("Performance Test", False, f"Too slow: {duration:.2f} seconds")
        except Exception as e:
            self.log_test("Performance Test", False, f"Failed: {e}")
    
    async def run_all_tests(self):
        """Run all integration tests."""
        print("🧪 ZAP RAG Security Agent - Integration Test Suite")
        print("=" * 60)
        print()
        
        # Run tests
        await self.test_core_agent_initialization()
        await self.test_zap_collector_initialization()
        self.test_stack_detector_initialization()
        self.test_preprocessing_functions()
        self.test_baseline_data_loading()
        self.test_stack_detection_functionality()
        self.test_suspicious_content_detection()
        self.test_html_content_analysis()
        self.test_comprehensive_stack_detection()
        self.test_metadata_generation()
        self.test_error_handling()
        self.test_performance()
        
        # Generate report
        self.generate_test_report()
    
    def generate_test_report(self):
        """Generate comprehensive test report."""
        print("\n" + "=" * 60)
        print("📊 INTEGRATION TEST REPORT")
        print("=" * 60)
        
        total_tests = self.passed_tests + self.failed_tests
        pass_rate = (self.passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Pass Rate: {pass_rate:.1f}%")
        
        if self.failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"  - {result['test']}: {result['message']}")
        
        # Save detailed report
        report_file = f"integration_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_tests": total_tests,
                    "passed": self.passed_tests,
                    "failed": self.failed_tests,
                    "pass_rate": pass_rate
                },
                "results": self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        if self.failed_tests == 0:
            print("\n🎉 ALL TESTS PASSED! Integration is working correctly.")
            return True
        else:
            print(f"\n⚠️  {self.failed_tests} tests failed. Please review the issues above.")
            return False


async def main():
    """Main function to run integration tests."""
    test_suite = IntegrationTestSuite()
    success = await test_suite.run_all_tests()
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
