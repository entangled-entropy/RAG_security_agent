#!/usr/bin/env python3
"""
Advanced Analysis Examples for ZAP RAG Security Agent

This example demonstrates advanced security analysis capabilities including:
- Custom security queries
- Batch analysis
- Report generation
- Integration with external tools
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
from src.zap_rag_security_agent.detectors.stack_detector import StackDetector
from src.zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text


async def advanced_security_analysis():
    """Example of advanced security analysis with custom queries."""
    print("=== Advanced Security Analysis Example ===\n")
    
    agent = SecurityAnalysisAgent(
        persist_path="./chroma_data",
        collection_name="security_memory",
        model="gpt-4o"
    )
    
    try:
        await agent.initialize()
        print("✓ Advanced security agent initialized")
        
        # Advanced security queries
        advanced_queries = [
            {
                "query": "Find all SQL injection attempts with UNION-based attacks",
                "context": "Focus on UNION SELECT patterns and database fingerprinting"
            },
            {
                "query": "Identify XSS vulnerabilities in form inputs and URL parameters",
                "context": "Look for script injection patterns and DOM manipulation"
            },
            {
                "query": "Detect authentication bypass attempts and session hijacking",
                "context": "Check for weak session management and token manipulation"
            },
            {
                "query": "Find exposed API keys, passwords, and sensitive credentials",
                "context": "Look for hardcoded secrets and credential leaks"
            },
            {
                "query": "Analyze web technology stack for known vulnerabilities",
                "context": "Check for outdated frameworks and vulnerable components"
            },
            {
                "query": "Identify CSRF attacks and request forgery attempts",
                "context": "Look for missing CSRF tokens and cross-origin requests"
            },
            {
                "query": "Find file upload vulnerabilities and path traversal attacks",
                "context": "Check for directory traversal and malicious file uploads"
            },
            {
                "query": "Detect XML external entity (XXE) injection attempts",
                "context": "Look for XML processing vulnerabilities and entity references"
            }
        ]
        
        results = []
        for i, query_data in enumerate(advanced_queries, 1):
            print(f"\n🔍 Advanced Query {i}: {query_data['query']}")
            print(f"Context: {query_data['context']}")
            
            try:
                result = await agent.analyze_traffic(query_data['query'])
                results.append({
                    "query": query_data['query'],
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })
                print("✓ Analysis completed")
            except Exception as e:
                print(f"❌ Analysis failed: {e}")
                results.append({
                    "query": query_data['query'],
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
        
        # Generate summary report
        await generate_security_report(results)
        
    except Exception as e:
        print(f"❌ Advanced analysis failed: {e}")
    finally:
        await agent.close()


async def batch_analysis_example():
    """Example of batch analysis for multiple traffic sources."""
    print("\n=== Batch Analysis Example ===\n")
    
    agent = SecurityAnalysisAgent()
    
    try:
        await agent.initialize()
        print("✓ Batch analysis agent initialized")
        
        # Simulate batch analysis for different traffic types
        batch_queries = [
            "Analyze all POST requests for injection vulnerabilities",
            "Check all GET requests for XSS and parameter pollution",
            "Examine all authentication-related traffic for security issues",
            "Review all API endpoints for authorization bypasses",
            "Scan all file upload requests for malicious content"
        ]
        
        batch_results = []
        for query in batch_queries:
            print(f"📊 Processing: {query}")
            try:
                result = await agent.analyze_traffic(query)
                batch_results.append({
                    "query": query,
                    "status": "completed",
                    "result": result
                })
            except Exception as e:
                batch_results.append({
                    "query": query,
                    "status": "failed",
                    "error": str(e)
                })
        
        print(f"\n✓ Batch analysis completed: {len(batch_results)} queries processed")
        
    except Exception as e:
        print(f"❌ Batch analysis failed: {e}")
    finally:
        await agent.close()


async def stack_detection_analysis():
    """Example of web technology stack analysis."""
    print("\n=== Stack Detection Analysis Example ===\n")
    
    detector = StackDetector()
    
    # Sample traffic data for analysis
    sample_traffic = [
        {
            "headers": """Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Powered-By: PHP/8.1.2
Server: nginx/1.20.2
X-Framework: Laravel""",
            "html": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 6.2">
    <title>Test Page</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>Test Page</h1>
    </div>
</body>
</html>""",
            "scripts": [
                "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js",
                "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/js/bootstrap.bundle.min.js"
            ]
        }
    ]
    
    for i, traffic in enumerate(sample_traffic, 1):
        print(f"🔍 Analyzing Traffic Sample {i}")
        
        # Detect stack from traffic
        result = detector.detect_from_traffic(
            headers_text=traffic["headers"],
            html_content=traffic["html"],
            script_srcs=traffic["scripts"]
        )
        
        print(f"✓ Technologies detected: {result.get('total_detected', 0)}")
        print(f"✓ Detection methods: {result.get('detection_methods', [])}")
        print(f"✓ Confidence: {result.get('confidence', 0.0):.2f}")
        
        if result.get('top_component'):
            top = result['top_component']
            print(f"✓ Top component: {top.get('name', 'Unknown')} v{top.get('version', 'N/A')}")
        
        print()


async def custom_preprocessing_example():
    """Example of custom preprocessing and analysis."""
    print("\n=== Custom Preprocessing Example ===\n")
    
    # Sample suspicious traffic
    suspicious_traffic = [
        {
            "type": "path",
            "content": "/api/users?id=1' OR '1'='1' --",
            "description": "SQL injection attempt in path"
        },
        {
            "type": "query", 
            "content": "search=<script>alert('xss')</script>&filter=all",
            "description": "XSS attempt in query parameters"
        },
        {
            "type": "headers",
            "content": """Host: example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-API-Key: sk-1234567890abcdef
Cookie: session_id=abc123; admin_token=secret456""",
            "description": "Headers with sensitive information"
        },
        {
            "type": "body",
            "content": '{"username": "admin", "password": "secret123", "query": "1\' OR \'1\'=\'1"}',
            "description": "POST body with SQL injection attempt"
        }
    ]
    
    for i, traffic in enumerate(suspicious_traffic, 1):
        print(f"🔍 Processing Suspicious Traffic {i}: {traffic['description']}")
        
        # Normalize and analyze
        normalized, meta = normalize_chunk_text(traffic['content'], traffic['type'])
        
        print(f"✓ Content normalized: {len(normalized)} chars")
        print(f"✓ Suspicion score: {meta.get('suspicion_score', 0)}")
        print(f"✓ Suspicious: {meta.get('suspicious', False)}")
        print(f"✓ Suspicious tags: {meta.get('suspicious_tags', [])}")
        
        if meta.get('stack_detection'):
            stack_info = meta['stack_detection']
            print(f"✓ Stack detection: {stack_info.get('total_detected', 0)} technologies")
        
        print(f"✓ Normalized content: {normalized[:100]}...")
        print()


async def generate_security_report(results):
    """Generate a comprehensive security report."""
    print("\n=== Security Report Generation ===\n")
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_queries": len(results),
        "successful_queries": len([r for r in results if 'result' in r]),
        "failed_queries": len([r for r in results if 'error' in r]),
        "results": results
    }
    
    # Save report to file
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✓ Security report generated: {report_file}")
    print(f"✓ Total queries: {report['total_queries']}")
    print(f"✓ Successful: {report['successful_queries']}")
    print(f"✓ Failed: {report['failed_queries']}")


async def integration_test():
    """Test integration between all components."""
    print("\n=== Integration Test ===\n")
    
    try:
        # Test collector
        collector = ZAPCollector()
        print("✓ ZAP collector initialized")
        
        # Test detector
        detector = StackDetector()
        print("✓ Stack detector initialized")
        
        # Test normalizer
        test_content = "Test content for normalization"
        normalized, meta = normalize_chunk_text(test_content, "body")
        print("✓ Traffic normalizer working")
        
        # Test agent
        agent = SecurityAnalysisAgent()
        print("✓ Security agent initialized")
        
        print("\n🎉 All components integrated successfully!")
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")


async def main():
    """Main function to run all advanced examples."""
    print("🚀 ZAP RAG Security Agent - Advanced Analysis Examples")
    print("=" * 70)
    
    # Run examples
    await advanced_security_analysis()
    await batch_analysis_example()
    await stack_detection_analysis()
    await custom_preprocessing_example()
    await integration_test()
    
    print("\n✅ All advanced examples completed!")


if __name__ == "__main__":
    asyncio.run(main())
