#!/usr/bin/env python3
"""
Quick Query Tester - Test predefined security queries

This script runs a set of predefined security queries to test
the retrieval and reconstruction functionality.
"""

import asyncio
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from test_queries import QueryTester


async def run_predefined_queries():
    """Run a set of predefined security queries."""
    
    # Predefined security queries to test
    test_queries = [
        "SQL injection",
        "XSS cross site scripting",
        "authentication login",
        "API key exposed",
        "password credentials",
        "admin access",
        "file upload",
        "directory traversal",
        "command injection",
        "CSRF token",
        "session management",
        "error messages",
        "debug information",
        "version disclosure",
        "sensitive data",
        "vulnerable components",
        "security headers",
        "HTTPS SSL",
        "cookies session",
        "user input validation"
    ]
    
    tester = QueryTester()
    
    try:
        await tester.initialize()
        
        print("🔍 QUICK SECURITY QUERY TESTER")
        print("=" * 50)
        print(f"Testing {len(test_queries)} predefined security queries...")
        print("=" * 50)
        
        for i, query in enumerate(test_queries, 1):
            print(f"\n[{i}/{len(test_queries)}] Testing: '{query}'")
            print("-" * 50)
            
            results = await tester.query_traffic(query, limit=3)
            tester.display_results(results, reconstruct=True, show_metadata=False)
            
            # Small delay between queries
            await asyncio.sleep(0.5)
        
        print("\n" + "=" * 50)
        print("✅ All predefined queries completed!")
        print("=" * 50)
        
    except Exception as e:
        print(f"[ERROR] Error: {e}")
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(run_predefined_queries())
