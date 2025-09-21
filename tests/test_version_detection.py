#!/usr/bin/env python3
"""
Version Detection Test Script

This script tests if version information is being properly detected, stored,
and retrieved from the database.
"""

import asyncio
import sqlite3
import sys
import os
from typing import List, Dict, Any

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)

# Configuration
DB_PATH = "./chroma_data"
DB_SQLITE_PATH = f"{DB_PATH}/chroma.sqlite3"
COLLECTION_NAME = "security_memory"


class VersionDetectionTester:
    """Test version detection and retrieval."""
    
    def __init__(self):
        self.memory: ChromaDBVectorMemory = None
        self.db_path = DB_SQLITE_PATH
    
    async def initialize(self):
        """Initialize the ChromaDB memory."""
        print("[*] Initializing ChromaDB memory...")
        
        config = PersistentChromaDBVectorMemoryConfig(
            collection_name=COLLECTION_NAME,
            persistence_path=DB_PATH,
            embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
                model_name="all-MiniLM-L6-v2"
            ),
            k=5,
            score_threshold=0.3,
        )
        self.memory = ChromaDBVectorMemory(config=config)
        print("[+] ChromaDB memory initialized")
    
    def check_metadata_fields(self):
        """Check what metadata fields are stored in the database."""
        print("\n[INFO] Checking metadata fields in database...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Get all unique metadata keys
        cur.execute("SELECT DISTINCT key FROM embedding_metadata ORDER BY key")
        keys = [row[0] for row in cur.fetchall()]
        
        print(f"[INFO] Found {len(keys)} metadata fields:")
        for key in keys:
            print(f"  - {key}")
        
        # Check for version-related fields
        version_keys = [k for k in keys if 'version' in k.lower() or 'stack' in k.lower()]
        if version_keys:
            print(f"\n[INFO] Version/Stack related fields: {version_keys}")
        else:
            print("\n[WARNING] No version/stack related fields found!")
        
        conn.close()
        return keys
    
    def check_stack_detection_errors(self):
        """Check for stack detection errors."""
        print("\n[INFO] Checking stack detection errors...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Count stack detection errors
        cur.execute("SELECT COUNT(*) FROM embedding_metadata WHERE key = 'stack_detection_error'")
        error_count = cur.fetchone()[0]
        
        if error_count > 0:
            print(f"[WARNING] Found {error_count} stack detection errors")
            
            # Get sample errors
            cur.execute("SELECT string_value FROM embedding_metadata WHERE key = 'stack_detection_error' LIMIT 3")
            errors = [row[0] for row in cur.fetchall()]
            
            print("[INFO] Sample errors:")
            for i, error in enumerate(errors, 1):
                print(f"  {i}. {error}")
        else:
            print("[INFO] No stack detection errors found")
        
        conn.close()
        return error_count
    
    def check_version_data(self):
        """Check if any version data is stored."""
        print("\n[INFO] Checking for version data in metadata...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Look for any metadata that might contain version info
        version_queries = [
            "SELECT COUNT(*) FROM embedding_metadata WHERE string_value LIKE '%version%'",
            "SELECT COUNT(*) FROM embedding_metadata WHERE string_value LIKE '%jquery%'",
            "SELECT COUNT(*) FROM embedding_metadata WHERE string_value LIKE '%bootstrap%'",
            "SELECT COUNT(*) FROM embedding_metadata WHERE string_value LIKE '%react%'",
            "SELECT COUNT(*) FROM embedding_metadata WHERE string_value LIKE '%angular%'",
        ]
        
        version_counts = {}
        for query in version_queries:
            cur.execute(query)
            count = cur.fetchone()[0]
            query_name = query.split("LIKE '%")[1].split("%'")[0]
            version_counts[query_name] = count
        
        print("[INFO] Version-related data counts:")
        for term, count in version_counts.items():
            print(f"  - {term}: {count} occurrences")
        
        # Get sample version data
        cur.execute("SELECT string_value FROM embedding_metadata WHERE string_value LIKE '%version%' LIMIT 5")
        version_samples = [row[0] for row in cur.fetchall()]
        
        if version_samples:
            print("\n[INFO] Sample version data:")
            for i, sample in enumerate(version_samples, 1):
                print(f"  {i}. {sample[:100]}...")
        else:
            print("\n[WARNING] No version data found in metadata!")
        
        conn.close()
        return version_counts
    
    async def test_version_queries(self):
        """Test queries for version-related information."""
        print("\n[INFO] Testing version-related queries...")
        
        version_queries = [
            "jquery version",
            "bootstrap version", 
            "outdated libraries",
            "vulnerable versions",
            "old versions",
            "version disclosure",
            "library versions",
            "framework versions",
            "javascript libraries",
            "web technologies"
        ]
        
        results_summary = {}
        
        for query in version_queries:
            print(f"\n[QUERY] Testing: '{query}'")
            
            try:
                results = await self.memory.query(query)
                if hasattr(results, 'results'):
                    results = results.results
                elif hasattr(results, 'documents'):
                    results = results.documents
                
                result_count = len(results)
                results_summary[query] = result_count
                
                print(f"[RESULT] Found {result_count} results")
                
                # Check if any results contain version info
                version_found = False
                for doc in results[:3]:  # Check first 3 results
                    content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                    meta = getattr(doc, "metadata", None) or (doc.get("metadata") if isinstance(doc, dict) else None) or {}
                    
                    if content and ('version' in content.lower() or 'jquery' in content.lower() or 'bootstrap' in content.lower()):
                        version_found = True
                        print(f"[VERSION] Found version info in result: {content[:100]}...")
                        break
                
                if not version_found and result_count > 0:
                    print("[INFO] No obvious version info in top results")
                    
            except Exception as e:
                print(f"[ERROR] Query failed: {e}")
                results_summary[query] = -1
        
        return results_summary
    
    def analyze_traffic_for_versions(self):
        """Analyze traffic content for version information."""
        print("\n[INFO] Analyzing traffic content for version information...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Look for version patterns in the actual content
        version_patterns = [
            r'jquery[-\s]*(\d+\.\d+\.\d+)',
            r'bootstrap[-\s]*(\d+\.\d+\.\d+)',
            r'version[:\s]*(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+)',
        ]
        
        import re
        version_matches = {}
        
        for pattern in version_patterns:
            # Search in the fulltext search table
            cur.execute("""
                SELECT efs.string_value, COUNT(*) as count
                FROM embedding_fulltext_search efs
                JOIN embedding_metadata em ON efs.rowid = em.id
                WHERE efs.string_value REGEXP ?
                GROUP BY efs.string_value
                LIMIT 10
            """, (pattern,))
            
            matches = cur.fetchall()
            if matches:
                version_matches[pattern] = matches
                print(f"\n[PATTERN] {pattern}:")
                for content, count in matches:
                    print(f"  - {content[:80]}... (found {count} times)")
        
        conn.close()
        return version_matches
    
    async def close(self):
        """Close the memory connection."""
        if self.memory:
            await self.memory.close()


async def main():
    """Main function."""
    tester = VersionDetectionTester()
    
    try:
        await tester.initialize()
        
        # Run all checks
        metadata_fields = tester.check_metadata_fields()
        error_count = tester.check_stack_detection_errors()
        version_counts = tester.check_version_data()
        query_results = await tester.test_version_queries()
        version_matches = tester.analyze_traffic_for_versions()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 VERSION DETECTION ANALYSIS SUMMARY")
        print("=" * 60)
        
        print(f"Metadata fields: {len(metadata_fields)}")
        print(f"Stack detection errors: {error_count}")
        print(f"Version-related metadata: {sum(version_counts.values())}")
        print(f"Successful queries: {len([r for r in query_results.values() if r > 0])}")
        print(f"Version patterns found: {len(version_matches)}")
        
        if error_count > 0:
            print("\n❌ ISSUE: Stack detection is failing - versions not being stored")
            print("   Fix: The stack detector function signature was updated")
            print("   Action: Re-run the collector to capture versions properly")
        else:
            print("\n✅ Stack detection is working")
        
        if sum(version_counts.values()) == 0:
            print("\n❌ ISSUE: No version data found in metadata")
            print("   This suggests stack detection isn't working properly")
        else:
            print(f"\n✅ Found {sum(version_counts.values())} version-related entries")
        
    except Exception as e:
        print(f"[ERROR] Error: {e}")
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(main())
