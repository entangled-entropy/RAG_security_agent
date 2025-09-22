#!/usr/bin/env python3
"""
Reprocess existing ChromaDB data with new version management system.

This script will take existing traffic data and add outdated component detection.
"""

import sys
import os
import asyncio
import sqlite3
import json
from typing import Dict, List, Any

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from zap_rag_security_agent.detectors.stack_detector import detect_stack_from_traffic


class DataReprocessor:
    """Reprocess existing data with version management."""
    
    def __init__(self):
        self.memory = None
        self.db_path = "./chroma_data/chroma.sqlite3"
        self.collection_name = "security_memory"
    
    async def initialize(self):
        """Initialize the ChromaDB memory."""
        print("[*] Initializing ChromaDB memory...")
        
        config = PersistentChromaDBVectorMemoryConfig(
            collection_name=self.collection_name,
            persistence_path="./chroma_data",
            embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
                model_name="all-MiniLM-L6-v2"
            ),
            k=3,
            score_threshold=0.3,
        )
        self.memory = ChromaDBVectorMemory(config=config)
        print("[+] ChromaDB memory initialized")
    
    def get_traffic_groups(self) -> List[str]:
        """Get all traffic group IDs from the database."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Get all group_ids that have stack detection data
        cur.execute("""
            SELECT DISTINCT group_meta.string_value
            FROM embedding_metadata group_meta
            JOIN embedding_metadata stack_meta 
              ON group_meta.id = stack_meta.id AND stack_meta.key = 'stack_detection'
            WHERE group_meta.key = 'group_id'
        """)
        
        groups = [row[0] for row in cur.fetchall()]
        conn.close()
        
        print(f"[INFO] Found {len(groups)} traffic groups with stack detection data")
        return groups
    
    def get_group_data(self, group_id: str) -> Dict[str, Any]:
        """Get all data for a group ID."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Get all parts for this group
        sql = """
        SELECT part_meta.string_value AS part,
               efs.string_value AS text
        FROM embedding_metadata part_meta
        JOIN embedding_fulltext_search efs ON part_meta.id = efs.rowid
        JOIN embedding_metadata group_meta 
          ON group_meta.id = part_meta.id AND group_meta.key = 'group_id'
        WHERE part_meta.key = 'part' AND group_meta.string_value = ?
        ORDER BY CASE LOWER(part_meta.string_value)
            WHEN 'path' THEN 1
            WHEN 'query' THEN 2
            WHEN 'headers' THEN 3
            WHEN 'body' THEN 4
            WHEN 'resp_path' THEN 5
            WHEN 'resp_query' THEN 6
            WHEN 'resp_headers' THEN 7
            WHEN 'resp_body' THEN 8
            ELSE 9 END, part_meta.string_value;
        """
        
        cur.execute(sql, (str(group_id),))
        rows = cur.fetchall()
        conn.close()
        
        # Organize data by part type
        data = {
            'path': '',
            'query': '',
            'headers': '',
            'body': '',
            'resp_path': '',
            'resp_query': '',
            'resp_headers': '',
            'resp_body': ''
        }
        
        for part, text in rows:
            if text and text.strip():
                data[part] = text.strip()
        
        return data
    
    def extract_script_srcs(self, html_content: str) -> List[str]:
        """Extract script src URLs from HTML content."""
        import re
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        return matches
    
    def extract_meta_content(self, html_content: str) -> str:
        """Extract meta tags content from HTML."""
        import re
        meta_pattern = r'<meta[^>]+>'
        matches = re.findall(meta_pattern, html_content, re.IGNORECASE)
        return '\n'.join(matches)
    
    async def reprocess_group(self, group_id: str) -> Dict[str, Any]:
        """Reprocess a single group with version management."""
        print(f"[INFO] Reprocessing group {group_id}...")
        
        # Get existing data
        data = self.get_group_data(group_id)
        
        # Extract components for stack detection
        headers_text = data.get('headers', '') + '\n' + data.get('resp_headers', '')
        html_content = data.get('body', '') + data.get('resp_body', '')
        script_srcs = self.extract_script_srcs(html_content)
        meta_content = self.extract_meta_content(html_content)
        post_data = data.get('body', '') if data.get('body', '').strip() else ''
        
        # Run stack detection with version management
        result = detect_stack_from_traffic(
            headers_text=headers_text,
            html_content=html_content,
            script_srcs=script_srcs,
            meta_content=meta_content,
            post_data=post_data,
            url="https://example.com"  # Default URL
        )
        
        return result
    
    async def update_group_metadata(self, group_id: str, stack_result: Dict[str, Any]):
        """Update group metadata with new version information."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Get the document ID for this group
        cur.execute("""
            SELECT efs.rowid
            FROM embedding_metadata group_meta
            JOIN embedding_fulltext_search efs ON group_meta.id = efs.rowid
            WHERE group_meta.key = 'group_id' AND group_meta.string_value = ?
            LIMIT 1
        """, (str(group_id),))
        
        result = cur.fetchone()
        if not result:
            conn.close()
            return False
        
        doc_id = result[0]
        
        # Add outdated components metadata
        if stack_result.get('outdated_components'):
            outdated_json = json.dumps(stack_result['outdated_components'])
            cur.execute("""
                INSERT OR REPLACE INTO embedding_metadata (id, key, string_value)
                VALUES (?, 'outdated_components', ?)
            """, (doc_id, outdated_json))
        
        # Add total outdated count
        total_outdated = stack_result.get('total_outdated', 0)
        cur.execute("""
            INSERT OR REPLACE INTO embedding_metadata (id, key, int_value)
            VALUES (?, 'total_outdated', ?)
        """, (doc_id, total_outdated))
        
        # Update existing stack detection with version info
        if stack_result.get('detected_technologies'):
            # Add version info to each detected technology
            enhanced_techs = {}
            for tech_name, tech_info in stack_result['detected_technologies'].items():
                if isinstance(tech_info, dict):
                    enhanced_techs[tech_name] = tech_info
            
            enhanced_json = json.dumps(enhanced_techs)
            cur.execute("""
                INSERT OR REPLACE INTO embedding_metadata (id, key, string_value)
                VALUES (?, 'enhanced_technologies', ?)
            """, (doc_id, enhanced_json))
        
        conn.commit()
        conn.close()
        return True
    
    async def reprocess_all(self, limit: int = 10):
        """Reprocess all traffic groups with version management."""
        print(f"[*] Starting reprocessing of up to {limit} traffic groups...")
        
        groups = self.get_traffic_groups()
        processed = 0
        
        for group_id in groups[:limit]:
            try:
                # Reprocess with version management
                stack_result = await self.reprocess_group(group_id)
                
                # Update metadata
                success = await self.update_group_metadata(group_id, stack_result)
                
                if success:
                    processed += 1
                    print(f"[+] Updated group {group_id} with version data")
                    
                    # Show some results
                    if stack_result.get('outdated_components'):
                        print(f"  Found {len(stack_result['outdated_components'])} outdated components:")
                        for comp in stack_result['outdated_components'][:3]:
                            name = comp.get('name', 'Unknown')
                            version = comp.get('version', 'N/A')
                            latest = comp.get('latest_version', 'N/A')
                            status = comp.get('security_status', 'unknown')
                            print(f"    - {name} v{version} → v{latest} ({status})")
                else:
                    print(f"[-] Failed to update group {group_id}")
                    
            except Exception as e:
                print(f"[-] Error processing group {group_id}: {e}")
        
        print(f"\n[INFO] Successfully processed {processed} groups")
        return processed
    
    async def close(self):
        """Close the memory connection."""
        if self.memory:
            await self.memory.close()


async def main():
    """Main function."""
    reprocessor = DataReprocessor()
    
    try:
        await reprocessor.initialize()
        
        # Reprocess a few groups to test
        processed = await reprocessor.reprocess_all(limit=5)
        
        if processed > 0:
            print(f"\n✅ Successfully reprocessed {processed} groups with version management!")
            print("You can now query for 'outdated versions' in test_queries.py")
        else:
            print("\n❌ No groups were processed")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await reprocessor.close()


if __name__ == "__main__":
    asyncio.run(main())
