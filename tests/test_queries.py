#!/usr/bin/env python3
"""
Interactive Query Tester for ZAP RAG Security Agent

This script allows you to test semantic queries against captured traffic
without sending to the LLM. Perfect for testing retrieval and reconstruction.

Usage:
    python test_queries.py
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


class QueryTester:
    """Interactive query tester for testing retrieval and reconstruction."""
    
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
            k=3,
            score_threshold=0.3,
        )
        self.memory = ChromaDBVectorMemory(config=config)
        print("[+] ChromaDB memory initialized")
    
    async def query_traffic(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Query traffic data and return results."""
        print(f"\n[INFO] Running query: '{query}'...")
        
        try:
            results = await self.memory.query(query)
            if hasattr(results, 'results'):
                results = results.results
            elif hasattr(results, 'documents'):
                results = results.documents
            
            print(f"[INFO] Query returned {len(results)} results")
            return results[:limit]
        except Exception as e:
            print(f"[ERROR] Error querying ChromaDB: {e}")
            return []
    
    def fetch_group_parts(self, group_id: str) -> List[tuple[str, str]]:
        """Fetch all parts for a group_id from the database."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Try different column names for compatibility
        sql_template = """
        SELECT part_meta.string_value AS part,
               efs.{fts_col} AS text
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
        
        for fts_col in ("string_value", "content"):
            try:
                sql = sql_template.format(fts_col=fts_col)
                cur.execute(sql, (str(group_id),))
                rows = cur.fetchall()
                conn.close()
                return rows
            except sqlite3.OperationalError:
                continue
        
        conn.close()
        return []
    
    def reconstruct_http_message(self, group_id: str) -> str:
        """Reconstruct a complete HTTP message from stored parts."""
        rows = self.fetch_group_parts(group_id)
        if not rows:
            return f"(no chunks found for group_id={group_id})"
        
        path, body = None, None
        query_items, headers_lines, other_parts = [], [], []
        resp_path, resp_body = None, None
        resp_query_items, resp_headers_lines, resp_other_parts = [], [], []
        
        for part, text in rows:
            t = (text or "").strip()
            if not t:
                continue
            p = part.lower()
            if p == "path":
                if path is None:
                    path = t
            elif p == "query":
                query_items.append(t)
            elif p in ("headers", "header"):
                for line in t.splitlines():
                    if line.strip():
                        headers_lines.append(line.strip())
            elif p == "body":
                body = t if body is None else body + "\n" + t
            elif p == "resp_path":
                if resp_path is None:
                    resp_path = t
            elif p == "resp_query":
                resp_query_items.append(t)
            elif p in ("resp_headers", "resp_header"):
                for line in t.splitlines():
                    if line.strip():
                        resp_headers_lines.append(line.strip())
            elif p == "resp_body":
                resp_body = t if resp_body is None else resp_body + "\n" + t
            else:
                other_parts.append((p, t))
        
        # Build output
        out_lines = []
        
        # Request section
        if path or query_items or headers_lines or body:
            out_lines.append("=== REQUEST ===")
            if path:
                out_lines.append("[PATH]")
                out_lines.append(path)
            if query_items:
                out_lines.append("[QUERY]")
                if len(query_items) == 1 and ("=" not in query_items[0] or "&" in query_items[0]):
                    out_lines.append(query_items[0])
                else:
                    out_lines.append("&".join(q for q in query_items if q))
            if headers_lines:
                out_lines.append("[HEADERS]")
                out_lines.extend(headers_lines)
            if body:
                out_lines.append("[BODY]")
                out_lines.append(body)
        
        # Response section
        if resp_path or resp_query_items or resp_headers_lines or resp_body:
            out_lines.append("\n=== RESPONSE ===")
            if resp_path:
                out_lines.append("[PATH]")
                out_lines.append(resp_path)
            if resp_query_items:
                out_lines.append("[QUERY]")
                if len(resp_query_items) == 1 and ("=" not in resp_query_items[0] or "&" in resp_query_items[0]):
                    out_lines.append(resp_query_items[0])
                else:
                    out_lines.append("&".join(q for q in resp_query_items if q))
            if resp_headers_lines:
                out_lines.append("[HEADERS]")
                out_lines.extend(resp_headers_lines)
            if resp_body:
                out_lines.append("[BODY]")
                out_lines.append(resp_body)
        
        # Other parts
        for p, t in other_parts:
            out_lines.append(f"[{p.upper()}]")
            out_lines.append(t)
        
        return "\n".join(out_lines)
    
    def reconstruct_http_message_with_analysis(self, group_id: str) -> str:
        """Reconstruct a complete HTTP message with analysis metadata for better context."""
        # First, get the basic HTTP message
        http_message = self.reconstruct_http_message(group_id)
        
        # Query for analysis metadata
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        analysis_sql = """
        SELECT 
            m1.key,
            m1.string_value,
            m1.float_value,
            m1.int_value
        FROM embedding_metadata m1
        JOIN embedding_metadata group_meta 
          ON group_meta.id = m1.id AND group_meta.key = 'group_id'
        WHERE group_meta.string_value = ?
          AND m1.key IN (
              'suspicion_score', 'suspicious', 'suspicious_tags', 'chunk_type',
              'stack_detection', 'top_component', 'component_candidates',
              'security_analysis', 'security_issues_summary', 'stack_detection_error'
          )
        ORDER BY m1.key;
        """
        
        cur.execute(analysis_sql, (str(group_id),))
        analysis_rows = cur.fetchall()
        conn.close()
        
        # Build analysis section
        analysis_lines = []
        analysis_data = {}
        
        # Process analysis metadata
        for key, string_val, float_val, int_val in analysis_rows:
            value = string_val if string_val is not None else (float_val if float_val is not None else int_val)
            if value is not None:
                analysis_data[key] = value
        
        # Add analysis section if we have data
        if analysis_data:
            analysis_lines.append("\n[ANALYSIS]")
            
            # Suspicion analysis
            if 'suspicion_score' in analysis_data:
                score = analysis_data['suspicion_score']
                suspicious = analysis_data.get('suspicious', False)
                tags = analysis_data.get('suspicious_tags', '[]')
                analysis_lines.append(f"Suspicion Score: {score} ({'SUSPICIOUS' if suspicious else 'CLEAN'})")
                if tags and tags != '[]':
                    analysis_lines.append(f"Suspicious Tags: {tags}")
            
            # Stack detection
            if 'stack_detection' in analysis_data:
                stack_info = analysis_data['stack_detection']
                if stack_info:
                    try:
                        import json
                        # Handle both old format (Python dict string) and new format (JSON)
                        if isinstance(stack_info, str):
                            if stack_info.startswith('{') and "'" in stack_info and '"' not in stack_info:
                                # Old format: Python dict string with single quotes
                                import ast
                                stack_data = ast.literal_eval(stack_info)
                            else:
                                # New format: JSON
                                stack_data = json.loads(stack_info)
                        else:
                            stack_data = stack_info
                            
                        total_detected = stack_data.get('total_detected', 0)
                        confidence = stack_data.get('confidence', 0.0)
                        analysis_lines.append(f"Technologies Detected: {total_detected} (confidence: {confidence:.2f})")
                        
                        # Add detection methods
                        methods = stack_data.get('detection_methods', [])
                        if methods:
                            analysis_lines.append(f"Detection Methods: {', '.join(methods)}")
                    except (json.JSONDecodeError, AttributeError, ValueError, SyntaxError):
                        analysis_lines.append(f"Stack Detection: {stack_info}")
            
            # Top component
            if 'top_component' in analysis_data:
                top_comp = analysis_data['top_component']
                if top_comp:
                    try:
                        import json
                        # Handle both old format (Python dict string) and new format (JSON)
                        if isinstance(top_comp, str):
                            if top_comp.startswith('{') and "'" in top_comp and '"' not in top_comp:
                                # Old format: Python dict string with single quotes
                                import ast
                                comp_data = ast.literal_eval(top_comp)
                            else:
                                # New format: JSON
                                comp_data = json.loads(top_comp)
                        else:
                            comp_data = top_comp
                            
                        name = comp_data.get('name', 'Unknown')
                        version = comp_data.get('version', 'N/A')
                        comp_type = comp_data.get('type', 'Unknown')
                        confidence = comp_data.get('confidence', 0.0)
                        is_vulnerable = comp_data.get('is_vulnerable', False)
                        
                        vuln_status = " ⚠️ VULNERABLE" if is_vulnerable else ""
                        analysis_lines.append(f"Top Component: {name} v{version} ({comp_type}, confidence: {confidence:.2f}){vuln_status}")
                    except (json.JSONDecodeError, AttributeError, ValueError, SyntaxError):
                        analysis_lines.append(f"Top Component: {top_comp}")
            
            # Component candidates
            if 'component_candidates' in analysis_data:
                candidates = analysis_data['component_candidates']
                if candidates:
                    try:
                        import json
                        # Handle both old format (Python dict string) and new format (JSON)
                        if isinstance(candidates, str):
                            if candidates.startswith('[') and "'" in candidates and '"' not in candidates:
                                # Old format: Python list string with single quotes
                                import ast
                                candidates_data = ast.literal_eval(candidates)
                            else:
                                # New format: JSON
                                candidates_data = json.loads(candidates)
                        else:
                            candidates_data = candidates
                            
                        if candidates_data:
                            analysis_lines.append("Component Candidates:")
                            for comp in candidates_data[:5]:  # Show top 5
                                name = comp.get('name', 'Unknown')
                                version = comp.get('version', 'N/A')
                                confidence = comp.get('confidence', 0.0)
                                is_vulnerable = comp.get('is_vulnerable', False)
                                vuln_status = " ⚠️ VULNERABLE" if is_vulnerable else ""
                                analysis_lines.append(f"  - {name} v{version} (confidence: {confidence:.2f}){vuln_status}")
                    except (json.JSONDecodeError, AttributeError, ValueError, SyntaxError):
                        analysis_lines.append(f"Component Candidates: {candidates}")
            
            # Security analysis
            if 'security_analysis' in analysis_data:
                sec_analysis = analysis_data['security_analysis']
                if sec_analysis:
                    try:
                        import json
                        # Handle both old format (Python dict string) and new format (JSON)
                        if isinstance(sec_analysis, str):
                            if sec_analysis.startswith('{') and "'" in sec_analysis and '"' not in sec_analysis:
                                # Old format: Python dict string with single quotes
                                import ast
                                sec_data = ast.literal_eval(sec_analysis)
                            else:
                                # New format: JSON
                                sec_data = json.loads(sec_analysis)
                        else:
                            sec_data = sec_analysis
                            
                        total_issues = sec_data.get('total_security_issues', 0)
                        high_severity = sec_data.get('high_severity_issues', 0)
                        medium_severity = sec_data.get('medium_severity_issues', 0)
                        risk_score = sec_data.get('security_risk_score', 0)
                        has_vulnerabilities = sec_data.get('has_vulnerabilities', False)
                        
                        analysis_lines.append(f"Security Issues: {total_issues} total ({high_severity} high, {medium_severity} medium)")
                        analysis_lines.append(f"Security Risk Score: {risk_score}")
                        if has_vulnerabilities:
                            analysis_lines.append("⚠️ VULNERABILITIES DETECTED")
                    except (json.JSONDecodeError, AttributeError, ValueError, SyntaxError):
                        analysis_lines.append(f"Security Analysis: {sec_analysis}")
            
            # Security issues summary
            if 'security_issues_summary' in analysis_data:
                issues_summary = analysis_data['security_issues_summary']
                if issues_summary:
                    try:
                        import json
                        # Handle both old format (Python dict string) and new format (JSON)
                        if isinstance(issues_summary, str):
                            if issues_summary.startswith('[') and "'" in issues_summary and '"' not in issues_summary:
                                # Old format: Python list string with single quotes
                                import ast
                                issues_data = ast.literal_eval(issues_summary)
                            else:
                                # New format: JSON
                                issues_data = json.loads(issues_summary)
                        else:
                            issues_data = issues_summary
                            
                        if issues_data:
                            analysis_lines.append("Security Issues Summary:")
                            for issue in issues_data[:3]:  # Show top 3
                                issue_type = issue.get('type', 'Unknown')
                                severity = issue.get('severity', 'Unknown')
                                description = issue.get('description', 'No description')
                                analysis_lines.append(f"  - {issue_type} ({severity}): {description}")
                    except (json.JSONDecodeError, AttributeError, ValueError, SyntaxError):
                        analysis_lines.append(f"Security Issues: {issues_summary}")
            
            # Stack detection errors
            if 'stack_detection_error' in analysis_data:
                error = analysis_data['stack_detection_error']
                analysis_lines.append(f"Stack Detection Error: {error}")
        
        # Combine HTTP message and analysis
        if analysis_lines:
            return http_message + "\n".join(analysis_lines)
        else:
            return http_message
    
    def display_results(self, results: List[Dict[str, Any]], reconstruct: bool = True, show_metadata: bool = False, with_analysis: bool = True):
        """Display query results with optional reconstruction and analysis."""
        if not results:
            print("[INFO] No results found.")
            return
        
        print(f"\n[INFO] Displaying {len(results)} results:")
        print("=" * 80)
        
        for i, doc in enumerate(results, 1):
            print(f"\n[RESULT {i}]")
            
            # Show metadata if requested
            if show_metadata:
                meta = getattr(doc, "metadata", None) or (doc.get("metadata") if isinstance(doc, dict) else None) or {}
                print(f"Metadata: {meta}")
            
            # Get group_id for reconstruction
            meta = getattr(doc, "metadata", None) or (doc.get("metadata") if isinstance(doc, dict) else None) or {}
            group_id = meta.get("group_id")
            
            if reconstruct and group_id:
                print(f"Group ID: {group_id}")
                if with_analysis:
                    full_msg = self.reconstruct_http_message_with_analysis(group_id)
                    print("Reconstructed HTTP Message with Analysis:")
                else:
                    full_msg = self.reconstruct_http_message(group_id)
                    print("Reconstructed HTTP Message:")
                print("-" * 40)
                print(full_msg)
            else:
                content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                print("Content:")
                print("-" * 40)
                print((content or "")[:500])
            
            print("-" * 80)
    
    def get_database_stats(self):
        """Get statistics about the database."""
        print("\n[INFO] Database Statistics:")
        print("=" * 40)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            
            # Count total documents
            cur.execute("SELECT COUNT(*) FROM embedding_metadata WHERE key = 'type' AND string_value = 'traffic'")
            traffic_count = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM embedding_metadata WHERE key = 'type' AND string_value = 'baseline'")
            baseline_count = cur.fetchone()[0]
            
            # Count unique group_ids
            cur.execute("SELECT COUNT(DISTINCT string_value) FROM embedding_metadata WHERE key = 'group_id'")
            unique_groups = cur.fetchone()[0]
            
            print(f"Traffic documents: {traffic_count}")
            print(f"Baseline documents: {baseline_count}")
            print(f"Unique HTTP requests: {unique_groups}")
            
            # Check for analysis metadata
            analysis_fields = ['suspicion_score', 'stack_detection', 'top_component', 'component_candidates', 'security_analysis']
            print(f"\nAnalysis metadata availability:")
            for field in analysis_fields:
                cur.execute(f"SELECT COUNT(*) FROM embedding_metadata WHERE key = '{field}'")
                count = cur.fetchone()[0]
                print(f"  {field}: {count} records")
            
            conn.close()
        except Exception as e:
            print(f"[ERROR] Error getting database stats: {e}")
    
    async def interactive_mode(self):
        """Run interactive query mode."""
        print("\n" + "=" * 60)
        print("🔍 INTERACTIVE QUERY TESTER")
        print("=" * 60)
        print("Test semantic queries against captured traffic")
        print("Commands:")
        print("  - Type any query to search")
        print("  - 'stats' - Show database statistics")
        print("  - 'help' - Show this help")
        print("  - 'analysis on/off' - Toggle analysis display")
        print("  - 'metadata on/off' - Toggle metadata display")
        print("  - 'quit' - Exit")
        print("\nSuggested queries for stack detection:")
        print("  - 'technologies detected' - Find requests with technology detection")
        print("  - 'vulnerable components' - Find vulnerable technologies")
        print("  - 'PHP nginx' - Find PHP and nginx usage")
        print("  - 'jQuery Bootstrap' - Find frontend frameworks")
        print("  - 'security issues' - Find security problems")
        print("=" * 60)
        
        # Default settings
        show_analysis = True
        show_metadata = False
        
        while True:
            try:
                user_input = input("\n>>> ").strip()
                
                if user_input.lower() in {'quit', 'exit', 'q'}:
                    print("[*] Exiting...")
                    break
                elif user_input.lower() == 'stats':
                    self.get_database_stats()
                elif user_input.lower() == 'help':
                    print("\nCommands:")
                    print("  - Type any query to search (e.g., 'SQL injection', 'XSS', 'authentication')")
                    print("  - 'stats' - Show database statistics")
                    print("  - 'analysis on/off' - Toggle analysis display (currently: {})".format('ON' if show_analysis else 'OFF'))
                    print("  - 'metadata on/off' - Toggle metadata display (currently: {})".format('ON' if show_metadata else 'OFF'))
                    print("  - 'help' - Show this help")
                    print("  - 'quit' - Exit")
                elif user_input.lower() == 'analysis on':
                    show_analysis = True
                    print("[*] Analysis display enabled")
                elif user_input.lower() == 'analysis off':
                    show_analysis = False
                    print("[*] Analysis display disabled")
                elif user_input.lower() == 'metadata on':
                    show_metadata = True
                    print("[*] Metadata display enabled")
                elif user_input.lower() == 'metadata off':
                    show_metadata = False
                    print("[*] Metadata display disabled")
                elif user_input:
                    results = await self.query_traffic(user_input)
                    self.display_results(results, reconstruct=True, show_metadata=show_metadata, with_analysis=show_analysis)
                else:
                    print("[!] Please enter a query or command")
                    
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Exiting...")
                break
            except Exception as e:
                print(f"[ERROR] Error: {e}")
    
    async def close(self):
        """Close the memory connection."""
        if self.memory:
            await self.memory.close()


async def main():
    """Main function."""
    tester = QueryTester()
    
    try:
        await tester.initialize()
        
        # Show initial stats
        tester.get_database_stats()
        
        # Run interactive mode
        await tester.interactive_mode()
        
    except Exception as e:
        print(f"[ERROR] Error: {e}")
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(main())
