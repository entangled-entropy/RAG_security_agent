"""
Security Analysis Agent

Main RAG-powered security analysis agent using AutoGen and ChromaDB.
Provides interactive security analysis of HTTP traffic with intelligent
vulnerability detection and recommendations.
"""

import asyncio
import sqlite3
from typing import List, Dict, Any, Optional
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_ext.models.openai import OpenAIChatCompletionClient

from ..detectors.client_script_analyzer import ClientScriptAnalyzer


class SecurityAnalysisAgent:
    """
    RAG-powered security analysis agent for HTTP traffic analysis.
    
    Combines ChromaDB vector memory with OpenAI GPT models to provide
    intelligent security analysis of captured HTTP traffic.
    """
    
    def __init__(
        self,
        persist_path: str = "./chroma_data",
        collection_name: str = "security_memory",
        model: str = "gpt-4o",
        k: int = 3,
        score_threshold: float = 0.3
    ):
        """
        Initialize the Security Analysis Agent.
        
        Args:
            persist_path: Path to persist ChromaDB data
            collection_name: Name of the ChromaDB collection
            model: OpenAI model to use for analysis
            k: Number of top documents to retrieve
            score_threshold: Minimum similarity score for retrieval
        """
        self.persist_path = persist_path
        self.collection_name = collection_name
        self.model = model
        self.k = k
        self.score_threshold = score_threshold
        
        self.memory: Optional[ChromaDBVectorMemory] = None
        self.model_client: Optional[OpenAIChatCompletionClient] = None
        self.assistant_agent: Optional[AssistantAgent] = None
        self.script_analyzer: Optional[ClientScriptAnalyzer] = None
        
        self.system_prompt = (
            "You are SecurityAnalysisAgent, a security analyst. "
            "Use memory context to detect vulnerabilities, exposed secrets, "
            "outdated components, and suspicious patterns. "
            "Pay special attention to client-side JavaScript analysis results, "
            "including obfuscated code, suspicious patterns, and custom scripts. "
            "Provide concise, actionable answers."
            "check library version is outdated or has known exploits and CVEs and show me"
            "do your own research and check whether its really safe or vulnerable, do not take the tags and scores for granted"
        )
    
    async def initialize(self) -> None:
        """Initialize the agent and its components."""
        print("[*] Initializing Security Analysis Agent...")
        
        # Initialize ChromaDB memory
        config = PersistentChromaDBVectorMemoryConfig(
            collection_name=self.collection_name,
            persistence_path=self.persist_path,
            embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
                model_name="all-MiniLM-L6-v2"
            ),
            k=self.k,
            score_threshold=self.score_threshold,
        )
        self.memory = ChromaDBVectorMemory(config=config)
        
        # Initialize OpenAI model
        self.model_client = OpenAIChatCompletionClient(model=self.model)
        
        # Initialize assistant agent
        self.assistant_agent = AssistantAgent(
            name="SecurityAnalysisAgent",
            model_client=self.model_client,
            memory=[self.memory],
            system_message=self.system_prompt,
        )
        
        # Initialize script analyzer for on-demand analysis
        self.script_analyzer = ClientScriptAnalyzer()
        
        print("[+] Security Analysis Agent initialized successfully")
    
    async def query_memory(self, query: str) -> List[Dict[str, Any]]:
        """
        Query the ChromaDB memory for relevant documents.
        
        Args:
            query: Search query string
            
        Returns:
            List of relevant documents
        """
        if not self.memory:
            raise RuntimeError("Agent not initialized. Call initialize() first.")
        
        print(f"\n[INFO] Running query: '{query}'...")
        try:
            results = await self.memory.query(query)
            if hasattr(results, "results"):
                return results.results
            elif hasattr(results, "documents"):
                return results.documents
            else:
                return results
        except Exception as e:
            print(f"[ERROR] Error querying ChromaDB: {e}")
            return []
    
    def reconstruct_http_message(self, group_id: str, db_path: Optional[str] = None, include_body: bool = False) -> str:
        """
        Reconstruct a complete HTTP message from stored parts.
        
        Args:
            group_id: Group ID to reconstruct
            db_path: Path to ChromaDB SQLite database
            
        Returns:
            Reconstructed HTTP message
        """
        if db_path is None:
            db_path = f"{self.persist_path}/chroma.sqlite3"
        
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Query for all parts of the group
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
            ELSE 5 END, part_meta.string_value;
        """
        
        # Try different column names for compatibility
        for fts_col in ("string_value", "content"):
            try:
                sql = sql_template.format(fts_col=fts_col)
                cur.execute(sql, (str(group_id),))
                rows = cur.fetchall()
                conn.close()
                break
            except sqlite3.OperationalError:
                continue
        else:
            conn.close()
            return f"(no chunks found for group_id={group_id})"
        
        # Reconstruct the message
        path, body = None, None
        query_items, headers_lines, other_parts = [], [], []
        
        for part, text in rows:
            t = (text or "").strip()
            if not t:
                continue
            p = part.lower()
            # Strictly skip any response parts to avoid leaking responses
            if p.startswith("resp_") or p in ("resp_path", "resp_query", "resp_headers", "resp_body"):
                continue
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
            else:
                other_parts.append((p, t))
        
        # Build output (request-only summary by default; omit BODY to reduce tokens)
        out_lines = []
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
        if include_body and body:
            out_lines.append("[BODY]")
            out_lines.append(body)
        for p, t in other_parts:
            if p.startswith("resp_"):
                continue
            out_lines.append(f"[{p.upper()}]")
            out_lines.append(t)
        
        return "\n".join(out_lines)
    
    def reconstruct_client_script_analysis(self, group_id: str, db_path: Optional[str] = None) -> str:
        """
        Reconstruct client-side script analysis results for a group.
        
        Args:
            group_id: Group ID to reconstruct
            db_path: Path to ChromaDB SQLite database
            
        Returns:
            Reconstructed client-side script analysis
        """
        if db_path is None:
            db_path = f"{self.persist_path}/chroma.sqlite3"
        
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Query for client script analysis
        script_sql = """
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
              'script_id', 'script_url', 'script_type', 'analysis_confidence',
              'is_suspicious', 'is_obfuscated', 'is_custom', 'complexity_score',
              'suspicion_density', 'reasons'
          )
        ORDER BY m1.key;
        """
        
        cur.execute(script_sql, (str(group_id),))
        script_rows = cur.fetchall()
        conn.close()
        
        if not script_rows:
            return ""
        
        # Group by script_id
        scripts = {}
        for key, string_val, float_val, int_val in script_rows:
            value = string_val if string_val is not None else (float_val if float_val is not None else int_val)
            if value is not None:
                # Extract script_id from the row to group related metadata
                # This is a simplified approach - in practice, you'd need to join with the actual content
                if key == 'script_id':
                    script_id = value
                    if script_id not in scripts:
                        scripts[script_id] = {}
                elif 'script_id' in locals():
                    scripts[script_id][key] = value
        
        if not scripts:
            return ""
        
        # Build script analysis section
        analysis_lines = []
        analysis_lines.append("\n[CLIENT-SIDE SCRIPT ANALYSIS]")
        
        for script_id, script_data in scripts.items():
            analysis_lines.append(f"\nScript ID: {script_id}")
            analysis_lines.append(f"URL: {script_data.get('script_url', 'N/A')}")
            analysis_lines.append(f"Type: {script_data.get('script_type', 'N/A')}")
            analysis_lines.append(f"Confidence: {script_data.get('analysis_confidence', 0.0):.2f}")
            analysis_lines.append(f"Suspicious: {'Yes' if script_data.get('is_suspicious') else 'No'}")
            analysis_lines.append(f"Obfuscated: {'Yes' if script_data.get('is_obfuscated') else 'No'}")
            analysis_lines.append(f"Custom: {'Yes' if script_data.get('is_custom') else 'No'}")
            analysis_lines.append(f"Complexity Score: {script_data.get('complexity_score', 0.0):.2f}")
            analysis_lines.append(f"Suspicion Density: {script_data.get('suspicion_density', 0.0):.2f}")
            
            reasons = script_data.get('reasons', '[]')
            if reasons and reasons != '[]':
                analysis_lines.append(f"Analysis Reasons: {reasons}")
        
        return "\n".join(analysis_lines)
    
    def reconstruct_http_message_with_analysis(self, group_id: str, db_path: Optional[str] = None) -> str:
        """
        Reconstruct a complete HTTP message with analysis metadata for better context.
        
        Args:
            group_id: Group ID to reconstruct
            db_path: Path to ChromaDB SQLite database
            
        Returns:
            Reconstructed HTTP message with analysis data
        """
        if db_path is None:
            db_path = f"{self.persist_path}/chroma.sqlite3"
        
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # First, get the basic HTTP message (request-only summary)
        http_message = self.reconstruct_http_message(group_id, db_path, include_body=False)
        
        # Query for analysis metadata
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
                        stack_data = json.loads(stack_info) if isinstance(stack_info, str) else stack_info
                        total_detected = stack_data.get('total_detected', 0)
                        confidence = stack_data.get('confidence', 0.0)
                        analysis_lines.append(f"Technologies Detected: {total_detected} (confidence: {confidence:.2f})")
                        
                        # Add detection methods
                        methods = stack_data.get('detection_methods', [])
                        if methods:
                            analysis_lines.append(f"Detection Methods: {', '.join(methods)}")
                    except (json.JSONDecodeError, AttributeError):
                        analysis_lines.append(f"Stack Detection: {stack_info}")
            
            # Top component
            if 'top_component' in analysis_data:
                top_comp = analysis_data['top_component']
                if top_comp:
                    try:
                        import json
                        comp_data = json.loads(top_comp) if isinstance(top_comp, str) else top_comp
                        name = comp_data.get('name', 'Unknown')
                        version = comp_data.get('version', 'N/A')
                        comp_type = comp_data.get('type', 'Unknown')
                        confidence = comp_data.get('confidence', 0.0)
                        is_vulnerable = comp_data.get('is_vulnerable', False)
                        
                        vuln_status = " ⚠️ VULNERABLE" if is_vulnerable else ""
                        analysis_lines.append(f"Top Component: {name} v{version} ({comp_type}, confidence: {confidence:.2f}){vuln_status}")
                    except (json.JSONDecodeError, AttributeError):
                        analysis_lines.append(f"Top Component: {top_comp}")
            
            # Component candidates
            if 'component_candidates' in analysis_data:
                candidates = analysis_data['component_candidates']
                if candidates:
                    try:
                        import json
                        candidates_data = json.loads(candidates) if isinstance(candidates, str) else candidates
                        if candidates_data:
                            analysis_lines.append("Component Candidates:")
                            for comp in candidates_data[:5]:  # Show top 5
                                name = comp.get('name', 'Unknown')
                                version = comp.get('version', 'N/A')
                                confidence = comp.get('confidence', 0.0)
                                is_vulnerable = comp.get('is_vulnerable', False)
                                vuln_status = " ⚠️ VULNERABLE" if is_vulnerable else ""
                                analysis_lines.append(f"  - {name} v{version} (confidence: {confidence:.2f}){vuln_status}")
                    except (json.JSONDecodeError, AttributeError):
                        analysis_lines.append(f"Component Candidates: {candidates}")
            
            # Security analysis
            if 'security_analysis' in analysis_data:
                sec_analysis = analysis_data['security_analysis']
                if sec_analysis:
                    try:
                        import json
                        sec_data = json.loads(sec_analysis) if isinstance(sec_analysis, str) else sec_analysis
                        total_issues = sec_data.get('total_security_issues', 0)
                        high_severity = sec_data.get('high_severity_issues', 0)
                        medium_severity = sec_data.get('medium_severity_issues', 0)
                        risk_score = sec_data.get('security_risk_score', 0)
                        has_vulnerabilities = sec_data.get('has_vulnerabilities', False)
                        
                        analysis_lines.append(f"Security Issues: {total_issues} total ({high_severity} high, {medium_severity} medium)")
                        analysis_lines.append(f"Security Risk Score: {risk_score}")
                        if has_vulnerabilities:
                            analysis_lines.append("⚠️ VULNERABILITIES DETECTED")
                    except (json.JSONDecodeError, AttributeError):
                        analysis_lines.append(f"Security Analysis: {sec_analysis}")
            
            # Security issues summary
            if 'security_issues_summary' in analysis_data:
                issues_summary = analysis_data['security_issues_summary']
                if issues_summary:
                    try:
                        import json
                        issues_data = json.loads(issues_summary) if isinstance(issues_summary, str) else issues_summary
                        if issues_data:
                            analysis_lines.append("Security Issues Summary:")
                            for issue in issues_data[:3]:  # Show top 3
                                issue_type = issue.get('type', 'Unknown')
                                severity = issue.get('severity', 'Unknown')
                                description = issue.get('description', 'No description')
                                analysis_lines.append(f"  - {issue_type} ({severity}): {description}")
                    except (json.JSONDecodeError, AttributeError):
                        analysis_lines.append(f"Security Issues: {issues_summary}")
            
            # Stack detection errors
            if 'stack_detection_error' in analysis_data:
                error = analysis_data['stack_detection_error']
                analysis_lines.append(f"Stack Detection Error: {error}")
        
        # Add client-side script analysis
        script_analysis = self.reconstruct_client_script_analysis(group_id, db_path)
        
        # Combine HTTP message and analysis (no response bodies)
        if analysis_lines:
            result = http_message + "\n".join(analysis_lines)
        else:
            result = http_message
        
        if script_analysis:
            result += script_analysis
        
        return result
    
    async def analyze_client_scripts(self, html_content: str, base_url: str = "") -> Dict[str, Any]:
        """
        Analyze client-side JavaScript in HTML content.
        
        Args:
            html_content: HTML content to analyze
            base_url: Base URL for resolving relative script URLs
            
        Returns:
            Analysis results from the client script analyzer
        """
        if not self.script_analyzer:
            return {"error": "Script analyzer not initialized"}
        
        try:
            return self.script_analyzer.analyze_html_response(html_content, base_url)
        except Exception as e:
            return {"error": f"Script analysis failed: {e}"}
    
    def display_documents(self, documents: List[Dict[str, Any]], limit: int = 5, reconstruct: bool = False, with_analysis: bool = True) -> None:
        """
        Display retrieved documents with optional reconstruction.
        
        Args:
            documents: List of documents to display
            limit: Maximum number of documents to show
            reconstruct: Whether to reconstruct full HTTP messages
            with_analysis: Whether to include analysis metadata (only when reconstruct=True)
        """
        if not documents:
            print("[INFO] No documents found.")
            return
        
        print(f"[INFO] Displaying top {min(len(documents), limit)} documents:")
        for i, doc in enumerate(documents[:limit], 1):
            print(f"\n[INFO] Doc {i}:")
            if reconstruct:
                meta = getattr(doc, "metadata", None) or (doc.get("metadata") if isinstance(doc, dict) else None) or {}
                group_id = meta.get("group_id")
                if group_id:
                    if with_analysis:
                        full_msg = self.reconstruct_http_message_with_analysis(group_id)
                    else:
                        full_msg = self.reconstruct_http_message(group_id)
                    print(full_msg[:1000])  # Increased limit to show analysis data
                else:
                    content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                    print((content or "")[:500])
            else:
                content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                print((content or "")[:500])
    
    async def analyze_traffic(self, query: str, reconstruct: bool = True, with_analysis: bool = True) -> None:
        """
        Analyze HTTP traffic for security vulnerabilities.
        
        Args:
            query: Security analysis query
            reconstruct: Whether to reconstruct full HTTP messages
            with_analysis: Whether to include analysis metadata in reconstruction
        """
        if not self.assistant_agent:
            raise RuntimeError("Agent not initialized. Call initialize() first.")
        
        # Query memory for relevant documents
        docs = await self.query_memory(query)
        if not docs:
            print("[!] No relevant documents found.")
            return
        
        # Collect unique group_ids
        group_ids = []
        for d in docs:
            meta = getattr(d, "metadata", None) or (d.get("metadata") if isinstance(d, dict) else None) or {}
            gid = meta.get("group_id")
            if gid and gid not in group_ids:
                group_ids.append(gid)
        
        print(f"[INFO] Found {len(group_ids)} unique group_ids from results")
        
        # Reconstruct each group with analysis data (request-only summary)
        reconstructed = [self.reconstruct_http_message_with_analysis(gid) for gid in group_ids]
        
        # Show samples
        for i, msg in enumerate(reconstructed[:2], 1):
            print(f"\n[DEBUG] Reconstructed sample {i}:\n{msg[:600]}...\n")
        
        if not reconstructed:
            print("[!] Nothing to send to OpenAI.")
            return
        
        print(f"[INFO] Sending {len(reconstructed)} reconstructed docs to OpenAI")
        
        # If query explicitly asks for vulnerable script, only send targeted JS snippets
        def wants_vulnerable_script(q: str) -> bool:
            ql = (q or "").lower()
            return ("script" in ql or "javascript" in ql or "js" in ql) and ("vulnerab" in ql or "suspicious" in ql or "malicious" in ql)

        if wants_vulnerable_script(query):
            targeted_prompts: List[str] = []
            try:
                # Only in this mode we touch response bodies to extract scripts
                for gid in group_ids[:3]:
                    full_msg = self.reconstruct_http_message(gid, include_body=True)
                    headers_section = []
                    body_text = ""
                    lines = full_msg.splitlines()
                    mode = None
                    for line in lines:
                        if line.strip() == "[HEADERS]":
                            mode = "headers"
                            continue
                        if line.strip() == "[BODY]":
                            mode = "body"
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            mode = None
                            continue
                        if mode == "headers":
                            headers_section.append(line)
                        elif mode == "body":
                            body_text += ("\n" if body_text else "") + line
                    is_html = any(h.lower().startswith("content-type") and "html" in h.lower() for h in headers_section) or ("<script" in body_text.lower())
                    if is_html and self.script_analyzer:
                        host = None
                        for h in headers_section:
                            if h.lower().startswith("host:"):
                                host = h.split(":", 1)[1].strip()
                                break
                        base_url = f"http://{host}" if host else ""
                        analysis = await asyncio.get_running_loop().run_in_executor(None, self.script_analyzer.analyze_html_response, body_text, base_url)
                        scripts_for_llm = (analysis or {}).get('scripts_for_llm') or []
                        for script in scripts_for_llm[:3]:
                            targeted_prompts.append(self.script_analyzer.get_llm_analysis_prompt(script))
            except Exception:
                targeted_prompts = []

            if not targeted_prompts:
                print("[INFO] No vulnerable scripts detected to send.")
                return
            task = "\n\n---\n\n".join(targeted_prompts)
        else:
            # Build task for OpenAI without any response bodies
            task = (
                "Analyze the following HTTP traffic for vulnerabilities. "
                "The traffic includes analysis metadata showing detected technologies, "
                "version information, security assessments, and client-side script analysis. "
                "Only requests and analysis summaries are included (no response bodies). "
                "Pay special attention to any suspicious or obfuscated JavaScript code, "
                "custom scripts with high complexity, and potential security vulnerabilities "
                "in client-side code:\n\n" +
                "\n\n---\n\n".join(reconstructed[:3])
            )
        
        # Run assistant
        stream = self.assistant_agent.run_stream(task=task)
        await Console(stream)
    
    async def interactive_console(self) -> None:
        """Start interactive security analysis console."""
        if not self.assistant_agent:
            raise RuntimeError("Agent not initialized. Call initialize() first.")
        
        print("\n[*] Launching interactive console. Type your questions below (or 'quit' to exit).")
        while True:
            try:
                user_input = input("\n>>> ").strip()
                if user_input.lower() in {"quit", "exit"}:
                    print("[*] Exiting.")
                    break
                
                await self.analyze_traffic(user_input)
                
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Interrupted. Exiting.")
                break
    
    async def close(self) -> None:
        """Close the agent and clean up resources."""
        if self.model_client:
            await self.model_client.close()
        if self.memory:
            await self.memory.close()
        print("[*] Agent closed successfully")


async def main():
    """Main entry point for the Security Analysis Agent."""
    agent = SecurityAnalysisAgent()
    await agent.initialize()
    
    try:
        await agent.interactive_console()
    finally:
        await agent.close()


if __name__ == "__main__":
    asyncio.run(main())
