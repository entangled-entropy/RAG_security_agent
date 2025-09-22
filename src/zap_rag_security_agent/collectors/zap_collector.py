"""
ZAP Traffic Collector

Collects HTTP traffic from OWASP ZAP and stores it in ChromaDB with intelligent preprocessing.
Supports both real-time collection and batch processing of historical data.

Features:
- Real-time ZAP traffic monitoring
- Intelligent chunking of HTTP messages (path, query, headers, body)
- Security-focused preprocessing and normalization
- Suspicious pattern detection and tagging
- ChromaDB vector storage with metadata
"""

import asyncio
import time
import urllib.parse
from typing import Dict, List, Any, Generator, Optional
try:
    from zapv2 import ZAPv2
except Exception:  # pragma: no cover
    ZAPv2 = None

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_core.memory import MemoryContent, MemoryMimeType

from ..preprocessing.normalizer import normalize_chunk_text
from ..preprocessing.script_extractor import ScriptExtractor
from ..detectors.client_script_analyzer import ClientScriptAnalyzer
from ..data.baseline import BASELINE_DOCS


class ZAPCollector:
    """
    ZAP Traffic Collector for RAG Security Agent.
    
    Collects HTTP traffic from OWASP ZAP, processes it with security-focused
    preprocessing, and stores it in ChromaDB for RAG analysis.
    """
    
    def __init__(
        self,
        zap_api_url: str = "http://localhost:8090",
        persist_path: str = "./chroma_data",
        collection_name: str = "security_memory",
        batch_size: int = 50,
        poll_interval: float = 0.2,
        enable_script_analysis: bool = True,
        script_analysis_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the ZAP Collector.
        
        Args:
            zap_api_url: ZAP API endpoint URL
            persist_path: Path to persist ChromaDB data
            collection_name: Name of the ChromaDB collection
            batch_size: Batch size for processing historical messages
            poll_interval: Polling interval for new messages (seconds)
            enable_script_analysis: Whether to enable client-side script analysis
            script_analysis_config: Configuration for script analysis
        """
        self.zap_api_url = zap_api_url
        self.persist_path = persist_path
        self.collection_name = collection_name
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.enable_script_analysis = enable_script_analysis
        self.script_analysis_config = script_analysis_config or {}
        
        self.memory: ChromaDBVectorMemory = None
        self.zap: ZAPv2 = None
        self.script_analyzer: Optional[ClientScriptAnalyzer] = None
    
    async def initialize(self) -> None:
        """Initialize the collector and its components."""
        print("[*] Initializing ZAP Collector...")
        
        if not ZAPv2:
            raise ConnectionError("python-owasp-zap-v2.4 is not installed. Install it or skip ZAP-dependent tests.")

        # Initialize ChromaDB memory
        config = PersistentChromaDBVectorMemoryConfig(
            collection_name=self.collection_name,
            persistence_path=self.persist_path,
            embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
                model_name="all-MiniLM-L6-v2"
            ),
            k=3,
            score_threshold=0.3,
        )
        self.memory = ChromaDBVectorMemory(config=config)
        
        # Connect to ZAP
        self.zap = ZAPv2(apikey=None)
        self.zap._baseurl = self.zap_api_url
        
        # Test connection
        try:
            version = self.zap.core.version
            print(f"[+] Connected to ZAP (version: {version})")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to ZAP at {self.zap_api_url}: {e}")
        
        # Initialize script analyzer if enabled
        if self.enable_script_analysis:
            self.script_analyzer = ClientScriptAnalyzer(self.script_analysis_config)
            print("[+] Client-side script analyzer initialized")
        
        print("[+] ZAP Collector initialized successfully")
    
    async def seed_baseline(self) -> None:
        """Seed the memory with baseline security knowledge."""
        print("[*] Indexing baseline security knowledge...")
        
        for i, doc in enumerate(BASELINE_DOCS, start=1):
            content = MemoryContent(
                content=doc,
                mime_type=MemoryMimeType.TEXT,
                metadata={"type": "baseline", "id": f"baseline-{i}"}
            )
            try:
                await self.memory.add(content)
            except Exception:
                # Already exists or other non-fatal error
                pass
        
        print("[+] Baseline seeding complete")
    
    async def _analyze_client_scripts(self, resp_text: str, group_id: str, base_url: str = "") -> List[Dict[str, Any]]:
        """
        Analyze client-side JavaScript in HTTP responses.
        
        Args:
            resp_text: HTTP response text
            group_id: Group ID for the message
            
        Returns:
            List of script analysis results
        """
        if not self.script_analyzer or not resp_text:
            return []
        
        try:
            # Extract HTML content from response
            if "\r\n\r\n" in resp_text:
                html_content = resp_text.split("\r\n\r\n", 1)[1]
            elif "\n\n" in resp_text:
                html_content = resp_text.split("\n\n", 1)[1]
            else:
                html_content = resp_text
            
            # Analyze scripts
            analysis_result = self.script_analyzer.analyze_html_response(html_content, base_url)
            
            # Store analysis results as separate memory entries
            script_entries = []
            for script in analysis_result.get('scripts_for_llm', []):
                script_meta = {
                    "type": "client_script_analysis",
                    "group_id": group_id,
                    "script_id": script.get('id', ''),
                    "script_url": script.get('url', ''),
                    "script_type": script.get('type', ''),
                    "analysis_confidence": script.get('analysis', {}).get('confidence', 0.0),
                    "is_suspicious": script.get('analysis', {}).get('is_suspicious', False),
                    "is_obfuscated": script.get('analysis', {}).get('is_obfuscated', False),
                    "is_custom": script.get('analysis', {}).get('is_custom', False),
                    "complexity_score": script.get('analysis', {}).get('complexity_score', 0.0),
                    "suspicion_density": script.get('analysis', {}).get('suspicion_density', 0.0),
                    "reasons": str(script.get('analysis', {}).get('reasons', [])),
                }
                
                script_content = MemoryContent(
                    content=script.get('content', ''),
                    mime_type=MemoryMimeType.TEXT,
                    metadata=script_meta,
                )
                script_entries.append(script_content)
            
            return script_entries
            
        except Exception as e:
            print(f"[!] Error analyzing client scripts for group {group_id}: {e}")
            return []
    
    def _parse_request_first_line(self, request_header: str) -> tuple:
        """Parse HTTP request first line into method, URL, and version."""
        if not request_header:
            return None, None, None
        
        first = request_header.splitlines()[0].strip()
        parts = first.split()
        
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], None
        else:
            return None, None, None
    
    def _extract_path(self, req_header: str) -> str:
        """Extract path from HTTP request header."""
        try:
            first_line = req_header.splitlines()[0] if req_header else ""
            parts = first_line.split()
            if len(parts) >= 2:
                url = parts[1]
                parsed = urllib.parse.urlparse(url)
                return parsed.path or "/"
        except Exception:
            pass
        return ""
    
    def _extract_query(self, req_header: str) -> str:
        """Extract query string from HTTP request header."""
        try:
            first_line = req_header.splitlines()[0] if req_header else ""
            parts = first_line.split()
            if len(parts) >= 2:
                url = parts[1]
                parsed = urllib.parse.urlparse(url)
                return parsed.query or ""
        except Exception:
            pass
        return ""
    
    def _chunk_message(self, req_text: str, group_id: str, prefix: str = "") -> Generator[Dict[str, Any], None, None]:
        """
        Break HTTP request into structured chunks with security analysis.
        
        Args:
            req_text: Raw HTTP request text
            group_id: Unique identifier for grouping chunks
            
        Yields:
            Dictionary containing chunk data and metadata
        """
        chunks = []
        
        # Parse request line
        first_line = req_text.splitlines()[0] if req_text else ""
        if first_line.startswith("[Request]"):
            try:
                parts = first_line.split()
                url = parts[2] if len(parts) > 2 else ""
            except Exception:
                url = ""
            
            parsed = urllib.parse.urlparse(url or "")
            
            # Path chunk
            path_text = parsed.path or "/"
            norm_path, meta_path = normalize_chunk_text(path_text, chunk_type="path")
            yield {
                "group_id": group_id,
                "part": f"{prefix}path" if prefix else "path",
                "id": f"{group_id}-{prefix}path" if prefix else f"{group_id}-path",
                "content": norm_path,
                "meta": meta_path,
            }
            
            # Query chunk
            query_text = parsed.query or ""
            if query_text:
                norm_query, meta_query = normalize_chunk_text(query_text, chunk_type="query")
                yield {
                    "group_id": group_id,
                    "part": f"{prefix}query" if prefix else "query",
                    "id": f"{group_id}-{prefix}query" if prefix else f"{group_id}-query",
                    "content": norm_query,
                    "meta": meta_query,
                }
        
        # Headers chunk
        headers_lines = []
        in_headers = False
        for line in req_text.splitlines():
            if line.strip() == "":
                continue
            if ":" in line:
                headers_lines.append(line.strip())
                in_headers = True
            elif in_headers and line.strip():
                headers_lines.append(line.strip())
        
        headers_block = "\n".join(headers_lines).strip()
        if headers_block:
            norm_headers, meta_headers = normalize_chunk_text(headers_block, chunk_type="headers")
            yield {
                "group_id": group_id,
                "part": f"{prefix}headers" if prefix else "headers",
                "id": f"{group_id}-{prefix}headers" if prefix else f"{group_id}-headers",
                "content": norm_headers,
                "meta": meta_headers,
            }
        
        # Body chunk
        if "\r\n\r\n" in req_text:
            body = req_text.split("\r\n\r\n", 1)[1].strip()
        elif "\n\n" in req_text:
            body = req_text.split("\n\n", 1)[1].strip()
        else:
            body = ""
        
        if body:
            norm_body, meta_body = normalize_chunk_text(body, chunk_type="body")
            yield {
                "group_id": group_id,
                "part": f"{prefix}body" if prefix else "body",
                "id": f"{group_id}-{prefix}body" if prefix else f"{group_id}-body",
                "content": norm_body,
                "meta": meta_body,
            }
    
    async def _process_message(self, message: Dict[str, Any]) -> None:
        """Process a single ZAP message and store in memory."""
        group_id = str(message["id"])
        req_text = (message.get("requestHeader", "") + "\r\n\r\n" + message.get("requestBody", "")).strip()
        resp_text = (message.get("responseHeader", "") + "\r\n\r\n" + message.get("responseBody", "")).strip()
        
        if not req_text and not resp_text:
            return
        
        tasks = []
        
        # Process request
        if req_text:
            for chunk in self._chunk_message(req_text, group_id, prefix="req_"):
                # Merge chunk metadata with collector metadata
                meta = {
                    "type": "traffic",
                    "group_id": chunk["group_id"],
                    "part": chunk["part"],
                    "id": chunk["id"],
                }
                
                # Include security analysis metadata
                if isinstance(chunk.get("meta"), dict):
                    for k, v in chunk["meta"].items():
                        # Ensure only primitive types for ChromaDB metadata
                        meta[k] = v if isinstance(v, (str, int, float, bool)) else str(v)
                
                content = MemoryContent(
                    content=chunk["content"],
                    mime_type=MemoryMimeType.TEXT,
                    metadata=meta,
                )
                tasks.append(self.memory.add(content))

                # Add an analysis summary document to improve retrievability for queries like
                # "outdated library" or "vulnerable versions" by indexing keywords in content.
                analysis_summary_lines = []
                # Top component summary
                top_comp = chunk.get("meta", {}).get("top_component") if isinstance(chunk.get("meta"), dict) else None
                if isinstance(top_comp, dict) and (top_comp.get("name") or top_comp.get("version")):
                    name = top_comp.get("name", "")
                    version = top_comp.get("version", "")
                    is_vuln = top_comp.get("is_vulnerable", False)
                    is_outdated = top_comp.get("is_outdated", False)
                    status_terms = []
                    if is_vuln:
                        status_terms.append("vulnerable")
                    if is_outdated:
                        status_terms.append("outdated")
                    if status_terms:
                        analysis_summary_lines.append(
                            f"Component {name} {version} is {' and '.join(status_terms)} (security issue)."
                        )
                # Candidates and outdated components
                comp_candidates_json = chunk.get("meta", {}).get("component_candidates") if isinstance(chunk.get("meta"), dict) else None
                if comp_candidates_json:
                    try:
                        import json as _json
                        candidates = _json.loads(comp_candidates_json) if isinstance(comp_candidates_json, str) else comp_candidates_json
                    except Exception:
                        candidates = []
                    for comp in (candidates or [])[:5]:
                        nm = comp.get("name", "")
                        ver = comp.get("version", "")
                        tags = []
                        if comp.get("is_vulnerable"):
                            tags.append("vulnerable")
                        if comp.get("is_outdated"):
                            tags.append("outdated")
                        if tags:
                            analysis_summary_lines.append(
                                f"Component {nm} {ver} is {' and '.join(tags)} (security issue)."
                            )
                outdated_components_json = chunk.get("meta", {}).get("outdated_components") if isinstance(chunk.get("meta"), dict) else None
                if outdated_components_json:
                    try:
                        import json as _json
                        outdated_list = _json.loads(outdated_components_json) if isinstance(outdated_components_json, str) else outdated_components_json
                    except Exception:
                        outdated_list = []
                    for comp in (outdated_list or [])[:5]:
                        nm = comp.get("name", "")
                        ver = comp.get("version", "")
                        latest = comp.get("latest_version", "")
                        is_v = comp.get("is_vulnerable", False)
                        status = "vulnerable" if is_v else "outdated"
                        analysis_summary_lines.append(
                            f"Component {nm} {ver} -> {latest} is {status} (security issue)."
                        )

                # Only create one summary per request based on headers to avoid duplicates
                if analysis_summary_lines and chunk.get("part") == ("req_headers" if prefix == "req_" else "req_headers"):
                    summary_text = "[ANALYSIS SUMMARY]\n" + "\n".join(analysis_summary_lines)
                    summary_meta = {
                        "type": "analysis",
                        "group_id": chunk["group_id"],
                        "part": "analysis",
                        "id": f"{group_id}-analysis-{chunk['part']}",
                        "suspicious": True,
                        # Ensure primitives only for ChromaDB metadata (no lists)
                        "suspicious_tags": str(((chunk.get("meta", {}) or {}).get("suspicious_tags", []) + ["security issues", "vulnerable", "outdated"])),
                    }
                    tasks.append(self.memory.add(MemoryContent(
                        content=summary_text,
                        mime_type=MemoryMimeType.TEXT,
                        metadata=summary_meta,
                    )))
        
        # Process response
        if resp_text:
            # Only analyze scripts for HTML responses
            is_html = False
            try:
                header_section = resp_text.split("\r\n\r\n", 1)[0]
            except Exception:
                header_section = resp_text
            for line in header_section.splitlines():
                if line.lower().startswith("content-type:") and "text/html" in line.lower():
                    is_html = True
                    break

            # Determine the base URL from the request (if present)
            page_url = ""
            try:
                # Try to extract URL from the special first line format
                first_line = req_text.splitlines()[0] if req_text else ""
                if first_line.startswith("[Request]"):
                    parts = first_line.split()
                    page_url = parts[2] if len(parts) > 2 else ""
                else:
                    # Fallback: try extracting Host header and path
                    host = ""
                    path = "/"
                    for line in req_text.splitlines():
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break
                    # Try to find request line like: GET /path HTTP/1.1
                    for line in req_text.splitlines():
                        if line.startswith("GET ") or line.startswith("POST ") or line.startswith("PUT ") or line.startswith("DELETE "):
                            parts = line.split()
                            if len(parts) >= 2:
                                path = parts[1]
                            break
                    # Normalize absolute/authority-relative cases
                    if path.startswith("http://") or path.startswith("https://"):
                        page_url = path
                    elif path.startswith("//"):
                        page_url = f"https:{path}"
                    elif path.startswith("https:/") and not path.startswith("https://"):
                        page_url = "https://" + path[len("https:/"):]
                    elif path.startswith("http:/") and not path.startswith("http://"):
                        page_url = "http://" + path[len("http:/"):]
                    elif host:
                        scheme = "https"  # default to https if unknown
                        if not path.startswith("/"):
                            path = "/" + path
                        page_url = f"{scheme}://{host}{path}"
            except Exception:
                page_url = ""
            
            for chunk in self._chunk_message(resp_text, group_id, prefix="resp_"):
                # Merge chunk metadata with collector metadata
                meta = {
                    "type": "traffic",
                    "group_id": chunk["group_id"],
                    "part": chunk["part"],
                    "id": chunk["id"],
                }
                
                # Include security analysis metadata
                if isinstance(chunk.get("meta"), dict):
                    for k, v in chunk["meta"].items():
                        # Ensure only primitive types for ChromaDB metadata
                        meta[k] = v if isinstance(v, (str, int, float, bool)) else str(v)
                
                content = MemoryContent(
                    content=chunk["content"],
                    mime_type=MemoryMimeType.TEXT,
                    metadata=meta,
                )
                tasks.append(self.memory.add(content))

                # Also add analysis summary for response-derived analysis to boost retrievability
                analysis_summary_lines = []
                top_comp = chunk.get("meta", {}).get("top_component") if isinstance(chunk.get("meta"), dict) else None
                if isinstance(top_comp, dict) and (top_comp.get("name") or top_comp.get("version")):
                    name = top_comp.get("name", "")
                    version = top_comp.get("version", "")
                    is_vuln = top_comp.get("is_vulnerable", False)
                    is_outdated = top_comp.get("is_outdated", False)
                    status_terms = []
                    if is_vuln:
                        status_terms.append("vulnerable")
                    if is_outdated:
                        status_terms.append("outdated")
                    if status_terms:
                        analysis_summary_lines.append(
                            f"Component {name} {version} is {' and '.join(status_terms)} (security issue)."
                        )
                comp_candidates_json = chunk.get("meta", {}).get("component_candidates") if isinstance(chunk.get("meta"), dict) else None
                if comp_candidates_json:
                    try:
                        import json as _json
                        candidates = _json.loads(comp_candidates_json) if isinstance(comp_candidates_json, str) else comp_candidates_json
                    except Exception:
                        candidates = []
                    for comp in (candidates or [])[:5]:
                        nm = comp.get("name", "")
                        ver = comp.get("version", "")
                        tags = []
                        if comp.get("is_vulnerable"):
                            tags.append("vulnerable")
                        if comp.get("is_outdated"):
                            tags.append("outdated")
                        if tags:
                            analysis_summary_lines.append(
                                f"Component {nm} {ver} is {' and '.join(tags)} (security issue)."
                            )
                outdated_components_json = chunk.get("meta", {}).get("outdated_components") if isinstance(chunk.get("meta"), dict) else None
                if outdated_components_json:
                    try:
                        import json as _json
                        outdated_list = _json.loads(outdated_components_json) if isinstance(outdated_components_json, str) else outdated_components_json
                    except Exception:
                        outdated_list = []
                    for comp in (outdated_list or [])[:5]:
                        nm = comp.get("name", "")
                        ver = comp.get("version", "")
                        latest = comp.get("latest_version", "")
                        is_v = comp.get("is_vulnerable", False)
                        status = "vulnerable" if is_v else "outdated"
                        analysis_summary_lines.append(
                            f"Component {nm} {ver} -> {latest} is {status} (security issue)."
                        )

                # Only create one summary per response based on headers to avoid duplicates
                if analysis_summary_lines and chunk.get("part") == "resp_headers":
                    summary_text = "[ANALYSIS SUMMARY]\n" + "\n".join(analysis_summary_lines)
                    summary_meta = {
                        "type": "analysis",
                        "group_id": chunk["group_id"],
                        "part": "analysis",
                        "id": f"{group_id}-analysis-{chunk['part']}",
                        "suspicious": True,
                        # Ensure primitives only for ChromaDB metadata (no lists)
                        "suspicious_tags": str(((chunk.get("meta", {}) or {}).get("suspicious_tags", []) + ["security issues", "vulnerable", "outdated"])),
                    }
                    tasks.append(self.memory.add(MemoryContent(
                        content=summary_text,
                        mime_type=MemoryMimeType.TEXT,
                        metadata=summary_meta,
                    )))
            
            # Analyze client-side scripts if enabled and content looks like HTML
            if self.enable_script_analysis and is_html:
                script_entries = await self._analyze_client_scripts(resp_text, group_id, base_url=page_url)
                for script_entry in script_entries:
                    tasks.append(self.memory.add(script_entry))
        
        if tasks:
            await asyncio.gather(*tasks)
    
    async def collect_historical(self) -> None:
        """Process all historical ZAP messages."""
        print("[*] Processing historical ZAP messages...")
        
        all_msgs = self.zap.core.messages()
        total_count = len(all_msgs)
        print(f"[+] ZAP reports {total_count} messages in history")
        
        processed = 0
        for i in range(0, total_count, self.batch_size):
            batch = all_msgs[i:i + self.batch_size]
            tasks = []
            
            for message in batch:
                tasks.append(self._process_message(message))
            
            if tasks:
                await asyncio.gather(*tasks)
            
            processed += len(batch)
            print(f"[+] Processed {processed}/{total_count} historical messages")
        
        print("[*] Historical message processing complete")
    
    async def collect_realtime(self) -> None:
        """Start real-time collection of new ZAP messages."""
        print("[*] Starting real-time message collection...")
        
        all_msgs = self.zap.core.messages()
        last_id = max([int(m["id"]) for m in all_msgs]) if all_msgs else 0
        
        try:
            while True:
                all_msgs = self.zap.core.messages()
                new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]
                
                for message in new_msgs:
                    await self._process_message(message)
                    last_id = max(last_id, int(message["id"]))
                    print(f"[+] Stored new request {message['id']} into memory")
                
                await asyncio.sleep(self.poll_interval)
                
        except KeyboardInterrupt:
            print("\n[!] Real-time collection stopped by user")
    
    async def collect_all(self) -> None:
        """Collect both historical and real-time messages."""
        await self.collect_historical()
        await self.collect_realtime()
    
    async def close(self) -> None:
        """Close the collector and clean up resources."""
        if self.memory:
            await self.memory.close()
        print("[*] ZAP Collector closed successfully")


async def main():
    """Main entry point for the ZAP Collector."""
    collector = ZAPCollector()
    await collector.initialize()
    
    try:
        # Uncomment to seed baseline knowledge
        # await collector.seed_baseline()
        
        # Start collection
        await collector.collect_all()
    finally:
        await collector.close()


if __name__ == "__main__":
    asyncio.run(main())
