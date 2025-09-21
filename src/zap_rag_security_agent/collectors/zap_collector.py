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
from typing import Dict, List, Any, Generator
from zapv2 import ZAPv2

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_core.memory import MemoryContent, MemoryMimeType

from ..preprocessing.normalizer import normalize_chunk_text
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
        poll_interval: float = 0.2
    ):
        """
        Initialize the ZAP Collector.
        
        Args:
            zap_api_url: ZAP API endpoint URL
            persist_path: Path to persist ChromaDB data
            collection_name: Name of the ChromaDB collection
            batch_size: Batch size for processing historical messages
            poll_interval: Polling interval for new messages (seconds)
        """
        self.zap_api_url = zap_api_url
        self.persist_path = persist_path
        self.collection_name = collection_name
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        
        self.memory: ChromaDBVectorMemory = None
        self.zap: ZAPv2 = None
    
    async def initialize(self) -> None:
        """Initialize the collector and its components."""
        print("[*] Initializing ZAP Collector...")
        
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
        
        # Process response
        if resp_text:
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
