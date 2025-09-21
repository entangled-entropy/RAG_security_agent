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
        k: int = 5,
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
        
        self.system_prompt = (
            "You are SecurityAnalysisAgent, a security analyst. "
            "Use memory context to detect vulnerabilities, exposed secrets, "
            "outdated components, and suspicious patterns. "
            "Provide concise, actionable answers."
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
    
    def reconstruct_http_message(self, group_id: str, db_path: Optional[str] = None) -> str:
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
        
        # Build output
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
        if body:
            out_lines.append("[BODY]")
            out_lines.append(body)
        for p, t in other_parts:
            out_lines.append(f"[{p.upper()}]")
            out_lines.append(t)
        
        return "\n".join(out_lines)
    
    def display_documents(self, documents: List[Dict[str, Any]], limit: int = 5, reconstruct: bool = False) -> None:
        """
        Display retrieved documents with optional reconstruction.
        
        Args:
            documents: List of documents to display
            limit: Maximum number of documents to show
            reconstruct: Whether to reconstruct full HTTP messages
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
                    full_msg = self.reconstruct_http_message(group_id)
                    print(full_msg[:500])
                else:
                    content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                    print((content or "")[:500])
            else:
                content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                print((content or "")[:500])
    
    async def analyze_traffic(self, query: str, reconstruct: bool = True) -> None:
        """
        Analyze HTTP traffic for security vulnerabilities.
        
        Args:
            query: Security analysis query
            reconstruct: Whether to reconstruct full HTTP messages
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
        
        # Reconstruct each group
        reconstructed = [self.reconstruct_http_message(gid) for gid in group_ids]
        
        # Show samples
        for i, msg in enumerate(reconstructed[:2], 1):
            print(f"\n[DEBUG] Reconstructed sample {i}:\n{msg[:400]}...\n")
        
        if not reconstructed:
            print("[!] Nothing to send to OpenAI.")
            return
        
        print(f"[INFO] Sending {len(reconstructed)} reconstructed docs to OpenAI")
        
        # Build task for OpenAI
        task = (
            "Analyze the following HTTP traffic for vulnerabilities:\n\n" +
            "\n\n---\n\n".join(reconstructed[:5])  # limit to avoid token explosion
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
