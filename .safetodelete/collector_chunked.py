"""
collector_chunked.py

Collector Script for ZAP + ChromaDB RAG Memory (chunked + suspicious-pattern detection)

- Connects to the OWASP ZAP API running in Docker.
- Collects HTTP requests/responses captured by ZAP.
- Chunks each message into (path, query, headers, body).
- Uses preprocess.normalize_chunk_text(...) which wraps preprocess_payload and
  adds suspicion scoring / tags.
- Stores normalized content and metadata into a persistent ChromaDBVectorMemory.

Usage:
    poetry run python collector_chunked.py

Make sure:
    - ZAP is running in Docker with API enabled and accessible at ZAP_API_URL
    - chroma_data/ is writable for persistence
"""

import asyncio
import time
import urllib.parse
import re
import base64  # used previously in earlier normalize attempts; keep available
from typing import Dict

from zapv2 import ZAPv2

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_core.memory import MemoryContent, MemoryMimeType

# Import from new modular structure
from src.zap_rag_security_agent.preprocessing.normalizer import normalize_chunk_text
from src.zap_rag_security_agent.data.baseline_docs import BASELINE_DOCS

# ------------------------
# Config
# ------------------------
ZAP_API_URL = "http://localhost:8090"     # ZAP API endpoint (not the proxy)
PERSIST_PATH = "./chroma_data"
COLLECTION_NAME = "security_memory"
BATCH_SIZE = 50
POLL_INTERVAL = 0.2  # seconds


# ------------------------
# Helpers: Extractors
# ------------------------
def parse_request_first_line(request_header: str):
    """
    Return method, full_url, http_version from first line of request header.
    """
    if not request_header:
        return None, None, None
    first = request_header.splitlines()[0].strip()
    parts = first.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], None
    return None, None, None


def extract_path(req_header: str) -> str:
    """
    Extract the path from the request line in the HTTP header.
    Example: "GET https://example.com/foo/bar?x=1 HTTP/1.1" -> "/foo/bar"
    """
    try:
        first_line = req_header.splitlines()[0] if req_header else ""
        parts = first_line.split()
        if len(parts) >= 2:
            url = parts[1]
            parsed = urllib.parse.urlparse(url)
            return parsed.path or "/"
    except Exception:
        return ""
    return ""


def extract_query(req_header: str) -> str:
    """
    Extract the query string from the request line in the HTTP header.
    Example: returns "x=1&y=2"
    """
    try:
        first_line = req_header.splitlines()[0] if req_header else ""
        parts = first_line.split()
        if len(parts) >= 2:
            url = parts[1]
            parsed = urllib.parse.urlparse(url)
            return parsed.query or ""
    except Exception:
        return ""
    return ""


# ------------------------
# Chunking (uses preprocess.normalize_chunk_text)
# ------------------------
def chunk_message(req_text: str, group_id: str):
    """
    Break request/response into structured & normalized chunks.
    Each chunk is a dict containing:
      - group_id, part, id, content (normalized), meta (suspicion metadata)
    chunk_type for preprocess: 'path', 'query', 'headers', 'body'
    """
    chunks = []

    # 1. Request line -> path + query
    first_line = req_text.splitlines()[0] if req_text else ""
    if first_line.startswith("[Request]"):
        # Example: [Request] GET https://example.com/foo/bar?x=1 HTTP/1.1
        try:
            parts = first_line.split()
            url = parts[2] if len(parts) > 2 else ""
        except Exception:
            url = ""

        parsed = urllib.parse.urlparse(url or "")

        # Path chunk
        path_text = parsed.path or "/"
        norm_path, meta_path = normalize_chunk_text(path_text, chunk_type="path")
        chunks.append({
            "group_id": group_id,
            "part": "path",
            "id": f"{group_id}-path",
            "content": norm_path,
            "meta": meta_path,
        })

        # Query params as single normalized chunk (preserve k=v lines)
        q = parsed.query or ""
        if q:
            norm_q, meta_q = normalize_chunk_text(q, chunk_type="query")
            chunks.append({
                "group_id": group_id,
                "part": "query",
                "id": f"{group_id}-query",
                "content": norm_q,
                "meta": meta_q,
            })

    # 2. Headers: pick block after first_line up to blank line (or simple heuristic)
    # We'll capture any lines with colon ":" as headers (robust enough for our logs)
    headers_lines = []
    in_headers = False
    for line in req_text.splitlines():
        if line.strip() == "":
            # blank line may separate headers and body; keep scanning
            continue
        # Treat any "Key: value" or common header-like lines as header lines
        if ":" in line:
            headers_lines.append(line.strip())
            in_headers = True
        elif in_headers and line.strip():
            # some headers may span multiple lines; include them conservatively
            headers_lines.append(line.strip())

    headers_block = "\n".join(headers_lines).strip()
    if headers_block:
        norm_headers, meta_headers = normalize_chunk_text(headers_block, chunk_type="headers")
        chunks.append({
            "group_id": group_id,
            "part": "headers",
            "id": f"{group_id}-headers",
            "content": norm_headers,
            "meta": meta_headers,
        })

    # 3. Body (after blank line)
    if "\r\n\r\n" in req_text:
        body = req_text.split("\r\n\r\n", 1)[1].strip()
    else:
        # fallback: if no CRLFCRLF, look for double-newline
        if "\n\n" in req_text:
            body = req_text.split("\n\n", 1)[1].strip()
        else:
            body = ""

    if body:
        norm_body, meta_body = normalize_chunk_text(body, chunk_type="body")
        chunks.append({
            "group_id": group_id,
            "part": "body",
            "id": f"{group_id}-body",
            "content": norm_body,
            "meta": meta_body,
        })

    return chunks


# ------------------------
# Baseline seeding (idempotent)
# ------------------------
async def seed_baseline(memory: ChromaDBVectorMemory):
    """
    Index baseline docs (OWASP top10 etc.). Idempotent: ignores failures if doc exists.
    """
    print("[*] Indexing baseline security knowledge...")
    for i, doc in enumerate(BASELINE_DOCS, start=1):
        content = MemoryContent(
            content=doc,
            mime_type=MemoryMimeType.TEXT,
            metadata={"type": "baseline", "id": f"baseline-{i}"}
        )
        try:
            await memory.add(content)
        except Exception:
            # already present or other non-fatal error; ignore to remain idempotent
            pass
    print("[+] Baseline seeding complete.")


# ------------------------
# Collector core
# ------------------------
async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
    """
    Process history in batches then watch ZAP for new messages in realtime.
    Uses normalize_chunk_text to produce content and suspicious metadata.
    """
    print("[*] Watching ZAP for requests... (Ctrl+C to stop)")

    all_msgs = zap.core.messages()
    total_count = len(all_msgs)
    print(f"[+] ZAP reports {total_count} messages in history.")

    processed = 0
    last_id = 0

    # 1) Process history in batches
    for i in range(0, total_count, BATCH_SIZE):
        batch = all_msgs[i:i + BATCH_SIZE]
        tasks = []

        for m in batch:
            group_id = str(m["id"])
            # Build a single raw request text: header + blank line + body
            req_text = (m.get("requestHeader", "") + "\r\n\r\n" + m.get("requestBody", "")).strip()
            if not req_text:
                continue

            chunks = chunk_message(req_text, group_id)
            for chunk in chunks:
                # Merge chunk meta with collector metadata
                meta = {
                    "type": "traffic",
                    "group_id": chunk["group_id"],
                    "part": chunk["part"],
                    "id": chunk["id"],
                }
                # include suspicion meta fields returned by preprocess, but ensure primitives
                if isinstance(chunk.get("meta"), dict):
                    for k, v in chunk["meta"].items():
                        # store only primitive types (Chroma metadata requirement)
                        meta[k] = v if isinstance(v, (str, int, float, bool)) else str(v)

                content = MemoryContent(
                    content=chunk["content"],
                    mime_type=MemoryMimeType.TEXT,
                    metadata=meta,
                )
                tasks.append(memory.add(content))

            last_id = max(last_id, int(m["id"]))

        if tasks:
            await asyncio.gather(*tasks)
        processed += len(batch)
        print(f"[+] Processed {processed}/{total_count} historical messages.")

    print("[*] Finished indexing history.")
    print("[*] Now watching for new messages...")

    # 2) Live monitoring
    try:
        while True:
            all_msgs = zap.core.messages()
            new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]

            for m in new_msgs:
                group_id = str(m["id"])
                req_text = (m.get("requestHeader", "") + "\r\n\r\n" + m.get("requestBody", "")).strip()
                if not req_text:
                    continue

                chunks = chunk_message(req_text, group_id)
                for chunk in chunks:
                    meta = {
                        "type": "traffic",
                        "group_id": chunk["group_id"],
                        "part": chunk["part"],
                        "id": chunk["id"],
                    }
                    if isinstance(chunk.get("meta"), dict):
                        for k, v in chunk["meta"].items():
                            meta[k] = v if isinstance(v, (str, int, float, bool)) else str(v)

                    content = MemoryContent(
                        content=chunk["content"],
                        mime_type=MemoryMimeType.TEXT,
                        metadata=meta,
                    )
                    await memory.add(content)

                last_id = max(last_id, int(m["id"]))
                print(f"[+] Stored new request {m['id']} into memory.")

            await asyncio.sleep(POLL_INTERVAL)  # throttle

    except KeyboardInterrupt:
        print("\n[!] Collector stopped by user.")


# ------------------------
# Entrypoint
# ------------------------
async def main():
    print("[*] Initializing ChromaDBVectorMemory...")
    config = PersistentChromaDBVectorMemoryConfig(
        collection_name=COLLECTION_NAME,
        persistence_path=PERSIST_PATH,
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
        k=3,
        score_threshold=0.3,
    )
    memory = ChromaDBVectorMemory(config=config)

    # Seed baseline once (uncomment if needed)
    # await seed_baseline(memory)

    # Connect to ZAP
    zap = ZAPv2(apikey=None)
    zap._baseurl = ZAP_API_URL  # explicitly set API URL
    print("[+] Connected to ZAP API.")

    # Start collector loop
    await collector_loop(memory, zap)

    # Cleanup
    await memory.close()
    print("[*] Memory closed cleanly.")


if __name__ == "__main__":
    asyncio.run(main())