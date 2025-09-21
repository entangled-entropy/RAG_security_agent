# v1
# import asyncio
# import uuid
# from autogen_core.memory import MemoryContent, MemoryMimeType
# from autogen_ext.memory.chromadb import (
#     ChromaDBVectorMemory,
#     PersistentChromaDBVectorMemoryConfig,
#     SentenceTransformerEmbeddingFunctionConfig,
# )
# from preprocess import normalize_text, extract_query_params, canonicalize_headers

# PERSIST_PATH = "./chroma_data"
# COLLECTION_NAME = "security_memory"


# async def init_memory():
#     """Initialize persistent ChromaDB memory store."""
#     config = PersistentChromaDBVectorMemoryConfig(
#         collection_name=COLLECTION_NAME,
#         persistence_path=PERSIST_PATH,
#         embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
#             model_name="all-MiniLM-L6-v2"
#         ),
#         k=5,
#         score_threshold=0.3,
#     )
#     return ChromaDBVectorMemory(config=config)


# async def ingest_http_message(memory: ChromaDBVectorMemory, http_message: dict):
#     """
#     Ingest a single HTTP message (dict format) into memory, chunked into parts.
#     Expected http_message keys: id, path, query, headers, body
#     """

#     msg_id = http_message.get("id", str(uuid.uuid4()))

#     # --- Chunk path ---
#     if http_message.get("path"):
#         await memory.add(
#             MemoryContent(
#                 content=normalize_text(http_message["path"]),
#                 mime_type=MemoryMimeType.TEXT,
#                 metadata={
#                     "id": f"{msg_id}_path",
#                     "type": "traffic",
#                     "part": "path",
#                 },
#             )
#         )
 
#     # --- Chunk query ---
#     if http_message.get("query"):
#         norm_q = normalize_text(http_message["query"])
#         params = extract_query_params(http_message["query"])
#         await memory.add(
#             MemoryContent(
#                 content=norm_q,
#                 mime_type=MemoryMimeType.TEXT,
#                 metadata={
#                     "id": f"{msg_id}_query",
#                     "type": "traffic",
#                     "part": "query",
#                     # store params as string instead of dict
#                     "params": str(params),
#                 },
#             )
#         )

#     # --- Chunk headers ---
#     if http_message.get("headers"):
#         norm_h = normalize_text(http_message["headers"])
#         headers_dict = canonicalize_headers(http_message["headers"])
#         await memory.add(
#             MemoryContent(
#                 content=norm_h,
#                 mime_type=MemoryMimeType.TEXT,
#                 metadata={
#                     "id": f"{msg_id}_headers",
#                     "type": "traffic",
#                     "part": "headers",
#                     # store headers as string instead of dict
#                     "headers": str(headers_dict),
#                 },
#             )
#         )


#     # --- Chunk body ---
#     if http_message.get("body"):
#         await memory.add(
#             MemoryContent(
#                 content=normalize_text(http_message["body"]),
#                 mime_type=MemoryMimeType.TEXT,
#                 metadata={
#                     "id": f"{msg_id}_body",
#                     "type": "traffic",
#                     "part": "body",
#                 },
#             )
#         )

#     print(f"[+] Ingested traffic message {msg_id}")


# async def main():
#     memory = await init_memory()

#     # Example: mock HTTP message
#     http_message = {
#         "id": "req123",
#         "path": "/api/login",
#         "query": "user=admin&pass=1234%20or%201%3D1",
#         "headers": "User-Agent: curl/7.85.0\nAccept: */*\n",
#         "body": '{"username":"admin","password":"1234"}',
#     }

#     await ingest_http_message(memory, http_message)

#     await memory.close()


# if __name__ == "__main__":
#     asyncio.run(main())




# v2
# """
# Collector (Chunked) for ZAP + ChromaDB RAG Memory
# -------------------------------------------------
# - Continuously listens to ZAP traffic (like collector.py).
# - Splits requests into structured chunks: path, query, body, headers.
# - Preprocesses & normalizes payloads (decodes encodings, strips tokens).
# - Stores chunks in persistent ChromaDB memory.

# Usage:
#     poetry run python collector_chunked.py
# """

# import asyncio
# import time
# import urllib.parse
# from zapv2 import ZAPv2

# from autogen_ext.memory.chromadb import (
#     ChromaDBVectorMemory,
#     PersistentChromaDBVectorMemoryConfig,
#     SentenceTransformerEmbeddingFunctionConfig,
# )
# from autogen_core.memory import MemoryContent, MemoryMimeType
# from baseline_docs import BASELINE_DOCS
# from preprocess import preprocess_payload


# # =====================
# # Config
# # =====================
# ZAP_API_URL = "http://localhost:8090"
# PERSIST_PATH = "./chroma_data"
# COLLECTION_NAME = "security_memory"


# # =====================
# # Helper functions
# # =====================
# def chunk_message(msg: dict) -> dict:
#     """
#     Break a ZAP HTTP message into chunks (path, query, headers, body).
#     """
#     req_header = msg.get("requestHeader", "")
#     req_body = msg.get("requestBody", "")
#     # Response currently ignored for chunking

#     # Extract path + query
#     first_line = req_header.splitlines()[0] if req_header else ""
#     path = ""
#     query = ""
#     if first_line:
#         try:
#             parts = first_line.split()
#             if len(parts) >= 2:
#                 url = parts[1]
#                 parsed = urllib.parse.urlparse(url)
#                 path = parsed.path or ""
#                 query = parsed.query or ""
#         except Exception:
#             pass

#     # Extract headers (minus first line)
#     headers = "\n".join(req_header.splitlines()[1:])

#     return {
#         "path": preprocess_payload(path),
#         "query": preprocess_payload(query),
#         "headers": preprocess_payload(headers),
#         "body": preprocess_payload(req_body),
#     }


# async def seed_baseline(memory: ChromaDBVectorMemory):
#     print("\n[*] Indexing baseline security knowledge...")
#     for i, doc in enumerate(BASELINE_DOCS, start=1):
#         content = MemoryContent(
#             content=doc,
#             mime_type=MemoryMimeType.TEXT,
#             metadata={"type": "baseline", "id": f"baseline-{i}"},
#         )
#         await memory.add(content)


# def connect_to_zap() -> ZAPv2:
#     print("[*] Connecting to ZAP API...")
#     zap = ZAPv2(apikey=None)
#     version = zap.core.version
#     print(f"[+] Connected to ZAP (version: {version})")
#     return zap


# async def process_and_store(msg: dict, memory: ChromaDBVectorMemory):
#     """
#     Process one ZAP message -> chunk -> preprocess -> store in memory.
#     """
#     chunks = chunk_message(msg)
#     for chunk_type, value in chunks.items():
#         if not value:
#             continue
#         content = MemoryContent(
#             content=value,
#             mime_type=MemoryMimeType.TEXT,
#             metadata={
#                 "type": "traffic",
#                 "id": f"req-{msg['id']}-{chunk_type}",
#                 "chunk": chunk_type,
#             },
#         )
#         await memory.add(content)
#     print(f"[+] Ingested traffic message req{msg['id']} ({len(chunks)} chunks)")


# async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
#     """
#     Continuous collector loop (like collector.py).
#     """
#     print("[*] Watching ZAP for new requests... (Ctrl+C to stop)")
#     last_id = 0

#     try:
#         while True:
#             all_msgs = zap.core.messages()
#             new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]

#             if new_msgs:
#                 for m in new_msgs:
#                     await process_and_store(m, memory)
#                     last_id = max(last_id, int(m["id"]))

#             await asyncio.sleep(0.1)

#     except KeyboardInterrupt:
#         print("\n[!] Collector stopped by user.")


# # =====================
# # Entrypoint
# # =====================
# async def main():
#     config = PersistentChromaDBVectorMemoryConfig(
#         collection_name=COLLECTION_NAME,
#         persistence_path=PERSIST_PATH,
#         embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
#             model_name="all-MiniLM-L6-v2"
#         ),
#         k=3,
#         score_threshold=0.3,
#     )
#     memory = ChromaDBVectorMemory(config=config)

#     await seed_baseline(memory)
#     zap = connect_to_zap()
#     await collector_loop(memory, zap)

#     await memory.close()


# if __name__ == "__main__":
#     asyncio.run(main())


# v3
# """
# Continuous chunking collector that connects to ZAP, chunks & preprocesses traffic,
# and stores chunks into persistent ChromaDB via autogen_ext.memory.chromadb.

# Usage:
#     poetry run python collector_chunked.py
# """

# import asyncio
# import time
# import urllib.parse
# from zapv2 import ZAPv2

# from autogen_ext.memory.chromadb import (
#     ChromaDBVectorMemory,
#     PersistentChromaDBVectorMemoryConfig,
#     SentenceTransformerEmbeddingFunctionConfig,
# )
# from autogen_core.memory import MemoryContent, MemoryMimeType

# from preprocess import preprocess_payload
# from baseline_docs import BASELINE_DOCS

# # ------------------------
# # Config
# # ------------------------
# ZAP_API_URL = "http://localhost:8090"     # ZAP API endpoint
# PERSIST_PATH = "./chroma_data"
# COLLECTION_NAME = "security_memory"
# BATCH_SIZE = 50
# POLL_INTERVAL = 0.1  # seconds


# # ------------------------
# # Helpers
# # ------------------------
# def parse_request_first_line(request_header: str):
#     """
#     Return method, full_url, http_version from first line of request header.
#     """
#     if not request_header:
#         return None, None, None
#     first = request_header.splitlines()[0].strip()
#     parts = first.split()
#     if len(parts) >= 3:
#         return parts[0], parts[1], parts[2]
#     if len(parts) == 2:
#         return parts[0], parts[1], None
#     return None, None, None

# def chunk_message(msg: dict):
#     """
#     Given a ZAP message (dictionary as from zap.core.messages()),
#     produce a list of (chunk_type, normalized_text, metadata_dict).
#     metadata values are only simple JSON-serializable primitives (str/int/bool).
#     """
#     req_header = msg.get("requestHeader", "") or ""
#     req_body = msg.get("requestBody", "") or ""
#     resp_header = msg.get("responseHeader", "") or ""
#     resp_body = msg.get("responseBody", "") or ""

#     method, full_url, http_version = parse_request_first_line(req_header)

#     # parse URL parts
#     host = ""
#     path = ""
#     query = ""
#     if full_url:
#         try:
#             parsed = urllib.parse.urlparse(full_url)
#             host = parsed.netloc or ""
#             path = parsed.path or ""
#             query = parsed.query or ""
#         except Exception:
#             pass

#     chunks = []

#     # full combined doc (optional, useful for forensic export)
#     full_text = "[Request]\n" + req_header + ("\n" + req_body if req_body else "") \
#                 + "\n\n[Response]\n" + resp_header + ("\n" + resp_body if resp_body else "")
#     full_norm = preprocess_payload(full_text, chunk_type=None)
#     chunks.append(("full", full_norm, {
#         "id": f"req-{msg.get('id')}-full",
#         "type": "traffic",
#         "part": "full",
#         "host": host,
#         "method": method or "",
#         "path": path or "",
#     }))

#     # path
#     p_norm = preprocess_payload(path, chunk_type="path")
#     if p_norm:
#         chunks.append(("path", p_norm, {
#             "id": f"req-{msg.get('id')}-path",
#             "type": "traffic",
#             "part": "path",
#             "host": host,
#             "method": method or "",
#             "path": path or "",
#         }))

#     # query (store as canonicalized lines)
#     q_norm = preprocess_payload(query, chunk_type="query")
#     if q_norm:
#         # store a short preview of params as metadata
#         param_preview = ",".join([kv.split("=")[0] for kv in q_norm.splitlines()[:5]])
#         chunks.append(("query", q_norm, {
#             "id": f"req-{msg.get('id')}-query",
#             "type": "traffic",
#             "part": "query",
#             "host": host,
#             "method": method or "",
#             "params_preview": param_preview,
#         }))

#     # headers
#     headers_only = "\n".join(req_header.splitlines()[1:]) if req_header else ""
#     h_norm = preprocess_payload(headers_only, chunk_type="headers")
#     if h_norm:
#         # metadata: include user-agent if present (string)
#         ua = ""
#         for line in headers_only.splitlines():
#             if ":" in line:
#                 k, v = line.split(":", 1)
#                 if k.strip().lower() == "user-agent":
#                     ua = v.strip()[:200]
#         chunks.append(("headers", h_norm, {
#             "id": f"req-{msg.get('id')}-headers",
#             "type": "traffic",
#             "part": "headers",
#             "host": host,
#             "method": method or "",
#             "user_agent": ua,
#         }))

#     # body
#     b_norm = preprocess_payload(req_body, chunk_type="body")
#     if b_norm:
#         chunks.append(("body", b_norm, {
#             "id": f"req-{msg.get('id')}-body",
#             "type": "traffic",
#             "part": "body",
#             "host": host,
#             "method": method or "",
#         }))

#     return chunks


# # ------------------------
# # Baseline seeding (idempotent)
# # ------------------------
# async def seed_baseline(memory: ChromaDBVectorMemory):
#     print("[*] Indexing baseline security knowledge...")
#     for i, doc in enumerate(BASELINE_DOCS, start=1):
#         content = MemoryContent(
#             content=doc,
#             mime_type=MemoryMimeType.TEXT,
#             metadata={"type": "baseline", "id": f"baseline-{i}"}
#         )
#         try:
#             await memory.add(content)
#         except Exception:
#             # might already exist; ignore for idempotency
#             pass
#     print("[+] Baseline seeding complete.")


# # ------------------------
# # Collector core
# # ------------------------
# async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
#     print("[*] Loading ZAP history and processing existing messages in batches...")
#     all_msgs = zap.core.messages()
#     total_count = len(all_msgs)
#     print(f"[+] ZAP reports {total_count} messages in history.")

#     # Process old messages in batches to avoid excessive API calls
#     last_id = 0
#     processed = 0
#     for i in range(0, total_count, BATCH_SIZE):
#         batch = all_msgs[i:i + BATCH_SIZE]
#         tasks = []
#         for m in batch:
#             chunks = chunk_message(m)
#             for part, text, meta in chunks:
#                 # metadata values must be primitive; ensure conversion
#                 meta_safe = {k: (v if isinstance(v, (str, int, float, bool)) else str(v)) for k, v in meta.items()}
#                 content = MemoryContent(content=text, mime_type=MemoryMimeType.TEXT, metadata=meta_safe)
#                 tasks.append(memory.add(content))
#             last_id = max(last_id, int(m["id"]))
#         if tasks:
#             await asyncio.gather(*tasks)
#         processed += len(batch)
#         print(f"[+] Processed {processed}/{total_count} historical messages.")

#     print("[*] Finished loading history. Now watching for new messages...")

#     # Real-time loop for new messages
#     try:
#         while True:
#             all_msgs = zap.core.messages()
#             new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]
#             if new_msgs:
#                 for m in new_msgs:
#                     chunks = chunk_message(m)
#                     for part, text, meta in chunks:
#                         meta_safe = {k: (v if isinstance(v, (str, int, float, bool)) else str(v)) for k, v in meta.items()}
#                         content = MemoryContent(content=text, mime_type=MemoryMimeType.TEXT, metadata=meta_safe)
#                         try:
#                             await memory.add(content)
#                         except Exception as e:
#                             print(f"[!] Failed to add chunk for req {m['id']} part {part}: {e}")
#                     last_id = max(last_id, int(m["id"]))
#                     print(f"[+] Stored new request {m['id']} into memory (chunked).")
#             await asyncio.sleep(POLL_INTERVAL)
#     except KeyboardInterrupt:
#         print("\n[!] Collector stopped by user.")


# # ------------------------
# # Entrypoint
# # ------------------------
# async def main():
#     print("[*] Initializing ChromaDBVectorMemory...")
#     config = PersistentChromaDBVectorMemoryConfig(
#         collection_name=COLLECTION_NAME,
#         persistence_path=PERSIST_PATH,
#         embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
#             model_name="all-MiniLM-L6-v2"
#         ),
#         k=3,
#         score_threshold=0.3,
#     )
#     memory = ChromaDBVectorMemory(config=config)

#     await seed_baseline(memory)

#     zap = ZAPv2(apikey=None)
#     # set the API URL explicitly
#     zap._baseurl = ZAP_API_URL
#     print("[+] Connected to ZAP API.")

#     await collector_loop(memory, zap)

#     await memory.close()
#     print("[*] Memory closed cleanly.")


# if __name__ == "__main__":
#     asyncio.run(main())


# # v4
# import asyncio
# import time
# import urllib.parse
# from zapv2 import ZAPv2

# from autogen_ext.memory.chromadb import (
#     ChromaDBVectorMemory,
#     PersistentChromaDBVectorMemoryConfig,
#     SentenceTransformerEmbeddingFunctionConfig,
# )
# from autogen_core.memory import MemoryContent, MemoryMimeType

# from preprocess import preprocess_payload
# from baseline_docs import BASELINE_DOCS

# # ------------------------
# # Config
# # ------------------------
# ZAP_API_URL = "http://localhost:8090"     # ZAP API endpoint
# PERSIST_PATH = "./chroma_data"
# COLLECTION_NAME = "security_memory"
# BATCH_SIZE = 50
# POLL_INTERVAL = 0.1  # seconds


# # ------------------------
# # Helpers
# # ------------------------
# def parse_request_first_line(request_header: str):
#     """
#     Return method, full_url, http_version from first line of request header.
#     """
#     if not request_header:
#         return None, None, None
#     first = request_header.splitlines()[0].strip()
#     parts = first.split()
#     if len(parts) >= 3:
#         return parts[0], parts[1], parts[2]
#     if len(parts) == 2:
#         return parts[0], parts[1], None
#     return None, None, None

# def extract_path(req_header: str) -> str:
#     """
#     Extract the path from the request line in the HTTP header.
#     Example: "GET https://example.com/foo/bar?x=1 HTTP/1.1" -> "/foo/bar"
#     """
#     try:
#         first_line = req_header.splitlines()[0] if req_header else ""
#         parts = first_line.split()
#         if len(parts) >= 2:
#             url = parts[1]
#             parsed = urllib.parse.urlparse(url)
#             return parsed.path or "/"
#     except Exception:
#         return ""
#     return ""

# def extract_query(req_header: str) -> str:
#     """
#     Extract the query string from the request line in the HTTP header.
#     Example: "GET https://example.com/foo/bar?x=1&y=2 HTTP/1.1" -> "x=1&y=2"
#     """
#     try:
#         first_line = req_header.splitlines()[0] if req_header else ""
#         parts = first_line.split()
#         if len(parts) >= 2:
#             url = parts[1]
#             parsed = urllib.parse.urlparse(url)
#             return parsed.query or ""
#     except Exception:
#         return ""
#     return ""


# def chunk_message(msg: dict):
#     """
#     Break a ZAP message into structured chunks: path, query, body, headers, full.
#     Each chunk includes a group_id so parts can be recombined later.
#     """
#     msg_id = msg.get("id")
#     group_id = f"req-{msg_id}"

#     req_header = msg.get("requestHeader", "")
#     req_body = msg.get("requestBody", "")
#     resp_header = msg.get("responseHeader", "")
#     resp_body = msg.get("responseBody", "")

#     # --- Path ---
#     path = extract_path(req_header)
#     yield (
#         "path",
#         path,
#         {"type": "traffic", "id": f"{group_id}-path", "group_id": group_id, "part": "path"},
#     )

#     # --- Query ---
#     query = extract_query(req_header)
#     if query:
#         yield (
#             "query",
#             query,
#             {"type": "traffic", "id": f"{group_id}-query", "group_id": group_id, "part": "query"},
#         )

#     # --- Body ---
#     if req_body.strip():
#         b_norm = preprocess_payload(req_body, chunk_type="body")
#         yield (
#             "body",
#             b_norm,
#             {"type": "traffic", "id": f"{group_id}-body", "group_id": group_id, "part": "body"},
#         )

#     # --- Headers ---
#     if req_header.strip():
#         h_norm = preprocess_payload(req_header, chunk_type="headers")
#         yield (
#             "headers",
#             h_norm,
#             {"type": "traffic", "id": f"{group_id}-headers", "group_id": group_id, "part": "headers"},
#         )

#     # --- Full (fallback raw) ---
#     full_text = f"[Request]\n{req_header}\n{req_body}\n\n[Response]\n{resp_header}\n{resp_body}"
#     yield (
#         "full",
#         full_text,
#         {"type": "traffic", "id": f"{group_id}-full", "group_id": group_id, "part": "full"},
#     )

# # ------------------------
# # Baseline seeding (idempotent)
# # ------------------------
# async def seed_baseline(memory: ChromaDBVectorMemory):
#     print("[*] Indexing baseline security knowledge...")
#     for i, doc in enumerate(BASELINE_DOCS, start=1):
#         content = MemoryContent(
#             content=doc,
#             mime_type=MemoryMimeType.TEXT,
#             metadata={"type": "baseline", "id": f"baseline-{i}"}
#         )
#         try:
#             await memory.add(content)
#         except Exception:
#             # might already exist; ignore for idempotency
#             pass
#     print("[+] Baseline seeding complete.")


# # ------------------------
# # Collector core
# # ------------------------
# async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
#     print("[*] Loading ZAP history and processing existing messages in batches...")
#     all_msgs = zap.core.messages()
#     total_count = len(all_msgs)
#     print(f"[+] ZAP reports {total_count} messages in history.")

#     # Process old messages in batches to avoid excessive API calls
#     last_id = 0
#     processed = 0
#     for i in range(0, total_count, BATCH_SIZE):
#         batch = all_msgs[i:i + BATCH_SIZE]
#         tasks = []
#         for m in batch:
#             chunks = chunk_message(m)
#             for part, text, meta in chunks:
#                 # metadata values must be primitive
#                 meta_safe = {
#                     k: (v if isinstance(v, (str, int, float, bool)) else str(v))
#                     for k, v in meta.items()
#                 }
#                 content = MemoryContent(
#                     content=text,  # only store raw text, not dicts
#                     mime_type=MemoryMimeType.TEXT,
#                     metadata=meta_safe
#                 )
#                 tasks.append(memory.add(content))
#             last_id = max(last_id, int(m["id"]))
#         if tasks:
#             await asyncio.gather(*tasks)
#         processed += len(batch)
#         print(f"[+] Processed {processed}/{total_count} historical messages.")

#     # all_docs = await memory.get_all()
#     # count = len(all_docs)
#     # print(f"Number of documents: {count}")

#     print("[*] Finished loading history. Now watching for new messages...")

#     # Real-time loop for new messages
#     try:
#         while True:
#             all_msgs = zap.core.messages()
#             new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]
#             if new_msgs:
#                 for m in new_msgs:
#                     chunks = chunk_message(m)
#                     for part, text, meta in chunks:
#                         meta_safe = {k: (v if isinstance(v, (str, int, float, bool)) else str(v)) for k, v in meta.items()}
#                         content = MemoryContent(content=text, mime_type=MemoryMimeType.TEXT, metadata=meta_safe)
#                         try:
#                             await memory.add(content)
#                         except Exception as e:
#                             print(f"[!] Failed to add chunk for req {m['id']} part {part}: {e}")
#                     last_id = max(last_id, int(m["id"]))
#                     print(f"[+] Stored new request {m['id']} into memory (chunked).")
#             await asyncio.sleep(POLL_INTERVAL)
#     except KeyboardInterrupt:
#         print("\n[!] Collector stopped by user.")


# # ------------------------
# # Entrypoint
# # ------------------------
# async def main():
#     print("[*] Initializing ChromaDBVectorMemory...")
#     config = PersistentChromaDBVectorMemoryConfig(
#         collection_name=COLLECTION_NAME,
#         persistence_path=PERSIST_PATH,
#         embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
#             model_name="all-MiniLM-L6-v2"
#         ),
#         k=3,
#         score_threshold=0.3,
#     )
#     memory = ChromaDBVectorMemory(config=config)

#     await seed_baseline(memory)

#     zap = ZAPv2(apikey=None)
#     # set the API URL explicitly
#     zap._baseurl = ZAP_API_URL
#     print("[+] Connected to ZAP API.")

#     await collector_loop(memory, zap)

#     await memory.close()
#     print("[*] Memory closed cleanly.")


# if __name__ == "__main__":
#     asyncio.run(main())


# v5 
# preprocess_payload is not utlizied
# import asyncio
# import time
# import urllib.parse
# from zapv2 import ZAPv2
# import re

# from autogen_ext.memory.chromadb import (
#     ChromaDBVectorMemory,
#     PersistentChromaDBVectorMemoryConfig,
#     SentenceTransformerEmbeddingFunctionConfig,
# )
# from autogen_core.memory import MemoryContent, MemoryMimeType

# from preprocess import preprocess_payload
# from baseline_docs import BASELINE_DOCS

# # ------------------------
# # Config
# # ------------------------
# ZAP_API_URL = "http://localhost:8090"     # ZAP API endpoint
# PERSIST_PATH = "./chroma_data"
# COLLECTION_NAME = "security_memory"
# BATCH_SIZE = 50
# POLL_INTERVAL = 0.1  # seconds


# # ------------------------
# # Helpers
# # ------------------------
# def parse_request_first_line(request_header: str):
#     """
#     Return method, full_url, http_version from first line of request header.
#     """
#     if not request_header:
#         return None, None, None
#     first = request_header.splitlines()[0].strip()
#     parts = first.split()
#     if len(parts) >= 3:
#         return parts[0], parts[1], parts[2]
#     if len(parts) == 2:
#         return parts[0], parts[1], None
#     return None, None, None

# def extract_path(req_header: str) -> str:
#     """
#     Extract the path from the request line in the HTTP header.
#     Example: "GET https://example.com/foo/bar?x=1 HTTP/1.1" -> "/foo/bar"
#     """
#     try:
#         first_line = req_header.splitlines()[0] if req_header else ""
#         parts = first_line.split()
#         if len(parts) >= 2:
#             url = parts[1]
#             parsed = urllib.parse.urlparse(url)
#             return parsed.path or "/"
#     except Exception:
#         return ""
#     return ""

# def extract_query(req_header: str) -> str:
#     """
#     Extract the query string from the request line in the HTTP header.
#     Example: "GET https://example.com/foo/bar?x=1&y=2 HTTP/1.1" -> "x=1&y=2"
#     """
#     try:
#         first_line = req_header.splitlines()[0] if req_header else ""
#         parts = first_line.split()
#         if len(parts) >= 2:
#             url = parts[1]
#             parsed = urllib.parse.urlparse(url)
#             return parsed.query or ""
#     except Exception:
#         return ""
#     return ""



# def normalize_value(val: str) -> str:
#     """
#     Normalize suspicious/encoded values:
#       - URL-decode (%xx, +)
#       - Try Base64 decode (if safe)
#       - Highlight attack-like tokens
#     """
#     if not val:
#         return val

#     # URL decode
#     try:
#         val = urllib.parse.unquote_plus(val)
#     except Exception:
#         pass

#     # Base64 decode if it looks like base64 (simple heuristic)
#     if re.fullmatch(r"[A-Za-z0-9+/=]+", val) and len(val) % 4 == 0:
#         try:
#             decoded = base64.b64decode(val, validate=True).decode("utf-8", errors="ignore")
#             if decoded and len(decoded) > 2:
#                 val = f"{val} [base64→ {decoded}]"
#         except Exception:
#             pass

#     # Highlight attack-like tokens
#     attack_tokens = [
#         ";", "--", "' OR", "' or", "${", "<script>", "../", "%00"
#     ]
#     for t in attack_tokens:
#         if t.lower() in val.lower():
#             val = val.replace(t, f"[ATTACK:{t}]")

#     return val


# def chunk_message(req_text: str, group_id: str):
#     """
#     Break request/response into structured & normalized chunks.
#     Each chunk is tagged with part=path|query|header|body.
#     """

#     chunks = []

#     # 1. Extract request line
#     first_line = req_text.splitlines()[0] if req_text else ""
#     if first_line.startswith("[Request]"):
#         try:
#             parts = first_line.split()
#             url = parts[2] if len(parts) > 2 else ""
#         except Exception:
#             url = ""
        
#         parsed = urllib.parse.urlparse(url)

#         # Path chunk
#         if parsed.path:
#             chunks.append({
#                 "group_id": group_id,
#                 "part": "path",
#                 "id": f"{group_id}-path",
#                 "content": normalize_value(parsed.path.strip())
#             })

#         # Query params as separate chunks (normalized)
#         if parsed.query:
#             for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
#                 norm_v = normalize_value(v)
#                 chunks.append({
#                     "group_id": group_id,
#                     "part": "query",
#                     "id": f"{group_id}-param-{k}",
#                     "content": f"{k}={norm_v}".strip()
#                 })

#     # 2. Headers
#     headers_section = []
#     in_headers = False
#     for line in req_text.splitlines():
#         if line.lower().startswith("host:") or ":" in line:
#             in_headers = True
#         if in_headers and line.strip():
#             headers_section.append(line.strip())

#     for idx, header in enumerate(headers_section):
#         chunks.append({
#             "group_id": group_id,
#             "part": "header",
#             "id": f"{group_id}-header-{idx}",
#             "content": normalize_value(header)
#         })

#     # 3. Body (normalized if present)
#     if "\r\n\r\n" in req_text:
#         body = req_text.split("\r\n\r\n", 1)[1].strip()
#         if body:
#             chunks.append({
#                 "group_id": group_id,
#                 "part": "body",
#                 "id": f"{group_id}-body",
#                 "content": normalize_value(body)
#             })

#     return chunks

# # ------------------------
# # Baseline seeding (idempotent)
# # ------------------------
# async def seed_baseline(memory: ChromaDBVectorMemory):
#     print("[*] Indexing baseline security knowledge...")
#     for i, doc in enumerate(BASELINE_DOCS, start=1):
#         content = MemoryContent(
#             content=doc,
#             mime_type=MemoryMimeType.TEXT,
#             metadata={"type": "baseline", "id": f"baseline-{i}"}
#         )
#         try:
#             await memory.add(content)
#         except Exception:
#             # might already exist; ignore for idempotency
#             pass
#     print("[+] Baseline seeding complete.")


# # ------------------------
# # Collector core
# # ------------------------

# async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
#     """
#     Collect ZAP messages, chunk them, normalize, and store in memory.
#     First processes history in batches, then monitors for new traffic.
#     """
#     print("[*] Watching ZAP for requests... (Ctrl+C to stop)")

#     all_msgs = zap.core.messages()
#     total_count = len(all_msgs)
#     print(f"[+] ZAP reports {total_count} messages in history.")

#     processed = 0
#     last_id = 0
#     batch_size = 50

#     # ----------------------
#     # 1. Process history
#     # ----------------------
#     for i in range(0, total_count, batch_size):
#         batch = all_msgs[i:i + batch_size]
#         tasks = []

#         for m in batch:
#             group_id = str(m["id"])
#             req_text = (m.get("requestHeader", "") + "\r\n\r\n" + m.get("requestBody", "")).strip()
#             if not req_text:
#                 continue

#             chunks = chunk_message(req_text, group_id)
#             for chunk in chunks:
#                 meta_safe = {
#                     "group_id": chunk["group_id"],
#                     "part": chunk["part"],
#                     "id": chunk["id"],
#                 }
#                 content = MemoryContent(
#                     content=chunk["content"],
#                     mime_type=MemoryMimeType.TEXT,
#                     metadata=meta_safe,
#                 )
#                 tasks.append(memory.add(content))

#             last_id = max(last_id, int(m["id"]))

#         if tasks:
#             await asyncio.gather(*tasks)
#         processed += len(batch)
#         print(f"[+] Processed {processed}/{total_count} historical messages.")

#     print("[*] Finished indexing history.")
#     print("[*] Now watching for new messages...")

#     # ----------------------
#     # 2. Live monitoring
#     # ----------------------
#     try:
#         while True:
#             all_msgs = zap.core.messages()
#             new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]

#             for m in new_msgs:
#                 group_id = str(m["id"])
#                 req_text = (m.get("requestHeader", "") + "\r\n\r\n" + m.get("requestBody", "")).strip()
#                 if not req_text:
#                     continue

#                 chunks = chunk_message(req_text, group_id)
#                 for chunk in chunks:
#                     meta_safe = {
#                         "group_id": chunk["group_id"],
#                         "part": chunk["part"],
#                         "id": chunk["id"],
#                     }
#                     content = MemoryContent(
#                         content=chunk["content"],
#                         mime_type=MemoryMimeType.TEXT,
#                         metadata=meta_safe,
#                     )
#                     await memory.add(content)

#                 last_id = max(last_id, int(m["id"]))
#                 print(f"[+] Stored new request {m['id']} into memory.")

#             await asyncio.sleep(0.2)  # throttle a bit

#     except KeyboardInterrupt:
#         print("\n[!] Collector stopped by user.")


# # ------------------------
# # Entrypoint
# # ------------------------
# async def main():
#     print("[*] Initializing ChromaDBVectorMemory...")
#     config = PersistentChromaDBVectorMemoryConfig(
#         collection_name=COLLECTION_NAME,
#         persistence_path=PERSIST_PATH,
#         embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
#             model_name="all-MiniLM-L6-v2"
#         ),
#         k=3,
#         score_threshold=0.3,
#     )
#     memory = ChromaDBVectorMemory(config=config)

#     # await seed_baseline(memory) # only run when needed

#     zap = ZAPv2(apikey=None)
#     # set the API URL explicitly
#     zap._baseurl = ZAP_API_URL
#     print("[+] Connected to ZAP API.")

#     await collector_loop(memory, zap)

#     await memory.close()
#     print("[*] Memory closed cleanly.")


# if __name__ == "__main__":
#     asyncio.run(main())





# v6
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

# Import the new preprocessing wrapper which calls preprocess_payload AND
# computes suspicion_score, suspicious_tags, and returns annotated text.
from preprocess import normalize_chunk_text  # must exist in preprocess.py
from baseline_docs import BASELINE_DOCS

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