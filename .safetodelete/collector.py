"""
better use collector_chunked.py
this is deprecated
Collector Script for ZAP + ChromaDB RAG Memory
----------------------------------------------
- Connects to the OWASP ZAP API running in Docker.
- Collects HTTP requests/responses captured by ZAP.
- Stores them in a persistent ChromaDB vector memory.
- Seeds the memory with baseline OWASP Top 10 knowledge.

Usage:
    poetry run python collector.py
"""

import asyncio
import time
from zapv2 import ZAPv2

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_core.memory import MemoryContent, MemoryMimeType

# Import from new modular structure
from src.zap_rag_security_agent.data.baseline_docs import BASELINE_DOCS

# =====================
# Config Block
# =====================
ZAP_API_URL = "http://localhost:8090"     # ZAP API (not the proxy!)
PERSIST_PATH = "./chroma_data"            # Folder to persist memory
COLLECTION_NAME = "security_memory"       # Logical name for collection

# =====================
# Helper Functions Block
# =====================
def format_message(msg: dict) -> str:
    """
    Convert a ZAP HTTP message into a plain text document for memory storage.
    """
    req_header = msg.get("requestHeader", "")
    req_body = msg.get("requestBody", "")
    resp_header = msg.get("responseHeader", "")
    resp_body = msg.get("responseBody", "")

    return f"""
[Request]
{req_header}
{req_body}

[Response]
{resp_header}
{resp_body}
""".strip()


async def seed_baseline(memory: ChromaDBVectorMemory):
    """
    Seed the memory with OWASP Top 10 baseline knowledge.
    Idempotent: will skip duplicates on reruns.
    """
    print("\n[*] Indexing baseline security knowledge...")
    for i, doc in enumerate(BASELINE_DOCS, start=1):
        content = MemoryContent(
            content=doc,
            mime_type=MemoryMimeType.TEXT,
            metadata={"type": "baseline", "id": f"baseline-{i}"}
        )
        await memory.add(content)


def connect_to_zap() -> ZAPv2:
    """
    Connect to the ZAP API and return a ZAPv2 instance.
    """
    print("[*] Connecting to ZAP API...")
    zap = ZAPv2(apikey=None)
    # zap._baseurl = ZAP_API_URL  # Must set manually
    version = zap.core.version
    print(f"[+] Connected to ZAP (version: {version})")
    print("msg count:", len(zap.core.messages()))
    return zap


# =====================
# Main Loop Block
# =====================

# async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
#     """
#     Poll ZAP for new HTTP messages and store them in memory.
#     """
#     print("[*] Watching ZAP for new requests... (Ctrl+C to stop)")
#     last_id = 0

#     try:
#         while True:
#             # need to speed up in batches later
#             all_msgs = zap.core.messages()
#             new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]

#             for m in new_msgs:
#                 doc_text = format_message(m)
#                 content = MemoryContent(
#                     content=doc_text,
#                     mime_type=MemoryMimeType.TEXT,
#                     metadata={"type": "traffic", "id": f"req-{m['id']}"}
#                 )
#                 await memory.add(content)
#                 print(f"[+] Stored request {m['id']} into memory.")
#                 last_id = max(last_id, int(m["id"]))

#             time.sleep(2)

#     except KeyboardInterrupt:
#         print("\n[!] Collector stopped by user.")


async def collector_loop(memory: ChromaDBVectorMemory, zap: ZAPv2):
    """
    Poll ZAP for new HTTP messages and store them in memory.
    """
    print("[*] Watching ZAP for new requests... (Ctrl+C to stop)")
    processed_count = 0  # Track number of processed messages
    start_time = time.time()  # Start time for ETA calculation

    try:
        # 1. Load existing (old) messages into memory (with batching and ETA)
        print("\n[*] Loading existing messages into memory...")
        all_msgs = zap.core.messages()  # Load all current messages
        total_count = len(all_msgs)  # Total number of messages at the start
        print("total_count: ",total_count)

        # Filter old messages
        existing_msgs = [m for m in all_msgs if int(m["id"]) <= total_count]
        
        # Set the starting point for new messages
        last_id = len(existing_msgs)  # last_id will be set as the length of old messages

        # Process old messages in batches with ETA
        batch_size = 50  # You can adjust the batch size
        print("batch size: ", batch_size)
        for i in range(0, len(existing_msgs), batch_size):
            batch = existing_msgs[i:i + batch_size]
            processed_count = await process_batch(batch, memory, last_id, processed_count, start_time, total_count)
            last_id = max(last_id, int(batch[-1]["id"]))  # Update last_id after each batch

        # Finish loading old messages
        print(f"\n[*] Loaded {processed_count}/{total_count} old messages into memory.")

        # 2. Start monitoring for new messages (no batching, no ETA)
        print("[*] Now watching for new messages...")

        # Now, `last_id` tracks the last processed old message, so we start tracking new messages from there.
        while True:
            all_msgs = zap.core.messages()
            new_msgs = [m for m in all_msgs if int(m["id"]) > last_id]

            if new_msgs:
                # Process each new message individually (no batching, no ETA)
                for m in new_msgs:
                    doc_text = format_message(m)
                    content = MemoryContent(
                        content=doc_text,
                        mime_type=MemoryMimeType.TEXT,
                        metadata={"type": "traffic", "id": f"req-{m['id']}"}
                    )
                    await memory.add(content)
                    last_id = max(last_id, int(m["id"]))  # Update last_id after processing each new message
                    print(f"[+] Stored new request {m['id']} into memory.")

            await asyncio.sleep(0.01)  # Short sleep to avoid high CPU usage

    except KeyboardInterrupt:
        print("\n[!] Collector stopped by user.")


async def process_batch(batch, memory, last_id, processed_count, start_time, total_count):
    """
    Process a batch of messages, storing them in memory and reporting progress.
    """
    batch_start_time = time.time()

    tasks = []
    for m in batch:
        doc_text = format_message(m)
        content = MemoryContent(
            content=doc_text,
            mime_type=MemoryMimeType.TEXT,
            metadata={"type": "traffic", "id": f"req-{m['id']}"}
        )
        tasks.append(memory.add(content))

    await asyncio.gather(*tasks)

    # Update the last_id to the most recent message ID in this batch
    last_id = max(last_id, int(batch[-1]["id"]))

    # Track progress
    processed_count += len(batch)
    batch_time = time.time() - batch_start_time
    elapsed_time = time.time() - start_time

    # Estimate ETA
    if processed_count > 0:
        avg_batch_time = elapsed_time / processed_count
        remaining_msgs = total_count - processed_count  # Remaining messages to process
        eta = avg_batch_time * remaining_msgs
        print(f"[+] Processed {processed_count}/{total_count} messages in {elapsed_time:.2f} seconds. ETA: {eta:.2f}s")

    # Print detailed message after each batch
    print(f"[+] Processed {len(batch)} messages in {batch_time:.2f} seconds. Total processed: {processed_count}/{total_count}.")
    
    # Return updated processed_count to reflect progress
    return processed_count


# =====================
# Entrypoint
# =====================
async def main():
    # Init memory
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

    # Seed knowledge
    await seed_baseline(memory)

    # Connect to ZAP
    zap = connect_to_zap()

    # Start collector loop
    await collector_loop(memory, zap)

    # Cleanup
    await memory.close()


if __name__ == "__main__":
    asyncio.run(main())
