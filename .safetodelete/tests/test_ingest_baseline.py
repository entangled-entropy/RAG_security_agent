"""
Ingest baseline security documents into ChromaDB memory.
Baseline docs are imported from ../baseline_docs.py
"""

import sys
import os
import asyncio

# Ensure we can import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from baseline_docs import BASELINE_DOCS  # <-- import here

from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_core.memory import MemoryContent, MemoryMimeType

# Persistent storage path for ChromaDB
PERSIST_PATH = "./chroma_data"
COLLECTION_NAME = "security_memory"

async def main():
    print("[*] Initializing ChromaDB for baseline ingestion...")

    # Configure persistent memory with embeddings
    config = PersistentChromaDBVectorMemoryConfig(
        collection_name=COLLECTION_NAME,
        persistence_path=PERSIST_PATH,
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
    )

    memory = ChromaDBVectorMemory(config=config)

    # Ingest baseline docs into memory
    for doc in BASELINE_DOCS:
        # Convert 'tags' list into a string
        tags = ", ".join(doc["metadata"]["tags"])

        # Add document to memory
        await memory.add(
            MemoryContent(
                content=doc["content"],
                mime_type=MemoryMimeType.TEXT,
                metadata={
                    "type": "baseline",
                    **doc["metadata"],  # merge user metadata here
                    "tags": tags,  # convert tags list into a string
                    "id": doc["id"],  # enforce id
                },
            )
        )
        print(f"[+] Ingested baseline doc: {doc['id']}")

    print(f"[✓] Ingested {len(BASELINE_DOCS)} baseline documents into ChromaDB.")

if __name__ == "__main__":
    asyncio.run(main())
