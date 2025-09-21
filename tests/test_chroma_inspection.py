import asyncio
import sqlite3
from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from sentence_transformers import SentenceTransformer

### DB config ###
# DB = "./chroma_data_sep20_bak"
DB = "./chroma_data"
DB_PATH = f"{DB}/chroma.sqlite3"
#################

# Setup ChromaDB Configuration and Memory
def setup_chromadb_memory() -> ChromaDBVectorMemory:
    """Initialize ChromaDBVectorMemory with given configuration."""
    print("[INFO] Setting up ChromaDB...")
    
    config = PersistentChromaDBVectorMemoryConfig(
        collection_name="security_memory", 
        persistence_path=DB,
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
        k=5,
        score_threshold=0.3,
    )
    memory = ChromaDBVectorMemory(config=config)
    print("[INFO] ChromaDB setup complete.")
    return memory

# Query ChromaDB for documents
async def query_chromadb(memory: ChromaDBVectorMemory, query: str):
    """Query ChromaDB for documents based on the provided query string."""
    print(f"\n\n[INFO] Running query: '{query}'...")
    
    try:
        results = await memory.query(query)
        # Extract results correctly based on response structure
        if hasattr(results, 'results'):
            results = results.results
        elif hasattr(results, 'documents'):
            results = results.documents
        
        print(f"[INFO] Query returned {len(results)} results.")
        return results
    except Exception as e:
        print(f"[ERROR] Error querying ChromaDB: {e}")
        return []

# Display document snippets
# def display_documents(documents, limit=5):
#     """Display snippets from the retrieved documents."""
#     if documents:
#         print(f"[INFO] Displaying top {min(len(documents), limit)} documents:")
#         for i, doc in enumerate(documents[:limit], 1):
#             print(f"\n[INFO] Doc {i}:")
#             print(doc.content[:500])  # Display first 500 characters of each doc
#     else:
#         print("[INFO] No documents found.")

# def reconstruct_request(group_id, db_path="./chroma_data/chroma.sqlite3"):
#     """Reconstruct a full HTTP message from parts stored in ChromaDB."""
#     conn = sqlite3.connect(db_path)
#     cursor = conn.cursor()
    
#     cursor.execute("""
#         SELECT part_meta.string_value AS part,
#                efs.string_value AS text
#         FROM embedding_metadata part_meta
#         JOIN embedding_fulltext_search efs ON part_meta.id = efs.rowid
#         JOIN embedding_metadata group_meta ON group_meta.id = part_meta.id AND group_meta.key = 'group_id'
#         WHERE part_meta.key = 'part' AND group_meta.string_value = ?
#         ORDER BY CASE LOWER(part_meta.string_value)
#             WHEN 'path' THEN 1
#             WHEN 'query' THEN 2
#             WHEN 'headers' THEN 3
#             WHEN 'body' THEN 4
#             ELSE 5 END;
#     """, (str(group_id),))
    
#     rows = cursor.fetchall()
#     conn.close()
    
#     doc = []
#     for part, text in rows:
#         if text.strip():
#             doc.append(f"[{part.upper()}]\n{text.strip()}\n")
    
#     return "\n".join(doc)


def fetch_group_parts(group_id: str, db_path: str = DB_PATH) -> list[tuple[str, str]]:
    """
    Returns list of (part, text) tuples for the given group_id, ordered by
    path -> query -> headers -> body -> others.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    sql = """
    SELECT part_meta.string_value AS part,
           efs.string_value AS text
    FROM embedding_metadata part_meta
    JOIN embedding_fulltext_search efs ON part_meta.id = efs.rowid
    JOIN embedding_metadata group_meta ON group_meta.id = part_meta.id AND group_meta.key = 'group_id'
    WHERE part_meta.key = 'part' AND group_meta.string_value = ?
    ORDER BY CASE LOWER(part_meta.string_value)
        WHEN 'path' THEN 1
        WHEN 'query' THEN 2
        WHEN 'headers' THEN 3
        WHEN 'body' THEN 4
        ELSE 5 END, part_meta.string_value;
    """
    cur.execute(sql, (str(group_id),))
    rows = cur.fetchall()
    conn.close()
    return rows

def reconstruct_pretty(group_id: str, db_path: str = DB_PATH) -> str:
    """
    Reconstruct a single pretty request/response text for the given group_id.
    - Single [PATH], single [QUERY] (if present)
    - Single [HEADERS] block with joined lines (no repeated header labels)
    - Single [BODY] block
    - No extra blank lines
    """
    rows = fetch_group_parts(group_id, db_path)
    if not rows:
        return f"(no chunks found for group_id={group_id})"

    path = None
    query_items = []
    headers_lines = []
    body = None
    other_parts = []

    for part, text in rows:
        t = (text or "").strip()
        if not t:
            continue
        p = part.lower()
        if p == "path":
            # keep first path found
            if path is None:
                path = t
        elif p == "query":
            # query chunk might already be "k=v"; store raw
            query_items.append(t)
        elif p == "headers" or p == "header":
            # header lines might be multi-line; split and extend
            for line in t.splitlines():
                line = line.strip()
                if line:
                    headers_lines.append(line)
        elif p == "body":
            if body is None:
                body = t
            else:
                # concatenate multiple body chunks, if any
                body += ("\n" + t)
        else:
            other_parts.append((p, t))

    out_lines = []

    if path:
        out_lines.append("[PATH]")
        out_lines.append(path)

    if query_items:
        # If query items are "k=v", join by '&' to look like a query string, else join lines.
        # If already present as one chunk, it'll be single element.
        if len(query_items) == 1 and ("=" not in query_items[0] or "&" in query_items[0]):
            out_lines.append("[QUERY]")
            out_lines.append(query_items[0])
        else:
            out_lines.append("[QUERY]")
            out_lines.append("&".join(q for q in query_items if q))

    if headers_lines:
        out_lines.append("[HEADERS]")
        out_lines.extend(headers_lines)

    if body:
        out_lines.append("[BODY]")
        out_lines.append(body)

    # include any other parts (rare)
    for p, t in other_parts:
        out_lines.append(f"[{p.upper()}]")
        out_lines.append(t)

    # join with single newline between blocks, no trailing blank lines
    return "\n".join(out_lines)

def display_documents(documents, limit=5, reconstruct=False):
    """Display retrieved documents, optionally reconstruct full HTTP messages."""
    if not documents:
        print("[INFO] No documents found.")
        return
    
    print(f"[INFO] Displaying top {min(len(documents), limit)} documents:")
    for i, doc in enumerate(documents[:limit], 1):
        print(f"\n[INFO] Doc {i}:")
        if reconstruct:
            # assumes doc.metadata["group_id"] exists
            group_id = doc.metadata.get("group_id")
            if group_id:
                full_msg = reconstruct_pretty(group_id)
                print(full_msg[:1500])  # or full_msg if you want everything
            else:
                print(doc.content[:500])
        else:
            print(doc.content[:500])

# Test SentenceTransformer embeddings
def test_embeddings():
    """Test SentenceTransformer embeddings with a sample text."""
    print("\n\n[INFO] Testing SentenceTransformer embeddings...")
    
    model = SentenceTransformer('all-MiniLM-L6-v2')
    test_text = "API keys exposed in network traffic"
    embedding = model.encode(test_text)
    
    print(f"[INFO] Embedding for '{test_text}':")
    print(embedding[:10])  # Display first 10 values of the embedding vector

# Inspect ChromaDB SQLite database content
def inspect_sqlite_database():
    """Inspect the content of ChromaDB's SQLite database."""
    print("\n\n[INFO] Inspecting ChromaDB database content...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # List tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("[INFO] Tables in the ChromaDB SQLite database:")
        print(tables)

        # Inspect the 'document_embeddings' table for stored embeddings
        cursor.execute("SELECT * FROM document_embeddings LIMIT 10;")
        rows = cursor.fetchall()

        if rows:
            print("[INFO] Found embeddings in the database:")
            for row in rows:
                print(row)
        else:
            print("[INFO] No embeddings found in 'document_embeddings' table.")

        conn.close()
    except Exception as e:
        print(f"[ERROR] Error inspecting SQLite database: {e}")

# Main execution flow
async def main():
    """Main function to run the process."""
    
    # Step 1: Setup ChromaDB memory
    memory = setup_chromadb_memory()
    
    # Step 2: Query all documents in ChromaDB
    # all_documents = await query_chromadb(memory, query="*")
    # display_documents(all_documents)
    
    # Step 3: Test embeddings
    # test_embeddings()
    
    # Step 4: Run semantic query for a known term
    # query_term = "sql injection"
    query_term = "sql injection in traffic"
    query_results = await query_chromadb(memory, query=query_term)
    display_documents(query_results, reconstruct=True)
    # display_documents(query_results, limit=5, snippet_len=1500)

    
    # Step 5: Inspect ChromaDB SQLite database content
    # inspect_sqlite_database()
    
    # Step 6: Close ChromaDB memory connection
    await memory.close()

if __name__ == "__main__":
    asyncio.run(main())
