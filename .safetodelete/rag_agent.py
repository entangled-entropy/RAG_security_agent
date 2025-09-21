"""
rag_agent.py

RAG Security Agent using autogen and ChromaDBVectorMemory (documented API).

- At startup, show how many baseline and traffic docs are found in query results.
- Use system prompt + OpenAI for reasoning.
- Interactive query console.

Run:
    export OPENAI_API_KEY=sk-...
    poetry run python rag_agent.py
"""
import asyncio
import sqlite3
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_ext.models.openai import OpenAIChatCompletionClient

# Import from new modular structure
from src.zap_rag_security_agent.core.agent import SecurityAnalysisAgent

# ------------------------
# Config
# ------------------------
DB_PATH = "./chroma_data_sep20_bak/chroma.sqlite3"  # adjust to your chroma DB file if needed
PERSIST_PATH = "./chroma_data_sep20_bak"
COLLECTION_NAME = "security_memory"

SYSTEM_PROMPT = (
    "You are SecurityAnalysisAgent, a security analyst. "
    "Use memory context to detect vulnerabilities, exposed secrets, "
    "outdated components, and suspicious patterns. "
    "Provide concise, actionable answers."
)

# ------------------------
# Query / Reconstruction Helpers
# ------------------------
async def query_chromadb(memory: ChromaDBVectorMemory, query: str):
    """Query ChromaDB for documents based on the provided query string."""
    print(f"\n[INFO] Running query: '{query}'...")
    try:
        results = await memory.query(query)
        if hasattr(results, "results"):
            return results.results
        elif hasattr(results, "documents"):
            return results.documents
        else:
            return results
    except Exception as e:
        print(f"[ERROR] Error querying ChromaDB: {e}")
        return []


def fetch_group_parts(group_id: str, db_path: str = DB_PATH) -> list[tuple[str, str]]:
    """
    Returns list of (part, text) tuples for the given group_id, ordered by
    path -> query -> headers -> body -> others.
    This function tries the most common FTS column names for compatibility.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # First try the common/actual column name in many chroma installs
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

    # Try string_value first (common); fall back to content if necessary
    for fts_col in ("string_value", "content"):
        try:
            sql = sql_template.format(fts_col=fts_col)
            cur.execute(sql, (str(group_id),))
            rows = cur.fetchall()
            conn.close()
            return rows
        except sqlite3.OperationalError as e:
            # If column doesn't exist, try the next candidate
            last_err = e
            continue

    # If we reach here, re-raise last error for visibility
    conn.close()
    raise last_err


def reconstruct_pretty(group_id: str, db_path: str = DB_PATH) -> str:
    """
    Reconstruct a single pretty request/response text for the given group_id.
    - One [PATH], one [QUERY] (if present)
    - One [HEADERS] block with merged lines
    - One [BODY] block
    - No repeated labels or empty lines
    """
    rows = fetch_group_parts(group_id, db_path)
    if not rows:
        return f"(no chunks found for group_id={group_id})"

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
            # header chunk might contain multiple lines; split & extend
            for line in t.splitlines():
                if line.strip():
                    headers_lines.append(line.strip())
        elif p == "body":
            body = t if body is None else body + "\n" + t
        else:
            other_parts.append((p, t))

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


def display_documents(documents, limit=5, reconstruct=False):
    """Display retrieved documents, optionally reconstruct full HTTP messages."""
    if not documents:
        print("[INFO] No documents found.")
        return

    print(f"[INFO] Displaying top {min(len(documents), limit)} documents:")
    for i, doc in enumerate(documents[:limit], 1):
        print(f"\n[INFO] Doc {i}:")
        if reconstruct:
            # support both object attributes and dict-like results
            meta = getattr(doc, "metadata", None) or (doc.get("metadata") if isinstance(doc, dict) else None) or {}
            group_id = meta.get("group_id")
            if group_id:
                full_msg = reconstruct_pretty(group_id)
                print(full_msg[:500])
            else:
                content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
                print((content or "")[:500])
        else:
            content = getattr(doc, "content", None) or (doc.get("content") if isinstance(doc, dict) else "")
            print((content or "")[:500])


# ------------------------
# Entrypoint
# ------------------------
async def main():
    print("[*] Initializing persistent ChromaDB memory...")
    config = PersistentChromaDBVectorMemoryConfig(
        collection_name=COLLECTION_NAME,
        persistence_path=PERSIST_PATH,
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
    )
    memory = ChromaDBVectorMemory(config=config)

    model_client = OpenAIChatCompletionClient(model="gpt-4o")
    assistant_agent = AssistantAgent(
        name="SecurityAnalysisAgent",
        model_client=model_client,
        memory=[memory],
        system_message=SYSTEM_PROMPT,
    )

    print("\n[*] Launching interactive console. Type your questions below (or 'quit' to exit).")
    while True:
        try:
            user_input = input("\n>>> ").strip()
            if user_input.lower() in {"quit", "exit"}:
                print("[*] Exiting.")
                break

            # Query memory
            docs = await query_chromadb(memory, user_input)
            if not docs:
                print("[!] No docs retrieved.")
                continue

            # Collect unique group_ids
            group_ids = []
            for d in docs:
                meta = getattr(d, "metadata", None) or (d.get("metadata") if isinstance(d, dict) else None) or {}
                gid = meta.get("group_id")
                if gid and gid not in group_ids:
                    group_ids.append(gid)

            print(f"[INFO] Found {len(group_ids)} unique group_ids from results")

            # Reconstruct each group
            reconstructed = [reconstruct_pretty(gid) for gid in group_ids]

            # Show samples
            for i, msg in enumerate(reconstructed[:2], 1):
                print(f"\n[DEBUG] Reconstructed sample {i}:\n{msg[:400]}...\n")

            if not reconstructed:
                print("[!] Nothing to send to OpenAI.")
                continue

            print(f"[INFO] Sending {len(reconstructed)} reconstructed docs to OpenAI")

            # Build task for OpenAI
            task = (
                "Analyze the following HTTP traffic for vulnerabilities:\n\n" +
                "\n\n---\n\n".join(reconstructed[:5])  # limit to avoid token explosion
            )

            # Run assistant
            stream = assistant_agent.run_stream(task=task)
            await Console(stream)

        except (KeyboardInterrupt, EOFError):
            print("\n[*] Interrupted. Exiting.")
            break

    await model_client.close()
    await memory.close()


if __name__ == "__main__":
    asyncio.run(main())
