#!/usr/bin/env python3
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.core.agent import SecurityAnalysisAgent


async def main():
    persist_path = os.environ.get("PERSIST_PATH", os.path.join(os.path.dirname(__file__), '..', 'chroma_data'))
    agent = SecurityAnalysisAgent(persist_path=persist_path, k=3)
    await agent.initialize()
    try:
        print("[*] Query console (no LLM). Type your query (or 'quit').")
        while True:
            try:
                q = input("\nquery> ").strip()
                if not q:
                    continue
                if q.lower() in {"quit", "exit"}:
                    print("[*] Exiting.")
                    break
                docs = await agent.query_memory(q)
                if not docs:
                    print("[!] No documents found. Tip: run the collector first to populate memory.")
                    continue
                # Collect unique group_ids
                group_ids = []
                for d in docs:
                    meta = getattr(d, "metadata", None) or (d.get("metadata") if isinstance(d, dict) else None) or {}
                    gid = meta.get("group_id")
                    if gid and gid not in group_ids:
                        group_ids.append(gid)

                print(f"[INFO] Found {len(group_ids)} unique group_ids")
                for i, gid in enumerate(group_ids[:5], 1):
                    msg = agent.reconstruct_http_message_with_analysis(gid)
                    print(f"\n--- Result {i} (group_id={gid}) ---")
                    # Show request + analysis
                    print(msg[:2000])
                    # Show a limited response snippet
                    resp_snip = agent.get_response_snippet(gid, max_chars=1000)
                    if resp_snip:
                        print("\n[RESPONSE SNIPPET] (first 500 chars)")
                        print(resp_snip)
                    print()
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Interrupted. Exiting.")
                break
    finally:
        await agent.close()


if __name__ == "__main__":
    asyncio.run(main())


