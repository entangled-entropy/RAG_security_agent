import os
import pytest
import asyncio

PERSIST_PATH = os.environ.get("PERSIST_PATH", "/home/entropy/playground/detoxio/RAG_security_agent/chroma_data")


def test_schematic_query_rnd():
    try:
        from zap_rag_security_agent.core.agent import SecurityAnalysisAgent
    except Exception:
        pytest.skip("autogen dependencies not installed in current env")

    async def _run():
        agent = SecurityAnalysisAgent(persist_path=PERSIST_PATH, k=3)
        docs = await agent.query_memory("security risks in client-side scripts")
        if not docs:
            pytest.skip("No documents in memory yet; run collector first.")
        meta = getattr(docs[0], "metadata", None) or (docs[0].get("metadata") if isinstance(docs[0], dict) else None) or {}
        gid = meta.get("group_id")
        if not gid:
            pytest.skip("No group_id available in top doc")
        msg = agent.reconstruct_http_message_with_analysis(gid)
        assert "[PATH]" in msg
        assert "[ANALYSIS]" in msg or "[CLIENT-SIDE SCRIPT ANALYSIS]" in msg

    asyncio.run(_run())


