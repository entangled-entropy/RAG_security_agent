import os
import pytest
import asyncio

ZAP_URL = os.environ.get("ZAP_API_URL", "http://localhost:8090")
PERSIST_PATH = os.environ.get("PERSIST_PATH", "/home/entropy/playground/detoxio/RAG_security_agent/chroma_data")


def test_normalization_using_zap():
    try:
        import zapv2  # noqa: F401
    except Exception:
        pytest.skip("python-owasp-zap-v2.4 not installed in current env")

    async def _run():
        from zap_rag_security_agent.collectors.zap_collector import ZAPCollector
        from zap_rag_security_agent.core.agent import SecurityAnalysisAgent

        collector = ZAPCollector(zap_api_url=ZAP_URL, persist_path=PERSIST_PATH)
        await collector.initialize()
        try:
            all_msgs = collector.zap.core.messages()
            if not all_msgs:
                pytest.skip("No ZAP messages available; run a crawl/scan first.")
            batch = all_msgs[:10]
            await asyncio.gather(*(collector._process_message(m) for m in batch))

            agent = SecurityAnalysisAgent(persist_path=PERSIST_PATH, k=1)
            http = agent.reconstruct_http_message(str(batch[0]["id"]))
            assert "[PATH]" in http
            assert "[HEADERS]" in http
        finally:
            await collector.close()

    asyncio.run(_run())


