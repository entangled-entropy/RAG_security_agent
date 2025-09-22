import os
import pytest
import asyncio

ZAP_URL = os.environ.get("ZAP_API_URL", "http://localhost:8090")
PERSIST_PATH = os.environ.get("PERSIST_PATH", "/home/entropy/playground/detoxio/RAG_security_agent/chroma_data")


def test_chunk_generated_using_zap():
    try:
        import zapv2  # noqa: F401
    except Exception:
        pytest.skip("python-owasp-zap-v2.4 not installed in current env")

    async def _run():
        from zap_rag_security_agent.collectors.zap_collector import ZAPCollector

        collector = ZAPCollector(zap_api_url=ZAP_URL, persist_path=PERSIST_PATH)
        await collector.initialize()
        try:
            all_msgs = collector.zap.core.messages()
            if not all_msgs:
                pytest.skip("No ZAP messages available; run a crawl/scan first.")

            msg = all_msgs[0]
            req_text = (msg.get("requestHeader", "") + "\r\n\r\n" + msg.get("requestBody", "")).strip()
            parts = list(collector._chunk_message(req_text, str(msg["id"]), prefix="req_"))
            part_names = [p["part"] for p in parts]
            assert "req_path" in part_names
            assert "req_headers" in part_names
        finally:
            await collector.close()

    asyncio.run(_run())


