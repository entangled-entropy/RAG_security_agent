"""
Runtime-like tests for ZAPCollector with mocked ZAP and in-memory memory writes.
Reuses the actual collector code; we stub out ZAP and memory layer.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock

from zap_rag_security_agent.collectors.zap_collector import ZAPCollector


class DummyMemory:
    def __init__(self):
        self.add_calls = []
    async def add(self, content):
        self.add_calls.append(content)
    async def close(self):
        pass


def build_mock_message(id: int, url: str, html_body: str = "", headers: str = "Content-Type: text/html\r\nHost: example.com\r\n"):
    req = f"[Request] GET {url} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{html_body}"
    return {
        "id": id,
        "requestHeader": req,
        "requestBody": "",
        "responseHeader": resp,
        "responseBody": "",
    }


@pytest.mark.asyncio
async def test_collector_normalization_and_chunking(monkeypatch):
    collector = ZAPCollector(enable_script_analysis=False)
    await collector.initialize()

    # stub memory and zap
    collector.memory = DummyMemory()
    collector.zap = Mock()
    html = """
    <html><head><script src="/dist/app.js"></script></head><body>Hello</body></html>
    """
    msg = build_mock_message(1, "https://example.com/path?q=1", html)
    collector.zap.core = Mock()
    collector.zap.core.messages = Mock(return_value=[msg])

    await collector.collect_historical()

    # ensure chunks were added: path, headers, maybe body
    parts = [c.metadata.get("part") for c in collector.memory.add_calls]
    assert any(p and p.endswith("path") for p in parts)
    assert any(p and p.endswith("headers") for p in parts)


@pytest.mark.asyncio
async def test_collector_memory_write_without_db(monkeypatch):
    collector = ZAPCollector(enable_script_analysis=False)
    await collector.initialize()
    collector.memory = DummyMemory()
    collector.zap = Mock()
    msg = build_mock_message(2, "https://example.com/page", "<html>ok</html>")
    collector.zap.core = Mock()
    collector.zap.core.messages = Mock(return_value=[msg])

    await collector.collect_historical()

    # validate we wrote MemoryContent objects with metadata
    assert len(collector.memory.add_calls) > 0
    first = collector.memory.add_calls[0]
    assert hasattr(first, "metadata") and isinstance(first.metadata, dict)


