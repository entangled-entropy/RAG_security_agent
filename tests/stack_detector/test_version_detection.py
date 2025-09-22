import os
import pytest


def test_version_detection_from_zap_html():
    try:
        from zapv2 import ZAPv2
    except Exception:
        pytest.skip("python-owasp-zap-v2.4 not installed in current env")

    from zap_rag_security_agent.detectors.stack_detector import StackDetector

    zap_api_url = os.environ.get("ZAP_API_URL", "http://localhost:8090")
    zap = ZAPv2(apikey=None)
    zap._baseurl = zap_api_url

    msgs = zap.core.messages()
    if not msgs:
        pytest.skip("No ZAP messages available; run a crawl/scan first.")

    html = None
    for m in msgs:
        hdr = m.get("responseHeader", "")
        if "text/html" in hdr.lower():
            full = (hdr + "\r\n\r\n" + m.get("responseBody", "")).strip()
            html = full.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in full else full
            break

    if not html:
        pytest.skip("No HTML response found in ZAP history")

    det = StackDetector()
    res = det.detect_from_html(html, url="")
    assert isinstance(res, dict)


