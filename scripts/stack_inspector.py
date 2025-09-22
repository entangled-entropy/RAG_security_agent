#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def main():
    try:
        from zapv2 import ZAPv2
    except Exception as e:
        print("[!] python-owasp-zap-v2.4 not installed:", e)
        return

    from zap_rag_security_agent.detectors.stack_detector import StackDetector

    zap_url = os.environ.get("ZAP_API_URL", "http://localhost:8090")
    zap = ZAPv2(apikey=None)
    zap._baseurl = zap_url

    print(f"[*] Connecting to ZAP at {zap_url} ...")
    msgs = zap.core.messages()
    if not msgs:
        print("[!] No messages in ZAP history. Browse a site via ZAP first.")
        return

    det = StackDetector()
    printed = 0
    for m in msgs:
        hdr = m.get("responseHeader", "")
        if "text/html" not in hdr.lower():
            continue
        full = (hdr + "\r\n\r\n" + m.get("responseBody", "")).strip()
        html = full.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in full else full
        res = det.detect_from_html(html, url=m.get("requestHeader", ""))
        print("\n=== Stack Detection Result ===")
        print("Detection method:", res.get("detection_method"))
        print("Total detected:", res.get("total_detected"))
        std = res.get("standard_libraries", [])
        if std:
            print("Standard libraries:")
            for lib in std:
                print(f"  - {lib.get('name','?')} v{lib.get('version','?')} (conf: {lib.get('confidence',0):.2f})")
        custom = res.get("custom_libraries", [])
        if custom:
            print("Custom libraries:")
            for lib in custom:
                print(f"  - {lib.get('name','?')} v{lib.get('version','?')}")
        printed += 1
        if printed >= 3:
            break

    if printed == 0:
        print("[!] No HTML responses found in ZAP history.")


if __name__ == "__main__":
    main()


