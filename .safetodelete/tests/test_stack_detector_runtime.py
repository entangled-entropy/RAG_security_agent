"""
Tests for StackDetector using real class and small inputs (no external network).
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.detectors.stack_detector import StackDetector


def test_version_detection_helper():
    sd = StackDetector()
    results = {
        "jQuery": {"versions": ["3.6.0"], "categories": ["JavaScript"], "confidence": 0.9},
        "React": {"versions": ["18.2.0"], "categories": ["JavaScript"], "confidence": 0.9},
    }
    versions = sd.detect_versions_from_results(results)
    assert versions.get("jQuery") == "3.6.0"
    assert versions.get("React") == "18.2.0"


def test_vulnerable_script_detection_helper():
    sd = StackDetector()
    script = "document.body.innerHTML = userInput; eval('alert(1)')"
    matches = sd.detect_vulnerable_script_from_text(script)
    assert "innerHTML_dangerous" in matches or "xss_vulnerable" in matches
    assert "eval_usage" in matches or "unsafe_eval" in matches


