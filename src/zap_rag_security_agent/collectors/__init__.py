"""
ZAP RAG Security Agent - Collectors Module

This module contains traffic collection components for the RAG security agent.
Collectors gather HTTP traffic from various sources and prepare it for analysis.

Components:
- ZAPCollector: Collects traffic from OWASP ZAP with intelligent preprocessing
"""

from .zap_collector import ZAPCollector

__all__ = [
    "ZAPCollector",
]