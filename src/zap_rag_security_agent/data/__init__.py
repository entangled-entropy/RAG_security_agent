"""
ZAP RAG Security Agent - Data Module

This module contains baseline security knowledge and data models for the RAG agent.
Data components provide foundational security concepts and knowledge for analysis.

Components:
- Baseline security knowledge (OWASP Top 10, security patterns, etc.)
"""

from .baseline import BASELINE_DOCS

__all__ = [
    "BASELINE_DOCS",
]
