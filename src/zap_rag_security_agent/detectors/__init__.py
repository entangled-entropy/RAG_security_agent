"""
ZAP RAG Security Agent - Detectors Module

This module contains detection components for web technologies and security analysis.
Detectors analyze HTTP traffic to identify technologies, vulnerabilities, and security issues.

Components:
- StackDetector: Advanced web technology stack detection with security analysis
"""

from .stack_detector import StackDetector, detect_stack_from_traffic

__all__ = [
    "StackDetector",
    "detect_stack_from_traffic",
]