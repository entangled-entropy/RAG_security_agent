"""
ZAP RAG Security Agent

A comprehensive security analysis tool that combines OWASP ZAP traffic collection
with Retrieval-Augmented Generation (RAG) for intelligent security vulnerability detection.

Key Features:
- Real-time ZAP traffic collection and analysis
- Web technology stack detection with vulnerability assessment
- Intelligent preprocessing and normalization of HTTP traffic
- RAG-powered security analysis using ChromaDB and AutoGen
- OWASP Top 10 baseline knowledge integration

Modules:
- core: Main RAG agent and orchestration
- collectors: ZAP traffic collection and processing
- detectors: Web technology and vulnerability detection
- preprocessing: Traffic normalization and security analysis
- data: Baseline security knowledge and data models
- utils: Helper functions and utilities
"""

__version__ = "0.1.0"
__author__ = "entropy"
__email__ = "arunmozhivarman97010@gmail.com"

from .core.agent import SecurityAnalysisAgent
from .collectors.zap_collector import ZAPCollector
from .detectors.stack_detector import StackDetector
from .preprocessing.normalizer import normalize_chunk_text, preprocess_payload

__all__ = [
    "SecurityAnalysisAgent",
    "ZAPCollector", 
    "StackDetector",
    "normalize_chunk_text",
    "preprocess_payload",
]
