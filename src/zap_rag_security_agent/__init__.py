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

# Import core components that don't require external dependencies
from .preprocessing.normalizer import normalize_chunk_text, preprocess_payload

# Import stack detector only if Wappalyzer is available
try:
    from .detectors.stack_detector import StackDetector
    _stack_detector_available = True
except ImportError:
    _stack_detector_available = False

# Import collector only if zapv2 is available
try:
    from .collectors.zap_collector import ZAPCollector
    _collector_available = True
except ImportError:
    _collector_available = False

# Import agent only if autogen is available
try:
    from .core.agent import SecurityAnalysisAgent
    _agent_available = True
except ImportError:
    _agent_available = False

__all__ = [
    "normalize_chunk_text",
    "preprocess_payload",
]

if _stack_detector_available:
    __all__.append("StackDetector")

if _collector_available:
    __all__.append("ZAPCollector")

if _agent_available:
    __all__.append("SecurityAnalysisAgent")
