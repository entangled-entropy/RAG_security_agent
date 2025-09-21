#!/usr/bin/env python3
"""
Simple script to run the ZAP collector without import issues.
"""

import warnings
import sys
import os

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*found in sys.modules.*")

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import asyncio
from zap_rag_security_agent.collectors.zap_collector import main

if __name__ == "__main__":
    asyncio.run(main())
