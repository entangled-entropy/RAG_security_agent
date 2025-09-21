# ZAP RAG Security Agent

A comprehensive security analysis tool that combines OWASP ZAP traffic collection with Retrieval-Augmented Generation (RAG) for intelligent security vulnerability detection and analysis.

## 🎯 Overview

The ZAP RAG Security Agent is an advanced security analysis platform that leverages the power of Large Language Models (LLMs) combined with real-time HTTP traffic analysis to provide intelligent security insights. It integrates OWASP ZAP for traffic collection, ChromaDB for vector storage, and AutoGen for conversational AI analysis.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   OWASP ZAP     │───▶│  RAG Security   │───▶│   ChromaDB      │
│   (Traffic)     │    │     Agent       │    │  (Vector Store) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   OpenAI GPT    │
                       │  (Analysis)     │
                       └─────────────────┘
```

## 🚀 Key Features

### 🔍 **Intelligent Traffic Analysis**
- Real-time HTTP traffic collection from OWASP ZAP
- Advanced chunking and preprocessing of HTTP messages
- Security-focused normalization and redaction
- Suspicious pattern detection and annotation

### 🛡️ **Advanced Security Detection**
- Web technology stack detection using Wappalyzer
- Version vulnerability checking for known libraries
- Credential detection and redaction
- SQL injection, XSS, and command injection detection
- Security risk scoring and assessment

### 🧠 **RAG-Powered Analysis**
- ChromaDB vector storage for semantic search
- OWASP Top 10 baseline knowledge integration
- Context-aware security analysis
- Interactive conversational interface
- Intelligent vulnerability correlation

### 📊 **Comprehensive Reporting**
- Detailed security analysis reports
- Vulnerability prioritization
- Technology stack analysis
- Risk assessment and recommendations

## 📁 Project Structure

```
zap_rag_security_agent/
├── src/zap_rag_security_agent/          # Main package
│   ├── core/                            # Core RAG agent
│   │   └── agent.py                     # SecurityAnalysisAgent
│   ├── collectors/                      # Traffic collection
│   │   └── zap_collector.py             # ZAP traffic collector
│   ├── detectors/                       # Security detection
│   │   └── stack_detector.py            # Web technology detection
│   ├── preprocessing/                   # Traffic normalization
│   │   └── normalizer.py                # Security-focused preprocessing
│   ├── data/                           # Baseline knowledge
│   │   └── baseline.py                  # OWASP Top 10 knowledge
│   └── utils/                          # Helper utilities
├── tests/                              # Test suite
├── examples/                           # Usage examples
├── docs/                              # Documentation
└── scripts/                           # Utility scripts
```

## 🛠️ Installation

### Prerequisites

- Python 3.13+
- OWASP ZAP running in Docker
- OpenAI API key

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd RAG_security_agent
   ```

2. **Install dependencies:**
   ```bash
   poetry install
   ```

3. **Set up OWASP ZAP:**
   ```bash
   docker run -d -p 8080:8080 -p 8090:8090 \
     -v $(pwd):/zap/wrk/:rw \
     -t owasp/zap2docker-stable zap.sh -daemon \
     -host 0.0.0.0 -port 8080 -config api.disablekey=true
   ```

4. **Set environment variables:**
   ```bash
   export OPENAI_API_KEY="your-openai-api-key"
   ```

## 🚀 Quick Start

### 1. Start Traffic Collection

```python
from zap_rag_security_agent.collectors import ZAPCollector

# Initialize collector
collector = ZAPCollector()
await collector.initialize()

# Start collecting traffic
await collector.collect_all()
```

### 2. Run Security Analysis

```python
from zap_rag_security_agent.core import SecurityAnalysisAgent

# Initialize agent
agent = SecurityAnalysisAgent()
await agent.initialize()

# Start interactive analysis
await agent.interactive_console()
```

### 3. Command Line Usage

```bash
# Start traffic collection
poetry run python -m zap_rag_security_agent.collectors.zap_collector

# Start security analysis
poetry run python -m zap_rag_security_agent.core.agent
```

## 📖 Usage Examples

### Basic Security Analysis

```python
from zap_rag_security_agent.core import SecurityAnalysisAgent

agent = SecurityAnalysisAgent()
await agent.initialize()

# Analyze specific traffic
await agent.analyze_traffic("Find SQL injection vulnerabilities")
```

### Custom Stack Detection

```python
from zap_rag_security_agent.detectors import detect_stack_from_traffic

result = detect_stack_from_traffic(
    headers_text="X-Powered-By: PHP/8.1.2",
    html_content="<script src='jquery-1.12.0.min.js'></script>",
    script_srcs=["https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.0/jquery.min.js"]
)

print(f"Technologies detected: {result['total_detected']}")
print(f"Security risk score: {result['security_analysis']['security_risk_score']}")
```

### Traffic Preprocessing

```python
from zap_rag_security_agent.preprocessing import normalize_chunk_text

# Normalize and analyze HTTP headers
normalized, metadata = normalize_chunk_text(
    "Authorization: Bearer abc123\nX-API-Key: secret456", 
    "headers"
)

print(f"Suspicion score: {metadata['suspicion_score']}")
print(f"Stack detection: {metadata.get('stack_detection', {})}")
```

## 🔧 Configuration

### ZAP Collector Configuration

```python
collector = ZAPCollector(
    zap_api_url="http://localhost:8090",
    persist_path="./chroma_data",
    collection_name="security_memory",
    batch_size=50,
    poll_interval=0.2
)
```

### Security Agent Configuration

```python
agent = SecurityAnalysisAgent(
    persist_path="./chroma_data",
    collection_name="security_memory",
    model="gpt-4o",
    k=5,
    score_threshold=0.3
)
```

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
poetry run pytest

# Run specific test modules
poetry run pytest tests/test_stack_detection.py
poetry run pytest tests/test_security_features.py

# Run with coverage
poetry run pytest --cov=zap_rag_security_agent
```

## 📊 Security Features

### Vulnerability Detection

- **SQL Injection**: Detects SQL injection patterns in requests
- **XSS**: Identifies Cross-Site Scripting vulnerabilities
- **Command Injection**: Finds command injection attempts
- **CSRF**: Detects Cross-Site Request Forgery issues
- **XXE**: Identifies XML External Entity vulnerabilities

### Technology Analysis

- **Stack Detection**: Identifies web technologies and frameworks
- **Version Checking**: Checks for known vulnerable versions
- **Credential Detection**: Finds exposed API keys and secrets
- **Security Headers**: Analyzes security header implementation

### Risk Assessment

- **Security Risk Scoring**: Calculates overall security risk (0-100)
- **Vulnerability Prioritization**: Ranks vulnerabilities by severity
- **Technology Risk**: Assesses risk from technology stack
- **Credential Exposure**: Identifies sensitive data exposure

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP ZAP](https://www.zaproxy.org/) for traffic collection
- [Wappalyzer](https://www.wappalyzer.com/) for technology detection
- [ChromaDB](https://www.trychroma.com/) for vector storage
- [AutoGen](https://microsoft.github.io/autogen/) for conversational AI
- [OpenAI](https://openai.com/) for language model capabilities

## 📞 Support

For support, please open an issue in the GitHub repository or contact the development team.

## 🔮 Roadmap

- [ ] Enhanced vulnerability correlation
- [ ] Custom security rule engine
- [ ] Integration with more security tools
- [ ] Advanced reporting and dashboards
- [ ] Machine learning-based threat detection
- [ ] API for external integrations

---

**⚠️ Security Notice**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before testing any systems.
