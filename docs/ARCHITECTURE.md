# ZAP RAG Security Agent - Architecture Documentation

## 🏗️ System Architecture

The ZAP RAG Security Agent is built on a modular architecture that combines multiple security analysis techniques with modern AI capabilities. The system is designed to be scalable, maintainable, and extensible.

## 📋 Core Components

### 1. **Core Agent** (`src/zap_rag_security_agent/core/`)

The central orchestrator that coordinates all security analysis activities.

**Key Files:**
- `agent.py` - Main SecurityAnalysisAgent class

**Responsibilities:**
- Initialize and manage ChromaDB vector memory
- Coordinate with OpenAI GPT models
- Provide interactive security analysis interface
- Reconstruct HTTP messages from stored chunks
- Manage conversation flow and context

**Key Classes:**
```python
class SecurityAnalysisAgent:
    - initialize() -> None
    - query_memory(query: str) -> List[Dict]
    - reconstruct_http_message(group_id: str) -> str
    - analyze_traffic(query: str) -> None
    - interactive_console() -> None
```

### 2. **Collectors** (`src/zap_rag_security_agent/collectors/`)

Components responsible for gathering HTTP traffic from various sources.

**Key Files:**
- `zap_collector.py` - ZAP traffic collection with intelligent preprocessing

**Responsibilities:**
- Connect to OWASP ZAP API
- Collect HTTP requests and responses
- Chunk traffic into structured components (path, query, headers, body)
- Apply security-focused preprocessing
- Store processed data in ChromaDB

**Key Classes:**
```python
class ZAPCollector:
    - initialize() -> None
    - collect_historical() -> None
    - collect_realtime() -> None
    - _chunk_message(req_text: str, group_id: str) -> Generator
    - _process_message(message: Dict) -> None
```

### 3. **Detectors** (`src/zap_rag_security_agent/detectors/`)

Advanced detection components for web technologies and security analysis.

**Key Files:**
- `stack_detector.py` - Web technology stack detection with security analysis

**Responsibilities:**
- Detect web technologies using Wappalyzer
- Identify vulnerable library versions
- Detect credentials and sensitive data
- Analyze POST data for security issues
- Provide security risk assessment

**Key Classes:**
```python
class StackDetector:
    - detect_from_headers(headers_text: str) -> Dict
    - detect_from_html(html_content: str) -> Dict
    - detect_from_script_src(script_srcs: List[str]) -> Dict
    - check_version_vulnerability(lib_name: str, version: str) -> Dict
    - detect_credentials_in_content(content: str) -> Dict
    - analyze_post_data(post_data: str) -> Dict
```

### 4. **Preprocessing** (`src/zap_rag_security_agent/preprocessing/`)

Traffic normalization and security analysis utilities.

**Key Files:**
- `normalizer.py` - Advanced traffic normalization with security analysis

**Responsibilities:**
- Normalize HTTP traffic components
- Detect and redact sensitive information
- Identify suspicious patterns (SQLi, XSS, CMDi)
- Annotate suspicious tokens
- Integrate with stack detection

**Key Functions:**
```python
def normalize_chunk_text(chunk_text: str, chunk_type: str) -> Tuple[str, Dict]
def preprocess_payload(text: str, chunk_type: str) -> str
def compute_suspicion_score(text: str) -> Tuple[int, List[str]]
def annotate_suspicious_tokens(text: str) -> str
```

### 5. **Data** (`src/zap_rag_security_agent/data/`)

Baseline security knowledge and data models.

**Key Files:**
- `baseline.py` - OWASP Top 10 and security knowledge

**Responsibilities:**
- Provide baseline security knowledge
- Seed ChromaDB with security concepts
- Support RAG-based security analysis

## 🔄 Data Flow

```
1. HTTP Traffic Collection
   ZAP → ZAPCollector → Chunking → Preprocessing → ChromaDB

2. Security Analysis
   User Query → SecurityAnalysisAgent → ChromaDB Query → GPT Analysis → Response

3. Stack Detection
   HTTP Content → StackDetector → Technology Analysis → Security Assessment → Metadata
```

## 🗄️ Data Storage

### ChromaDB Vector Database

**Collections:**
- `security_memory` - Main collection for all security data

**Document Types:**
- `traffic` - HTTP traffic chunks with metadata
- `baseline` - OWASP Top 10 security knowledge

**Metadata Schema:**
```json
{
  "type": "traffic|baseline",
  "group_id": "req-123",
  "part": "path|query|headers|body",
  "id": "req-123-path",
  "suspicion_score": 5,
  "suspicious": true,
  "suspicious_tags": ["sql_injection", "xss"],
  "stack_detection": {
    "total_detected": 3,
    "confidence": 0.85,
    "detection_methods": ["headers", "html"]
  },
  "security_analysis": {
    "security_risk_score": 75,
    "has_vulnerabilities": true,
    "has_credentials": false
  }
}
```

## 🔧 Configuration

### Environment Variables
```bash
OPENAI_API_KEY=sk-...          # OpenAI API key
ZAP_API_URL=http://localhost:8090  # ZAP API endpoint
CHROMA_PERSIST_PATH=./chroma_data  # ChromaDB storage path
```

### Configuration Classes
```python
# ZAP Collector Configuration
ZAPCollector(
    zap_api_url="http://localhost:8090",
    persist_path="./chroma_data",
    collection_name="security_memory",
    batch_size=50,
    poll_interval=0.2
)

# Security Agent Configuration
SecurityAnalysisAgent(
    persist_path="./chroma_data",
    collection_name="security_memory",
    model="gpt-4o",
    k=5,
    score_threshold=0.3
)
```

## 🚀 Deployment Architecture

### Development Environment
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   OWASP     │    │   Python    │    │  ChromaDB   │
│     ZAP     │◄───┤   RAG Agent │───►│  (Local)    │
│  (Docker)   │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                           │
                           ▼
                   ┌─────────────┐
                   │   OpenAI    │
                   │     API     │
                   └─────────────┘
```

### Production Environment
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Load      │    │   RAG       │    │  ChromaDB   │
│  Balancer   │◄───┤   Agent     │───►│  Cluster    │
│             │    │  (Multiple) │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                           │
                           ▼
                   ┌─────────────┐
                   │   OpenAI    │
                   │     API     │
                   └─────────────┘
```

## 🔒 Security Considerations

### Data Protection
- Sensitive data redaction in preprocessing
- Secure credential handling
- Encrypted data transmission
- Access control and authentication

### Privacy
- No persistent storage of sensitive user data
- Configurable data retention policies
- Audit logging for compliance

### Performance
- Asynchronous processing for scalability
- Batch processing for efficiency
- Caching for frequently accessed data
- Resource monitoring and optimization

## 🧪 Testing Strategy

### Unit Tests
- Individual component testing
- Mock external dependencies
- Test edge cases and error conditions

### Integration Tests
- End-to-end workflow testing
- Real ZAP integration testing
- ChromaDB integration testing

### Security Tests
- Penetration testing of the agent itself
- Vulnerability scanning
- Security configuration validation

## 📈 Monitoring and Observability

### Metrics
- Traffic collection rate
- Analysis response time
- Error rates and types
- Resource utilization

### Logging
- Structured logging with correlation IDs
- Security event logging
- Performance monitoring
- Error tracking and alerting

### Health Checks
- Component health status
- External service connectivity
- Database health and performance
- API endpoint availability

## 🔮 Future Enhancements

### Planned Features
- Machine learning-based threat detection
- Advanced vulnerability correlation
- Custom security rule engine
- Integration with more security tools
- Real-time threat intelligence feeds

### Scalability Improvements
- Horizontal scaling support
- Microservices architecture
- Event-driven processing
- Distributed processing capabilities

### Security Enhancements
- Advanced threat modeling
- Behavioral analysis
- Anomaly detection
- Automated response capabilities
