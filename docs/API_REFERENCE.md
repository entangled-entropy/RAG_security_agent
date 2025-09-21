# ZAP RAG Security Agent - API Reference

## 📚 Core API Reference

This document provides comprehensive API documentation for the ZAP RAG Security Agent components.

## 🔧 Core Agent API

### SecurityAnalysisAgent

Main orchestrator for security analysis operations.

```python
class SecurityAnalysisAgent:
    def __init__(
        self,
        persist_path: str = "./chroma_data",
        collection_name: str = "security_memory",
        model: str = "gpt-4o",
        k: int = 5,
        score_threshold: float = 0.3
    )
```

#### Methods

##### `async initialize() -> None`
Initialize the agent and its components.

**Returns:** None

**Raises:**
- `RuntimeError`: If initialization fails

**Example:**
```python
agent = SecurityAnalysisAgent()
await agent.initialize()
```

##### `async query_memory(query: str) -> List[Dict[str, Any]]`
Query the ChromaDB memory for relevant documents.

**Parameters:**
- `query` (str): Search query string

**Returns:**
- `List[Dict[str, Any]]`: List of relevant documents

**Raises:**
- `RuntimeError`: If agent not initialized

**Example:**
```python
docs = await agent.query_memory("SQL injection vulnerabilities")
```

##### `reconstruct_http_message(group_id: str, db_path: Optional[str] = None) -> str`
Reconstruct a complete HTTP message from stored parts.

**Parameters:**
- `group_id` (str): Group ID to reconstruct
- `db_path` (Optional[str]): Path to ChromaDB SQLite database

**Returns:**
- `str`: Reconstructed HTTP message

**Example:**
```python
message = agent.reconstruct_http_message("req-123")
```

##### `async analyze_traffic(query: str, reconstruct: bool = True) -> None`
Analyze HTTP traffic for security vulnerabilities.

**Parameters:**
- `query` (str): Security analysis query
- `reconstruct` (bool): Whether to reconstruct full HTTP messages

**Example:**
```python
await agent.analyze_traffic("Find XSS vulnerabilities")
```

##### `async interactive_console() -> None`
Start interactive security analysis console.

**Example:**
```python
await agent.interactive_console()
```

##### `async close() -> None`
Close the agent and clean up resources.

**Example:**
```python
await agent.close()
```

## 🚀 Collectors API

### ZAPCollector

Collects HTTP traffic from OWASP ZAP with intelligent preprocessing.

```python
class ZAPCollector:
    def __init__(
        self,
        zap_api_url: str = "http://localhost:8090",
        persist_path: str = "./chroma_data",
        collection_name: str = "security_memory",
        batch_size: int = 50,
        poll_interval: float = 0.2
    )
```

#### Methods

##### `async initialize() -> None`
Initialize the collector and its components.

**Raises:**
- `ConnectionError`: If ZAP connection fails

**Example:**
```python
collector = ZAPCollector()
await collector.initialize()
```

##### `async seed_baseline() -> None`
Seed the memory with baseline security knowledge.

**Example:**
```python
await collector.seed_baseline()
```

##### `async collect_historical() -> None`
Process all historical ZAP messages.

**Example:**
```python
await collector.collect_historical()
```

##### `async collect_realtime() -> None`
Start real-time collection of new ZAP messages.

**Example:**
```python
await collector.collect_realtime()
```

##### `async collect_all() -> None`
Collect both historical and real-time messages.

**Example:**
```python
await collector.collect_all()
```

##### `async close() -> None`
Close the collector and clean up resources.

**Example:**
```python
await collector.close()
```

## 🔍 Detectors API

### StackDetector

Advanced stack detection with security analysis capabilities.

```python
class StackDetector:
    def __init__(self)
```

#### Methods

##### `detect_from_headers(headers_text: str, url: str = "") -> Dict[str, Any]`
Detect technologies from HTTP headers.

**Parameters:**
- `headers_text` (str): Raw headers text
- `url` (str): Optional URL for context

**Returns:**
- `Dict[str, Any]`: Detection results with metadata

**Example:**
```python
detector = StackDetector()
result = detector.detect_from_headers("X-Powered-By: PHP/8.1.2")
```

##### `detect_from_html(html_content: str, url: str = "") -> Dict[str, Any]`
Detect technologies from HTML content.

**Parameters:**
- `html_content` (str): Raw HTML content
- `url` (str): Optional URL for context

**Returns:**
- `Dict[str, Any]`: Detection results with metadata

**Example:**
```python
result = detector.detect_from_html("<script src='jquery.min.js'></script>")
```

##### `detect_from_script_src(script_srcs: List[str]) -> Dict[str, Any]`
Detect technologies from script src URLs.

**Parameters:**
- `script_srcs` (List[str]): List of script src URLs

**Returns:**
- `Dict[str, Any]`: Detection results with metadata

**Example:**
```python
result = detector.detect_from_script_src([
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"
])
```

##### `check_version_vulnerability(lib_name: str, version: str) -> Dict[str, Any]`
Check if a library version is vulnerable.

**Parameters:**
- `lib_name` (str): Library name
- `version` (str): Version to check

**Returns:**
- `Dict[str, Any]`: Vulnerability check results

**Example:**
```python
result = detector.check_version_vulnerability("jquery", "1.12.0")
```

##### `detect_credentials_in_content(content: str) -> Dict[str, Any]`
Detect credentials and security issues in content.

**Parameters:**
- `content` (str): Content to analyze

**Returns:**
- `Dict[str, Any]`: Credential detection results

**Example:**
```python
result = detector.detect_credentials_in_content("api_key: sk-1234567890")
```

##### `analyze_post_data(post_data: str) -> Dict[str, Any]`
Analyze POST data for security issues.

**Parameters:**
- `post_data` (str): POST data to analyze

**Returns:**
- `Dict[str, Any]`: POST data analysis results

**Example:**
```python
result = detector.analyze_post_data('{"username": "admin", "password": "secret"}')
```

### detect_stack_from_traffic

Comprehensive stack detection from various traffic components.

```python
def detect_stack_from_traffic(
    headers_text: str = "",
    html_content: str = "",
    script_srcs: List[str] = None,
    meta_content: str = "",
    post_data: str = "",
    url: str = ""
) -> Dict[str, Any]
```

**Parameters:**
- `headers_text` (str): HTTP headers
- `html_content` (str): HTML content
- `script_srcs` (List[str]): List of script src URLs
- `meta_content` (str): Meta tags content
- `post_data` (str): POST data content
- `url` (str): Base URL for context

**Returns:**
- `Dict[str, Any]`: Combined detection results with security analysis

**Example:**
```python
result = detect_stack_from_traffic(
    headers_text="X-Powered-By: PHP/8.1.2",
    html_content="<script src='jquery.min.js'></script>",
    script_srcs=["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"]
)
```

## 🔧 Preprocessing API

### normalize_chunk_text

Higher-level normalizer with security analysis.

```python
def normalize_chunk_text(chunk_text: str, chunk_type: str = None) -> Tuple[str, Dict]
```

**Parameters:**
- `chunk_text` (str): Text to normalize
- `chunk_type` (str): Type of chunk ("path", "query", "headers", "body")

**Returns:**
- `Tuple[str, Dict]`: Normalized text and metadata

**Example:**
```python
normalized, meta = normalize_chunk_text("admin' OR '1'='1", "query")
```

### preprocess_payload

Normalize a payload based on chunk type.

```python
def preprocess_payload(text: str, chunk_type: str = None) -> str
```

**Parameters:**
- `text` (str): Text to preprocess
- `chunk_type` (str): Type of chunk

**Returns:**
- `str`: Preprocessed text

**Example:**
```python
normalized = preprocess_payload("password=secret123", "body")
```

### compute_suspicion_score

Compute suspicion score for text.

```python
def compute_suspicion_score(text: str) -> Tuple[int, List[str]]
```

**Parameters:**
- `text` (str): Text to analyze

**Returns:**
- `Tuple[int, List[str]]`: Suspicion score and matched tags

**Example:**
```python
score, tags = compute_suspicion_score("'; DROP TABLE users; --")
```

### annotate_suspicious_tokens

Annotate suspicious tokens in text.

```python
def annotate_suspicious_tokens(text: str) -> str
```

**Parameters:**
- `text` (str): Text to annotate

**Returns:**
- `str`: Annotated text

**Example:**
```python
annotated = annotate_suspicious_tokens("admin' OR '1'='1")
```

## 📊 Data Models

### Detection Result Schema

```python
{
    "detected_technologies": Dict[str, Any],
    "standard_libraries": List[Dict[str, Any]],
    "custom_libraries": List[Dict[str, Any]],
    "top_component": Optional[Dict[str, Any]],
    "detection_methods": List[str],
    "confidence": float,
    "total_detected": int,
    "component_candidates": List[Dict[str, Any]],
    "security_analysis": {
        "total_security_issues": int,
        "high_severity_issues": int,
        "medium_severity_issues": int,
        "security_risk_score": float,
        "has_vulnerabilities": bool,
        "credential_analysis": Dict[str, Any],
        "post_data_analysis": Dict[str, Any]
    }
}
```

### Metadata Schema

```python
{
    "type": "traffic|baseline",
    "group_id": str,
    "part": "path|query|headers|body",
    "id": str,
    "suspicion_score": int,
    "suspicious": bool,
    "suspicious_tags": List[str],
    "chunk_type": str,
    "stack_detection": Optional[Dict[str, Any]],
    "security_analysis": Optional[Dict[str, Any]]
}
```

## 🚨 Error Handling

### Common Exceptions

#### `ConnectionError`
Raised when unable to connect to external services (ZAP, ChromaDB).

#### `RuntimeError`
Raised when operations are attempted before proper initialization.

#### `ValueError`
Raised when invalid parameters are provided.

### Error Handling Example

```python
try:
    agent = SecurityAnalysisAgent()
    await agent.initialize()
    await agent.analyze_traffic("Find vulnerabilities")
except ConnectionError as e:
    print(f"Connection failed: {e}")
except RuntimeError as e:
    print(f"Initialization error: {e}")
finally:
    await agent.close()
```

## 📈 Performance Considerations

### Memory Usage
- ChromaDB vector storage is memory-efficient
- Batch processing reduces memory overhead
- Configurable batch sizes for different use cases

### Processing Speed
- Asynchronous operations for better performance
- Parallel processing of multiple requests
- Caching of frequently accessed data

### Scalability
- Horizontal scaling support
- Configurable resource limits
- Load balancing capabilities

## 🔒 Security Considerations

### Data Protection
- Sensitive data redaction
- Secure credential handling
- Encrypted data transmission

### Privacy
- No persistent storage of sensitive data
- Configurable data retention
- Audit logging

### Access Control
- API key authentication
- Role-based access control
- Secure configuration management
