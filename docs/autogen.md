## AutoGen usage cheatsheet

This project uses AutoGen components for agents, UI streaming, vector memory over ChromaDB, and model clients.

### Imported symbols and how they are used

- autogen_agentchat.agents
  - AssistantAgent: instantiated; `run_stream(task=...)` used for streaming chat.

- autogen_agentchat.ui
  - Console: awaited with a stream to render streamed tokens.

- autogen_ext.memory.chromadb
  - ChromaDBVectorMemory: instantiated; methods: `add`, `query`, `close`.
  - PersistentChromaDBVectorMemoryConfig: instantiated to configure persistence, k, score threshold.
  - SentenceTransformerEmbeddingFunctionConfig: instantiated to configure embedding model.

- autogen_ext.models.openai
  - OpenAIChatCompletionClient: instantiated; method: `close`.

- autogen_core.memory
  - MemoryContent: instantiated to wrap content for vector memory.
  - MemoryMimeType: enum; `MemoryMimeType.TEXT` used.

---

### AssistantAgent + Console (streaming)

```python
# Create an assistant agent and stream a response to the console
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
import asyncio

async def main():
    # Model client (OpenAI-compatible)
    model_client = OpenAIChatCompletionClient(model="gpt-4o")

    # Vector memory (ChromaDB)
    mem_cfg = PersistentChromaDBVectorMemoryConfig(
        collection_name="security_memory",
        persistence_path="./chroma_data",
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
        k=3,
        score_threshold=0.3,
    )
    memory = ChromaDBVectorMemory(config=mem_cfg)

    # Assistant with memory and system prompt
    agent = AssistantAgent(
        name="SecurityAnalysisAgent",
        model_client=model_client,
        memory=[memory],
        system_message="You are a helpful security analysis assistant.",
    )

    # Stream a task; Console renders streamed tokens
    stream = agent.run_stream(task="Summarize common XSS vectors briefly.")
    await Console(stream)

    # Close resources
    await model_client.close()
    await memory.close()

asyncio.run(main())
```

### ChromaDBVectorMemory: configure, add, query, close

```python
from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)
from autogen_core.memory import MemoryContent, MemoryMimeType
import asyncio

async def use_memory():
    # Persistent ChromaDB config
    cfg = PersistentChromaDBVectorMemoryConfig(
        collection_name="security_memory",
        persistence_path="./chroma_data",
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
        k=3,                  # top-k results on query
        score_threshold=0.3,  # min similarity score filter
    )
    memory = ChromaDBVectorMemory(config=cfg)

    # Add a text document with metadata
    await memory.add(MemoryContent(
        content="Reflected XSS occurs when user input is returned unescaped.",
        mime_type=MemoryMimeType.TEXT,
        metadata={"type": "baseline", "topic": "xss", "id": "baseline-1"},
    ))

    # Query relevant docs
    results = await memory.query("What is reflected XSS?")
    docs = getattr(results, "results", None) or getattr(results, "documents", None) or results
    print(docs)

    # Close when done
    await memory.close()

asyncio.run(use_memory())
```

### OpenAIChatCompletionClient: lifecycle

```python
from autogen_ext.models.openai import OpenAIChatCompletionClient
import asyncio

async def use_client():
    client = OpenAIChatCompletionClient(model="gpt-4o")
    # Typically used via AssistantAgent; close when done
    await client.close()

asyncio.run(use_client())
```

### MemoryContent and MemoryMimeType

```python
from autogen_core.memory import MemoryContent, MemoryMimeType

text_entry = MemoryContent(
    content="SQLi often abuses unparameterized queries like ' OR 1=1 --",
    mime_type=MemoryMimeType.TEXT,
    metadata={"type": "baseline", "topic": "sqli", "severity": "high"},
)
```

### Using retrieved context with AssistantAgent.run_stream

```python
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console

async def analyze_with_context(agent: AssistantAgent, memory, question: str):
    # Retrieve relevant context
    results = await memory.query(question)
    docs = getattr(results, "results", None) or getattr(results, "documents", None) or results
    context = "\n\n---\n\n".join(
        getattr(d, "content", None) or (d.get("content") if isinstance(d, dict) else "")
        for d in (docs or [])[:3]
    )

    task = f"Use the context to answer:\n\nQuestion: {question}\n\nContext:\n{context}"
    stream = agent.run_stream(task=task)
    await Console(stream)
```

---

Notes
- Tune recall/precision via `k` and `score_threshold` in `PersistentChromaDBVectorMemoryConfig`.
- Use `SentenceTransformerEmbeddingFunctionConfig` to pick embedding models.
- Always close model clients and memories (`await ...close()`).

