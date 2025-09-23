## Project Objective

We are building a **RAG-based (Retrieval-Augmented Generation) Security Analysis Agent** that integrates **OWASP ZAP** (for web traffic collection) with **AutoGen multi-agent framework** (for reasoning, retrieval, and collaboration).

The goal is to:
- Capture **live web traffic** (requests/responses) via ZAP.
- Store traffic in a **vector memory** (ChromaDB).
- Seed memory with **baseline security knowledge** (OWASP Top 10, common vulnerabilities).
- Use **RAG Security Agent(s)** to analyze traffic:
    - Detect exposed API keys, passwords, and tokens.
    - Identify outdated components or libraries (like Wappalyzer).
    - Flag insecure patterns (e.g., SQL injection markers, XSS payloads).
- Provide a **query interface** (via AutoGen agents) for a user to ask questions about the captured traffic.

## Architecture

```
            ┌──────────────────────────┐
            │        OWASP ZAP         │
            │        (Traffic)         │
            └────────────┬─────────────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ ZAPCollector  │
                 │  - chunking   │
                 │  - normalize  │
                 │  - metadata   │
                 │  - script     │
                 │    analysis   │
                 └───────┬───────┘
                         │  writes (documents + metadata)
                         ▼
                 ┌─────────────────┐
                 │    ChromaDB     │
                 │ (Vector Store)  │
                 └───────┬─────────┘
         seed baseline?  │  read/query
         (optional)      │
                         ▼
            ┌─────────────────────────┐
            │  SecurityAnalysisAgent  │
            │  - retrieve (k, score)  │
            │  - reconstruct request  │
            │  - show analysis blocks │
            │  - targeted JS prompts  │
            └────────────┬────────────┘
                         │ task
                         ▼
                  ┌──────────────┐
                  │  OpenAI GPT  │
                  │  (Analysis)  │
                  └──────────────┘

Notes:
- Baseline knowledge ingestion is opt-in (can be invoked before collection).
- Client-side script analyzer downloads external scripts in-memory only; results are stored as analysis entries in Chroma.
- Agent reconstructs request-only views by default and may append short response snippets for context.
```

## How it works:

1.  **Data collection and preprocessing (to store in DB)**

	- Source: OWASP ZAP messages (request/response) from Docker.
	
	- Normalization: Path canonicalization, query re‑assembly, header line splitting, and body sanitization to reduce noise.
	
	- Chunking: Each HTTP exchange is split into parts (`path`, `query`, `headers`, `body`) and saved as separate, addressable chunks tagged with a `group_id` so we can reconstruct later. This improves recall and lets us query specific layers.
	
	- Client‑side analysis: HTML responses are scanned; scripts are extracted and scored for obfuscation, suspicious density, and “customness”. Targeted JS regions are selected for deeper model analysis.
	
	- Metadata enrichment: We attach fields like `group_id`, `part`, suspicion metrics, stack detection, component candidates, and summarized security findings. All metadata is stored as primitives for efficient filtering.


2.  **Schematic search engine (how it’s built and why)**

	- Storage: ChromaDB persistent store with an embedding model (`all-MiniLM-L6-v2`) for semantic retrieval.
	
	- Structure-aware retrieval: We combine vector similarity with metadata filters (`part` = headers/query/body, `group_id`, component tags, suspicion flags) and targeted SQLite queries over Chroma’s FTS tables for precise reconstruction.
	
	- This Hybrid (semantic + structured) search yields high precision for questions like “show requests with outdated libraries” or “paths that include suspicious query parameters”.


3.  **RAG agent design (methods and rationale)**

	- Retriever: Top‑k semantic results (with a score threshold) from Chroma.
	
	- Reconstruction: For each `group_id`, we rebuild a clean, request‑only view and append analysis blocks (stack detection, component versions, vulnerability summaries). We include a small response snippet for context.
	
	- Keeping the request view concise reduces tokens and hallucinations; targeted response snippets provide just enough context without leaking full bodies.


4. **Data to LLM flow**

	- Query → retrieve top documents → deduplicate to unique `group_id`s.
	
	- Reconstruct request + analysis → append up to N chars of the response (snippet) when helpful.
	
	- Concatenate a small set (top few) into a task payload for the LLM, with clear separators and instructions.
