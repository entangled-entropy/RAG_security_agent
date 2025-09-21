"""
List the most common keywords in stored ChromaDB memory.
"""

# working v2 improved
# import asyncio
# from autogen_ext.memory.chromadb import (
#     ChromaDBVectorMemory,
#     PersistentChromaDBVectorMemoryConfig,
#     SentenceTransformerEmbeddingFunctionConfig,
# )

# PERSIST_PATH = "./chroma_data"
# COLLECTION_NAME = "security_memory"

# async def main():
#     print("[INFO] Starting ChromaDB setup...")

#     # Configuration for ChromaDB
#     config = PersistentChromaDBVectorMemoryConfig(
#         collection_name=COLLECTION_NAME,
#         persistence_path=PERSIST_PATH,
#         embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
#             model_name="all-MiniLM-L6-v2"
#         ),
#         k=3,
#     )

#     print(f"[INFO] ChromaDB configuration created with collection: {COLLECTION_NAME} and path: {PERSIST_PATH}")
    
#     # Initialize the ChromaDB memory object
#     memory = ChromaDBVectorMemory(config=config)
#     print("[INFO] ChromaDB memory object initialized.")

#     query = "sql"  # You can modify this query string as needed
#     print(f"[INFO] Querying ChromaDB with the query: '{query}'")

#     try:
#         # Attempt to query for all documents
#         docs = await memory.query(query=query)
#         print("[INFO] Query executed successfully.")

#         # Check the actual structure of docs and adjust accordingly
#         if hasattr(docs, 'results'):  # If it has a 'results' attribute
#             docs = docs.results
#             print(f"[INFO] 'results' attribute found in query response. Using it.")
#         elif hasattr(docs, 'documents'):  # If it's called 'documents'
#             docs = docs.documents
#             print(f"[INFO] 'documents' attribute found in query response. Using it.")
#         else:
#             print("[ERROR] Unexpected structure of MemoryQueryResult!")
#             raise ValueError("Unexpected structure of MemoryQueryResult")

#         # Print the total number of documents retrieved
#         print(f"[INFO] Total number of documents retrieved: {len(docs)}")
        
#         # Print only the first 2 documents
#         print(f"[INFO] Displaying snippets of the first 2 documents:")
#         for i, doc in enumerate(docs[:2], start=1):  # Display only the first 2
#             print(f"\n[INFO] Document {i}:")
#             print(f"[INFO] Document content (up to 500 characters):\n{doc.content[:500]}")
    
#     except Exception as e:
#         print(f"[ERROR] Error retrieving documents: {e}")
#         return

#     await memory.close()
#     print("[INFO] ChromaDB memory object closed.")

# if __name__ == "__main__":
#     print("[INFO] Starting main execution...")
#     asyncio.run(main())
#     print("[INFO] Main execution finished.")

import asyncio
from collections import Counter
import re
from autogen_ext.memory.chromadb import (
    ChromaDBVectorMemory,
    PersistentChromaDBVectorMemoryConfig,
    SentenceTransformerEmbeddingFunctionConfig,
)

PERSIST_PATH = "./chroma_data"
COLLECTION_NAME = "security_memory"

# Simple function to clean and tokenize text (for keyword extraction)
def tokenize(text):
    # Lowercase and remove non-alphabetic characters
    text = text.lower()
    words = re.findall(r'\b\w+\b', text)  # Tokenize based on word boundaries
    return words

async def main():
    # Configuration for ChromaDB
    config = PersistentChromaDBVectorMemoryConfig(
        collection_name=COLLECTION_NAME,
        persistence_path=PERSIST_PATH,
        embedding_function_config=SentenceTransformerEmbeddingFunctionConfig(
            model_name="all-MiniLM-L6-v2"
        ),
        k=3,
    )
    
    # Initialize the ChromaDB memory object
    memory = ChromaDBVectorMemory(config=config)
    print("[INFO] ChromaDB memory object initialized.")

    query = "arun"  # Wildcard to fetch all documents
    print(f"[INFO] Querying ChromaDB with the query: '{query}'")

    try:
        # Attempt to query for all documents
        docs = await memory.query(query=query)
        print("[INFO] Query executed successfully.")

        # Check the actual structure of docs and adjust accordingly
        if hasattr(docs, 'results'):  # If it has a 'results' attribute
            docs = docs.results
            print(f"[INFO] 'results' attribute found in query response. Using it.")
        elif hasattr(docs, 'documents'):  # If it's called 'documents'
            docs = docs.documents
            print(f"[INFO] 'documents' attribute found in query response. Using it.")
        else:
            raise ValueError("Unexpected structure of MemoryQueryResult")

        # Tokenize all documents and collect all words
        all_words = []
        for doc in docs:
            content = doc.content  # Assuming `content` holds the document text
            all_words.extend(tokenize(content))

        # Count word frequencies
        word_counts = Counter(all_words)

        # List the most common keywords (top 10 in this case)
        most_common = word_counts.most_common(10)
        # print("[INFO] Most common keywords in stored ChromaDB memory:")
        for word, count in most_common:
            print(f"[INFO] Keyword: {word}, Frequency: {count}")
    
    except Exception as e:
        print(f"[ERROR] Error retrieving documents: {e}")
        return

    await memory.close()
    print("[INFO] ChromaDB memory object closed.")

if __name__ == "__main__":
    print("[INFO] Starting main execution...")
    asyncio.run(main())
    print("[INFO] Main execution finished.")
