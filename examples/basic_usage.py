#!/usr/bin/env python3
"""
Basic Usage Example for ZAP RAG Security Agent

This example demonstrates the basic usage of the ZAP RAG Security Agent
for collecting traffic and performing security analysis.
"""

import asyncio
from src.zap_rag_security_agent.core.agent import SecurityAnalysisAgent
from src.zap_rag_security_agent.collectors.zap_collector import ZAPCollector


async def basic_collection_example():
    """Example of basic traffic collection."""
    print("=== Basic Traffic Collection Example ===\n")
    
    # Initialize collector
    collector = ZAPCollector(
        zap_api_url="http://localhost:8090",
        persist_path="./chroma_data",
        collection_name="security_memory"
    )
    
    try:
        # Initialize and start collection
        await collector.initialize()
        print("✓ Collector initialized successfully")
        
        # Seed baseline knowledge
        await collector.seed_baseline()
        print("✓ Baseline knowledge seeded")
        
        # Collect historical traffic
        await collector.collect_historical()
        print("✓ Historical traffic collected")
        
        print("\n[INFO] Collection complete. You can now run security analysis.")
        
    except Exception as e:
        print(f"❌ Collection failed: {e}")
    finally:
        await collector.close()


async def basic_analysis_example():
    """Example of basic security analysis."""
    print("\n=== Basic Security Analysis Example ===\n")
    
    # Initialize agent
    agent = SecurityAnalysisAgent(
        persist_path="./chroma_data",
        collection_name="security_memory",
        model="gpt-4o"
    )
    
    try:
        # Initialize agent
        await agent.initialize()
        print("✓ Security agent initialized successfully")
        
        # Example security queries
        queries = [
            "Find SQL injection vulnerabilities",
            "Identify XSS attack patterns",
            "Check for exposed credentials",
            "Analyze web technology stack",
            "Find authentication bypass attempts"
        ]
        
        for query in queries:
            print(f"\n🔍 Analyzing: {query}")
            try:
                await agent.analyze_traffic(query)
            except Exception as e:
                print(f"❌ Analysis failed: {e}")
        
        print("\n[INFO] Analysis complete.")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
    finally:
        await agent.close()


async def interactive_example():
    """Example of interactive security analysis."""
    print("\n=== Interactive Security Analysis Example ===\n")
    
    agent = SecurityAnalysisAgent()
    
    try:
        await agent.initialize()
        print("✓ Interactive mode ready")
        print("Type your security questions below (or 'quit' to exit):")
        
        # Start interactive console
        await agent.interactive_console()
        
    except Exception as e:
        print(f"❌ Interactive mode failed: {e}")
    finally:
        await agent.close()


async def main():
    """Main example function."""
    print("🚀 ZAP RAG Security Agent - Basic Usage Examples")
    print("=" * 60)
    
    # Run examples
    await basic_collection_example()
    await basic_analysis_example()
    
    # Uncomment to run interactive example
    # await interactive_example()


if __name__ == "__main__":
    asyncio.run(main())
