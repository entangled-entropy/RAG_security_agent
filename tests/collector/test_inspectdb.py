import os
import pytest
import sqlite3

PERSIST_PATH = os.environ.get("PERSIST_PATH", "/home/entropy/playground/detoxio/RAG_security_agent/chroma_data")


def test_inspectdb_after_processing_requests():
    db_path = os.path.join(PERSIST_PATH, "chroma.sqlite3")
    if not os.path.exists(db_path):
        pytest.skip("Chroma DB not found; run collector to populate first.")

    # Inspect core tables for presence of expected parts
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        assert any("embedding" in t for t in tables)

        # Check that we have some stored metadata entries for parts
        # embedding_metadata table is used in reconstruction
        cur.execute("SELECT COUNT(*) FROM embedding_metadata")
        count = cur.fetchone()[0]
        assert count > 0
    finally:
        conn.close()


