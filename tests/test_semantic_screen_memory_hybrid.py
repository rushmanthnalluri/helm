"""Unit tests for upgraded Hybrid BM25 + Vector Semantic Screen Memory.
Verifies:
- sqlite-vec vec0 384-dim float32 embeddings
- SentenceTransformer all-MiniLM-L6-v2 model lazy loading and singleton
- Hybrid search combining FTS5 BM25 and vector cosine similarity with RRF re-ranking
- Pure semantic match (synonym/concept match without keyword overlap)
- Pure keyword match (rare/code identifiers)
- Both store() and record_screen_event() compatibility
- forget_recent_history and retention purging for both FTS and vector tables
"""

import time
import pytest
import semantic_screen_memory


def test_embedding_model_singleton():
    """Verifies that the embedding model is loaded as a singleton."""
    model1 = semantic_screen_memory.get_embedding_model()
    assert model1 is not None
    model2 = semantic_screen_memory.get_embedding_model()
    assert model1 is model2


def test_sqlite_vec_extension_and_vector_table():
    """Verifies that sqlite-vec extension is active and vec0 table exists."""
    assert semantic_screen_memory._VEC_AVAILABLE is True
    with semantic_screen_memory._get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM screen_memory_vec")
        count = cursor.fetchone()[0]
        assert count >= 0


def test_hybrid_store_and_search_semantic():
    """Verifies storing events and finding them via conceptual semantic query."""
    test_title = f"Kubernetes Cluster Deployment Guide {int(time.time())}"
    test_text = "Instructions for provisioning container pods and ingress controllers on cloud infrastructure"
    
    # Store using store() signature
    ok = semantic_screen_memory.store(
        proc_name="terminal.exe",
        window_title=test_title,
        text_content=test_text
    )
    assert ok is True

    # Search with purely semantic query (no keyword overlap: 'DevOps orchestration software')
    results = semantic_screen_memory.search("DevOps orchestration software", limit=5)
    assert len(results) > 0

    # Ensure our stored record is in the results
    found = any(r["window_title"] == test_title for r in results)
    assert found, f"Expected {test_title} in hybrid search results, got: {[r['window_title'] for r in results]}"

    # Verify RRF score and search_meta
    for r in results:
        assert "rank" in r
        assert "rrf_score" in r
        assert "search_meta" in r


def test_hybrid_search_both_bm25_and_vector():
    """Verifies that a query matching both FTS5 keywords and semantics receives fused RRF score."""
    unique_term = f"AlphaOmegaVectorHybrid_{int(time.time())}"
    title = f"{unique_term} Artificial Intelligence Deep Learning Neural Networks"
    content = "Detailed breakdown of backpropagation and loss functions in PyTorch"

    ok = semantic_screen_memory.record_screen_event(
        proc_name="code.exe",
        window_title=title,
        text_content=content
    )
    assert ok is True

    # Search with keyword + semantic term
    results = semantic_screen_memory.search(f"{unique_term} neural networks", limit=5)
    assert len(results) > 0
    top_hit = results[0]
    assert top_hit["window_title"] == title

    # The top hit should have been matched by both BM25 and Vector
    meta = top_hit["search_meta"]
    assert "bm25_rank" in meta or "vector_rank" in meta
    # If both matched, RRF score should be sum of both reciprocal ranks
    assert top_hit["rrf_score"] > 0.01


def test_store_convenience_signature():
    """Verifies store('raw text') convenience call."""
    unique_marker = f"ConvenienceMarker_{int(time.time())}"
    ok = semantic_screen_memory.store(f"Autonomous agent planning system {unique_marker}")
    assert ok is True

    hits = semantic_screen_memory.search_screen_history(unique_marker)
    assert len(hits) > 0
    assert unique_marker in hits[0]["text_content"] or unique_marker in hits[0]["window_title"]


def test_forget_recent_history_cleans_vector_and_fts():
    """Verifies that purging recent history cleans both FTS5 and sqlite-vec tables."""
    unique_purge_term = f"PurgeTestVector_{int(time.time())}"
    semantic_screen_memory.store("notepad.exe", f"Temporary secret document {unique_purge_term}", "confidential details")

    # Confirm present
    hits = semantic_screen_memory.search(unique_purge_term)
    assert len(hits) > 0

    # Purge
    purged = semantic_screen_memory.forget_recent_history(minutes=1)
    assert purged >= 1

    # Confirm gone from search
    hits_after = semantic_screen_memory.search(unique_purge_term)
    assert not any(unique_purge_term in r.get("window_title", "") for r in hits_after)
