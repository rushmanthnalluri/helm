"""tests/test_ambient_screen_vision.py - Automated tests for Continuous Ambient Screen Intelligence.

Verifies:
1. Perceptual hashing (64-bit dHash) and hamming distance calculations.
2. Perceptual deduplication of visually identical or near-identical screen frames.
3. Privacy preservation and redaction for sensitive windows (passwords, banking, incognito).
4. Natural language and keyword queries against visual screen history via query_visual_history().
"""

import time
import unittest
from unittest.mock import patch
from PIL import Image
import semantic_screen_memory


class TestAmbientScreenVision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._vec_patcher = patch("semantic_screen_memory._encode_text_to_vec", return_value=b"\x00" * (384 * 4))
        cls._vec_patcher.start()
        semantic_screen_memory.init_screen_memory_db()

    @classmethod
    def tearDownClass(cls):
        cls._vec_patcher.stop()

    def test_compute_perceptual_hash_and_hamming_distance(self):
        # Flat white image -> all 0s in difference comparison
        img_white = Image.new("L", (100, 100), color=255)
        hash_white = semantic_screen_memory.compute_perceptual_hash(img_white)
        self.assertEqual(len(hash_white), 16)
        self.assertEqual(semantic_screen_memory.hamming_distance(hash_white, hash_white), 0)

        # Inverted gradient (left brighter than right) -> all 1s in difference comparison -> 'ffffffffffffffff'
        img_grad = Image.new("L", (100, 100))
        for x in range(100):
            for y in range(100):
                img_grad.putpixel((x, y), int((99 - x) * 2.55))

        hash_grad = semantic_screen_memory.compute_perceptual_hash(img_grad)
        self.assertEqual(len(hash_grad), 16)
        self.assertEqual(hash_grad, "ffffffffffffffff")

        dist = semantic_screen_memory.hamming_distance(hash_grad, hash_white)
        self.assertEqual(dist, 64)

    def test_perceptual_deduplication(self):
        """Identical or near-identical frames for the same process should update timestamp rather than add duplicates."""
        test_proc = f"editor_{int(time.time() * 1000)}.exe"
        title = "Sprint Planning Notes"
        img = Image.new("L", (100, 100), color=128)

        # Record first frame
        ok1 = semantic_screen_memory.record_screen_event(
            proc_name=test_proc,
            window_title=title,
            text_content="Sprint backlog item 1: finish tests",
            image_or_hash=img,
            dedup_threshold=4
        )
        self.assertTrue(ok1)

        # Count records for this process
        with semantic_screen_memory._get_db() as conn:
            cnt1 = conn.execute("SELECT count(*) FROM screen_timeline WHERE proc_name = ?", (test_proc,)).fetchone()[0]
        self.assertEqual(cnt1, 1)

        # Record second frame with identical image (hamming dist = 0)
        time.sleep(0.01)
        ok2 = semantic_screen_memory.record_screen_event(
            proc_name=test_proc,
            window_title=title,
            text_content="Sprint backlog item 1: finish tests",
            image_or_hash=img,
            dedup_threshold=4
        )
        self.assertTrue(ok2)

        # Count should still be 1 because deduplication prevented duplicate clutter
        with semantic_screen_memory._get_db() as conn:
            cnt2 = conn.execute("SELECT count(*) FROM screen_timeline WHERE proc_name = ?", (test_proc,)).fetchone()[0]
        self.assertEqual(cnt2, 1)

    def test_sensitive_content_redaction_and_safeguards(self):
        """Sensitive process/window content must be redacted to safeguard privacy while preserving hash metadata."""
        test_proc = f"bank_client_{int(time.time() * 1000)}.exe"
        sensitive_title = "My Bank Online Banking Login"
        sensitive_text = "Account Balance $124,500.23 Password: secretpassword123"

        ok = semantic_screen_memory.record_screen_event(
            proc_name=test_proc,
            window_title=sensitive_title,
            text_content=sensitive_text,
            drop_sensitive=False
        )
        self.assertTrue(ok)

        # Query visual history with sensitive filtered out
        history_clean = semantic_screen_memory.query_visual_history(include_sensitive=False)
        self.assertFalse(any(h["proc_name"] == test_proc for h in history_clean))

        # Query visual history with include_sensitive=True
        history_all = semantic_screen_memory.query_visual_history(include_sensitive=True)
        sensitive_entries = [h for h in history_all if h["proc_name"] == test_proc]
        self.assertGreater(len(sensitive_entries), 0)
        entry = sensitive_entries[0]
        self.assertTrue(entry["is_sensitive"])
        # Sensitive text must be redacted!
        self.assertEqual(entry["text_content"], "[REDACTED_SENSITIVE_CONTENT]")
        self.assertNotIn("secretpassword123", entry["text_content"])
        self.assertIsNotNone(entry["perceptual_hash"])

    def test_query_visual_history_natural_language(self):
        """Natural language queries against visual history return matching entries."""
        unique_marker = f"UniqueProjectFalcon_{int(time.time() * 1000)}"
        test_proc = "code.exe"
        title = f"Project Falcon Architecture - {unique_marker}"
        text = f"Decoupled HAL layer design and ambient screen perceptual indexing details for {unique_marker}"

        ok = semantic_screen_memory.record_screen_event(
            proc_name=test_proc,
            window_title=title,
            text_content=text,
            summary="Architecture blueprint"
        )
        self.assertTrue(ok)

        # Query by keyword / title
        results = semantic_screen_memory.query_visual_history(query=unique_marker)
        self.assertGreater(len(results), 0)
        found = any(r["window_title"] == title for r in results)
        self.assertTrue(found)
        top = [r for r in results if r["window_title"] == title][0]
        self.assertEqual(top["proc_name"], test_proc)
        self.assertIn("Architecture blueprint", top["summary"])


if __name__ == "__main__":
    unittest.main()
