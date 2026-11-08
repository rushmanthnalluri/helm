"""Unit & Integration Tests for Batch 12:
- Production-Hardened Trust Layer & Encrypted Ephemeral Memory
- Scoped Revocable Token Manager
- HMAC Audit Ledger & Remote Anchor Verification
- Encrypted Screen Memory & Ephemeral Retention Pruning
- Hands-Free Local Wake-Word Engine
"""

import os
import sys
import time
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import crypto_vault
import client_token_auth
import agent_audit_ledger
import semantic_screen_memory
import homie_mcp
import wake_word_engine

class TestBatch12TrustLayer(unittest.TestCase):

    def test_crypto_vault_roundtrip_and_tamper(self):
        """Tests authenticated encryption, decryption, and tamper detection."""
        plaintext = "Confidential API Secret: sk-998877665544"
        token = crypto_vault.encrypt(plaintext)
        self.assertTrue(token.startswith("vault:"))

        # Different encryptions have unique IVs
        token2 = crypto_vault.encrypt(plaintext)
        self.assertNotEqual(token, token2)

        # Successful decryption
        decrypted = crypto_vault.decrypt(token)
        self.assertEqual(decrypted, plaintext)

        # Tampering with ciphertext raises ValueError
        corrupted = token[:-3] + "xyz"
        with self.assertRaises(ValueError):
            crypto_vault.decrypt(corrupted)

    def test_client_token_least_privilege_and_revocation(self):
        """Verifies default READ_ONLY scope, denial on higher tiers, and instant revocation."""
        secret, meta = client_token_auth.create_client_token("test_subagent_worker")
        token_id = meta["token_id"]

        # Default scope must be READ_ONLY
        self.assertEqual(meta["scopes"], ["READ_ONLY"])

        # Validate READ_ONLY tool allowed
        ok, msg, _ = client_token_auth.validate_client_token(secret, "READ_ONLY")
        self.assertTrue(ok, msg)

        # Validate WRITE_EXEC tool denied
        ok, msg, _ = client_token_auth.validate_client_token(secret, "WRITE_EXEC")
        self.assertFalse(ok)
        self.assertIn("lacks required capability scope", msg)

        # Revocation
        revoked, rev_msg = client_token_auth.revoke_client_token(token_id)
        self.assertTrue(revoked)
        ok_after_rev, _, _ = client_token_auth.validate_client_token(secret, "READ_ONLY")
        self.assertFalse(ok_after_rev)

    def test_mcp_scoped_token_enforcement(self):
        """Verifies MCP server enforces client token capability scopes."""
        secret, meta = client_token_auth.create_client_token("claude_read_worker", scopes=["READ_ONLY"])

        # READ_ONLY tool homie_get_vitals should succeed with this token
        res = homie_mcp.execute_mcp_tool("homie_get_vitals", {}, caller_id="token_agent", client_token=secret)
        self.assertNotIn("Security Gate: Access denied", res)

        # WRITE_EXEC tool homie_set_clipboard should be rejected
        res_write = homie_mcp.execute_mcp_tool("homie_set_clipboard", {"text": "hello"}, caller_id="token_agent", client_token=secret)
        self.assertIn("Security Gate: Access denied", res_write)

    def test_hmac_ledger_and_remote_anchor_verification(self):
        """Verifies HMAC ledger chain integrity and remote anchor matching."""
        hmac_key = agent_audit_ledger.get_ledger_secret_key()
        hash1 = agent_audit_ledger.record_agent_action("caller_hmac", "homie_get_vitals", "READ_ONLY", {}, decision="ALLOW", secret_key=hmac_key)
        self.assertTrue(bool(hash1))

        # Anchor current head
        anchor, _ = agent_audit_ledger.anchor_head_hash_to_remote()
        self.assertIsNotNone(anchor)

        # Match against remote anchor
        ok, msg = agent_audit_ledger.verify_against_remote_anchor(anchor, secret_key=hmac_key)
        self.assertTrue(ok, msg)

        # Rollback detection (fake higher remote count)
        tampered_anchor = {"head_hash": anchor["head_hash"], "count": anchor["count"] + 10}
        ok_rollback, err = agent_audit_ledger.verify_against_remote_anchor(tampered_anchor, secret_key=hmac_key)
        self.assertFalse(ok_rollback)
        self.assertIn("Rollback detected", err)

    def test_screen_memory_encrypted_and_privacy_forget(self):
        """Verifies encrypted storage, keyword search, app exclusion, and instant forget."""
        test_proc = "vscode.exe"
        test_title = "Homie Architecture Design"
        test_text = "Project secret key: batch12_alpha_omega_99"

        # Record encrypted event
        recorded = semantic_screen_memory.record_screen_event(test_proc, test_title, text_content=test_text, encrypt_at_rest=True)
        self.assertTrue(recorded)

        # Search should decrypt and find keyword
        hits = semantic_screen_memory.search_screen_history("batch12_alpha_omega_99")
        self.assertGreaterEqual(len(hits), 1)
        self.assertIn("batch12_alpha_omega_99", hits[0]["text_content"])

        # Excluded app should be skipped
        skipped = semantic_screen_memory.record_screen_event("1password.exe", "Master Passwords Vault", text_content="vault data")
        self.assertFalse(skipped)

        # Privacy forget (last 15 minutes)
        purged = semantic_screen_memory.forget_recent_history(minutes=15)
        self.assertGreaterEqual(purged, 1)

        # Verify searched item is gone
        hits_after = semantic_screen_memory.search_screen_history("batch12_alpha_omega_99")
        self.assertEqual(len(hits_after), 0)

    def test_wake_word_detector_simulation(self):
        """Verifies hands-free wake word detection, RMS calculation, and debounce."""
        wake_events = []
        detector = wake_word_engine.WakeWordDetector(wake_word="homie", on_wake_callback=lambda ts: wake_events.append(ts))

        # Energy RMS calculation
        pcm = b"\x10\x00" * 100
        energy = detector.compute_energy(pcm)
        self.assertGreater(energy, 0)

        # Trigger wake word
        matched = detector.simulate_wake_word("hey homie what is my battery status")
        self.assertTrue(matched)
        self.assertEqual(len(wake_events), 1)

        # Immediate repeat should debounce (return False)
        immediate_repeat = detector.simulate_wake_word("hey homie repeat")
        self.assertFalse(immediate_repeat)

if __name__ == "__main__":
    unittest.main()
