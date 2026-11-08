"""Unit and security tests for Batch 10 features:
- Dynamic random nonce prompt-injection boundaries (homie_mcp.py)
- Window title untrusted tagging (homie_mcp.py)
- Strict application allowlist & elevated terminal protection (homie_mcp.py)
- Remote ledger head anchoring to prevent silent tail rewriting (agent_audit_ledger.py)
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_mcp
import agent_audit_ledger

class TestBatch10Features(unittest.TestCase):
    def test_nonce_wrapped_untrusted_content(self):
        """Verifies dynamic random nonce generation in untrusted content tags."""
        text = "Confidential text or prompt injection"
        out1 = homie_mcp.wrap_untrusted_content_with_nonce(text, source="Screen")
        out2 = homie_mcp.wrap_untrusted_content_with_nonce(text, source="Screen")

        self.assertIn("[UNTRUSTED_DATA_NONCE_", out1)
        self.assertIn("[/UNTRUSTED_DATA_NONCE_", out1)
        # Nonces should be uniquely generated per invocation
        self.assertNotEqual(out1, out2)

    def test_window_titles_tagged_as_untrusted(self):
        """Verifies that homie_list_windows tags scraped window titles with nonces."""
        res = homie_mcp.execute_mcp_tool("homie_list_windows", {})
        if "Found" in res:
            self.assertIn("[UNTRUSTED_DATA_NONCE_", res)

    def test_elevated_terminal_blocking(self):
        """Verifies that terminals capable of executing arbitrary code are blocked."""
        # Standard safe app blocked check
        out_cmd = homie_mcp.execute_mcp_tool("homie_launch_app", {"app_name": "cmd"}, caller_id="agent")
        self.assertIn("Blocked", out_cmd)
        self.assertIn("confirmation", out_cmd.lower())

        out_powershell = homie_mcp.execute_mcp_tool("homie_launch_app", {"app_name": "powershell"}, caller_id="agent")
        self.assertIn("Blocked", out_powershell)
        self.assertIn("confirmation", out_powershell.lower())

        # Unapproved arbitrary executable
        out_random = homie_mcp.execute_mcp_tool("homie_launch_app", {"app_name": "malicious.exe"}, caller_id="agent")
        self.assertIn("Blocked", out_random)
        self.assertIn("allowlist", out_random.lower())

    def test_ledger_head_anchor(self):
        """Verifies ledger head anchoring generation."""
        agent_audit_ledger.record_agent_action("unit_test", "homie_get_vitals", "READ_ONLY", {})
        anchor, msg = agent_audit_ledger.anchor_head_hash_to_remote()
        self.assertIsNotNone(anchor)
        self.assertGreater(anchor["count"], 0)
        self.assertEqual(len(anchor["head_hash"]), 64)
        self.assertIn(anchor["head_hash_short"], msg)

if __name__ == '__main__':
    unittest.main()
