"""Unit & Integration Tests for Batch 13:
Hardened Trust Layer Defense-in-Depth & Bound Token Verification:
- Test 1: Call with no token -> denied when enforcement active
- Test 2: A (False, False) decision -> not executed (denied with DENY_PRIVILEGE)
- Test 3: Taint, then a new caller_id -> still tainted (workstation-level taint tracking)
- Test 4: Approval for args A replayed with args B -> denied (argument hash binding)
- Test 5: Approval replayed twice -> denied (strict single-use enforcement)
- Test 6: Click on Telegram, Run dialog, or UAC -> denied (synthetic self-approval defense)
- Test 7: Type powershell / cmd + Enter -> denied (synthetic shell injection defense)
- Test 8: Swap a vault blob between two rows -> decryption fails (context / AAD binding)
"""

import os
import sys
import time
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import crypto_vault
import client_token_auth
import taint_tracker
import step_up_gate
import homie_mcp

class TestBatch13HardenedDefense(unittest.TestCase):

    def setUp(self):
        taint_tracker.clear_all_taints()
        client_token_auth.set_token_enforcement(False)

    def tearDown(self):
        taint_tracker.clear_all_taints()
        client_token_auth.set_token_enforcement(False)

    def test_call_with_no_token_denied_when_enforcement_active(self):
        """Verifies call with no token is denied when token enforcement is active."""
        client_token_auth.set_token_enforcement(True)
        res = homie_mcp.execute_mcp_tool("homie_get_vitals", {}, caller_id="unauth_agent", client_token=None)
        self.assertIn("Security Gate: Missing client authentication token", res)

    def test_false_false_decision_not_executed(self):
        """Verifies a (False, False) decision from taint tracker is not executed by MCP dispatcher."""
        # Mock taint tracker to return (False, False, "Explicit policy denial")
        orig_check = taint_tracker.check_action_privilege
        try:
            taint_tracker.check_action_privilege = lambda *a, **kw: (False, False, "Explicit policy denial")
            res = homie_mcp.execute_mcp_tool("homie_snap_window", {"app_name": "notepad", "position": "left"}, caller_id="test_agent")
            self.assertIn("Security Gate: Explicit policy denial", res)
        finally:
            taint_tracker.check_action_privilege = orig_check

    def test_taint_then_new_caller_id_still_tainted(self):
        """Verifies that spoofing a new caller_id does not evade workstation taint."""
        taint_tracker.mark_session_tainted("session_alpha", source="attacker_screen_read")
        self.assertTrue(taint_tracker.is_session_tainted("session_alpha"))

        # Fresh caller_id should still be tainted under workstation-level taint
        self.assertTrue(taint_tracker.is_session_tainted("agent_fresh_new_id"))

        # Calling WRITE_EXEC tool with fresh caller_id should be intercepted
        res = homie_mcp.execute_mcp_tool("homie_snap_window", {"app_name": "notepad", "position": "left"}, caller_id="agent_fresh_new_id")
        self.assertIn("Security Gate:", res)
        self.assertIn("STEP_UP_REQUIRED", res)

    def test_step_up_token_replay_with_args_mismatch_denied(self):
        """Verifies step-up token binds strictly to argument hash and denies argument tampering."""
        taint_tracker.mark_session_tainted("session_tamper")
        # Trigger step-up for benign args
        benign_args = {"text": "allowed text content"}
        allowed, step_up, reason = taint_tracker.check_action_privilege("session_tamper", "WRITE_EXEC", "homie_set_clipboard", benign_args)
        self.assertFalse(allowed)
        self.assertTrue(step_up)

        # Extract step up id
        import re
        m = re.search(r'\[ID:\s*([a-f0-9]+)\]', reason)
        self.assertIsNotNone(m)
        s_id = m.group(1)

        # Attempt to approve with mismatched args hash
        fake_args_hash = "0000000000000000"
        ok_app, _, msg = taint_tracker.approve_step_up(s_id, expected_args_hash=fake_args_hash)
        self.assertFalse(ok_app)
        self.assertIn("Argument mismatch", msg)

    def test_step_up_token_single_use_replayed_twice_denied(self):
        """Verifies step-up token is strictly single-use and cannot be replayed."""
        taint_tracker.mark_session_tainted("session_replay")
        allowed, step_up, reason = taint_tracker.check_action_privilege("session_replay", "WRITE_EXEC", "homie_set_clipboard", {"text": "once"})
        self.assertTrue(step_up)

        import re
        s_id = re.search(r'\[ID:\s*([a-f0-9]+)\]', reason).group(1)

        # First approval should succeed
        ok1, item1, msg1 = taint_tracker.approve_step_up(s_id)
        self.assertTrue(ok1, msg1)

        # Second approval with same ID must fail
        ok2, item2, msg2 = taint_tracker.approve_step_up(s_id)
        self.assertFalse(ok2)
        self.assertIn("Invalid or expired", msg2)

    def test_click_on_telegram_uac_or_run_denied(self):
        """Verifies synthetic clicks on security dialogs and approval UIs are blocked."""
        # Click targeting Telegram approval button
        res_tg = homie_mcp.execute_mcp_tool("homie_agent_click", {"x": 500, "y": 600, "element_name": "Telegram ApproveButton"})
        self.assertIn("Security Gate:", res_tg)
        self.assertIn("prohibited", res_tg.lower())

        # Click targeting User Account Control
        res_uac = homie_mcp.execute_mcp_tool("homie_agent_click", {"x": 400, "y": 500, "element_name": "User Account Control Yes"})
        self.assertIn("Security Gate:", res_uac)

    def test_type_powershell_or_cmd_denied(self):
        """Verifies synthetic typing of prohibited shell invocations is blocked."""
        res_ps = homie_mcp.execute_mcp_tool("homie_agent_type", {"text": "powershell -enc AAAA", "element_name": "TerminalInput"})
        self.assertIn("Security Gate:", res_ps)
        self.assertIn("prohibited", res_ps.lower())

        res_cmd = homie_mcp.execute_mcp_tool("homie_agent_type", {"text": "cmd.exe /c calc", "element_name": "RunBox"})
        self.assertIn("Security Gate:", res_cmd)

    def test_swap_vault_blob_between_two_rows_fails_decryption(self):
        """Verifies swapping a vault blob between different database rows fails decryption."""
        row1_secret = "Row 1 Confidential User Password"
        blob1 = crypto_vault.encrypt(row1_secret, context="table:screen_timeline:row:101")

        # Legitimate decryption with matching context succeeds
        self.assertEqual(crypto_vault.decrypt(blob1, context="table:screen_timeline:row:101"), row1_secret)

        # Attacker swaps blob1 into row 202 -> decryption MUST fail with ValueError
        with self.assertRaises(ValueError):
            crypto_vault.decrypt(blob1, context="table:screen_timeline:row:202")

if __name__ == "__main__":
    unittest.main()
