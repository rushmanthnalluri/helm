"""tests/test_batch38_security_hardening.py - Batch 38 Formal Security Hardening Acceptance Suite.

Directives Covered:
1. Signed Challenge V3 Cryptographic Caller Binding:
   - CHALLENGE_V3 strictly binds caller_id into canonical SHA-256 hash signed by mobile device.
   - verify_signed_approval_evidence rebuilds raw challenge string and recomputes hash from blob fields.
   - Tampered fields, mismatched hashes, or cross-caller approvals fail closed.
2. Anti-Burn DoS Defense in SQLite Approval Consumption:
   - consume_approved_action iterates candidate matching rows rather than burning on LIMIT 1.
   - Junk unauthenticated rows inserted by attackers are burned and skipped, allowing legitimate signed approvals to succeed.
3. Persistent Nonce Consumption at Supervisor Execution Time:
   - Blobs in user-writable SQLite cannot be replayed.
   - Supervisor records and verifies nonces against persistent nonce store upon consumption.
   - Duplicate row insertions with previously-consumed valid signatures fail closed.
4. Total Windows Key Chord Denial & Dangerous System Hotkey Blocks:
   - detect_blocked_system_chords blocks every chord containing a Windows key (Win+*, Win+1..9, Win+E, Win+S, Win+I, etc.).
   - Explicitly blocks Alt+Tab, Alt+Space, Alt+F4, Ctrl+Shift+Esc, Ctrl+Alt+Del, Ctrl+Esc, Ctrl+Shift+Enter.
5. Actuator Scoping Exemption for Non-Window Tools:
   - SupervisorActuator foreground TOCTOU checks scoped strictly to UI-interactive tools (click, type, mouse_move, hotkey).
   - Non-window tools (set_clipboard, snap_window, launch_app) skip foreground window checks.
6. Admin-Protected ProgramData Console Recovery Token:
   - Elevated recovery commands write tokens to C:\\ProgramData\\Homie\\console_recovery.token with owner/Admin-only DACL.
   - consume_console_recovery_token verifies and atomically consumes admin recovery tokens.
"""

import os
import sys
import time
import json
import hashlib
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor
import phone_approval_portal
import device_registry
import windows_tools
import policy_envelope
import taint_tracker
import db_utils
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    mint_test_action_approval,
    sign_test_challenge
)


class TestBatch38SecurityHardening(unittest.TestCase):

    def setUp(self):
        try:
            taint_tracker.human_clear_taint("EXPLICIT_HUMAN_CONFIRMATION")
        except Exception:
            pass
        phone_approval_portal.clear_active_challenges()
        device_registry.clear_consumed_nonces_for_testing()

    def test_1_challenge_v3_cryptographic_caller_binding(self):
        """Directive 1: CHALLENGE_V3 cryptographically binds caller_id into signed challenge hash."""
        priv_pem, pub_pem = enroll_test_device("primary_phone")
        authorized_caller = "worker_b38_alpha"
        unauthorized_caller = "worker_b38_bravo"
        tool_name = "homie_set_clipboard"
        args = {"text": "top_secret_data"}
        epoch = taint_tracker.get_taint_epoch()

        # Step 1: Generate approval challenge bound to authorized_caller
        challenge = phone_approval_portal.generate_approval_challenge(
            step_up_id="step_b38_bind",
            tool_name=tool_name,
            arguments=args,
            session_id="sess_b38",
            taint_epoch=epoch,
            device_id="primary_phone",
            ttl_seconds=60.0,
            caller_id=authorized_caller
        )
        self.assertEqual(challenge["version"], "CHALLENGE_V3")
        self.assertEqual(challenge["caller_id"], authorized_caller)

        # Step 2: Sign challenge hash
        sig = sign_test_challenge(priv_pem, challenge["challenge_hash"])
        counter = challenge.get("expected_counter", 1)

        ok, msg, _ = phone_approval_portal.verify_device_approval(
            "step_b38_bind", sig, device_id="primary_phone", counter=counter
        )
        self.assertTrue(ok, msg)

        # Step 3: Authorized caller consumes successfully
        sup = homie_supervisor.PolicySupervisor()
        args_hash = challenge["args_hash"].lower()

        # Unauthorized caller attempt MUST fail closed
        consumed_unauth = sup.consume_approved_action(unauthorized_caller, tool_name, args_hash, epoch)
        self.assertFalse(consumed_unauth, "Unauthorized caller was able to consume approval bound to another caller!")

        # Authorized caller attempt succeeds
        consumed_auth = sup.consume_approved_action(authorized_caller, tool_name, args_hash, epoch)
        self.assertTrue(consumed_auth, "Authorized caller failed to consume cryptographically bound approval")

    def test_2_tampered_challenge_fields_rejected_even_if_hash_signed(self):
        """Directive 1 & 2: Rebuilding signed challenge string catches tampered fields even if hash was signed."""
        priv_pem, pub_pem = enroll_test_device("primary_phone")
        caller_id = "worker_b38_tamper"
        tool_name = "homie_set_clipboard"
        args_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        epoch = taint_tracker.get_taint_epoch()
        nonce = "1234567890abcdef1234567890abcdef"
        expiry = int(time.time() + 60)
        seq = 1

        # Real challenge hash over tool_name="homie_set_clipboard"
        raw = f"CHALLENGE_V3|primary_phone|{caller_id}|{tool_name}|{args_hash}|{nonce}|{expiry}|{epoch}|{seq}"
        real_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        sig = sign_test_challenge(priv_pem, real_hash)

        # Attacker tampers with tool_name -> "homie_launch_app" in the blob while keeping original challenge_hash
        tampered_blob = {
            "version": "CHALLENGE_V3",
            "device_id": "primary_phone",
            "caller_id": caller_id,
            "tool_name": "homie_launch_app",
            "args_hash": args_hash,
            "nonce": nonce,
            "expiry": expiry,
            "taint_epoch": epoch,
            "challenge_seq": seq,
            "challenge_hash": real_hash,
            "signature": sig
        }

        # Supervisor must recompute hash from blob fields: mismatch between recomputed hash and blob hash fails closed
        valid = homie_supervisor.verify_signed_approval_evidence(
            tampered_blob, caller_id, "homie_launch_app", args_hash, epoch
        )
        self.assertFalse(valid, "Supervisor accepted tampered challenge blob!")

    def test_3_anti_burn_dos_junk_row_defense(self):
        """Directive 3: Malicious junk row at lower id does not burn approval for legitimate candidate rows."""
        priv_pem, pub_pem = enroll_test_device("primary_phone")
        caller_id = "worker_b38_burn"
        tool_name = "homie_set_clipboard"
        args = {"text": "genuine_action"}
        clean_args = json.dumps(args, sort_keys=True, separators=(',', ':'))
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
        epoch = taint_tracker.get_taint_epoch()

        # Step 1: Valid signed approval
        valid_blob = mint_test_action_approval(
            priv_pem, tool_name, args_hash, device_id="primary_phone", taint_epoch=epoch
        )
        valid_blob["caller_id"] = caller_id

        # Step 2: Insert junk forged row at id=1
        with db_utils.get_db() as conn:
            homie_supervisor._init_approved_actions_table(conn)
            # Row 1: Junk unauthenticated row
            conn.execute("""
                INSERT INTO approved_actions (caller_id, tool, args_hash, taint_epoch, expiry, consumed, signature_blob)
                VALUES (?, ?, ?, ?, ?, 0, 'JUNK_MALICIOUS_EVIDENCE')
            """, (caller_id, tool_name, args_hash.lower(), epoch, time.time() + 60.0))
            # Row 2: Genuine verified row
            conn.execute("""
                INSERT INTO approved_actions (caller_id, tool, args_hash, taint_epoch, expiry, consumed, signature_blob)
                VALUES (?, ?, ?, ?, ?, 0, ?)
            """, (caller_id, tool_name, args_hash.lower(), epoch, time.time() + 60.0, json.dumps(valid_blob)))
            conn.commit()

        # Supervisor must burn/skip row 1 and successfully consume row 2
        sup = homie_supervisor.PolicySupervisor()
        consumed = sup.consume_approved_action(caller_id, tool_name, args_hash, epoch)
        self.assertTrue(consumed, "Anti-Burn DoS failed: junk row 1 blocked legitimate approval consumption on row 2!")

    def test_4_sqlite_row_replay_rejected_by_persistent_nonce_store(self):
        """Directive 3: Re-inserting a valid signed blob into SQLite fails because nonce is already consumed."""
        priv_pem, pub_pem = enroll_test_device("primary_phone")
        caller_id = "worker_b38_replay"
        tool_name = "homie_set_clipboard"
        args = {"text": "replay_target"}
        clean_args = json.dumps(args, sort_keys=True, separators=(',', ':'))
        args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
        epoch = taint_tracker.get_taint_epoch()

        signed_blob = mint_test_action_approval(
            priv_pem, tool_name, args_hash, device_id="primary_phone", taint_epoch=epoch
        )
        signed_blob["caller_id"] = caller_id

        sup = homie_supervisor.PolicySupervisor()
        sup.record_approved_action(caller_id, tool_name, args_hash, epoch, ttl=60.0, signed_blob=signed_blob)

        # First consumption succeeds
        consumed1 = sup.consume_approved_action(caller_id, tool_name, args_hash, epoch)
        self.assertTrue(consumed1, "First valid consumption failed")

        # Attacker re-inserts the exact same valid signed blob into SQLite with consumed=0
        with db_utils.get_db() as conn:
            conn.execute("""
                INSERT INTO approved_actions (caller_id, tool, args_hash, taint_epoch, expiry, consumed, signature_blob)
                VALUES (?, ?, ?, ?, ?, 0, ?)
            """, (caller_id, tool_name, args_hash.lower(), epoch, time.time() + 60.0, json.dumps(signed_blob)))
            conn.commit()

        # Replay attempt MUST be rejected by persistent nonce store
        consumed2 = sup.consume_approved_action(caller_id, tool_name, args_hash, epoch)
        self.assertFalse(consumed2, "Replay attack succeeded on duplicated SQLite row!")

    def test_5_total_win_key_and_dangerous_chord_denial(self):
        """Directive 4: Total Win-key chord denial and dangerous system hotkey blocks."""
        # Win-key chords must all be detected and denied
        win_chords = [
            ({"hotkey": "win+e"}, "Win+E"),
            ({"hotkey": "win+s"}, "Win+S"),
            ({"hotkey": "win+1"}, "Win+1"),
            ({"hotkey": "win+i"}, "Win+I"),
            ({"hotkey": "win+r"}, "Win+R"),
            ({"hotkey": "win+x"}, "Win+X"),
        ]
        for arg, expected in win_chords:
            _, _, vks, tokens = windows_tools.canonicalize_keyboard_arguments(arg)
            chord = windows_tools.detect_blocked_system_chords(vks, tokens)
            self.assertEqual(chord, expected, f"Failed to detect blocked Win chord: {expected}")

        # Dangerous system chords
        sys_chords = [
            ({"hotkey": "alt+tab"}, "Alt+Tab"),
            ({"hotkey": "alt+space"}, "Alt+Space"),
            ({"hotkey": "alt+f4"}, "Alt+F4"),
            ({"hotkey": "ctrl+esc"}, "Ctrl+Esc"),
            ({"hotkey": "ctrl+shift+esc"}, "Ctrl+Shift+Esc"),
            ({"hotkey": "ctrl+shift+enter"}, "Ctrl+Shift+Enter"),
            ({"hotkey": "ctrl+alt+del"}, "Ctrl+Alt+Del"),
        ]
        for arg, expected in sys_chords:
            _, _, vks, tokens = windows_tools.canonicalize_keyboard_arguments(arg)
            chord = windows_tools.detect_blocked_system_chords(vks, tokens)
            self.assertEqual(chord, expected, f"Failed to detect dangerous system chord: {expected}")

    def test_6_actuator_scoping_exempts_non_window_tools(self):
        """Directive 5: Foreground TOCTOU check scoped strictly to UI tools; non-window tools are exempted."""
        sup = homie_supervisor.PolicySupervisor()
        actuator = homie_supervisor.SupervisorActuator(sup)

        # Configure policy envelope restricting to notepad.exe
        env = policy_envelope.PolicyEnvelope(
            envelope_id="env_test_scoping",
            allowed_process_images=["notepad.exe"],
            allowed_action_types=["homie_agent_type", "homie_set_clipboard"],
            step_budget=10,
            keystroke_cap=500,
            expiry=time.time() + 60.0,
            taint_epoch=0
        )
        env.is_active = True
        sup.envelope = env

        # Simulate foreground window being calc.exe (outside envelope)
        with patch("windows_tools.get_foreground_window", return_value={"proc_name": "calc.exe", "hwnd": 12345}):
            # UI interactive tool (homie_agent_type) must raise CompleteMediationBreachError due to TOCTOU mismatch
            with self.assertRaises(homie_supervisor.CompleteMediationBreachError) as cm:
                actuator.execute_actuator("homie_agent_type", {"text": "hello"}, caller_id="worker", seq=1)
            self.assertIn("TOCTOU detected", str(cm.exception))

            # Non-window tool (homie_set_clipboard) skips foreground window check
            with patch("homie_mcp.execute_mcp_tool", return_value="success"), \
                 patch.object(sup, "verify_and_consume_intent_token", return_value=True):
                res = actuator.execute_actuator("homie_set_clipboard", {"text": "safe"}, caller_id="worker", intent_token="dummy", seq=2)
                self.assertEqual(res, "success")

    def test_7_admin_recovery_token_programdata_path(self):
        """Directive 6: Elevated recovery commands write and consume tokens via C:\\ProgramData\\Homie."""
        import tempfile
        token = "admin_recovery_test_token_12345678"
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_token_path = os.path.join(tmpdir, "console_recovery.token")
            with patch("phone_approval_portal.ADMIN_RECOVERY_DIR", tmpdir), \
                 patch("phone_approval_portal.ADMIN_RECOVERY_TOKEN_PATH", fake_token_path):
                written = phone_approval_portal.write_admin_recovery_token(token, ttl_seconds=60.0)
                self.assertTrue(written, "Failed to write admin recovery token")
                self.assertTrue(os.path.exists(fake_token_path))

                # Verify consumption succeeds
                consumed = phone_approval_portal.consume_admin_recovery_token(token)
                self.assertTrue(consumed, "Failed to consume admin recovery token")
                self.assertFalse(os.path.exists(fake_token_path), "Token file was not atomically deleted")

                # Second consumption fails (single-use)
                consumed_again = phone_approval_portal.consume_admin_recovery_token(token)
                self.assertFalse(consumed_again, "Replay attack succeeded on consumed admin recovery token")


if __name__ == "__main__":
    unittest.main()
