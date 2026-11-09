"""tests/test_batch43_security_hardening.py - Batch 43 Security Hardening & Isolation Suite.

Directives Verified:
1. Safety floor diff is strictly empty: Every non-READ_ONLY tool in homie_supervisor is in COMPILED_IN_CONSEQUENTIAL_TOOLS.
2. Window title check elimination: Chrome tabs titled "Homie ..." are not falsely blocked as self-targeting.
3. Device registry failure fail-closed: Corrupted/failing registry denies confirmation rather than falling back.
4. Browser UIA domain resolution fail-closed: If UIA domain lookup fails in browser window, envelope denies without trusting worker args.
5. Recovery token single-use via DB record: Unelevated consumers enforce single-use via authoritative database record.
6. Supervisor Named Pipe MSG_CONFIRM and MSG_TAINT_QUERY protocol validation.
7. Real OS subprocess termination: TerminateProcess on daemon OS PID causes all ingress channels to fail closed immediately.
"""

import os
import sys
import time
import json
import secrets
import hashlib
import subprocess
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import windows_tools
import homie_supervisor
import phone_approval_portal
import device_registry
import rails_config
import rails_confirmation
import action_broker
import policy_envelope
import kill_switch
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    mint_test_action_approval
)


class TestBatch43SecurityHardening(unittest.TestCase):

    def setUp(self):
        os.environ["HOMIE_TEST_ENV"] = "1"
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        device_registry.clear_consumed_nonces_for_testing()

    def tearDown(self):
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False

    def test_1_safety_floor_diff_strictly_empty(self):
        """Directive 1: Explicitly categorized tool tiers with strict build-time unclassified detection."""
        m = homie_supervisor.get_allowed_tools_map()
        cfg = rails_config.get_rails_config()

        # 1. Every tool in allowed_tools_map MUST be explicitly classified
        unclassified = sorted(set(m.keys()) - rails_config.ALL_CLASSIFIED_TOOLS)
        self.assertEqual(unclassified, [], f"Build failure: unclassified tools found in allowed_tools_map: {unclassified}")

        # 2. Every WRITE_EXEC / CONSEQUENTIAL tool MUST be in COMPILED_IN_CONSEQUENTIAL_TOOLS
        missing_consequential = sorted(t for t, tier in m.items() if tier in ("WRITE_EXEC", "CONSEQUENTIAL") and t not in rails_config.COMPILED_IN_CONSEQUENTIAL_TOOLS)
        self.assertEqual(missing_consequential, [], f"Consequential floor violation: WRITE_EXEC tools missing from floor: {missing_consequential}")

        # 3. Every SENSITIVE_READ tool MUST be in COMPILED_IN_SENSITIVE_READS
        for t, tier in m.items():
            if tier == "SENSITIVE_READ":
                self.assertIn(t, rails_config.COMPILED_IN_SENSITIVE_READS)

        # 4. Sensitive reads do NOT require per-action human confirmation prompt
        self.assertFalse(cfg.is_confirmation_required("homie_capture_screen"))
        self.assertFalse(cfg.is_confirmation_required("homie_get_clipboard"))
        self.assertFalse(cfg.is_confirmation_required("homie_read_screen_memory"))

        # 5. Consequential tools (launch app, remember/forget facts) strictly require confirmation
        self.assertTrue(cfg.is_confirmation_required("homie_launch_app"))
        self.assertTrue(cfg.is_confirmation_required("homie_remember_fact"))
        self.assertTrue(cfg.is_confirmation_required("homie_forget_fact"))
        self.assertEqual(m.get("homie_remember_fact"), "WRITE_EXEC")
        self.assertEqual(m.get("homie_forget_fact"), "WRITE_EXEC")

    def test_2_window_title_homie_does_not_falsely_block(self):
        """Directive 2: Eliminating fragile 'homie' in title check prevents falsely blocking legitimate Chrome tabs."""
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        actuator = homie_supervisor.SupervisorActuator(sup)

        # Active foreground window is Chrome with Claude conversation discussing Homie
        claude_fg_info = {
            "pid": 98765,
            "proc_name": "chrome.exe",
            "title": "Homie AI workstation assistant upgrades - Claude - Google Chrome",
            "exe_path": r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        }

        # Mock foreground to Claude Chrome tab and point under cursor to Chrome window
        with patch.object(windows_tools, "get_foreground_window", return_value=claude_fg_info), \
             patch.object(windows_tools, "get_window_under_point", return_value=(11111, claude_fg_info)), \
             patch.object(sup, "verify_and_consume_intent_token", return_value=True), \
             patch("homie_mcp.execute_mcp_tool", return_value="Action homie_agent_click executed"):
            try:
                res = actuator.execute_actuator(
                    "homie_agent_click", {"x": 500, "y": 500}, caller_id="desktop_user", seq=1
                )
                self.assertIn("Action homie_agent_click executed", res)
            except homie_supervisor.CompleteMediationBreachError as cm:
                self.fail(f"False positive self-targeting block on title: {cm}")
            finally:
                sup.clean_shutdown()

    def test_3_device_registry_failure_fails_closed(self):
        """Directive 3: Corrupt or failing device registry lookup in confirm() fails closed."""
        gate = rails_confirmation.ConfirmationGate()
        req = gate.create_request("homie_set_clipboard", {"text": "secret"}, caller_id="assistant")

        with patch("device_registry.get_enrolled_devices", side_effect=IOError("Corrupt device registry on disk")):
            ok, msg, tok = gate.confirm(req.request_id)
            self.assertFalse(ok)
            self.assertIsNone(tok)
            self.assertIn("DENIED: Device registry unavailable or corrupted (fail-closed)", msg)

    def test_4_browser_domain_uia_failure_fails_closed(self):
        """Directive 4: When targeting a browser, failed UIA address bar resolution denies action."""
        envelope = policy_envelope.PolicyEnvelope(
            envelope_id="env_b43_1",
            allowed_process_images=["chrome.exe"],
            allowed_action_types=["homie_agent_click"],
            step_budget=10,
            keystroke_cap=500,
            expiry=time.time() + 300,
            taint_epoch=1,
            allowed_domains=["trusted-domain.com"]
        )
        envelope.is_active = True

        # Targeting chrome.exe, but UIA lookup returns None (cannot inspect address bar)
        ok, msg, ks, tok = envelope.reserve_step(
            tool_name="homie_agent_click",
            arguments={"x": 100, "y": 100, "url": "https://trusted-domain.com"},  # worker-attested url must be ignored
            current_process_image="chrome.exe",
            current_taint_epoch=1,
            current_domain=None  # failed UIA lookup
        )
        self.assertFalse(ok)
        self.assertIn("Browser domain could not be verified via UIA (fail-closed)", msg)

    def test_5_recovery_token_single_use_via_authoritative_db_record(self):
        """Directive 5: Unelevated consumers enforce single-use via DB record without needing file DELETE permission."""
        tok = secrets.token_hex(16)
        tok_hash = hashlib.sha256(tok.encode("utf-8")).hexdigest()
        now = time.time()
        exp = now + 300

        # Simulate token registered in SQLite
        import db_utils
        phone_approval_portal._init_recovery_tokens_table()
        with db_utils.get_db() as conn:
            conn.execute(
                "INSERT INTO console_recovery_tokens (token_hash, expires_at, consumed, created_at) VALUES (?, ?, 0, ?)",
                (tok_hash, exp, now)
            )
            conn.commit()

        # First consumption must succeed
        ok1 = phone_approval_portal.consume_admin_recovery_token(tok)
        self.assertTrue(ok1, "First consumption of valid token must succeed")

        # Second consumption of the same token MUST fail (single-use invariant)
        ok2 = phone_approval_portal.consume_admin_recovery_token(tok)
        self.assertFalse(ok2, "Replay/second consumption of single-use token must fail")

    def test_6_supervisor_named_pipe_confirm_and_taint_query(self):
        """Directive 6: Supervisor Named Pipe supports MSG_CONFIRM and MSG_TAINT_QUERY."""
        priv_pem, pub_pem = enroll_test_device("batch43_pipe_phone")
        pipe_name = r"\\.\pipe\test_batch43_pipe_" + secrets.token_hex(4)

        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        server = homie_supervisor.NamedPipeSupervisorServer(sup, pipe_name=pipe_name)
        server.start()
        time.sleep(0.15)

        client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
        try:
            connected = client.connect(timeout_sec=2.0)
            self.assertTrue(connected, "Client must connect to supervisor pipe")
            client.hello()

            # Test taint status query over pipe
            taint_status = client.get_taint_status()
            self.assertEqual(taint_status.get("status"), "OK")
            self.assertIn("taint_epoch", taint_status)

            # Test MSG_CONFIRM with valid mobile signature
            clean_args = json.dumps({"text": "pipe_data"}, sort_keys=True, separators=(',', ':'))
            args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
            sig_blob = mint_test_action_approval(
                priv_pem,
                "homie_set_clipboard",
                args_hash,
                device_id="batch43_pipe_phone",
                taint_epoch=taint_status.get("taint_epoch", 0)
            )

            confirm_res = client.confirm(
                "homie_set_clipboard", {"text": "pipe_data"}, signed_evidence=sig_blob, caller_id="desktop_user"
            )
            self.assertEqual(confirm_res.get("status"), "ALLOW")
            token = confirm_res.get("step_up_token")
            self.assertIsNotNone(token)
            self.assertTrue(token.startswith("tok_"))
        finally:
            client.close()
            server.stop()
            sup.clean_shutdown()

    def test_7_real_os_subprocess_supervisor_kill_fails_closed(self):
        """Directive 7: Real OS subprocess supervisor termination causes all channels to fail closed immediately."""
        pipe_name = r"\\.\pipe\test_batch43_daemon_" + secrets.token_hex(4)

        # Spawn REAL independent OS process running homie_supervisor_daemon.py
        proc = subprocess.Popen(
            [sys.executable, "homie_supervisor_daemon.py", "--pipe", pipe_name],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        time.sleep(1.0)  # allow daemon to start and create named pipe

        try:
            client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
            connected = client.connect(timeout_sec=3.0)
            self.assertTrue(connected, "Client must connect to daemon pipe")
            client.hello()

            # Action broker configured as pipe client to the daemon's pipe
            broker = action_broker.ActionBroker(pipe_client=client, pipe_name=pipe_name)
            self.assertIsNone(broker.supervisor, "Broker address space must NOT contain in-process supervisor")

            # 1. Action while daemon is alive succeeds (READ_ONLY tool)
            ok, msg, res = broker.execute_action("homie_get_vitals", {}, caller_id="desktop_user")
            self.assertTrue(ok, f"Action should succeed while daemon alive: {msg}")

            # 2. Terminate real OS process via TerminateProcess / proc.kill()
            client.close()
            proc.kill()
            proc.wait(timeout=3.0)

            # 3. Verify ALL ingress channels immediately fail closed
            channels = ["desktop_user", "desktop_voice", "telegram_remote", "phone_gateway", "ai_engine"]
            for ch in channels:
                ch_ok, ch_msg, _ = broker.execute_action("homie_get_vitals", {}, caller_id=ch)
                self.assertFalse(
                    ch_ok,
                    f"Channel '{ch}' must fail closed after daemon killed, got: {ch_msg}"
                )
                self.assertIn("fail-closed", ch_msg.lower())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    unittest.main()
