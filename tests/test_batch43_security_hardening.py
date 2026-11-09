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
        device_registry.clear_registry_for_testing()
        device_registry.clear_consumed_nonces_for_testing()

    def tearDown(self):
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        device_registry.clear_registry_for_testing()
        device_registry.clear_consumed_nonces_for_testing()

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
        self.assertTrue(cfg.is_confirmation_required("homie_http_fetch"))
        self.assertEqual(m.get("homie_http_fetch"), "WRITE_EXEC")
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
        """Directive 6: Supervisor Named Pipe supports MSG_CONFIRM, role-by-PID check, anti-replay, and MSG_TAINT_QUERY."""
        priv_pem, pub_pem = enroll_test_device("batch43_pipe_phone")
        pipe_name = r"\\.\pipe\test_batch43_pipe_" + secrets.token_hex(4)

        import psutil
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        sup.authorized_ui_pid = os.getpid()
        sup.authorized_ui_ctime = psutil.Process().create_time()
        server = homie_supervisor.NamedPipeSupervisorServer(sup, pipe_name=pipe_name)
        server.start()
        time.sleep(0.15)

        client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
        try:
            connected = client.connect(timeout_sec=2.0)
            self.assertTrue(connected, "Client must connect to supervisor pipe")
            client.hello()

            # 1. Test taint status query over pipe
            taint_status = client.get_taint_status()
            self.assertEqual(taint_status.get("status"), "OK")
            self.assertIn("taint_epoch", taint_status)

            # 2. Role-by-PID Enforcement: Confirm from unregistered PID must be REJECTED
            clean_args = json.dumps({"text": "pipe_data"}, sort_keys=True, separators=(',', ':'))
            args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
            sig_blob = mint_test_action_approval(
                priv_pem,
                "homie_set_clipboard",
                args_hash,
                device_id="batch43_pipe_phone",
                taint_epoch=taint_status.get("taint_epoch", 0)
            )

            confirm_unreg = client.confirm(
                "homie_set_clipboard", {"text": "pipe_data"}, signed_evidence=sig_blob
            )
            self.assertEqual(confirm_unreg.get("reason_code"), homie_supervisor.REASON_UNAUTHORIZED_TOKEN)
            self.assertTrue(any(w in confirm_unreg.get("error", "").lower() for w in ("untrusted pid", "untrusted or recycled pid")))

            # 3. Register current UI process PID with session token
            reg_res = client.register_ui(os.getpid(), session_token=sup.supervisor_session_token)
            self.assertEqual(reg_res.get("status"), "OK")

            # 4. Valid confirmation from registered UI succeeds
            confirm_res = client.confirm(
                "homie_set_clipboard", {"text": "pipe_data"}, signed_evidence=sig_blob
            )
            self.assertEqual(confirm_res.get("status"), "ALLOW")
            token = confirm_res.get("step_up_token")
            self.assertIsNotNone(token)
            self.assertTrue(token.startswith("tok_"))

            # 5. Nonce Anti-Replay: Presenting the exact same signed evidence blob again MUST FAIL
            replay_res = client.confirm(
                "homie_set_clipboard", {"text": "pipe_data"}, signed_evidence=sig_blob
            )
            self.assertEqual(replay_res.get("status"), "DENY")
            self.assertIn("verification failed", replay_res.get("reason", "").lower())

            # 6. No-Device Branch: Zero-trust doctrine strictly denies confirmation without enrolled phone
            device_registry.clear_registry_for_testing()
            no_phone_res = client.confirm(
                "homie_delete_file", {"path": "test.tmp"}
            )
            self.assertEqual(no_phone_res.get("status"), "DENY")
            self.assertIn("No mobile device enrolled", no_phone_res.get("reason", ""))
        finally:
            client.close()
            server.stop()
            sup.clean_shutdown()
            device_registry.clear_registry_for_testing()

    def test_7_real_os_subprocess_supervisor_kill_fails_closed(self):
        """Directive 7: Real OS subprocess supervisor executes WRITE_EXEC across pipe, and termination causes all channels to fail closed."""
        pipe_name = r"\\.\pipe\test_batch43_daemon_" + secrets.token_hex(4)

        # Spawn REAL independent OS process running homie_supervisor_daemon.py
        proc = subprocess.Popen(
            [sys.executable, "homie_supervisor_daemon.py", "--pipe", pipe_name, "--ui-pid", str(os.getpid())],
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
            client.register_ui(os.getpid())

            # Action broker configured as pipe client to the daemon's pipe
            broker = action_broker.ActionBroker(pipe_client=client, pipe_name=pipe_name)
            self.assertIsNone(broker.supervisor, "Broker address space must NOT contain in-process supervisor")

            # 1. READ_ONLY tool execution while daemon is alive succeeds
            ok_read, msg_read, res_read = broker.execute_action("homie_get_vitals", {}, caller_id="desktop_user")
            self.assertTrue(ok_read, f"Read-only action should succeed while daemon alive: {msg_read}")

            # 2. WRITE_EXEC tool execution across the pipe with complete mediation
            # Mint signed approval evidence from enrolled test device
            priv_pem, pub_pem = enroll_test_device("daemon_test_phone")
            clean_args = json.dumps({"text": "cross_pipe_success"}, sort_keys=True, separators=(',', ':'))
            args_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
            taint_status = client.get_taint_status()
            sig_blob = mint_test_action_approval(
                priv_pem,
                "homie_set_clipboard",
                args_hash,
                device_id="daemon_test_phone",
                taint_epoch=taint_status.get("taint_epoch", 0)
            )

            confirm_reply = client.confirm(
                "homie_set_clipboard", {"text": "cross_pipe_success"}, signed_evidence=sig_blob
            )
            self.assertEqual(confirm_reply.get("status"), "ALLOW", f"Confirm reply failed: {confirm_reply}")
            step_up_tok = confirm_reply.get("step_up_token")
            self.assertIsNotNone(step_up_tok)

            ok_write, msg_write, _ = broker.execute_action(
                "homie_set_clipboard", {"text": "cross_pipe_success"}, caller_id="desktop_user", step_up_token=step_up_tok
            )
            self.assertTrue(ok_write, f"WRITE_EXEC tool execution across pipe should succeed: {msg_write}")

            # 3. Terminate real OS process via TerminateProcess / proc.kill()
            client.close()
            proc.kill()
            proc.wait(timeout=3.0)

            # 4. Verify ALL ingress channels immediately fail closed
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

    def test_8_device_registry_tampering_or_deletion_fails_closed(self):
        """Directive 8: Enrolled device registry deletion or tampering strictly fails closed."""
        device_registry.clear_registry_for_testing()
        priv_pem, pub_pem = enroll_test_device("tamper_test_device")

        # Verify device registry and enrollment marker exist
        self.assertTrue(os.path.exists(device_registry.DEVICE_REGISTRY_PATH))
        self.assertTrue(os.path.exists(device_registry.DEVICE_ENROLLED_MARKER))

        # Now simulate attacker deleting .homie_device_keys.json to trigger no-device downgrade
        os.remove(device_registry.DEVICE_REGISTRY_PATH)

        # 1. get_enrolled_devices() MUST raise RuntimeError with TAMPERING_DETECTED
        with self.assertRaises(RuntimeError) as ctx:
            device_registry.get_enrolled_devices()
        self.assertIn("TAMPERING_DETECTED", str(ctx.exception))

        # 2. Confirmation gate confirm() MUST fail closed with REGISTRY_ERROR
        gate = rails_confirmation.get_confirmation_gate()
        req = gate.create_request("homie_set_clipboard", {"text": "secret"}, caller_id="assistant")
        ok, msg, tok = gate.confirm(req.request_id)
        self.assertFalse(ok)
        self.assertIsNone(tok)
        self.assertIn("unavailable or corrupted (fail-closed)", msg)

        # Cleanup
        device_registry.clear_registry_for_testing()


    def test_9_two_process_confirmation_request_creation_and_gesture_verification(self):
        """Directive 9: MSG_CREATE_CONFIRM_REQUEST = 13 delegates request creation across pipe, eliminating split-brain."""
        pipe_name = r"\\.\pipe\test_batch43_sync_" + secrets.token_hex(4)
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        server = homie_supervisor.NamedPipeSupervisorServer(sup, pipe_name=pipe_name)
        server.start()
        time.sleep(0.15)

        client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
        try:
            self.assertTrue(client.connect(timeout_sec=2.0))
            client.hello()

            # 0. Calling create_confirmation_request from un-attested PID must be REJECTED
            unreg_resp = client.create_confirmation_request("homie_delete_file", {"path": "unreg.tmp"}, caller_id="desktop_user")
            self.assertEqual(unreg_resp.get("reason_code"), homie_supervisor.REASON_UNAUTHORIZED_TOKEN)
            self.assertIn("rejected from untrusted pid", unreg_resp.get("error", "").lower())

            import psutil
            sup.authorized_ui_pid = os.getpid()
            sup.authorized_ui_ctime = psutil.Process().create_time()

            reg_res = client.register_ui(os.getpid())
            self.assertEqual(reg_res.get("status"), "OK")

            # 1. UI process requests creation of authoritative confirmation request across the pipe
            resp = client.create_confirmation_request("homie_delete_file", {"path": "sync_test.tmp"}, caller_id="desktop_user")
            self.assertEqual(resp.get("status"), "OK")
            req_id = resp.get("request_id")
            self.assertTrue(req_id.startswith("conf_"))

            # 2. When no mobile device is enrolled, confirmation is strictly DENIED
            no_dev_conf = client.confirm("homie_delete_file", {"path": "sync_test.tmp"}, req_id=req_id)
            self.assertEqual(no_dev_conf.get("status"), "DENY")
            self.assertIn("No mobile device enrolled", no_dev_conf.get("reason", ""))

            # 3. When mobile device is enrolled, verified signature allows execution
            import taint_tracker
            priv_k, pub_k = enroll_test_device("sync_test_phone")
            clean_args = json.dumps({"path": "sync_test.tmp"}, sort_keys=True, separators=(',', ':'))
            a_hash = hashlib.sha256(clean_args.encode('utf-8')).hexdigest()
            t_epoch = taint_tracker.get_taint_epoch()
            sig_blob = mint_test_action_approval(priv_k, "homie_delete_file", a_hash, device_id="sync_test_phone", taint_epoch=t_epoch)

            conf_resp = client.confirm("homie_delete_file", {"path": "sync_test.tmp"}, signed_evidence=sig_blob, req_id=req_id)
            self.assertEqual(conf_resp.get("status"), "ALLOW")
            self.assertTrue(conf_resp.get("step_up_token").startswith("tok_"))
        finally:
            client.close()
            server.stop()
            sup.clean_shutdown()

    def test_10_device_registry_tampering_fails_closed_across_windows_registry(self):
        """Directive 10: Registry tampering detection holds even if disk marker is deleted (Windows Registry backup)."""
        device_registry.clear_registry_for_testing()
        priv_pem, pub_pem = enroll_test_device("winreg_tamper_phone")

        # Set Windows Registry enrollment record explicitly
        device_registry._set_windows_registry_marker(True)

        # Attacker deletes BOTH .homie_device_keys.json AND .homie_device_enrolled.marker
        if os.path.exists(device_registry.DEVICE_REGISTRY_PATH):
            os.remove(device_registry.DEVICE_REGISTRY_PATH)
        if os.path.exists(device_registry.DEVICE_ENROLLED_MARKER):
            os.remove(device_registry.DEVICE_ENROLLED_MARKER)

        # Windows registry record persists!
        self.assertTrue(device_registry._check_windows_registry_marker())

        # Any attempt to load devices MUST raise RuntimeError with TAMPERING_DETECTED
        with self.assertRaises(RuntimeError) as ctx:
            device_registry._load_device_registry()
        self.assertIn("TAMPERING_DETECTED", str(ctx.exception))

        # Cleanup
        device_registry.clear_registry_for_testing()

    def test_11_unauthorized_process_cannot_register_as_ui(self):
        """Directive 11: Hostile same-user script (e.g. test_evil.py) cannot register as UI without kernel child or session token."""
        pipe_name = r"\\.\pipe\test_batch43_auth_" + secrets.token_hex(4)
        sup = homie_supervisor.PolicySupervisor()
        sup.state = homie_supervisor.STATE_ARMED
        server = homie_supervisor.NamedPipeSupervisorServer(sup, pipe_name=pipe_name)
        server.start()
        time.sleep(0.15)

        client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
        try:
            self.assertTrue(client.connect(timeout_sec=2.0))
            client.hello()

            import psutil
            # Hostile same-user script attempts registration without child attestation
            evil_res = client.register_ui(os.getpid())
            self.assertEqual(evil_res.get("reason_code"), "UNAUTHORIZED_IMAGE")
            self.assertIn("rejected", evil_res.get("error", "").lower())

            # Legitimate registration with daemon child attestation succeeds
            sup.authorized_ui_pid = os.getpid()
            sup.authorized_ui_ctime = psutil.Process().create_time()
            valid_res = client.register_ui(os.getpid())
            self.assertEqual(valid_res.get("status"), "OK")
        finally:
            client.close()
            server.stop()
            sup.clean_shutdown()

    def test_12_homie_http_fetch_pinned_egress_and_taint(self):
        """Directive 12: homie_http_fetch tool blocks SSRF to cloud metadata, and meeting/timeline tools taint session."""
        import homie_mcp
        import taint_tracker

        # Reset taint before test
        taint_tracker.clear_all_taints()

        # 1. homie_get_meeting_notes returns nonce-wrapped output and taints caller session
        caller = "test_fresh_agent_caller"
        self.assertFalse(taint_tracker.is_session_tainted(caller))
        notes_res = homie_mcp.execute_mcp_tool("homie_get_meeting_notes", {"limit": 1}, caller_id=caller)
        self.assertTrue(taint_tracker.is_session_tainted(caller))

        # 2. homie_http_fetch is WRITE_EXEC: requires intent/step-up, and blocks SSRF when mediated
        homie_mcp.set_active_supervisor_intent("intent_test_token")
        try:
            res_ssrf = homie_mcp.execute_mcp_tool("homie_http_fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
            self.assertIn("Fetch failed", res_ssrf)
            self.assertIn("SSRF Blocked", res_ssrf)
        finally:
            homie_mcp.set_active_supervisor_intent(None)

    def test_13_supervisor_spawned_worker_confinement_and_atomic_job_termination(self):
        """Directive 13: Policy Supervisor daemon directly spawns AppContainer confined worker,
        authoritatively records its PID, conveys worker_pid to registered UI, and terminates worker
        atomically on daemon shutdown via Job Object KILL_ON_JOB_CLOSE."""
        pipe_name = r"\\.\pipe\test_batch43_worker_" + secrets.token_hex(4)

        proc = subprocess.Popen(
            [sys.executable, "homie_supervisor_daemon.py", "--pipe", pipe_name, "--ui-pid", str(os.getpid())],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(1.2)

        try:
            client = homie_supervisor.NamedPipeSupervisorClient(pipe_name=pipe_name)
            connected = client.connect(timeout_sec=3.0)
            self.assertTrue(connected, "Client must connect to daemon pipe")

            # 1. Register UI process and verify supervisor returns authoritative worker_pid
            reg_res = client.register_ui(os.getpid())
            self.assertEqual(reg_res.get("status"), "OK")
            worker_pid = reg_res.get("worker_pid")
            self.assertIsNotNone(worker_pid, "Supervisor must report authoritative worker PID")
            self.assertTrue(isinstance(worker_pid, int) and worker_pid > 0)
            self.assertNotEqual(worker_pid, os.getpid(), "Worker PID must not be UI PID")
            self.assertNotEqual(worker_pid, proc.pid, "Worker PID must not be Supervisor Daemon PID")

            # 2. Verify worker process is running and its parent is the supervisor daemon
            import psutil
            self.assertTrue(psutil.pid_exists(worker_pid), f"Confined worker process {worker_pid} must be running")
            worker_ps = psutil.Process(worker_pid)
            self.assertEqual(worker_ps.ppid(), proc.pid, f"Worker parent PID must be supervisor daemon PID {proc.pid}")

            # 3. Verify worker process is running homie_worker.py
            cmdline = " ".join(worker_ps.cmdline())
            self.assertIn("homie_worker.py", cmdline)

            client.close()

            # 4. Terminate the supervisor daemon
            proc.kill()
            proc.wait(timeout=3.0)

            # 5. Verify AppContainer worker was atomically terminated by Windows Job Object
            time.sleep(0.5)
            self.assertFalse(psutil.pid_exists(worker_pid), f"Worker process {worker_pid} must be terminated when daemon dies (KILL_ON_JOB_CLOSE)")
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_14_foreground_window_missing_fields_fails_closed_in_actuator(self):
        """Directive: get_foreground_window() returning a dict without proc_name/pid must fail closed."""
        from unittest.mock import patch
        import homie_supervisor
        from homie_supervisor import SupervisorActuator, CompleteMediationBreachError

        actuator = SupervisorActuator(supervisor=None)

        # 1. Mock get_foreground_window returning dict missing proc_name and pid
        with patch("windows_tools.get_foreground_window", return_value={"hwnd": 1234, "title": "Untitled"}):
            with self.assertRaises(CompleteMediationBreachError) as ctx:
                actuator.execute_actuator("homie_agent_click", {"x": 100, "y": 100}, caller_id="desktop_user", seq=1)
            self.assertIn("Unable to reliably determine foreground window", str(ctx.exception))

        # 2. Mock get_foreground_window returning None
        with patch("windows_tools.get_foreground_window", return_value=None):
            with self.assertRaises(CompleteMediationBreachError) as ctx:
                actuator.execute_actuator("homie_agent_type", {"text": "hello"}, caller_id="desktop_user", seq=2)
            self.assertIn("Unable to reliably determine foreground window", str(ctx.exception))

if __name__ == "__main__":
    unittest.main()
