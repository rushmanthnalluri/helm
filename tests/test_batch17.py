"""Unit, integration, fuzz, and fail-closed security tests for Batch 17:
Helm Out-of-Process Policy Supervisor & Watchdog Architecture.
"""

import os
import sys
import time
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_supervisor
from helm_supervisor import (
    PolicySupervisor, SupervisorClient, BinaryFrameCodec,
    MSG_HELLO, MSG_PROPOSE, MSG_HEARTBEAT, MSG_SHUTDOWN,
    STATE_INIT, STATE_ARMED, STATE_LOCKED,
    REASON_OK, REASON_SYSTEM_LOCKED, REASON_LEASE_EXPIRED,
    REASON_UNKNOWN_TOOL, REASON_CANARY_DETECTED, REASON_SEQ_ROLLBACK,
    PayloadSizeError, FrameError, DIRTY_FLAG_PATH
)
import taint_tracker
import step_up_gate
import heartbeat_lease
import canary_monitor
import shadow_mode
import kill_switch


class TestBatch17Supervisor(unittest.TestCase):

    def setUp(self):
        # Reset security states for a clean test run
        taint_tracker.clear_all_taints()
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        import desktop_agent
        desktop_agent.reset_abort()
        shadow_mode.set_shadow_mode(False)
        shadow_mode.clear_rate_limits()
        
        # Clean lingering dirty flag and crash history
        from helm_supervisor import DIRTY_FLAG_PATH, CRASH_HISTORY_PATH
        for p in [DIRTY_FLAG_PATH, CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def tearDown(self):
        taint_tracker.clear_all_taints()
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        import desktop_agent
        desktop_agent.reset_abort()
        from helm_supervisor import DIRTY_FLAG_PATH, CRASH_HISTORY_PATH
        for p in [DIRTY_FLAG_PATH, CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
                pass

    def test_binary_framing_and_fuzz_limits(self):
        """Validates [u32 len][u8 ver][u8 type][u64 seq][payload] and fuzz bounds."""
        payload = {"action": "ping", "test_id": 1234}
        frame = BinaryFrameCodec.encode_frame(MSG_HELLO, 1, payload)
        
        self.assertGreaterEqual(len(frame), 14)
        ver, msg_type, seq, decoded, consumed = BinaryFrameCodec.decode_frame(frame)
        self.assertEqual(ver, 1)
        self.assertEqual(msg_type, MSG_HELLO)
        self.assertEqual(seq, 1)
        self.assertEqual(decoded["action"], "ping")
        self.assertEqual(consumed, len(frame))

        # Oversized frame rejection (> 1 MiB)
        huge_payload = {"data": "x" * (1024 * 1024 + 10)}
        with self.assertRaises(PayloadSizeError):
            BinaryFrameCodec.encode_frame(MSG_PROPOSE, 2, huge_payload)

        # Incomplete / corrupted frame handling
        with self.assertRaises(ValueError):
            BinaryFrameCodec.decode_frame(b"short")

        corrupted_header = b"\x00\x00\x00\x10\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01" + b"not_json_payload"
        with self.assertRaises(FrameError):
            BinaryFrameCodec.decode_frame(corrupted_header)

    def test_monotonic_sequence_anti_replay(self):
        """Verifies that replayed or decremented sequence numbers fail closed and lock supervisor."""
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()

        # Step 1: Normal HELLO with seq=1
        ack = client.hello()
        self.assertEqual(ack["status"], "OK")
        self.assertEqual(supervisor.state, STATE_ARMED)

        # Step 2: Attempt replay of seq=1
        replayed_frame = BinaryFrameCodec.encode_frame(MSG_HEARTBEAT, 1, {"progress_counter": 1})
        reply = supervisor.handle_raw_frame(replayed_frame)
        _, _, _, err_payload, _ = BinaryFrameCodec.decode_frame(reply)
        
        self.assertEqual(err_payload.get("reason_code"), REASON_SEQ_ROLLBACK)
        self.assertEqual(supervisor.state, STATE_LOCKED)
        self.assertIn("Sequence rollback/replay", supervisor.lock_reason)

        supervisor.clean_shutdown()

    def test_dirty_bit_boot_protection_and_human_unlock(self):
        """Verifies dirty-bit detection locks supervisor upon crash, requiring human unlock."""
        # Simulate abnormal termination by creating dirty flag before supervisor boot
        with open(DIRTY_FLAG_PATH, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": 9999, "crashed": True}))

        supervisor = PolicySupervisor()
        self.assertTrue(supervisor.dirty_boot_recovered)
        self.assertEqual(supervisor.state, STATE_LOCKED)

        # In LOCKED state, proposals must fail closed
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()
        
        decision = client.propose("helm_get_vitals", {})
        self.assertEqual(decision["status"], "DENY")
        self.assertEqual(decision["reason_code"], REASON_SYSTEM_LOCKED)

        # Human unlock with valid human phone token
        human_token = "human_authorized_admin_token"
        ok, msg = supervisor.human_unlock(human_token)
        self.assertTrue(ok)
        self.assertEqual(supervisor.state, STATE_ARMED)

        # Now proposals execute normally
        decision = client.propose("helm_get_vitals", {})
        self.assertEqual(decision["status"], "ALLOW")
        self.assertEqual(decision["reason_code"], REASON_OK)

        supervisor.clean_shutdown()

    def test_two_phase_action_logging(self):
        """Verifies INTENT is logged before actuator effect and OUTCOME is logged after."""
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()

        decision = client.propose("helm_get_vitals", {})
        self.assertEqual(decision["status"], "ALLOW")

        # Verify audit ledger has INTENT and OUTCOME entries
        import db_utils
        with db_utils.get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT decision FROM agent_audit_ledger ORDER BY id DESC LIMIT 5")
            recent_decisions = [r[0] for r in cur.fetchall()]
            
            has_outcome = any("OUTCOME:" in d and "SUCCESS" in d for d in recent_decisions)
            has_intent = any("INTENT:" in d for d in recent_decisions)
            self.assertTrue(has_intent, f"Expected INTENT in ledger decisions: {recent_decisions}")
            self.assertTrue(has_outcome, f"Expected OUTCOME in ledger decisions: {recent_decisions}")

        supervisor.clean_shutdown()

    def test_dead_man_heartbeat_lease_enforcement(self):
        """Verifies that expired heartbeat lease blocks all proposal execution."""
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()

        # Simulate lease expiration (time elapsed > 5 seconds)
        supervisor.last_heartbeat_time = time.time() - 6.0
        heartbeat_lease._ACTIVE_LEASES.clear()

        decision = client.propose("helm_get_vitals", {})
        self.assertEqual(decision["status"], "DENY")
        self.assertEqual(decision["reason_code"], REASON_LEASE_EXPIRED)

        # Renew lease via heartbeat
        supervisor.last_heartbeat_time = time.time()
        client.heartbeat(progress_counter=10)
        
        decision = client.propose("helm_get_vitals", {})
        self.assertEqual(decision["status"], "ALLOW")

        supervisor.clean_shutdown()

    def test_canary_exfiltration_scan_in_proposals(self):
        """Verifies supervisor intercepts and aborts canary leak in tool proposals."""
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()

        # Attacker crafts tool arguments containing canary secret
        canary = canary_monitor.DEFAULT_CANARY_TOKEN
        hostile_args = {"notes": f"Exfiltrating secret data: {canary}"}

        decision = client.propose("helm_set_clipboard", hostile_args)
        self.assertEqual(decision["status"], "DENY")
        self.assertEqual(decision["reason_code"], REASON_CANARY_DETECTED)
        self.assertEqual(supervisor.state, STATE_LOCKED)
        self.assertTrue(kill_switch.is_kill_switch_active())

        supervisor.clean_shutdown()

    def test_taint_step_up_in_supervisor(self):
        """Verifies that supervisor enforces out-of-band human step-up on tainted sessions."""
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()

        # Read clipboard marks session tainted
        decision = client.propose("helm_get_clipboard", {}, caller_id="test_worker_session")
        self.assertIn(decision["status"], ["ALLOW", "DENY"])

        # Subsequent sensitive write requires human step-up
        decision2 = client.propose("helm_snap_window", {"app_name": "notepad"}, caller_id="test_worker_session")
        self.assertEqual(decision2["status"], "NEEDS_HUMAN")
        self.assertIn("STEP_UP_REQUIRED", decision2["reason"])

        supervisor.clean_shutdown()

    def test_shadow_mode_in_supervisor(self):
        """Verifies that supervisor executes in non-mutating shadow mode when configured."""
        shadow_mode.set_shadow_mode(True)
        supervisor = PolicySupervisor()
        client = SupervisorClient(supervisor)
        client.connect()
        client.hello()

        decision = client.propose("helm_set_clipboard", {"text": "hello from shadow"})
        self.assertEqual(decision["status"], "SHADOW")
        self.assertIn("SHADOW_SIMULATION", decision["result"])

        shadow_mode.set_shadow_mode(False)
        supervisor.clean_shutdown()

    def test_out_of_process_named_pipe_ipc(self):
        """Verifies end-to-end Windows Named Pipe IPC communication between supervisor and worker."""
        from helm_supervisor import NamedPipeSupervisorServer, NamedPipeSupervisorClient
        pipe_name = rf"\\.\pipe\test_helm_pipe_{os.getpid()}_{int(time.time()*1000)}"
        
        supervisor = PolicySupervisor()
        server = NamedPipeSupervisorServer(supervisor, pipe_name=pipe_name)
        server.start()
        
        try:
            client = NamedPipeSupervisorClient(pipe_name=pipe_name)
            self.assertTrue(client.connect(), "Named pipe client should connect successfully")

            # 1. HELLO handshake
            ack = client.hello()
            self.assertEqual(ack["status"], "OK")
            self.assertEqual(ack["state"], STATE_ARMED)

            # 2. HEARTBEAT frame
            pong = client.heartbeat(progress_counter=1)
            self.assertEqual(pong["status"], "PONG")

            # 3. PROPOSE action frame
            decision = client.propose("helm_get_vitals", {})
            self.assertEqual(decision["status"], "ALLOW")
            self.assertEqual(decision["reason_code"], REASON_OK)
            self.assertIn("ram_pct", decision["result"])

            # 4. Clean shutdown
            shutdown_res = client.shutdown("test_complete")
            self.assertEqual(shutdown_res["status"], "SHUTDOWN_CLEAN")
        finally:
            server.stop()
            supervisor.clean_shutdown()


if __name__ == "__main__":
    unittest.main()
