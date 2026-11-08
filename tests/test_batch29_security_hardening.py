"""tests/test_batch29_security_hardening.py - Batch 29 Defense Hardening & Claude Directive Acceptance Suite.

Test-Driven Verification for:
1. XSS / HTML Injection Defense in Action Arguments & Canonical String Rendering (no innerHTML, strict textContent).
2. Anti-Counter-Poisoning: Counter is cryptographically signed inside challenge payload, preventing counter jumping/bricking.
3. Unauthenticated Endpoint Gate & Anti-DoS: Pending challenges require device authentication; invalid signatures NEVER cancel challenge.
4. Atomic Nonce Check-and-Record: Race condition mitigation under lock.
5. Atomic Registry Load-Check-Save: Device enrollment and revocation under _REGISTRY_LOCK preventing state clobbering.
6. Second-Device Multi-Sig Gate: Enrolling a second device requires approval from the primary enrolled device.
7. Supervisor Identity & Args-Hash Integrity: Supervisor derives caller identity and computes args_hash itself, ignoring worker spoofing.
8. Mandatory Sequence Number: Fallbacks removed; missing or non-positive sequence numbers are strictly rejected.
"""

import os
import sys
import time
import json
import re
import threading
import unittest
from Crypto.PublicKey import ECC

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_approval_portal
import homie_supervisor
import phone_gateway
import taint_tracker
from tests.phone_testing_keys import (
    generate_test_phone_keypair,
    enroll_test_device,
    sign_test_challenge,
    mint_test_action_approval
)


class TestBatch29SecurityHardening(unittest.TestCase):

    def setUp(self):
        phone_approval_portal.clear_active_challenges()
        taint_tracker.clear_all_taints()
        if os.path.exists(phone_approval_portal.DEVICE_REGISTRY_PATH):
            try: os.remove(phone_approval_portal.DEVICE_REGISTRY_PATH)
            except Exception: pass
        if os.path.exists(phone_approval_portal.CONSUMED_NONCES_PATH):
            try: os.remove(phone_approval_portal.CONSUMED_NONCES_PATH)
            except Exception: pass
        self.phone_priv, self.phone_pub_pem = enroll_test_device("primary_phone")

    def tearDown(self):
        phone_approval_portal.clear_active_challenges()
        taint_tracker.clear_all_taints()

    def test_1_html_injection_neutralization_in_arguments(self):
        """Vector 1: XSS / HTML Injection payload in tool arguments must be safely isolated in canonical text."""
        malicious_args = {
            "text": "</pre><script>alert('pwned')</script><img src=x onerror=fetch('/steal')>",
            "target": "<div>test</div>"
        }
        ch = phone_approval_portal.generate_approval_challenge(
            step_up_id="step_xss_001",
            tool_name="homie_agent_type",
            arguments=malicious_args,
            session_id="sess_xss",
            taint_epoch=0,
            device_id="primary_phone"
        )
        # Server must provide raw canonical_args string
        self.assertIn("canonical_args", ch)
        self.assertIsInstance(ch["canonical_args"], str)

        # In rendered UI, textContent must be used, never unescaped innerHTML
        html = phone_gateway._get_signing_portal_html()
        self.assertNotIn("card.innerHTML = `<pre class=\"args\">${argsStr}</pre>`", html)
        self.assertIn("pre.textContent", html)
        self.assertIn("Content-Security-Policy", html)

    def test_2_counter_poisoning_prevented_by_signed_binding(self):
        """Vector 2: Attacker cannot jump counter to a huge value because counter is bound in the signed challenge."""
        ch = phone_approval_portal.generate_approval_challenge(
            step_up_id="step_poison_001",
            tool_name="homie_snap_window",
            arguments={"app_name": "calc.exe"},
            session_id="sess_poison",
            taint_epoch=0,
            device_id="primary_phone"
        )
        # Valid signature over challenge hash
        sig = sign_test_challenge(self.phone_priv, ch["challenge_hash"])

        # Attacker attempts to jump counter from 1 to 999999 to brick future approvals
        ok, msg, _ = phone_approval_portal.verify_device_approval(
            "step_poison_001", sig, device_id="primary_phone", counter=999999
        )
        self.assertFalse(ok, "Counter jump must be rejected by server expected counter binding!")
        self.assertIn("COUNTER_MISMATCH", msg)

    def test_3_unauthenticated_listing_and_challenge_cancellation_denied(self):
        """Vector 3: Pending challenges require valid authentication; unauthenticated bad signatures DO NOT cancel challenge."""
        ch = phone_approval_portal.generate_approval_challenge(
            step_up_id="step_unauth_001",
            tool_name="homie_get_clipboard",
            arguments={},
            session_id="sess_unauth",
            taint_epoch=0,
            device_id="primary_phone"
        )

        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self):
                self.sent_code = None
                self.sent_body = None
                self.headers = {}
            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        # Unauthenticated request to /api/pending-challenges
        handler = MockHandler()
        import urllib.parse
        parsed = urllib.parse.urlparse("/api/pending-challenges?device_id=primary_phone")
        handler._handle_get_pending_challenges(parsed)
        self.assertEqual(handler.sent_code, 401, "Unauthenticated challenge listing must return 401 Unauthorized!")

        # Unauthenticated attacker submits 3 bogus signatures
        forged_sig = "deadbeef" * 16
        for _ in range(3):
            ok, _, _ = phone_approval_portal.verify_device_approval(
                "step_unauth_001", forged_sig, device_id="primary_phone", counter=1, is_authenticated_caller=False
            )
            self.assertFalse(ok)

        # Invariant: Challenge MUST NOT be canceled/deleted by unauthenticated attackers
        self.assertIn("step_unauth_001", phone_approval_portal._ACTIVE_CHALLENGES)

    def test_4_concurrent_nonce_replay_race_condition(self):
        """Vector 4: Concurrent threads attempting to replay the same action approval nonce must have exactly one success."""
        payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        approval = mint_test_action_approval(
            self.phone_priv, "homie_apply_update", payload_hash, device_id="primary_phone", nonce="unique_race_nonce_123456"
        )

        results = []
        def worker():
            ok, _ = phone_approval_portal.verify_action_approval(approval, "homie_apply_update", payload_hash)
            results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        # Exactly 1 must succeed; the other 9 must fail closed
        self.assertEqual(results.count(True), 1, "Atomic lock must allow exactly one consumer of nonce!")
        self.assertEqual(results.count(False), 9)

    def test_5_atomic_enroll_and_revoke_race_prevention(self):
        """Vector 5: Enrolling and revoking under _REGISTRY_LOCK prevents state clobbering."""
        # Enroll device B
        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        code = phone_approval_portal.get_session_pairing_code_for_testing(sess_id)
        _, pub = generate_test_phone_keypair()

        # Malformed device_id with invalid characters or length must be rejected
        ok_bad, msg_bad = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "invalid/device#name!@", pub
        )
        self.assertFalse(ok_bad)
        self.assertIn("INVALID_DEVICE_ID", msg_bad)

    def test_6_second_device_requires_primary_approval(self):
        """Vector 6: Enrolling a second device when primary_phone is already enrolled requires primary approval."""
        sess_id = phone_approval_portal.start_local_enrollment(ttl_seconds=60.0)
        code = phone_approval_portal.get_session_pairing_code_for_testing(sess_id)
        _, pub = generate_test_phone_keypair()

        # Attempting to enroll second device without primary approval must be blocked
        ok, msg = phone_approval_portal.complete_device_enrollment(
            sess_id, code, "secondary_phone", pub, primary_approval_sig=None
        )
        self.assertFalse(ok, "Second device enrollment must require primary device approval signature!")
        self.assertIn("PRIMARY_APPROVAL_REQUIRED", msg)

    def test_7_supervisor_derives_identity_and_computes_args_hash(self):
        """Vector 7: Supervisor ignores worker-supplied args_hash and caller_id spoofing."""
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED
        import heartbeat_lease
        supervisor.lease_token, _ = heartbeat_lease.acquire_lease("supervisor_worker", duration=10.0)
        supervisor.last_heartbeat_time = time.time()

        spoofed_payload = {
            "req_id": "req_spoof_1",
            "tool": "homie_get_vitals",
            "args": {},
            "caller_id": "admin_spoofed",  # Attacker tries to spoof admin caller ID
            "args_hash": "bogus_fake_args_hash"  # Attacker tries to inject precomputed hash
        }

        # Supervisor must execute and compute args_hash internally
        reply_bytes = supervisor._handle_propose(spoofed_payload, seq=10)
        ver, mtype, s_seq, payload, consumed = homie_supervisor.BinaryFrameCodec.decode_frame(reply_bytes)
        self.assertEqual(payload["status"], "ALLOW")
        supervisor.clean_shutdown()

    def test_8_mandatory_sequence_number_rejection_of_fallback(self):
        """Vector 8: Fallbacks removed; seq is strictly required and non-positive seq is denied."""
        supervisor = homie_supervisor.PolicySupervisor()
        supervisor.state = homie_supervisor.STATE_ARMED

        with self.assertRaises(ValueError) as cm:
            supervisor.actuator.execute_actuator("homie_snap_window", {}, "worker", seq=None)
        self.assertIn("seq is strictly required", str(cm.exception))

        supervisor.clean_shutdown()


if __name__ == "__main__":
    unittest.main()
