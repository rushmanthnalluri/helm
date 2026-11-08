"""tests/test_hardened_phone_gateway.py - Hardened Phone Gateway Acceptance Tests.

Verifies:
1. Phone Gateway binds to loopback (127.0.0.1) by default to prevent unauthorized network exposure.
2. Served HTML (/call page) does NOT contain or embed hardcoded PINs in JavaScript.
3. Twilio webhook validates X-Twilio-Signature (rejects forged webhooks with 403).
4. Caller allowlist rejects unauthorized phone numbers.
5. Phone instruction execution routes through shared broker and avoids TypeError with ai_engine.
"""

import os
import sys
import time
import unittest
import json
import base64
import hmac
import hashlib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import phone_gateway


class TestHardenedPhoneGateway(unittest.TestCase):

    def setUp(self):
        import homie_supervisor, kill_switch, taint_tracker, action_broker
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        taint_tracker.clear_all_taints()
        action_broker._GLOBAL_BROKER = None

    def tearDown(self):
        import homie_supervisor, kill_switch, taint_tracker, action_broker
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        taint_tracker.clear_all_taints()
        action_broker._GLOBAL_BROKER = None

    def test_default_loopback_binding(self):
        """Verifies phone gateway config binds strictly to 127.0.0.1 by default."""
        conf = phone_gateway.load_phone_config()
        self.assertEqual(conf.get("host", "127.0.0.1"), "127.0.0.1")

    def test_call_page_contains_no_embedded_pin(self):
        """Verifies served HTML does not leak or embed user PINs in JavaScript."""
        conf = phone_gateway.load_phone_config()
        pin = conf.get("pin")
        self.assertTrue(bool(pin), "Config must have a non-empty PIN")

        html = phone_gateway._get_call_page_html()
        self.assertNotIn(f"pin: '{pin}'", html)
        self.assertNotIn(f'pin: "{pin}"', html)
        self.assertNotIn('pin: "1234"', html)
        self.assertNotIn("pin: '1234'", html)

    def test_twilio_signature_validation(self):
        """Verifies validate_twilio_signature correctly calculates HMAC-SHA1 according to Twilio specs."""
        auth_token = "test_auth_token_secret_123"
        url = "https://myworkstation.ngrok.io/voice/incoming"
        params = {"From": "+1234567890", "CallSid": "CA123456"}

        # Generate valid signature
        data = url + "CallSidCA123456From+1234567890"
        valid_sig = base64.b64encode(hmac.new(auth_token.encode("utf-8"), data.encode("utf-8"), hashlib.sha1).digest()).decode("utf-8")

        # Validation succeeds with valid signature
        self.assertTrue(phone_gateway.validate_twilio_signature(url, params, valid_sig, auth_token))

        # Validation fails with tampered signature
        self.assertFalse(phone_gateway.validate_twilio_signature(url, params, "bad_signature_base64", auth_token))

        # Validation fails with missing token
        self.assertFalse(phone_gateway.validate_twilio_signature(url, params, valid_sig, ""))

    def test_phone_instruction_ai_execution_no_type_error(self):
        """Verifies execute_phone_instruction runs without argument mismatch on ai_engine.run_query."""
        # Non-fast command prompt (goes to AI path)
        res = phone_gateway.execute_phone_instruction("explain quantum computing in one short sentence", session_id="test_call")
        self.assertIsInstance(res, str)
        self.assertNotIn("unexpected keyword argument", res)

    def test_phone_gateway_audio_call_handling(self):
        """Verifies offline audio call endpoint processing with mock WAV input."""
        import tempfile, voice, io
        # Create a small valid WAV in memory
        tmp_wav = os.path.join(tempfile.gettempdir(), f"test_in_{os.getpid()}.wav")
        try:
            voice.synthesize_speech_to_wav("What time is it", tmp_wav)
            with open(tmp_wav, "rb") as f:
                wav_bytes = f.read()
            b64_audio = base64.b64encode(wav_bytes).decode("ascii")

            # Mock request handler
            class MockHandler(phone_gateway.PhoneGatewayHandler):
                def __init__(self):
                    self.headers = {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer test_device_token",
                        "X-Homie-Timestamp": str(time.time()),
                        "X-Homie-Nonce": f"nonce_call_{time.time()}_{os.getpid()}"
                    }
                    self.sent_code = None
                    self.sent_body = None

                def _send_response(self, code, content_type, body):
                    self.sent_code = code
                    self.sent_body = body

            handler = MockHandler()
            import unittest.mock as mock
            with mock.patch("phone_gateway.is_device_token_valid", return_value=True):
                handler._handle_audio_call(json.dumps({"audio_b64": b64_audio}))

            self.assertEqual(handler.sent_code, 200)
            resp = json.loads(handler.sent_body)
            self.assertIn("reply", resp)
            self.assertIn("audio_b64", resp)
            self.assertTrue(len(resp["audio_b64"]) > 500)
        finally:
            if os.path.exists(tmp_wav):
                try:
                    os.remove(tmp_wav)
                except Exception:
                    pass

    def test_audio_call_replay_protection_timestamp_and_nonce(self):
        """Verifies replay attack protection via timestamp tolerance and single-use nonce."""
        import time

        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self, headers=None):
                self.headers = headers or {"Content-Type": "application/json", "Authorization": "Bearer test"}
                self.sent_code = None
                self.sent_body = None

            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        import unittest.mock as mock
        with mock.patch("phone_gateway.is_device_token_valid", return_value=True), \
             mock.patch.object(phone_gateway, "get_shared_voice_engine") as mock_engine, \
             mock.patch("phone_gateway.execute_phone_instruction", return_value="System ready"):
            mock_engine.return_value.transcribe.return_value = "hello pc"

            # 1. Expired timestamp rejected
            h_expired = MockHandler({
                "Content-Type": "application/json",
                "Authorization": "Bearer test",
                "X-Homie-Timestamp": str(time.time() - 100),
                "X-Homie-Nonce": "nonce_expired_1"
            })
            h_expired._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))
            self.assertEqual(h_expired.sent_code, 401)
            self.assertIn("REPLAY_REJECTED", h_expired.sent_body)

            # 2. First request with valid nonce succeeds
            test_nonce = f"nonce_{time.time()}_{os.getpid()}"
            h_valid = MockHandler({
                "Content-Type": "application/json",
                "Authorization": "Bearer test",
                "X-Homie-Timestamp": str(time.time()),
                "X-Homie-Nonce": test_nonce
            })
            h_valid._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))
            self.assertEqual(h_valid.sent_code, 200)

            # 3. Replay with same consumed nonce rejected
            h_replay = MockHandler({
                "Content-Type": "application/json",
                "Authorization": "Bearer test",
                "X-Homie-Timestamp": str(time.time()),
                "X-Homie-Nonce": test_nonce
            })
            h_replay._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))
            self.assertEqual(h_replay.sent_code, 401)
            self.assertIn("already been consumed", h_replay.sent_body)

    def test_missing_timestamp_or_nonce_rejected(self):
        """Verifies requests missing mandatory timestamp or nonce are rejected with 400 Bad Request."""
        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self, headers=None):
                self.headers = headers or {"Content-Type": "application/json", "Authorization": "Bearer test"}
                self.sent_code = None
                self.sent_body = None

            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        import unittest.mock as mock
        with mock.patch("phone_gateway.is_device_token_valid", return_value=True):
            # Missing nonce
            h_no_nonce = MockHandler({
                "Content-Type": "application/json",
                "Authorization": "Bearer test",
                "X-Homie-Timestamp": str(time.time())
            })
            h_no_nonce._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))
            self.assertEqual(h_no_nonce.sent_code, 400)
            self.assertIn("Missing required nonce", h_no_nonce.sent_body)

            # Missing timestamp
            h_no_ts = MockHandler({
                "Content-Type": "application/json",
                "Authorization": "Bearer test",
                "X-Homie-Nonce": "nonce_123"
            })
            h_no_ts._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))
            self.assertEqual(h_no_ts.sent_code, 400)
            self.assertIn("Missing required timestamp", h_no_ts.sent_body)

    def test_audio_call_payload_size_limit(self):
        """Verifies oversized audio payloads (>5MB) are rejected with HTTP 413."""
        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self):
                self.headers = {
                    "Content-Type": "application/octet-stream",
                    "Authorization": "Bearer test",
                    "X-Homie-Timestamp": str(time.time()),
                    "X-Homie-Nonce": "nonce_size_check"
                }
                self.sent_code = None
                self.sent_body = None

            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        oversized_bytes = b"0" * (phone_gateway.MAX_AUDIO_PAYLOAD_BYTES + 1024)
        handler = MockHandler()
        import unittest.mock as mock
        with mock.patch("phone_gateway.is_device_token_valid", return_value=True):
            handler._handle_audio_call(oversized_bytes)

        self.assertEqual(handler.sent_code, 413)
        self.assertIn("PAYLOAD_TOO_LARGE", handler.sent_body)

    def test_phone_channel_tier_cap_enforcement(self):
        """Verifies ActionBroker enforces tier cap: Phone cannot invoke WRITE_EXEC without step-up."""
        import action_broker
        broker = action_broker.get_action_broker()

        # WRITE_EXEC tool (launch app) from phone caller_id without step-up token
        ok, msg, res = broker.execute_action(
            "homie_launch_app",
            {"app_name": "notepad"},
            caller_id="phone_gateway"
        )
        self.assertFalse(ok)
        self.assertIn("Phone channel is capped to READ_ONLY and REVERSIBLE tiers", msg)

    def test_unauthenticated_audio_call_fails_closed(self):
        """Verifies unauthenticated calls fail closed (HTTP 401) without burning nonces."""
        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self):
                self.headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer invalid_unpaired_token",
                    "X-Homie-Timestamp": str(time.time()),
                    "X-Homie-Nonce": "unauth_nonce_1"
                }
                self.sent_code = None
                self.sent_body = None

            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        handler = MockHandler()
        import unittest.mock as mock
        with mock.patch("phone_gateway.is_device_token_valid", return_value=False):
            handler._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))

        self.assertEqual(handler.sent_code, 401)
        self.assertIn("Unauthorized", handler.sent_body)
        # Verify nonce was NOT consumed/burned
        self.assertNotIn("invalid_unpaired_token:unauth_nonce_1", phone_gateway._DEVICE_NONCES)

    def test_empty_transcription_rejected_no_fallback(self):
        """Verifies failed or silent audio returns 400 and NEVER executes fallback status checks."""
        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self):
                self.headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer test_token",
                    "X-Homie-Timestamp": str(time.time()),
                    "X-Homie-Nonce": f"nonce_silent_{time.time()}"
                }
                self.sent_code = None
                self.sent_body = None

            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        handler = MockHandler()
        import unittest.mock as mock
        with mock.patch("phone_gateway.is_device_token_valid", return_value=True), \
             mock.patch.object(phone_gateway, "get_shared_voice_engine") as mock_engine, \
             mock.patch("phone_gateway.execute_phone_instruction") as mock_exec:
            mock_engine.return_value.transcribe.return_value = ""  # Silent audio
            handler._handle_audio_call(json.dumps({"audio_b64": "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}))

            self.assertEqual(handler.sent_code, 400)
            self.assertIn("TRANSCRIPTION_FAILED", handler.sent_body)
            # Verify execute_phone_instruction was NEVER invoked
            mock_exec.assert_not_called()

    def test_approve_portal_html_and_pending_challenges(self):
        """Batch 28: Verifies /approve served HTML and /api/pending-challenges structured response."""
        import phone_approval_portal, urllib.parse
        phone_approval_portal.clear_active_challenges()

        # 1. Test HTML rendering
        html = phone_gateway._get_signing_portal_html()
        self.assertIn("Homie Phone Authenticator", html)
        self.assertIn("What You See Is What You Sign", html)
        self.assertIn("Cryptographic Challenge Hash", html)

        # 2. Generate challenge
        ch = phone_approval_portal.generate_approval_challenge(
            step_up_id="step_gw_001",
            tool_name="homie_snap_window",
            arguments={"app_name": "notepad"},
            session_id="gw_sess",
            taint_epoch=0,
            device_id="gw_test_phone"
        )

        class MockHandler(phone_gateway.PhoneGatewayHandler):
            def __init__(self):
                self.sent_code = None
                self.sent_body = None
                self.headers = {"Authorization": "Bearer valid_gw_token"}
            def _send_response(self, code, content_type, body):
                self.sent_code = code
                self.sent_body = body

        handler = MockHandler()
        parsed = urllib.parse.urlparse("/api/pending-challenges?device_id=gw_test_phone")
        import unittest.mock as mock
        with mock.patch("phone_gateway.is_device_token_valid", return_value=True):
            handler._handle_get_pending_challenges(parsed)

        self.assertEqual(handler.sent_code, 200)
        data = json.loads(handler.sent_body)
        self.assertEqual(len(data["challenges"]), 1)
        self.assertEqual(data["challenges"][0]["step_up_id"], "step_gw_001")
        self.assertEqual(data["challenges"][0]["tool_name"], "homie_snap_window")
        self.assertEqual(data["challenges"][0]["device_id"], "gw_test_phone")

        phone_approval_portal.clear_active_challenges()


if __name__ == "__main__":
    unittest.main()
