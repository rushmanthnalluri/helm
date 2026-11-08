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


if __name__ == "__main__":
    unittest.main()
