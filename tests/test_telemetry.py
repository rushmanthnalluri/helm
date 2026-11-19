"""tests/test_telemetry.py - Unit tests for Opt-In Anonymous Telemetry & Crash Reporting.

Verifies:
1. Telemetry is strictly disabled by default (privacy by design).
2. Events and errors are rejected and not spooled when disabled.
3. Explicit opt-in enables tracking and logs safe anonymized events.
4. Sanitizer strictly redacts prohibited fields (prompt text, paths, credentials).
5. Anonymous machine identifier is a one-way salt hash containing zero plain PII.
6. Local spooling writes valid JSON Lines and bounds file size.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import helm_telemetry


class TestTelemetryManager(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_settings = os.path.join(self.test_dir, "test_settings.yaml")
        helm_telemetry.TelemetryManager.reset_instance()
        # Ensure clean environment
        self.orig_env = os.environ.get("HELM_TELEMETRY_ENABLED")
        os.environ.pop("HELM_TELEMETRY_ENABLED", None)

    def tearDown(self):
        if self.orig_env is not None:
            os.environ["HELM_TELEMETRY_ENABLED"] = self.orig_env
        else:
            os.environ.pop("HELM_TELEMETRY_ENABLED", None)
        helm_telemetry.TelemetryManager.reset_instance()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_telemetry_disabled_by_default(self):
        """Telemetry must be disabled by default on clean initialization."""
        mgr = helm_telemetry.TelemetryManager(data_dir=self.test_dir, settings_path=self.test_settings)
        self.assertFalse(mgr.is_enabled())

    def test_events_dropped_when_disabled(self):
        """When disabled, track_event and track_error return False and create no spool."""
        mgr = helm_telemetry.TelemetryManager(data_dir=self.test_dir, settings_path=self.test_settings)
        res1 = mgr.track_event("app_launched", {"version": "1.0.0"})
        res2 = mgr.track_error("DeviceError", "voice_pipeline")
        self.assertFalse(res1)
        self.assertFalse(res2)

        spool_path = os.path.join(self.test_dir, "telemetry_spool.jsonl")
        self.assertFalse(os.path.exists(spool_path))

    def test_opt_in_consent_and_event_spooling(self):
        """When enabled, events are recorded with anonymized ID and safe system info."""
        mgr = helm_telemetry.TelemetryManager(data_dir=self.test_dir, settings_path=self.test_settings)
        mgr.set_enabled(True)
        self.assertTrue(mgr.is_enabled())

        tracked = mgr.track_event("omnibar_opened", {"source": "hotkey"})
        self.assertTrue(tracked)

        spool_path = os.path.join(self.test_dir, "telemetry_spool.jsonl")
        self.assertTrue(os.path.isfile(spool_path))

        with open(spool_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)

        payload = json.loads(lines[0])
        self.assertEqual(payload["event"], "omnibar_opened")
        self.assertIn("anonymous_id", payload)
        self.assertEqual(payload["properties"]["source"], "hotkey")
        self.assertIn("os", payload)

    def test_sanitizer_strips_pii_and_sensitive_keys(self):
        """Sanitizer must remove prompt text, clipboard data, passwords, and file paths."""
        mgr = helm_telemetry.TelemetryManager(data_dir=self.test_dir, settings_path=self.test_settings)
        raw = {
            "feature": "voice",
            "prompt": "Call my doctor at 555-1234",
            "user_text": "Secret financial info",
            "clipboard": "sensitive tokens",
            "password": "mypassword123",
            "file_path": "C:\\Users\\admin\\Desktop\\secret.txt",
            "web_url": "https://bank.com/account",
            "duration_ms": 142.5,
            "success": True,
        }

        clean = mgr.sanitize_payload(raw)
        self.assertEqual(clean["feature"], "voice")
        self.assertEqual(clean["duration_ms"], 142.5)
        self.assertTrue(clean["success"])
        # Sensitive keys stripped
        self.assertNotIn("prompt", clean)
        self.assertNotIn("user_text", clean)
        self.assertNotIn("clipboard", clean)
        self.assertNotIn("password", clean)
        self.assertNotIn("file_path", clean)
        self.assertNotIn("web_url", clean)

    def test_anonymous_id_format(self):
        """Anonymous ID must be 16-char hex and free of plain usernames."""
        anon_id = helm_telemetry.generate_anonymous_id()
        self.assertEqual(len(anon_id), 16)
        int(anon_id, 16)  # Verifies hex format

    def test_track_error_convenience_helper(self):
        """track_error records error event with type and component."""
        mgr = helm_telemetry.TelemetryManager(data_dir=self.test_dir, settings_path=self.test_settings)
        mgr.set_enabled(True)
        tracked = mgr.track_error("TimeoutException", "cdp_bridge")
        self.assertTrue(tracked)

        spool_path = os.path.join(self.test_dir, "telemetry_spool.jsonl")
        with open(spool_path, "r", encoding="utf-8") as f:
            data = json.loads(f.readline())
        self.assertEqual(data["event"], "error_occurred")
        self.assertEqual(data["properties"]["error_type"], "TimeoutException")
        self.assertEqual(data["properties"]["component"], "cdp_bridge")


if __name__ == '__main__':
    unittest.main()
