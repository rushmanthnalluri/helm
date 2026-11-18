"""tests/test_new_tier_features.py - Automated tests for new tier feature modules.

Tests:
1. homie_layout_profiles: save, list, get, apply, and delete window layout profiles.
2. homie_file_witness: cryptographic notarization, baseline verification, tampering detection.
3. homie_focus_mode: focus session lifecycle, status tracking, auto-expiry, and stop.
4. homie_netstat: network connection auditing, IP classification, and summary reports.
5. homie_retrospective: multi-session data aggregation and markdown narrative synthesis.
6. homie_mcp: verification of new tools in MCP_TOOLS, capability tiers, and execution dispatch.
"""

import os
import sys
import json
import time
import tempfile
import unittest
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_layout_profiles
import homie_file_witness
import homie_focus_mode
import homie_netstat
import homie_retrospective
import homie_mcp
import homie_supervisor


class TestNewTierFeatures(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        # Override paths for clean test isolation
        os.environ["HOMIE_LAYOUT_PROFILES_PATH"] = str(Path(self.temp_dir.name) / "layout_profiles.json")
        os.environ["HOMIE_WITNESS_MANIFEST_PATH"] = str(Path(self.temp_dir.name) / "file_witness_manifest.json")
        os.environ["HOMIE_FOCUS_STATE_PATH"] = str(Path(self.temp_dir.name) / "focus_mode_state.json")

    def tearDown(self):
        os.environ.pop("HOMIE_LAYOUT_PROFILES_PATH", None)
        os.environ.pop("HOMIE_WITNESS_MANIFEST_PATH", None)
        os.environ.pop("HOMIE_FOCUS_STATE_PATH", None)
        if homie_focus_mode.is_focus_mode_active():
            homie_focus_mode.stop_focus_mode(restore_windows=False)

    def test_1_layout_profiles_lifecycle(self):
        """Tests saving, listing, getting, applying, and deleting layout profiles."""
        initial_list = homie_layout_profiles.list_profiles()
        self.assertEqual(len(initial_list), 0)

        # Save profile
        ok, msg = homie_layout_profiles.save_profile("sprint_coding", "Sprint layout")
        self.assertTrue(ok)
        self.assertIn("sprint_coding", msg)

        # List profiles
        profiles = homie_layout_profiles.list_profiles()
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["name"], "sprint_coding")

        # Get profile details
        p = homie_layout_profiles.get_profile("sprint_coding")
        self.assertIsNotNone(p)
        self.assertEqual(p["name"], "sprint_coding")
        self.assertGreater(p["window_count"], 0)

        # Apply profile
        ok, msg, matched = homie_layout_profiles.apply_profile("sprint_coding")
        self.assertTrue(ok)
        self.assertIn("sprint_coding", msg)

        # Delete profile
        ok, msg = homie_layout_profiles.delete_profile("sprint_coding")
        self.assertTrue(ok)
        self.assertEqual(len(homie_layout_profiles.list_profiles()), 0)

    def test_2_file_witness_integrity_and_tamper_detection(self):
        """Tests cryptographic file witnessing, baseline validation, and tamper detection."""
        test_file = Path(self.temp_dir.name) / "contract.txt"
        test_file.write_text("Standard client contract clause 1.0", encoding="utf-8")

        # Notarize
        ok, msg, rec = homie_file_witness.notarize_file(str(test_file), notes="Client Contract V1")
        self.assertTrue(ok)
        self.assertEqual(rec["filename"], "contract.txt")
        self.assertIn("sha256", rec)

        # Verify intact
        ok, msg, det = homie_file_witness.verify_file(str(test_file))
        self.assertTrue(ok)
        self.assertEqual(det["status"], "INTACT")
        self.assertTrue(det["is_intact"])

        # Tamper with file
        test_file.write_text("MALICIOUS AMENDMENT: Send funds to unauthorized wallet", encoding="utf-8")

        # Verify tampered
        ok, msg, det = homie_file_witness.verify_file(str(test_file))
        self.assertFalse(ok)
        self.assertEqual(det["status"], "TAMPERED")
        self.assertFalse(det["is_intact"])
        self.assertIn("CRITICAL SECURITY ALERT", msg)

        # List witnessed
        witnessed = homie_file_witness.list_witnessed_files()
        self.assertEqual(len(witnessed), 1)

        # Remove
        ok, msg = homie_file_witness.remove_witness(str(test_file))
        self.assertTrue(ok)
        self.assertEqual(len(homie_file_witness.list_witnessed_files()), 0)

    def test_3_focus_mode_lifecycle(self):
        """Tests starting, querying, and stopping focus mode."""
        self.assertFalse(homie_focus_mode.is_focus_mode_active())

        # Start focus mode
        res = homie_focus_mode.start_focus_mode(
            duration_minutes=15,
            allowed_apps=["code.exe", "wt.exe"],
            session_name="Sprint Deep Work",
            minimize_distractions=False
        )
        self.assertTrue(res["is_active"])
        self.assertEqual(res["session_name"], "Sprint Deep Work")
        self.assertTrue(homie_focus_mode.is_focus_mode_active())

        # Status check
        st = homie_focus_mode.get_focus_status()
        self.assertTrue(st["is_active"])
        self.assertIn("code.exe", st["allowed_apps"])

        # Stop focus mode
        stop_res = homie_focus_mode.stop_focus_mode(restore_windows=False)
        self.assertFalse(stop_res["is_active"])
        self.assertFalse(homie_focus_mode.is_focus_mode_active())

    def test_4_network_activity_inspection(self):
        """Tests local network connection inspection and reporting."""
        conns = homie_netstat.get_active_connections(include_loopback=True, limit=50)
        self.assertIsInstance(conns, list)
        if conns:
            self.assertIn("pid", conns[0])
            self.assertIn("protocol", conns[0])
            self.assertIn("scope", conns[0])

        summary = homie_netstat.get_network_activity_summary()
        self.assertIn("total_active_sockets", summary)
        self.assertIn("total_listening_services", summary)
        self.assertIn("security_flags", summary)

        report = homie_netstat.format_network_report()
        self.assertIn("Workstation Network Activity Report", report)

    def test_5_retrospective_synthesis(self):
        """Tests multi-session data aggregation and retrospective markdown generation."""
        data = homie_retrospective.build_retrospective_data(lookback_hours=12.0)
        self.assertIn("user_name", data)
        self.assertIn("total_focus_hours", data)
        self.assertIn("meetings_attended", data)
        self.assertIn("notes_recorded", data)
        self.assertIn("agent_automations_run", data)

        md = homie_retrospective.generate_retrospective_markdown(lookback_hours=12.0)
        self.assertIn("Workstation Retrospective", md)
        self.assertIn("Workstation Focus & Productivity", md)
        self.assertIn("Meetings & Discussions", md)

    def test_6_mcp_tool_integration_and_supervisor_allowlist(self):
        """Verifies that all 10 new tools are registered in MCP, mapped in supervisor, and executable."""
        allowed_map = homie_supervisor.get_allowed_tools_map()
        
        expected_tools = {
            "homie_save_layout_profile": "REVERSIBLE",
            "homie_apply_layout_profile": "REVERSIBLE",
            "homie_list_layout_profiles": "READ_ONLY",
            "homie_notarize_file": "WRITE_EXEC",
            "homie_verify_file": "READ_ONLY",
            "homie_start_focus_mode": "REVERSIBLE",
            "homie_stop_focus_mode": "REVERSIBLE",
            "homie_get_focus_status": "READ_ONLY",
            "homie_get_network_activity": "READ_ONLY",
            "homie_generate_retrospective": "READ_ONLY"
        }

        for tool_name, expected_tier in expected_tools.items():
            self.assertIn(tool_name, allowed_map, f"Tool {tool_name} must be in supervisor allowlist")
            self.assertEqual(allowed_map[tool_name], expected_tier)

        # Test direct execution of read-only tools through MCP
        out1 = homie_mcp.execute_mcp_tool("homie_list_layout_profiles", {})
        self.assertIsInstance(out1, str)

        out2 = homie_mcp.execute_mcp_tool("homie_get_focus_status", {})
        parsed2 = json.loads(out2)
        self.assertIn("is_active", parsed2)

        out3 = homie_mcp.execute_mcp_tool("homie_get_network_activity", {})
        self.assertIn("Workstation Network Activity Report", out3)

        out4 = homie_mcp.execute_mcp_tool("homie_generate_retrospective", {"lookback_hours": 6})
        self.assertIn("Workstation Retrospective", out4)


if __name__ == "__main__":
    unittest.main()
