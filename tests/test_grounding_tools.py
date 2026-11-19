"""Unit tests for grounding_tools.py and VLA integration."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import grounding_tools
import agent_tools
import helm_vla_agent
from helm_vla_agent import UIElementMark, HelmVLAAgent


class TestGroundingTools(unittest.TestCase):
    def test_get_screen_elements_structure(self):
        res = grounding_tools.get_screen_elements()
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)
        self.assertIn("count", res)
        self.assertIn("elements", res)
        self.assertIn("manifest", res)
        self.assertIn("window_title", res)
        self.assertTrue(res["ok"])

    def test_grounded_click_empty_target(self):
        res = grounding_tools.grounded_click("")
        self.assertFalse(res["ok"])
        self.assertIn("empty", res.get("error", "").lower())

    def test_grounded_type_empty_target(self):
        res = grounding_tools.grounded_type("", "hello")
        self.assertFalse(res["ok"])
        self.assertIn("empty", res.get("error", "").lower())

    def test_grounded_type_blocks_password_field(self):
        fake_mark = UIElementMark(
            mark_id=1,
            name="Password",
            control_type="Edit",
            left=10, top=10, right=100, bottom=40,
            center_x=55, center_y=25,
            is_password=True,
            is_enabled=True,
            raw_id="txtPassword"
        )
        vla = helm_vla_agent.get_vla_agent()
        with patch.object(vla, "find_element", return_value=fake_mark):
            res = grounding_tools.grounded_type("Password", "secret123")
            self.assertFalse(res["ok"])
            self.assertIn("password", res.get("error", "").lower())

    def test_grounded_type_blocks_prohibited_binary(self):
        fake_mark = UIElementMark(
            mark_id=2,
            name="Search",
            control_type="Edit",
            left=10, top=10, right=100, bottom=40,
            center_x=55, center_y=25,
            is_password=False,
            is_enabled=True,
            raw_id="txtSearch"
        )
        vla = helm_vla_agent.get_vla_agent()
        with patch.object(vla, "find_element", return_value=fake_mark):
            res = grounding_tools.grounded_type("Search", "powershell.exe -enc ...")
            self.assertFalse(res["ok"])
            self.assertIn("prohibited", res.get("error", "").lower())

    def test_grounding_tools_registered_in_agent_tools(self):
        full_reg = agent_tools.build_full_registry()
        schemas = {s["function"]["name"]: s["function"] for s in full_reg.schemas()}
        self.assertIn("get_screen_elements", schemas)
        self.assertIn("grounded_click", schemas)
        self.assertIn("grounded_type", schemas)

        # Check parameter schemas
        self.assertIn("target_description", schemas["grounded_click"]["parameters"]["properties"])
        self.assertIn("target_description", schemas["grounded_type"]["parameters"]["properties"])
        self.assertIn("text", schemas["grounded_type"]["parameters"]["properties"])
        self.assertIn("window_title", schemas["get_screen_elements"]["parameters"]["properties"])

    def test_helm_vla_agent_alias_and_methods(self):
        self.assertIs(helm_vla_agent.HelmVLAAgent, helm_vla_agent.VLAClosedLoopAgent)
        vla = helm_vla_agent.get_vla_agent()
        self.assertTrue(hasattr(vla, "find_element"))
        self.assertTrue(hasattr(vla, "grounded_click"))
        self.assertTrue(hasattr(vla, "grounded_type"))
        self.assertTrue(hasattr(vla, "get_screen_elements"))


if __name__ == "__main__":
    unittest.main()
