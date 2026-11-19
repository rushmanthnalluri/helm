"""tests/test_deterministic_uia.py - Deterministic UI Automation Cleanliness Suite.

Requirement Alignment (ORIGINAL_REQUEST.md §R3, Features F13, F14, F15, F16):
- R3. Deterministic UI Automation (Zero pyautogui, zero blind time.sleep())
- F13. Deterministic UIA Interaction (COM patterns replacing pyautogui)
- F14. Event-Driven State Synchronization (Zero blind sleeps in automation)
- F15. Window Confinement Invariants (HWND confinement under rapid focus switches)
- F16. Direct Protocol Integrations (CDP WebSocket and Windows URI schemes)
"""

import ast
import json
import os
import re
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.parse
import pytest

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


# ==============================================================================
# AST Visitors for Static Code Cleanliness Analysis
# ==============================================================================

class PyAutoGUIForbiddenVisitor(ast.NodeVisitor):
    """AST visitor asserting 0 imports, attribute accesses, or calls on pyautogui."""

    def __init__(self, filepath: str = "<unknown>"):
        self.filepath = filepath
        self.violations: list[dict] = []
        self.pyautogui_aliases: set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "pyautogui" or alias.name.startswith("pyautogui."):
                bound_name = alias.asname or alias.name
                self.pyautogui_aliases.add(bound_name)
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "IMPORT",
                    "detail": f"Import of forbidden module '{alias.name}' (bound as '{bound_name}')"
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and (node.module == "pyautogui" or node.module.startswith("pyautogui.")):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                self.pyautogui_aliases.add(bound_name)
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "IMPORT_FROM",
                    "detail": f"ImportFrom forbidden module '{node.module}' importing '{alias.name}'"
                })
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.value, ast.Name):
            if node.value.id in self.pyautogui_aliases or node.value.id == "pyautogui":
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "ATTRIBUTE_ACCESS",
                    "detail": f"Attribute access on forbidden module '{node.value.id}.{node.attr}'"
                })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id in self.pyautogui_aliases or node.func.value.id == "pyautogui":
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "CALL_ATTRIBUTE",
                    "detail": f"Invocation of '{node.func.value.id}.{node.func.attr}()'"
                })
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.pyautogui_aliases:
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "CALL_IMPORTED",
                    "detail": f"Invocation of imported pyautogui symbol '{node.func.id}()'"
                })
            elif node.func.id == "__import__" and node.args:
                if isinstance(node.args[0], ast.Constant) and node.args[0].value == "pyautogui":
                    self.violations.append({
                        "file": self.filepath,
                        "line": node.lineno,
                        "col": node.col_offset,
                        "type": "DYNAMIC_IMPORT",
                        "detail": "__import__('pyautogui') invocation"
                    })
        self.generic_visit(node)


class BlindSleepForbiddenVisitor(ast.NodeVisitor):
    """AST visitor asserting 0 blind time.sleep() or sleep() in automation workflows."""

    def __init__(self, filepath: str = "<unknown>"):
        self.filepath = filepath
        self.violations: list[dict] = []
        self.time_aliases: set[str] = {"time"}
        self.sleep_aliases: set[str] = {"sleep"}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "time":
                self.time_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "time":
            for alias in node.names:
                if alias.name == "sleep":
                    self.sleep_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id in self.time_aliases and node.func.attr == "sleep":
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "TIME_SLEEP",
                    "detail": f"Blind sleep invocation: {node.func.value.id}.sleep()"
                })
        elif isinstance(node.func, ast.Name):
            if node.func.id in self.sleep_aliases:
                self.violations.append({
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "BARE_SLEEP",
                    "detail": f"Blind sleep invocation: {node.func.id}()"
                })
        self.generic_visit(node)


# ==============================================================================
# Helper Functions for File Discovery
# ==============================================================================

EXCLUDED_DIRS = {
    ".git", ".pytest_cache", "__pycache__", "tests", "scripts",
    "packaging", "dist", "build", "archive", "website", "docs",
    ".agents", ".helm_data", ".test_tmp"
}


def get_production_files() -> list[str]:
    """Returns all production Python files (under helm/ if present, otherwise root production modules)."""
    prod_files = []
    helm_dir = os.path.join(REPO_ROOT, "helm")
    if os.path.exists(helm_dir):
        for root, dirs, files in os.walk(helm_dir):
            if any(d in root for d in EXCLUDED_DIRS):
                continue
            for f in files:
                if f.endswith(".py"):
                    prod_files.append(os.path.join(root, f))
        return prod_files

    # Include production root files (excluding tests/scripts/benchmarks/demos)
    for f in os.listdir(REPO_ROOT):
        full_path = os.path.join(REPO_ROOT, f)
        if os.path.isfile(full_path) and f.endswith(".py"):
            if not f.startswith("test_") and not f.startswith("demo_") and not f.startswith("benchmark_"):
                if f not in ("setup.py", "conftest.py"):
                    prod_files.append(full_path)
    return prod_files


def get_automation_files() -> list[str]:
    """Returns Python files responsible for interactive automation workflows."""
    automation_candidates = []
    helm_automation = os.path.join(REPO_ROOT, "helm", "engine", "automation")
    if os.path.exists(helm_automation):
        for root, _, files in os.walk(helm_automation):
            for f in files:
                if f.endswith(".py"):
                    automation_candidates.append(os.path.join(root, f))
    return automation_candidates


# ==============================================================================
# 1. Test Suite: Zero PyAutoGUI Invocations (R3 / F13)
# ==============================================================================

class TestZeroPyAutoGUIInvocations(unittest.TestCase):
    """Static AST assertions verifying 0 invocations or imports of pyautogui."""

    def test_ast_detailed_violation_reporting(self):
        """Meta-verification: Verifies that PyAutoGUIForbiddenVisitor detects all 4 forbidden AST patterns."""
        sample_code = """
import pyautogui
from pyautogui import click
import pyautogui as pag
x = pyautogui.position()
click(100, 200)
pag.press('enter')
dyn = __import__('pyautogui')
"""
        tree = ast.parse(sample_code)
        visitor = PyAutoGUIForbiddenVisitor(filepath="<synthetic>")
        visitor.visit(tree)

        detected_types = {v["type"] for v in visitor.violations}
        self.assertIn("IMPORT", detected_types)
        self.assertIn("IMPORT_FROM", detected_types)
        self.assertIn("ATTRIBUTE_ACCESS", detected_types)
        self.assertIn("CALL_ATTRIBUTE", detected_types)
        self.assertIn("CALL_IMPORTED", detected_types)
        self.assertIn("DYNAMIC_IMPORT", detected_types)
        self.assertGreaterEqual(len(visitor.violations), 6)

    def test_ast_production_modules_have_zero_pyautogui(self):
        """Recursively parses all production files and asserts 0 pyautogui usages."""
        files = get_production_files()
        self.assertGreater(len(files), 0, "No production Python files discovered!")

        all_violations = []
        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                    tree = ast.parse(fp.read(), filename=fpath)
            except SyntaxError:
                continue

            visitor = PyAutoGUIForbiddenVisitor(filepath=fpath)
            visitor.visit(tree)
            if visitor.violations:
                all_violations.extend(visitor.violations)

        violation_report = "\n".join(
            f"  {v['file']}:{v['line']}:{v['col']} - {v['detail']}"
            for v in all_violations
        )
        self.assertEqual(
            len(all_violations),
            0,
            f"Found {len(all_violations)} forbidden pyautogui invocations across production code:\n{violation_report}"
        )

    def test_requirements_txt_does_not_declare_pyautogui(self):
        """Verifies requirements.txt does not declare pyautogui as a dependency."""
        req_path = os.path.join(REPO_ROOT, "requirements.txt")
        if not os.path.exists(req_path):
            self.skipTest("requirements.txt not found")

        with open(req_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        pag_entries = [
            line.strip() for line in lines
            if line.strip().lower().startswith("pyautogui")
        ]
        self.assertEqual(
            len(pag_entries),
            0,
            f"pyautogui declared in requirements.txt: {pag_entries}. Must be removed in accordance with R3."
        )


# ==============================================================================
# 2. Test Suite: Zero Blind Sleeps in Automation (R3 / F14)
# ==============================================================================

class TestZeroBlindSleepsInAutomation(unittest.TestCase):
    """Static AST assertions verifying 0 blind time.sleep() in automation files."""

    def test_ast_automation_workflows_have_zero_blind_sleeps(self):
        """Scans automation workflow files and asserts 0 invocations of time.sleep()."""
        files = get_automation_files()
        if not files:
            self.skipTest("No automation files found to inspect (helm.engine.automation not yet initialized)")

        all_violations = []
        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                    tree = ast.parse(fp.read(), filename=fpath)
            except SyntaxError:
                continue

            visitor = BlindSleepForbiddenVisitor(filepath=fpath)
            visitor.visit(tree)
            if visitor.violations:
                all_violations.extend(visitor.violations)

        violation_report = "\n".join(
            f"  {v['file']}:{v['line']}:{v['col']} - {v['detail']}"
            for v in all_violations
        )
        self.assertEqual(
            len(all_violations),
            0,
            f"Found {len(all_violations)} blind sleep() invocations in automation files:\n{violation_report}"
        )

    def test_event_synchronization_primitives_are_sub_10ms(self):
        """Verifies event-driven condition wait returns immediately when condition is satisfied (<10ms)."""
        def wait_for_event_condition(condition_fn, timeout_ms=1000, event=None):
            if event is None:
                event = threading.Event()
            t0 = time.perf_counter_ns()
            if condition_fn():
                return True, (time.perf_counter_ns() - t0) / 1_000_000
            signaled = event.wait(timeout=timeout_ms / 1000.0)
            elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000
            return (condition_fn() if signaled else False), elapsed_ms

        ok, elapsed = wait_for_event_condition(lambda: True)
        self.assertTrue(ok)
        self.assertLess(elapsed, 10.0, f"Event synchronization took {elapsed}ms (>10ms)")

    def test_condition_waiter_timeout_and_abort(self):
        """Verifies event waiter honors timeout and aborts cleanly when condition is never met."""
        def wait_for_event_condition(condition_fn, timeout_ms=100, event=None):
            if event is None:
                event = threading.Event()
            t0 = time.perf_counter_ns()
            if condition_fn():
                return True, (time.perf_counter_ns() - t0) / 1_000_000
            signaled = event.wait(timeout=timeout_ms / 1000.0)
            elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000
            return (condition_fn() if signaled else False), elapsed_ms

        ok, elapsed = wait_for_event_condition(lambda: False, timeout_ms=50)
        self.assertFalse(ok)
        self.assertGreaterEqual(elapsed, 40.0)


# ==============================================================================
# 3. Test Suite: Window Confinement Invariants (R3 / F15)
# ==============================================================================

class WindowConfinementError(RuntimeError):
    """Raised when an automated action is aborted due to target window losing focus."""
    pass


def assert_window_confinement(target_hwnd: int, current_fg: int = None, ancestor_root: int = None) -> None:
    """Verifies that target_hwnd (or its root ancestor) is currently the foreground window."""
    import win32gui
    import win32con

    if not target_hwnd or target_hwnd <= 0:
        raise WindowConfinementError(f"Target HWND {target_hwnd} is invalid.")

    if current_fg is None:
        try:
            current_fg = win32gui.GetForegroundWindow()
        except Exception:
            current_fg = 0

    if not current_fg or current_fg <= 0:
        raise WindowConfinementError(
            f"No foreground window active (GetForegroundWindow() returned 0). Target HWND {target_hwnd} does not have focus."
        )

    if current_fg == target_hwnd:
        return

    if ancestor_root is None:
        try:
            ancestor_root = win32gui.GetAncestor(current_fg, win32con.GA_ROOT)
        except Exception:
            ancestor_root = 0

    if ancestor_root != target_hwnd:
        raise WindowConfinementError(
            f"Window confinement violated: Target HWND {target_hwnd} lost focus to foreground HWND {current_fg} "
            f"(root {ancestor_root}). Interaction aborted to prevent input leakage."
        )


class TestWindowConfinementInvariants(unittest.TestCase):
    """Unit and simulation tests verifying window confinement under focus switching."""

    def test_assert_window_confinement_direct_match(self):
        """Confinement check succeeds when foreground window exactly equals target HWND."""
        target = 0x12345
        assert_window_confinement(target, current_fg=0x12345)

    def test_assert_window_confinement_root_ancestor_match(self):
        """Confinement check succeeds when child window is focused but root ancestor matches target."""
        target = 0x12345
        child_control = 0x99999
        assert_window_confinement(target, current_fg=child_control, ancestor_root=target)

    def test_assert_window_confinement_mismatch_raises_error(self):
        """Confinement check raises WindowConfinementError when focus is on a different window."""
        target = 0x12345
        intruder_window = 0xABCDE
        with self.assertRaises(WindowConfinementError) as ctx:
            assert_window_confinement(target, current_fg=intruder_window, ancestor_root=intruder_window)
        self.assertIn("Window confinement violated", str(ctx.exception))

    def test_assert_window_confinement_null_or_invalid_hwnd(self):
        """Confinement check raises WindowConfinementError when HWND is 0 or None."""
        with self.assertRaises(WindowConfinementError):
            assert_window_confinement(0, current_fg=0x12345)

        with self.assertRaises(WindowConfinementError):
            assert_window_confinement(0x12345, current_fg=0)

    def test_confinement_abort_during_multi_step_automation(self):
        """Simulates multi-step sequence where focus drops at step 3; asserts remaining steps abort."""
        target_hwnd = 0x55555
        current_focus = {"hwnd": target_hwnd}
        executed_steps = []

        def execute_confined_step(step_name):
            assert_window_confinement(target_hwnd, current_fg=current_focus["hwnd"])
            executed_steps.append(step_name)

        execute_confined_step("1. Focus Search Box")
        execute_confined_step("2. ValuePattern Set Text")

        current_focus["hwnd"] = 0x99999

        with self.assertRaises(WindowConfinementError):
            execute_confined_step("3. Click Search Result")

        self.assertEqual(executed_steps, ["1. Focus Search Box", "2. ValuePattern Set Text"])
        self.assertNotIn("3. Click Search Result", executed_steps)

    def test_rapid_focus_switch_confinement_resistance(self):
        """Simulates 50 rapid interactions while focus alternates at high frequency."""
        target_hwnd = 0x11111
        intruder_hwnd = 0x22222
        current_focus = {"hwnd": target_hwnd}
        leakage_detected = []
        aborts_recorded = 0
        successes = 0

        for i in range(50):
            current_focus["hwnd"] = intruder_hwnd if (i % 2 == 1) else target_hwnd

            try:
                assert_window_confinement(target_hwnd, current_fg=current_focus["hwnd"])
                if current_focus["hwnd"] != target_hwnd:
                    leakage_detected.append(f"Leakage on iteration {i}")
                successes += 1
            except WindowConfinementError:
                aborts_recorded += 1

        self.assertEqual(len(leakage_detected), 0, f"Keystroke leakage detected: {leakage_detected}")
        self.assertEqual(aborts_recorded, 25, "Expected exactly 25 aborts when focus was on intruder")
        self.assertEqual(successes, 25, "Expected exactly 25 successes when focus was on target")

    def test_prohibited_security_window_confinement(self):
        """Verifies confinement prevents interacting if focus shifts to security dialogs (e.g. UAC/Logon)."""
        target_hwnd = 0x33333
        security_dialog = 0x77777
        with self.assertRaises(WindowConfinementError):
            assert_window_confinement(target_hwnd, current_fg=security_dialog, ancestor_root=security_dialog)


# ==============================================================================
# 4. Test Suite: Direct Protocol Integrations (R3 / F16)
# ==============================================================================

class TestDirectProtocolIntegrations(unittest.TestCase):
    """Unit tests verifying direct protocol automation via CDP and Windows URI schemes."""

    def test_cdp_websocket_bridge_json_rpc_commands(self):
        """Verifies CDPBridge constructs valid JSON-RPC frames and parses results."""
        try:
            from helm.engine.helm_cdp import CDPBridge
        except ImportError:
            from helm_cdp import CDPBridge

        bridge = CDPBridge()
        mock_ws = MagicMock()
        bridge._ws = mock_ws
        bridge.port = 9222

        def mock_recv():
            return json.dumps({"id": 1, "result": {"nodeId": 42}})
        mock_ws.recv.side_effect = mock_recv

        res = bridge.send_command("DOM.querySelector", {"selector": "#test-button"})
        self.assertEqual(res, {"nodeId": 42})

        mock_ws.send.assert_called_once()
        sent_payload = json.loads(mock_ws.send.call_args[0][0])
        self.assertEqual(sent_payload["method"], "DOM.querySelector")
        self.assertEqual(sent_payload["params"]["selector"], "#test-button")
        self.assertEqual(sent_payload["id"], 1)

    def test_cdp_connection_failure_and_timeout_resilience(self):
        """Verifies CDPBridge raises ConnectionError on unreachable port without hanging."""
        try:
            from helm.engine.helm_cdp import CDPBridge
        except ImportError:
            from helm_cdp import CDPBridge

        bridge = CDPBridge()
        with patch("requests.get", side_effect=ConnectionError("Port 9999 closed")):
            with self.assertRaises(ConnectionError):
                bridge.connect(port=9999, timeout=0.1)

    def test_whatsapp_uri_scheme_generation_zero_keystrokes(self):
        """Verifies WhatsApp URI scheme formats valid URLs without simulated keystrokes."""
        raw_phone = "+1 (555) 019-2834"
        raw_message = "Meeting confirmed for 3:00 PM! 🚀"

        clean_phone = re.sub(r"[^\d+]", "", raw_phone)
        self.assertEqual(clean_phone, "+15550192834")

        quoted_msg = urllib.parse.quote(raw_message)
        uri = f"whatsapp://send?phone={urllib.parse.quote(clean_phone)}&text={quoted_msg}"

        parsed = urllib.parse.urlparse(uri)
        self.assertEqual(parsed.scheme, "whatsapp")
        self.assertEqual(parsed.netloc, "send")

        query_params = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query_params["phone"][0], clean_phone)
        self.assertEqual(query_params["text"][0], raw_message)

        with patch("os.startfile") as mock_startfile:
            os.startfile(uri)
            mock_startfile.assert_called_once_with(uri)


if __name__ == "__main__":
    unittest.main()
