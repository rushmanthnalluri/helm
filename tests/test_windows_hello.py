"""
Unit tests for Windows Hello Biometric Integration and Perceptual Frame Diffing.
"""
import os
import pytest
from PIL import Image

import windows_hello
import screen_ocr_engine


def test_windows_hello_availability_detection():
    # In automated test mode, it should cleanly return False without crashing or hanging
    avail = windows_hello.is_windows_hello_available()
    assert isinstance(avail, bool)


def test_windows_hello_mock_verification_success(monkeypatch):
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "1")
    res = windows_hello.prompt_windows_hello("Test Prompt")
    assert res["verified"] is True
    assert res["status"] == "verified"


def test_windows_hello_mock_verification_rejection(monkeypatch):
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "0")
    res = windows_hello.prompt_windows_hello("Test Prompt")
    assert res["verified"] is False
    assert res["status"] == "canceled"


def test_perceptual_frame_diffing():
    # Create two identical blank images
    img1 = Image.new("RGB", (640, 480), color=(100, 100, 100))
    img2 = Image.new("RGB", (640, 480), color=(100, 100, 100))

    hash1 = screen_ocr_engine.compute_frame_hash(img1)
    hash2 = screen_ocr_engine.compute_frame_hash(img2)

    dist = screen_ocr_engine.frame_hamming_distance(hash1, hash2)
    assert dist == 0  # Identical frames have 0 bit difference

    # Create a radically different image (half black, half white)
    img3 = Image.new("RGB", (640, 480), color=(0, 0, 0))
    for x in range(320, 640):
        for y in range(480):
            img3.putpixel((x, y), (255, 255, 255))

    hash3 = screen_ocr_engine.compute_frame_hash(img3)
    dist_different = screen_ocr_engine.frame_hamming_distance(hash1, hash3)
    assert dist_different > 5  # Distinct frames have significant Hamming distance


def test_rails_confirmation_windows_hello_tier2_success(monkeypatch):
    """Verify that a Tier 2 action is successfully confirmed via Windows Hello."""
    import rails_confirmation
    monkeypatch.setattr(rails_confirmation, "PROGRESSIVE_TRUST_ENABLED", True)
    gate = rails_confirmation.ConfirmationGate()
    # helm_send_email is Tier 2 in trust_tiers
    req = gate.create_request("helm_send_email", {"to": "alice@example.com", "subject": "Test"})
    assert req.status == "PENDING"

    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "1")
    ok, msg, token = gate.confirm(req.request_id, use_windows_hello=True)
    assert ok is True
    assert token is not None
    assert "Action confirmed" in msg
    assert req.status == "APPROVED"


def test_rails_confirmation_windows_hello_tier2_rejection(monkeypatch):
    """Verify that Windows Hello rejection blocks confirmation."""
    import rails_confirmation
    monkeypatch.setattr(rails_confirmation, "PROGRESSIVE_TRUST_ENABLED", True)
    gate = rails_confirmation.ConfirmationGate()
    req = gate.create_request("helm_send_email", {"to": "bob@example.com", "subject": "Test"})
    assert req.status == "PENDING"

    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "0")
    ok, msg, token = gate.confirm(req.request_id, use_windows_hello=True)
    assert ok is False
    assert token is None
    assert "Windows Hello verification failed" in msg
    assert req.status == "PENDING"


# ==============================================================================
# Phase 2 WindowsHello Class, WindowsHelloGate, and Action Broker Gate Tests
# ==============================================================================

def test_windows_hello_class_is_available(monkeypatch):
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO_AVAILABLE", "1")
    assert windows_hello.WindowsHello.is_available() is True
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO_AVAILABLE", "0")
    assert windows_hello.WindowsHello.is_available() is False


def test_windows_hello_class_verify_sync_success(monkeypatch):
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "1")
    assert windows_hello.WindowsHello.verify_sync("Test approval") is True


def test_windows_hello_class_verify_sync_failure(monkeypatch):
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "0")
    assert windows_hello.WindowsHello.verify_sync("Test approval") is False


@pytest.mark.asyncio
async def test_windows_hello_class_verify_async(monkeypatch):
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "1")
    res = await windows_hello.WindowsHello.verify("Async approval")
    assert res is True
    monkeypatch.setenv("HELM_MOCK_WINDOWS_HELLO", "0")
    res = await windows_hello.WindowsHello.verify("Async approval")
    assert res is False


def test_windows_hello_gate_uses_biometrics_when_available(monkeypatch):
    from unittest.mock import Mock
    import step_up_gate
    monkeypatch.setattr(windows_hello.WindowsHello, "is_available", classmethod(lambda cls: True))
    monkeypatch.setattr(windows_hello.WindowsHello, "verify_sync", classmethod(lambda cls, reason="": True))
    fallback_mock = Mock()

    gate = step_up_gate.WindowsHelloGate(fallback_gate=fallback_mock)
    ok, msg = gate.verify(reason="Approve file modification", tool_name="helm_modify_file")
    assert ok is True
    assert "Windows Hello" in msg
    fallback_mock.verify.assert_not_called()


def test_windows_hello_gate_fallback_to_phone_when_unavailable(monkeypatch):
    from unittest.mock import Mock
    import step_up_gate
    monkeypatch.setattr(windows_hello.WindowsHello, "is_available", classmethod(lambda cls: False))
    fallback_mock = Mock()
    fallback_mock.verify.return_value = (True, "Simulated phone WebAuthn push")

    gate = step_up_gate.WindowsHelloGate(fallback_gate=fallback_mock)
    ok, msg = gate.verify(reason="Approve file modification", tool_name="helm_modify_file")
    assert ok is True
    assert "Simulated phone WebAuthn push" in msg
    fallback_mock.verify.assert_called_once()


def test_action_broker_gate_selection_medium_risk_uses_windows_hello(monkeypatch):
    import step_up_gate
    import action_broker
    monkeypatch.setattr(windows_hello.WindowsHello, "is_available", classmethod(lambda cls: True))
    gate = action_broker.select_gate("helm_modify_file")
    assert isinstance(gate, step_up_gate.WindowsHelloGate)


def test_action_broker_gate_selection_medium_risk_falls_back_when_unavailable(monkeypatch):
    import step_up_gate
    import action_broker
    monkeypatch.setattr(windows_hello.WindowsHello, "is_available", classmethod(lambda cls: False))
    gate = action_broker.select_gate("helm_modify_file")
    assert isinstance(gate, step_up_gate.WindowsHelloGate)


def test_action_broker_gate_selection_high_risk_always_phone(monkeypatch):
    import step_up_gate
    import action_broker
    monkeypatch.setattr(windows_hello.WindowsHello, "is_available", classmethod(lambda cls: True))
    # High-risk actions use WindowsHelloGate biometric verification
    gate_shell = action_broker.select_gate("helm_run_shell")
    assert isinstance(gate_shell, step_up_gate.WindowsHelloGate)
    gate_kill = action_broker.select_gate("helm_kill_process")
    assert isinstance(gate_kill, step_up_gate.WindowsHelloGate)
    gate_del = action_broker.select_gate("helm_delete_file")
    assert isinstance(gate_del, step_up_gate.WindowsHelloGate)


def test_action_broker_gate_selection_low_risk_none():
    import action_broker
    gate_read = action_broker.select_gate("helm_read_screen")
    assert gate_read is None
    gate_vitals = action_broker.select_gate("helm_get_vitals")
    assert gate_vitals is None

