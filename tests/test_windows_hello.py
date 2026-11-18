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
    monkeypatch.setenv("HOMIE_MOCK_WINDOWS_HELLO", "1")
    res = windows_hello.prompt_windows_hello("Test Prompt")
    assert res["verified"] is True
    assert res["status"] == "verified"


def test_windows_hello_mock_verification_rejection(monkeypatch):
    monkeypatch.setenv("HOMIE_MOCK_WINDOWS_HELLO", "0")
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
    # homie_send_email is Tier 2 in trust_tiers
    req = gate.create_request("homie_send_email", {"to": "alice@example.com", "subject": "Test"})
    assert req.status == "PENDING"

    monkeypatch.setenv("HOMIE_MOCK_WINDOWS_HELLO", "1")
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
    req = gate.create_request("homie_send_email", {"to": "bob@example.com", "subject": "Test"})
    assert req.status == "PENDING"

    monkeypatch.setenv("HOMIE_MOCK_WINDOWS_HELLO", "0")
    ok, msg, token = gate.confirm(req.request_id, use_windows_hello=True)
    assert ok is False
    assert token is None
    assert "Windows Hello verification failed" in msg
    assert req.status == "PENDING"

