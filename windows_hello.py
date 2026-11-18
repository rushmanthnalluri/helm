"""
Homie Windows Hello Biometric Authentication Integration.
Uses WinRT Windows.Security.Credentials.UI.UserConsentVerifier for native
fingerprint, facial recognition (IR camera), or Windows PIN verification.
"""
from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import sys
import threading
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Cache availability to avoid repeated WinRT overhead
_AVAILABILITY_CACHE: Optional[bool] = None
_CACHE_LOCK = threading.Lock()


class WindowsHello:
    """Windows Hello on-device biometric and PIN verification provider."""

    @classmethod
    def is_available(cls) -> bool:
        """Check if Windows Hello (biometrics or PIN) is configured and available.
        Checks UserConsentVerifier.CheckAvailabilityAsync() returns ConsentVerifierAvailability.AVAILABLE.
        """
        # Test mode hook for mocking in automated tests
        mock_avail = os.environ.get("HOMIE_MOCK_WINDOWS_HELLO_AVAILABLE")
        if mock_avail is not None:
            return mock_avail.lower() in ("1", "true", "yes")

        mock_env = os.environ.get("HOMIE_MOCK_WINDOWS_HELLO")
        if mock_env is not None:
            return mock_env.lower() in ("1", "true", "yes")

        # In automated test mode without explicit mock, avoid interactive prompts or hangs
        if os.environ.get("HOMIE_TEST_MODE") or os.environ.get("PYTEST_CURRENT_TEST"):
            return False

        global _AVAILABILITY_CACHE
        with _CACHE_LOCK:
            if _AVAILABILITY_CACHE is not None:
                return _AVAILABILITY_CACHE

        try:
            import winrt.windows.security.credentials.ui as consent_ui

            verifier = consent_ui.UserConsentVerifier
            check_fn = getattr(verifier, "check_availability_async", getattr(verifier, "CheckAvailabilityAsync", None))
            if not check_fn:
                with _CACHE_LOCK:
                    _AVAILABILITY_CACHE = False
                return False

            async def _check():
                avail = await check_fn()
                # 0 == UserConsentVerifierAvailability.AVAILABLE
                return int(avail) == 0

            try:
                loop = asyncio.new_event_loop()
                available = loop.run_until_complete(_check())
                loop.close()
            except RuntimeError:
                available = False

            with _CACHE_LOCK:
                _AVAILABILITY_CACHE = available
            logger.info("[WindowsHello] Availability check: %s", "Available" if available else "Unavailable")
            return available
        except ImportError:
            logger.debug("[WindowsHello] winrt module not installed.")
            with _CACHE_LOCK:
                _AVAILABILITY_CACHE = False
            return False
        except Exception as e:
            logger.warning("[WindowsHello] Error checking availability: %s", e)
            with _CACHE_LOCK:
                _AVAILABILITY_CACHE = False
            return False

    @classmethod
    async def verify(cls, reason: str = "Homie needs your approval") -> bool:
        """Trigger UserConsentVerifier.RequestVerificationAsync(reason).
        Returns True if biometric/PIN passes, False on cancel or failure.
        """
        mock_env = os.environ.get("HOMIE_MOCK_WINDOWS_HELLO")
        if mock_env is not None:
            res = mock_env.lower() in ("1", "true", "yes")
            logger.info("[WindowsHello] Mocked verify: %s", res)
            return res

        try:
            import winrt.windows.security.credentials.ui as consent_ui

            verifier = consent_ui.UserConsentVerifier
            req_fn = getattr(verifier, "request_verification_async", getattr(verifier, "RequestVerificationAsync", None))
            if not req_fn:
                logger.warning("[WindowsHello] RequestVerificationAsync not found on UserConsentVerifier")
                return False

            res = await req_fn(reason)
            # 0 == UserConsentVerificationResult.VERIFIED
            code = int(res)
            logger.info("[WindowsHello] RequestVerification result code: %d", code)
            return code == 0
        except Exception as e:
            logger.warning("[WindowsHello] Error during biometric verification: %s", e)
            return False

    @classmethod
    def verify_sync(cls, reason: str = "Homie needs your approval", timeout_seconds: float = 30.0) -> bool:
        """Synchronous wrapper for verify(reason) using asyncio.run() or a dedicated thread worker."""
        mock_env = os.environ.get("HOMIE_MOCK_WINDOWS_HELLO")
        if mock_env is not None:
            return mock_env.lower() in ("1", "true", "yes")

        try:
            # If an event loop is already running in current thread, run in a dedicated worker thread
            asyncio.get_running_loop()
            in_running_loop = True
        except RuntimeError:
            in_running_loop = False

        if not in_running_loop:
            try:
                return asyncio.run(asyncio.wait_for(cls.verify(reason), timeout=timeout_seconds))
            except Exception as e:
                logger.warning("[WindowsHello] verify_sync asyncio.run error: %s", e)
                return False

        # In running event loop: run in worker thread
        result = [False]

        def _worker():
            try:
                result[0] = asyncio.run(asyncio.wait_for(cls.verify(reason), timeout=timeout_seconds))
            except Exception as ex:
                logger.warning("[WindowsHello] verify_sync worker exception: %s", ex)
                result[0] = False

        t = threading.Thread(target=_worker, name="WindowsHelloWorker", daemon=True)
        t.start()
        t.join(timeout=timeout_seconds + 2.0)
        return result[0]


# Backward-compatible module-level functions
def is_windows_hello_available() -> bool:
    return WindowsHello.is_available()


def prompt_windows_hello(
    prompt_message: str = "Homie AI: Authorize consequential desktop action",
    timeout_seconds: float = 30.0,
) -> Dict[str, Any]:
    verified = WindowsHello.verify_sync(prompt_message, timeout_seconds=timeout_seconds)
    status = "verified" if verified else "canceled"
    return {"verified": verified, "status": status}
