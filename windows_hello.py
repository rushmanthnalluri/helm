"""
Homie Windows Hello Biometric Authentication Integration.
Uses WinRT Windows.Security.Credentials.UI.UserConsentVerifier for native
fingerprint, facial recognition (IR camera), or Windows PIN verification.
"""
import asyncio
import logging
import os
import sys
import threading
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Cache availability to avoid repeated WinRT overhead
_AVAILABILITY_CACHE: Optional[bool] = None
_CACHE_LOCK = threading.Lock()


def is_windows_hello_available() -> bool:
    """
    Check if Windows Hello (biometrics or PIN) is configured and available.
    Returns True if user has Windows Hello enabled.
    """
    global _AVAILABILITY_CACHE
    with _CACHE_LOCK:
        if _AVAILABILITY_CACHE is not None:
            return _AVAILABILITY_CACHE

    # In automated test environments, don't trigger interactive UI by default
    if os.environ.get("HOMIE_TEST_MODE") or os.environ.get("PYTEST_CURRENT_TEST"):
        return False

    try:
        import winrt.windows.security.credentials.ui as consent_ui
        
        async def _check():
            avail = await consent_ui.UserConsentVerifier.check_availability_async()
            # 0 == UserConsentVerifierAvailability.AVAILABLE
            return int(avail) == 0

        # Run in a clean event loop or thread if loop is already active
        try:
            loop = asyncio.new_event_loop()
            available = loop.run_until_complete(_check())
            loop.close()
        except RuntimeError:
            # Fallback if in an environment with complex loop lifecycle
            available = False

        with _CACHE_LOCK:
            _AVAILABILITY_CACHE = available
        logger.info(f"[WindowsHello] Availability check: {'Available' if available else 'Unavailable'}")
        return available
    except ImportError:
        logger.debug("[WindowsHello] winrt.windows.security.credentials.ui not installed.")
        with _CACHE_LOCK:
            _AVAILABILITY_CACHE = False
        return False
    except Exception as e:
        logger.warning(f"[WindowsHello] Error checking availability: {e}")
        with _CACHE_LOCK:
            _AVAILABILITY_CACHE = False
        return False


def prompt_windows_hello(
    prompt_message: str = "Homie AI: Authorize consequential desktop action",
    timeout_seconds: float = 30.0
) -> Dict[str, Any]:
    """
    Prompt the user with native Windows Hello biometric / PIN verification.
    Blocks synchronously until user completes verification, dismisses prompt,
    or timeout expires.

    Returns:
        dict with keys:
            - 'verified' (bool): True if biometrics / PIN matched
            - 'status' (str): 'verified', 'canceled', 'retries_exhausted', 'disabled', 'error'
            - 'error' (str): error description if applicable
    """
    # Test mode hook for mocking in automated tests
    mock_env = os.environ.get("HOMIE_MOCK_WINDOWS_HELLO")
    if mock_env == "1" or mock_env == "true":
        logger.info("[WindowsHello] Mocked verification: SUCCESS")
        return {"verified": True, "status": "verified", "method": "mock"}
    elif mock_env == "0" or mock_env == "false":
        logger.info("[WindowsHello] Mocked verification: REJECTED")
        return {"verified": False, "status": "canceled", "method": "mock"}

    try:
        import winrt.windows.security.credentials.ui as consent_ui
    except ImportError:
        return {
            "verified": False,
            "status": "unavailable",
            "error": "WinRT UserConsentVerifier module not installed",
        }

    result_holder = {"verified": False, "status": "unknown", "error": None}

    async def _verify_async():
        try:
            res = await consent_ui.UserConsentVerifier.request_verification_async(prompt_message)
            code = int(res)
            # UserConsentVerificationResult:
            # 0 = Verified
            # 1 = DeviceNotPresent
            # 2 = NotConfiguredForUser
            # 3 = DisabledByPolicy
            # 4 = DeviceBusy
            # 5 = RetriesExhausted
            # 6 = Canceled
            if code == 0:
                result_holder["verified"] = True
                result_holder["status"] = "verified"
            elif code == 6:
                result_holder["verified"] = False
                result_holder["status"] = "canceled"
            elif code == 5:
                result_holder["verified"] = False
                result_holder["status"] = "retries_exhausted"
            else:
                result_holder["verified"] = False
                result_holder["status"] = f"unverified_code_{code}"
        except Exception as e:
            result_holder["verified"] = False
            result_holder["status"] = "error"
            result_holder["error"] = str(e)

    def _worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                asyncio.wait_for(_verify_async(), timeout=timeout_seconds)
            )
        except asyncio.TimeoutError:
            result_holder["verified"] = False
            result_holder["status"] = "timeout"
            result_holder["error"] = f"Windows Hello prompt timed out after {timeout_seconds}s"
        except Exception as e:
            result_holder["verified"] = False
            result_holder["status"] = "error"
            result_holder["error"] = str(e)
        finally:
            loop.close()

    t = threading.Thread(target=_worker, name="WindowsHelloWorker", daemon=True)
    t.start()
    t.join(timeout=timeout_seconds + 2.0)

    logger.info(f"[WindowsHello] Prompt result: {result_holder['status']} (verified={result_holder['verified']})")
    return result_holder
