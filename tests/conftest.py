"""tests/conftest.py - PyTest Harness Isolation Fixture for Helm Test Suites.

Ensures every test executes with a clean slate:
- Purges lingering dirty-flag and crash-history markers.
- Resets emergency kill switch state.
- Resets taint tracking registries.
- Resets global action broker instance.
"""

import os
import sys
import tempfile
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# All test persistence lives in an ephemeral tree. In particular, device
# enrollment and daemon tests must not touch the user's registry, recovery
# token, PID, session token, settings, or SQLite database.
_TEST_STATE = tempfile.TemporaryDirectory(
    prefix="helm-pytest-", ignore_cleanup_errors=True
)
_TEST_STATE_DIR = _TEST_STATE.name
os.environ["HELM_TEST_STATE_DIR"] = _TEST_STATE_DIR
os.environ["HELM_DIR"] = os.path.join(_TEST_STATE_DIR, "config")
os.makedirs(os.environ["HELM_DIR"], exist_ok=True)

import helm_supervisor
import device_registry
import phone_approval_portal
import kill_switch
import taint_tracker
import action_broker
import db_utils


def _init_test_database():
    """Create the database table used by screen memory tests."""
    with db_utils.get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS screen_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                proc_name TEXT,
                window_title TEXT,
                text_content TEXT,
                summary TEXT
            )"""
        )
        conn.commit()


@pytest.fixture(autouse=True)
def clean_helm_test_isolation():
    """Autouse fixture providing test isolation for supervisor and kill switch states."""
    prior_test_env = os.environ.get("HELM_TEST_ENV")
    for p in [helm_supervisor.DIRTY_FLAG_PATH, helm_supervisor.CRASH_HISTORY_PATH]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    kill_switch._KILL_SWITCH_ACTIVE = False
    kill_switch._ENGAGED_REASON = ""
    taint_tracker.clear_all_taints()
    taint_tracker.set_standalone_mode(True)
    device_registry.clear_registry_for_testing()
    device_registry.clear_consumed_nonces_for_testing()
    _init_test_database()
    action_broker.set_action_broker(
        action_broker.ActionBroker(standalone_mode=True)
    )

    yield

    for p in [helm_supervisor.DIRTY_FLAG_PATH, helm_supervisor.CRASH_HISTORY_PATH]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    kill_switch._KILL_SWITCH_ACTIVE = False
    kill_switch._ENGAGED_REASON = ""
    taint_tracker.clear_all_taints()
    taint_tracker.set_standalone_mode(True)
    device_registry.clear_registry_for_testing()
    device_registry.clear_consumed_nonces_for_testing()
    phone_approval_portal._CONSOLE_RECOVERY_TOKENS.clear()
    phone_approval_portal._LOCAL_ENROLLMENT_SESSIONS.clear()
    action_broker._GLOBAL_BROKER = None
    if prior_test_env is None:
        os.environ.pop("HELM_TEST_ENV", None)
    else:
        os.environ["HELM_TEST_ENV"] = prior_test_env


def pytest_sessionfinish(session, exitstatus):
    _TEST_STATE.cleanup()
