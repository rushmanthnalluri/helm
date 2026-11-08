"""tests/conftest.py - PyTest Harness Isolation Fixture for Homie Test Suites.

Ensures every test executes with a clean slate:
- Purges lingering dirty-flag and crash-history markers.
- Resets emergency kill switch state.
- Resets taint tracking registries.
- Resets global action broker instance.
"""

import os
import sys
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import homie_supervisor
import kill_switch
import taint_tracker
import action_broker


@pytest.fixture(autouse=True)
def clean_homie_test_isolation():
    """Autouse fixture providing test isolation for supervisor and kill switch states."""
    for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    kill_switch._KILL_SWITCH_ACTIVE = False
    kill_switch._ENGAGED_REASON = ""
    taint_tracker.clear_all_taints()
    action_broker._GLOBAL_BROKER = None

    yield

    for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    kill_switch._KILL_SWITCH_ACTIVE = False
    kill_switch._ENGAGED_REASON = ""
    taint_tracker.clear_all_taints()
    action_broker._GLOBAL_BROKER = None
