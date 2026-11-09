"""tests/test_heartbeat_service.py - Tier 5 Acceptance Tests for Proactive Heartbeat.

Verifies:
1. Schedule due times persist across restarts (heartbeat_state.json).
2. Quiet hours enforcement (non-critical alerts held in log mode).
3. Catch-up inbox holds alerts when interface is closed or quiet hours active, delivered upon return.
4. Dismissible alerts (individual dismissal and inbox clearing).
5. Anti-overlap execution lock prevents duplicate/concurrent check execution.
6. Emergency kill switch halts heartbeat ticks immediately.
7. Custom check registration and state progression.
"""

from __future__ import annotations

import json
import tempfile
import time
from datetime import datetime
from pathlib import Path

import pytest

import kill_switch
from heartbeat_service import HeartbeatNotice, HeartbeatService


@pytest.fixture
def temp_hb_env():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        cfg_file = tmp_path / "heartbeat_checks.json"
        state_file = tmp_path / "heartbeat_state.json"
        inbox_file = tmp_path / "heartbeat_inbox.json"

        # Ensure kill switch is reset
        if kill_switch.is_kill_switch_active():
            kill_switch.disengage_kill_switch("human_test_cleanup")

        yield {
            "tmp_path": tmp_path,
            "cfg_file": cfg_file,
            "state_file": state_file,
            "inbox_file": inbox_file,
        }

        if kill_switch.is_kill_switch_active():
            kill_switch.disengage_kill_switch("human_test_cleanup")


def test_default_config_creation_and_load(temp_hb_env):
    service = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )
    cfg = service.load_config()
    assert cfg.get("enabled") is True
    assert "checks" in cfg
    assert len(cfg["checks"]) >= 2
    assert temp_hb_env["cfg_file"].exists()


def test_schedule_state_persistence_across_restarts(temp_hb_env):
    service1 = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )
    future_time = time.time() + 1800.0
    service1.save_state({"disk_space": future_time})

    # Simulate reboot: create a new service instance reading the same file
    service2 = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )
    loaded_state = service2.load_state()
    assert "disk_space" in loaded_state
    assert pytest.approx(loaded_state["disk_space"], 0.1) == future_time

    # Tick at an earlier time should not trigger disk_space check
    service2.register_check_runner("disk_space", lambda p: ("Disk Alert", "Out of space", "high"))
    notices = service2.tick(now=future_time - 100.0)
    assert len(notices) == 0


def test_quiet_hours_enforcement(temp_hb_env):
    service = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )

    # Configure quiet hours 22:00 to 08:00
    cfg = service.load_config()
    cfg["quiet_hours"] = {"enabled": True, "start_hour": 22, "end_hour": 8}
    service.save_config(cfg)

    # Midnight (01:00) should be in quiet hours
    dt_midnight = datetime(2026, 11, 9, 1, 0, 0)
    assert service.is_in_quiet_hours(now_dt=dt_midnight) is True

    # Noon (12:00) should not be in quiet hours
    dt_noon = datetime(2026, 11, 9, 12, 0, 0)
    assert service.is_in_quiet_hours(now_dt=dt_noon) is False


def test_catch_up_inbox_and_delivery(temp_hb_env):
    service = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )

    # Simulate interface being closed (user away)
    service.is_interface_open = False
    service.register_check_runner(
        "custom_alert",
        lambda p: ("Backup Complete", "Daily snapshot finished successfully", "medium"),
    )

    cfg = {
        "enabled": True,
        "quiet_hours": {"enabled": False},
        "checks": [
            {
                "id": "custom_alert",
                "name": "Custom",
                "enabled": True,
                "interval_seconds": 60.0,
            }
        ],
    }
    service.save_config(cfg)

    # Run tick
    surfaced = service.tick(now=1000.0)
    assert len(surfaced) == 1
    notice = surfaced[0]
    assert notice.held is True
    assert notice.delivery_mode == "log"

    # Verify pending inbox
    pending = service.get_pending_held_notices()
    assert len(pending) == 1
    assert pending[0].title == "Backup Complete"

    # User opens interface: delivery should catch up
    service.is_interface_open = True
    delivered = service.mark_notices_delivered()
    assert len(delivered) == 1
    assert delivered[0].held is False

    # No more pending held notices
    assert len(service.get_pending_held_notices()) == 0


def test_dismiss_notice_and_clear_inbox(temp_hb_env):
    service = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )

    n1 = HeartbeatNotice("n_1", "check_a", "Title 1", "Msg 1")
    n2 = HeartbeatNotice("n_2", "check_b", "Title 2", "Msg 2")
    service.save_inbox([n1, n2])

    assert len(service.load_inbox()) == 2

    # Dismiss n_1
    dismissed = service.dismiss_notice("n_1")
    assert dismissed is True

    inbox = service.load_inbox()
    assert inbox[0].dismissed is True
    assert inbox[1].dismissed is False

    # Clear inbox
    service.clear_inbox()
    assert len(service.load_inbox()) == 0


def test_anti_overlap_execution_lock(temp_hb_env):
    service = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )

    call_count = 0

    def slow_runner(params):
        nonlocal call_count
        call_count += 1
        return ("Slow Check", "Finished", "low")

    service.register_check_runner("slow_check", slow_runner)
    check_cfg = {"id": "slow_check", "enabled": True}

    # Simulate slow_check currently in flight
    service._running_checks.add("slow_check")

    res = service.execute_single_check(check_cfg, now=time.time())
    assert res is None
    assert call_count == 0  # Was skipped due to anti-overlap lock

    # Once lock released, can execute
    service._running_checks.remove("slow_check")
    res2 = service.execute_single_check(check_cfg, now=time.time())
    assert res2 is not None
    assert call_count == 1


def test_emergency_kill_switch_halts_heartbeat(temp_hb_env):
    service = HeartbeatService(
        config_path=temp_hb_env["cfg_file"],
        state_path=temp_hb_env["state_file"],
        inbox_path=temp_hb_env["inbox_file"],
    )

    call_count = 0
    service.register_check_runner("urgent_check", lambda p: ("Title", "Msg", "high"))
    cfg = {
        "enabled": True,
        "quiet_hours": {"enabled": False},
        "checks": [{"id": "urgent_check", "enabled": True, "interval_seconds": 10.0}],
    }
    service.save_config(cfg)

    # Engage kill switch
    kill_switch.engage_kill_switch("testing emergency kill switch on heartbeat")
    assert kill_switch.is_kill_switch_active() is True

    # Tick should return immediately without executing check
    surfaced = service.tick(now=5000.0)
    assert surfaced == []

    # Disengage kill switch with valid human token
    success, _ = kill_switch.disengage_kill_switch("human_test_admin")
    assert success is True
    assert kill_switch.is_kill_switch_active() is False
    surfaced_after = service.tick(now=5000.0)
    assert len(surfaced_after) == 1
