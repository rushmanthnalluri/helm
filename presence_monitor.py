"""Presence and Idle Catch-Up Monitor for Helm.
Detects when the user steps away from their PC and when they return,
compiling a timeline of notifications, reminders, and alerts that occurred during absence.
"""
import time
import threading
import event_log
import windows_tools

DEFAULT_AWAY_THRESHOLD_SECONDS = 300  # 5 minutes

class PresenceMonitor:
    def __init__(self, away_threshold_seconds=DEFAULT_AWAY_THRESHOLD_SECONDS, on_user_returned_callback=None, poll_interval=3.0, db_path=None):
        self.away_threshold_seconds = away_threshold_seconds
        self.on_user_returned_callback = on_user_returned_callback
        self.poll_interval = poll_interval
        self.db_path = db_path
        self.is_currently_away = False
        self.away_started_at = None
        self.keep_running = False
        self._thread = None

    def start(self):
        """Starts presence polling in a daemon thread."""
        if self.keep_running:
            return
        self.keep_running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stops the presence polling loop."""
        self.keep_running = False

    def check_presence(self, idle_seconds=None):
        """Single tick evaluation of user presence. Returns True if return event fired."""
        if idle_seconds is None:
            idle_seconds = windows_tools.get_idle_seconds()

        # 1. User transitioned to away
        if idle_seconds >= self.away_threshold_seconds and not self.is_currently_away:
            self.is_currently_away = True
            self.away_started_at = time.time() - idle_seconds
            event_log.log_event(
                event_type="presence",
                event_summary="User stepped away from PC",
                occurred_at=self.away_started_at,
                db_path=self.db_path
            )
            return False

        # 2. User transitioned back to active from away
        elif idle_seconds < 3.0 and self.is_currently_away:
            self.is_currently_away = False
            away_duration = max(1.0, time.time() - (self.away_started_at or (time.time() - 300)))
            absence_start = self.away_started_at or (time.time() - away_duration)
            self.away_started_at = None

            events_during_absence = event_log.get_events_since(absence_start, db_path=self.db_path)
            # Filter out the initial away presence event itself
            missed_events = [e for e in events_during_absence if e.get('event_type') != 'presence']

            mins = round(away_duration / 60.0, 1)
            event_log.log_event(
                event_type="presence",
                event_summary=f"User returned to PC after {mins} min away ({len(missed_events)} events during absence)",
                db_path=self.db_path
            )

            if self.on_user_returned_callback:
                try:
                    self.on_user_returned_callback(away_duration, missed_events)
                except Exception:
                    pass
            return True

        return False

    def _poll_loop(self):
        while self.keep_running:
            try:
                self.check_presence()
            except Exception:
                pass
            time.sleep(self.poll_interval)
