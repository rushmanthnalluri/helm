"""Windows Toast Notification Mirror for Helm.
Intercepts live Windows toast notifications using Windows Runtime (WinRT) APIs
and mirrors them to Telegram remote control and the persistent event log.
"""
import os
import time
import asyncio
import threading
import event_log

try:
    from winrt.windows.ui.notifications.management import (
        UserNotificationListener,
        UserNotificationListenerAccessStatus
    )
    from winrt.windows.ui.notifications import NotificationKinds
    WINRT_AVAILABLE = True
except ImportError:
    WINRT_AVAILABLE = False

class NotificationMirror:
    def __init__(self, on_notification_callback=None, poll_interval=3.5, db_path=None):
        self.on_notification_callback = on_notification_callback
        self.poll_interval = poll_interval
        self.db_path = db_path
        self.last_seen_id = 0
        self.initialized_history = False
        self.keep_running = False
        self._thread = None
        self._loop = None

    def is_supported(self):
        return WINRT_AVAILABLE

    def extract_notification_text(self, notification):
        """Extracts title and message body lines from a toast visual element."""
        texts = []
        try:
            visual = notification.notification.visual
            # Try ToastGeneric binding first
            binding = None
            try:
                binding = visual.get_binding("ToastGeneric")
            except Exception:
                pass

            if not binding:
                bindings = visual.bindings
                if bindings and len(bindings) > 0:
                    binding = bindings[0]

            if binding:
                for el in binding.get_text_elements():
                    t = (el.text or "").strip()
                    if t and t not in texts:
                        texts.append(t)
        except Exception:
            pass

        title = texts[0] if texts else ""
        body = " — ".join(texts[1:]) if len(texts) > 1 else ""
        full_text = " | ".join(texts)
        return title, body, full_text

    async def fetch_new_notifications(self):
        """Polls WinRT listener for new toast notifications."""
        if not WINRT_AVAILABLE:
            return []

        listener = UserNotificationListener.current
        status = listener.get_access_status()
        if status != UserNotificationListenerAccessStatus.ALLOWED:
            try:
                req_status = await listener.request_access_async()
                if req_status != UserNotificationListenerAccessStatus.ALLOWED:
                    return []
            except Exception:
                return []

        try:
            notifs = await listener.get_notifications_async(NotificationKinds.TOAST)
        except Exception:
            return []

        new_items = []
        max_id_seen = self.last_seen_id

        # First run: seed last_seen_id without blasting all historical toasts
        if not self.initialized_history:
            for n in notifs:
                if n.id > max_id_seen:
                    max_id_seen = n.id
            self.last_seen_id = max_id_seen
            self.initialized_history = True
            return []

        for n in notifs:
            if n.id > self.last_seen_id:
                if n.id > max_id_seen:
                    max_id_seen = n.id

                app_name = "Windows"
                try:
                    if n.app_info and n.app_info.display_info:
                        app_name = n.app_info.display_info.display_name or "Windows"
                except Exception:
                    pass

                title, body, full_text = self.extract_notification_text(n)
                if not full_text:
                    continue

                # Check focus mode / meeting suppression
                suppressed = False
                try:
                    import focus_tracker
                    suppressed = focus_tracker.is_foreground_window_fullscreen_or_meeting()
                except Exception:
                    pass

                item = {
                    'id': n.id,
                    'app': app_name,
                    'title': title,
                    'body': body,
                    'full_text': full_text,
                    'suppressed': suppressed
                }
                new_items.append(item)

                # Log to shared event log
                tag = " (Focus Suppressed)" if suppressed else ""
                summary = f"[{app_name}]{tag} {full_text}"
                event_log.log_event(
                    event_type="notification",
                    event_summary=summary,
                    db_path=self.db_path
                )

                if self.on_notification_callback:
                    try:
                        self.on_notification_callback(app_name, title, body, item)
                    except Exception:
                        pass

        self.last_seen_id = max_id_seen
        return new_items

    def _worker_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def poll_runner():
            while self.keep_running:
                try:
                    await self.fetch_new_notifications()
                except Exception:
                    pass
                await asyncio.sleep(self.poll_interval)

        self._loop.run_until_complete(poll_runner())

    def start(self):
        """Starts notification mirror polling in a daemon thread."""
        if not WINRT_AVAILABLE:
            print("[NotificationMirror] WinRT not available on this platform.")
            return False
        if self.keep_running:
            return True

        self.keep_running = True
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        """Stops notification mirror polling."""
        self.keep_running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
