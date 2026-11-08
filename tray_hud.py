"""System Tray Quick Menu and Unified Desktop HUD for Homie.
Exposes a responsive Windows system tray menu with instant access to Workspaces,
Pinned Notes, Meeting Loopback recording, and Productivity Focus summaries.
"""
import os
import pystray
from PIL import Image, ImageDraw
import quick_notes
import workspace_manager
import meeting_notes
import focus_tracker
import windows_tools

def truncate_for_menu(text: str, max_length: int = 28) -> str:
    """Truncates long text to fit cleanly inside native OS context menus."""
    clean = str(text or "").replace('\n', ' ').strip()
    if len(clean) <= max_length:
        return clean
    return clean[:max_length - 3] + "..."

def create_default_icon_image():
    """Generates a stylish glowing orb icon if no file icon is provided."""
    img = Image.new('RGBA', (64, 64), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Outer glow
    draw.ellipse((4, 4, 60, 60), fill=(99, 102, 241, 180)) # Indigo glow
    # Inner vibrant circle
    draw.ellipse((12, 12, 52, 52), fill=(168, 85, 247, 240)) # Purple core
    # Center dot
    draw.ellipse((22, 22, 42, 42), fill=(255, 255, 255, 255)) # White center
    return img

def get_workspace_menu_items():
    """Dynamically generates menu items for restoring saved workspace layouts."""
    presets = workspace_manager.get_all_presets()
    if not presets:
        return [pystray.MenuItem("No saved workspaces", lambda icon, item: None, enabled=False)]

    items = []
    for p in presets:
        def make_restore_cb(name):
            return lambda icon, item: workspace_manager.restore_workspace_preset(name)
        items.append(pystray.MenuItem(f"🖥 {p.capitalize()}", make_restore_cb(p)))
    return items

def get_pinned_notes_menu_items():
    """Dynamically generates menu items for pinned notes with click-to-copy."""
    pinned = quick_notes.get_pinned_notes(limit=8)
    if not pinned:
        return [pystray.MenuItem("No pinned notes", lambda icon, item: None, enabled=False)]

    items = []
    for n in pinned:
        txt = n['note_text']
        label = truncate_for_menu(txt, 26)
        def make_copy_cb(content):
            return lambda icon, item: windows_tools.set_clipboard_text(content)
        items.append(pystray.MenuItem(f"📌 {label}", make_copy_cb(txt)))
    return items

def build_tray_menu(app=None):
    """Constructs the comprehensive unified HUD system tray menu."""
    def on_copy_telegram_pairing_command(icon, item):
        bridge = getattr(app, 'telegram', None) if app else None
        if not bridge or not bridge.token:
            message = "Configure TELEGRAM_BOT_TOKEN before pairing a phone."
        else:
            command = bridge.get_pairing_command()
            if not command:
                message = "Telegram is already paired, or no pairing is available."
            else:
                ok, _ = windows_tools.set_clipboard_text(command)
                message = (
                    "Pairing command copied. Paste it into Homie's private Telegram chat within 15 minutes."
                    if ok else "Could not copy the pairing command to the clipboard."
                )

        try:
            icon.notify(message, "Homie Telegram pairing")
        except Exception:
            print(f"[Homie] {message}", flush=True)

    def on_meeting_start(icon, item):
        sess = meeting_notes.get_meeting_session()
        sess.start_meeting("Desktop Quick Meeting")

    def on_meeting_stop(icon, item):
        sess = meeting_notes.get_meeting_session()
        sess.stop_meeting()

    def on_copy_phone_call_url(icon, item):
        import phone_gateway
        import socket
        phone_gateway.start_phone_gateway(5055)
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "localhost"
        url = f"http://{ip}:5055/call"
        windows_tools.set_clipboard_text(url)
        try:
            icon.notify(f"Copied: {url}\nOpen on your phone to call your PC!", "Homie Phone Call")
        except Exception:
            pass

    def on_focus_report(icon, item):
        report = focus_tracker.get_focus_report(lookback_hours=24)
        if report:
            lines = [f"{r['application_name']}: {r['formatted_duration']}" for r in report[:5]]
            windows_tools.set_clipboard_text("\n".join(lines))

    def on_exit(icon, item):
        icon.stop()
        if app and hasattr(app, 'stop'):
            app.stop()

    meeting_sess = meeting_notes.get_meeting_session()
    is_meeting = meeting_sess.is_active if meeting_sess else False

    menu = pystray.Menu(
        pystray.MenuItem("🎙 Homie Voice Assistant", lambda icon, item: None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("🖥 Workspaces", pystray.Menu(lambda: get_workspace_menu_items())),
        pystray.MenuItem("📌 Pinned Notes", pystray.Menu(lambda: get_pinned_notes_menu_items())),
        pystray.MenuItem("📱 Copy Telegram pairing command", on_copy_telegram_pairing_command),
        pystray.MenuItem("📞 Copy Phone Call URL", on_copy_phone_call_url),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "⏹ Stop Meeting Notes" if is_meeting else "🎙 Start Meeting Notes",
            on_meeting_stop if is_meeting else on_meeting_start
        ),
        pystray.MenuItem("📊 Copy Focus Report (24h)", on_focus_report),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("❌ Exit Homie", on_exit)
    )
    return menu

def create_tray_hud(app=None, icon_path=None):
    """Creates a pystray Icon instance with the dynamic menu HUD."""
    image = None
    if icon_path and os.path.exists(icon_path):
        try:
            image = Image.open(icon_path)
        except Exception:
            pass

    if not image:
        image = create_default_icon_image()

    icon = pystray.Icon(
        name="Homie",
        icon=image,
        title="Homie - Windows AI Assistant",
        menu=build_tray_menu(app=app)
    )
    return icon
