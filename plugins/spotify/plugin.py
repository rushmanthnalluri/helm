"""Spotify Media Controller Plugin for Helm.

Provides real playback control, track search, and playback status using the spotipy library
and implements the HelmPlugin interface.
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("helm.plugins.spotify")

try:
    from helm_plugin_sdk import HelmPlugin, PluginContext, PluginTool, PluginCommand
except ImportError:
    # Graceful fallback if imported standalone
    class HelmPlugin:  # type: ignore
        def __init__(self, context: Any): self.context = context
        def initialize(self): pass
        def shutdown(self): pass
        def get_tools(self): return []
        def get_commands(self): return []
    PluginContext = Any  # type: ignore
    PluginTool = Any  # type: ignore
    PluginCommand = Any  # type: ignore

try:
    import spotipy
    from spotipy.oauth2 import SpotifyOAuth
    HAS_SPOTIPY = True
except ImportError:
    spotipy = None  # type: ignore
    SpotifyOAuth = None  # type: ignore
    HAS_SPOTIPY = False


def get_spotify_client(client: Optional[Any] = None) -> Any:
    """Gets or initializes a Spotipy client instance.

    If a client is explicitly supplied (e.g. for testing/mocking), returns that.
    Otherwise resolves credentials from environment variables:
    - SPOTIPY_AUTH_TOKEN / SPOTIFY_ACCESS_TOKEN
    - SPOTIPY_CLIENT_ID / SPOTIFY_CLIENT_ID + SPOTIPY_CLIENT_SECRET / SPOTIFY_CLIENT_SECRET
    """
    if client is not None:
        return client

    if not HAS_SPOTIPY:
        raise RuntimeError(
            "The 'spotipy' package is not installed. Please install it using `pip install spotipy`."
        )

    auth_token = os.environ.get("SPOTIPY_AUTH_TOKEN") or os.environ.get("SPOTIFY_ACCESS_TOKEN")
    if auth_token:
        return spotipy.Spotify(auth=auth_token)

    client_id = os.environ.get("SPOTIPY_CLIENT_ID") or os.environ.get("SPOTIFY_CLIENT_ID")
    client_secret = os.environ.get("SPOTIPY_CLIENT_SECRET") or os.environ.get("SPOTIFY_CLIENT_SECRET")
    redirect_uri = (
        os.environ.get("SPOTIPY_REDIRECT_URI")
        or os.environ.get("SPOTIFY_REDIRECT_URI")
        or "http://localhost:8888/callback"
    )

    if client_id and client_secret:
        auth_manager = SpotifyOAuth(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scope="user-modify-playback-state user-read-playback-state user-read-currently-playing",
        )
        return spotipy.Spotify(auth_manager=auth_manager)

    try:
        return spotipy.Spotify()
    except Exception as e:
        raise RuntimeError(
            f"Spotify credentials not configured. Please set SPOTIPY_CLIENT_ID & SPOTIPY_CLIENT_SECRET or SPOTIPY_AUTH_TOKEN: {e}"
        )


def spotify_play(query: str = "", **kwargs) -> Dict[str, Any]:
    """Search and play a track on Spotify by query, or resume playback if query is empty."""
    client = kwargs.get("client")
    try:
        sp = get_spotify_client(client=client)
        q = (query or "").strip()
        if q:
            results = sp.search(q=q, limit=1, type="track")
            tracks = results.get("tracks", {}).get("items", []) if results else []
            if not tracks:
                return {"ok": False, "error": f"No tracks found matching query: '{q}'"}

            track = tracks[0]
            track_uri = track.get("uri")
            track_name = track.get("name", "Unknown Track")
            artists = [a.get("name") for a in track.get("artists", []) if a.get("name")]
            artist_str = ", ".join(artists) if artists else "Unknown Artist"
            album_name = track.get("album", {}).get("name", "")

            sp.start_playback(uris=[track_uri])
            return {
                "ok": True,
                "action": "play",
                "status": "playing",
                "track": track_name,
                "artist": artist_str,
                "album": album_name,
                "uri": track_uri,
                "message": f"Playing '{track_name}' by {artist_str}",
            }
        else:
            sp.start_playback()
            return {
                "ok": True,
                "action": "play",
                "status": "resumed",
                "message": "Playback resumed.",
            }
    except Exception as e:
        return {"ok": False, "error": f"spotify_play failed: {e}"}


def spotify_pause(**kwargs) -> Dict[str, Any]:
    """Pause current Spotify playback."""
    client = kwargs.get("client")
    try:
        sp = get_spotify_client(client=client)
        sp.pause_playback()
        return {
            "ok": True,
            "action": "pause",
            "status": "paused",
            "message": "Playback paused.",
        }
    except Exception as e:
        return {"ok": False, "error": f"spotify_pause failed: {e}"}


def spotify_now_playing(**kwargs) -> Dict[str, Any]:
    """Return current track info from Spotify."""
    client = kwargs.get("client")
    try:
        sp = get_spotify_client(client=client)
        current = sp.current_playback()
        if not current or not current.get("item"):
            current = sp.current_user_playing_track()

        if current and current.get("item"):
            item = current["item"]
            track_name = item.get("name", "Unknown Track")
            artists = [a.get("name") for a in item.get("artists", []) if a.get("name")]
            artist_str = ", ".join(artists) if artists else "Unknown Artist"
            album_name = item.get("album", {}).get("name", "")
            is_playing = current.get("is_playing", False)
            progress_ms = current.get("progress_ms", 0)
            duration_ms = item.get("duration_ms", 0)
            uri = item.get("uri", "")

            status_str = "Playing" if is_playing else "Paused"
            return {
                "ok": True,
                "is_playing": is_playing,
                "status": status_str.lower(),
                "track": track_name,
                "artist": artist_str,
                "artists": artists,
                "album": album_name,
                "progress_ms": progress_ms,
                "duration_ms": duration_ms,
                "uri": uri,
                "message": f"{status_str}: '{track_name}' by {artist_str}",
            }

        return {
            "ok": True,
            "is_playing": False,
            "status": "stopped",
            "message": "No active playback found.",
        }
    except Exception as e:
        return {"ok": False, "error": f"spotify_now_playing failed: {e}"}


def spotify_search(query: str, limit: int = 5, **kwargs) -> Dict[str, Any]:
    """Search tracks on Spotify without immediately playing."""
    client = kwargs.get("client")
    try:
        sp = get_spotify_client(client=client)
        q = (query or "").strip()
        if not q:
            return {"ok": False, "error": "Query cannot be empty"}
        results = sp.search(q=q, limit=limit, type="track")
        items = results.get("tracks", {}).get("items", []) if results else []
        formatted = []
        for it in items:
            formatted.append({
                "name": it.get("name"),
                "artist": ", ".join([a.get("name") for a in it.get("artists", []) if a.get("name")]),
                "album": it.get("album", {}).get("name"),
                "uri": it.get("uri"),
                "duration_ms": it.get("duration_ms"),
            })
        return {
            "ok": True,
            "query": q,
            "count": len(formatted),
            "tracks": formatted,
        }
    except Exception as e:
        return {"ok": False, "error": f"spotify_search failed: {e}"}


def spotify_next(**kwargs) -> Dict[str, Any]:
    """Skip to next track on Spotify."""
    client = kwargs.get("client")
    try:
        sp = get_spotify_client(client=client)
        sp.next_track()
        return {"ok": True, "action": "next", "message": "Skipped to next track."}
    except Exception as e:
        return {"ok": False, "error": f"spotify_next failed: {e}"}


def spotify_previous(**kwargs) -> Dict[str, Any]:
    """Skip to previous track on Spotify."""
    client = kwargs.get("client")
    try:
        sp = get_spotify_client(client=client)
        sp.previous_track()
        return {"ok": True, "action": "previous", "message": "Skipped to previous track."}
    except Exception as e:
        return {"ok": False, "error": f"spotify_previous failed: {e}"}


# ---------------------------------------------------------------------------
# SpotifyPlugin HelmPlugin Implementation
# ---------------------------------------------------------------------------

class SpotifyPlugin(HelmPlugin):
    """Production Spotify Desktop/Web Player Plugin for Helm."""

    def initialize(self) -> None:
        self.logger.info("Initializing Spotify Plugin")
        # Validate spotipy availability or credentials availability
        if not HAS_SPOTIPY:
            self.logger.warning("spotipy library not installed; mocking or pip install spotipy required for live API.")

    def shutdown(self) -> None:
        self.logger.info("Shutting down Spotify Plugin")

    def get_tools(self) -> List[PluginTool]:
        return [
            PluginTool(
                name="spotify_play",
                description="Search and play a track on Spotify by query, or resume playback if query is empty.",
                handler=spotify_play,
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Track, artist, or album name to search and play"}
                    }
                },
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
            PluginTool(
                name="spotify_pause",
                description="Pause current Spotify playback.",
                handler=spotify_pause,
                parameters={"type": "object", "properties": {}},
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
            PluginTool(
                name="spotify_now_playing",
                description="Return current track info from Spotify.",
                handler=spotify_now_playing,
                parameters={"type": "object", "properties": {}},
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="spotify_search",
                description="Search tracks, artists, or albums on Spotify without playing.",
                handler=spotify_search,
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "limit": {"type": "integer", "description": "Max results to return"}
                    },
                    "required": ["query"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="spotify_next",
                description="Skip to next track on Spotify.",
                handler=spotify_next,
                parameters={"type": "object", "properties": {}},
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
            PluginTool(
                name="spotify_previous",
                description="Skip to previous track on Spotify.",
                handler=spotify_previous,
                parameters={"type": "object", "properties": {}},
                required_permissions=["network"],
                capability_tier="ACTIONS",
            ),
        ]

    def get_commands(self) -> List[PluginCommand]:
        return [
            PluginCommand(
                id="play",
                title="Play Track",
                description="Play track or resume playback",
                handler=spotify_play,
                shortcut="Ctrl+Shift+P",
            ),
            PluginCommand(
                id="pause",
                title="Pause Playback",
                description="Pause active playback",
                handler=spotify_pause,
                shortcut="Ctrl+Shift+Space",
            ),
            PluginCommand(
                id="now_playing",
                title="Now Playing",
                description="View currently playing track",
                handler=spotify_now_playing,
            ),
            PluginCommand(
                id="next",
                title="Next Track",
                description="Skip to next track",
                handler=spotify_next,
                shortcut="Ctrl+Shift+Right",
            ),
            PluginCommand(
                id="previous",
                title="Previous Track",
                description="Skip to previous track",
                handler=spotify_previous,
                shortcut="Ctrl+Shift+Left",
            ),
        ]
