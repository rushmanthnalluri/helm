"""Spotify Media Controller Plugin for Homie.

Provides real playback control, track search, and playback status using the spotipy library.
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("homie.plugins.spotify")

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
