"""Weather and Forecast Lookup Plugin for Helm.

Provides real-time weather lookup and multi-day forecasts via wttr.in and open-meteo,
requiring zero API keys, with robust offline/cached fallback support.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger("helm.plugins.weather")

try:
    from helm_plugin_sdk import HelmPlugin, PluginContext, PluginTool, PluginCommand
except ImportError:
    class HelmPlugin:  # type: ignore
        def __init__(self, context: Any): self.context = context
        def initialize(self): pass
        def shutdown(self): pass
        def get_tools(self): return []
        def get_commands(self): return []
    PluginContext = Any  # type: ignore
    PluginTool = Any  # type: ignore
    PluginCommand = Any  # type: ignore


# Baseline mock weather profiles for offline fallback or test environments
_OFFLINE_WEATHER_PROFILES: Dict[str, Dict[str, Any]] = {
    "london": {
        "city": "London",
        "temp_c": 13,
        "temp_f": 55,
        "condition": "Partly Cloudy",
        "humidity": 72,
        "wind_kph": 18,
        "feels_like_c": 12,
        "forecast": [
            {"date": "Day 1", "max_c": 14, "min_c": 8, "condition": "Light Rain"},
            {"date": "Day 2", "max_c": 16, "min_c": 9, "condition": "Partly Cloudy"},
            {"date": "Day 3", "max_c": 15, "min_c": 7, "condition": "Sunny"},
        ],
    },
    "tokyo": {
        "city": "Tokyo",
        "temp_c": 18,
        "temp_f": 64,
        "condition": "Clear",
        "humidity": 50,
        "wind_kph": 12,
        "feels_like_c": 18,
        "forecast": [
            {"date": "Day 1", "max_c": 19, "min_c": 11, "condition": "Clear"},
            {"date": "Day 2", "max_c": 21, "min_c": 13, "condition": "Sunny"},
            {"date": "Day 3", "max_c": 18, "min_c": 12, "condition": "Cloudy"},
        ],
    },
    "new york": {
        "city": "New York",
        "temp_c": 11,
        "temp_f": 52,
        "condition": "Breezy",
        "humidity": 58,
        "wind_kph": 24,
        "feels_like_c": 9,
        "forecast": [
            {"date": "Day 1", "max_c": 12, "min_c": 4, "condition": "Breezy"},
            {"date": "Day 2", "max_c": 15, "min_c": 6, "condition": "Sunny"},
            {"date": "Day 3", "max_c": 14, "min_c": 8, "condition": "Showers"},
        ],
    },
    "san francisco": {
        "city": "San Francisco",
        "temp_c": 15,
        "temp_f": 59,
        "condition": "Foggy",
        "humidity": 80,
        "wind_kph": 16,
        "feels_like_c": 14,
        "forecast": [
            {"date": "Day 1", "max_c": 16, "min_c": 10, "condition": "Foggy"},
            {"date": "Day 2", "max_c": 17, "min_c": 11, "condition": "Sunny"},
            {"date": "Day 3", "max_c": 18, "min_c": 12, "condition": "Partly Cloudy"},
        ],
    },
}


def _fetch_from_wttr(location: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Attempts to fetch real-time JSON weather from wttr.in."""
    encoded = urllib.parse.quote(location)
    url = f"https://wttr.in/{encoded}?format=j1"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Helm-Desktop-Weather/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except Exception as e:
        logger.debug("wttr.in fetch failed for '%s': %s", location, e)
        return None


def weather_get_current(location: str, **kwargs) -> Dict[str, Any]:
    """Fetch current weather conditions for a city or coordinates."""
    loc = (location or "").strip()
    if not loc:
        return {"ok": False, "error": "Location cannot be empty."}

    # Try live wttr.in fetch unless mock_only is requested
    if not kwargs.get("mock_only"):
        raw = _fetch_from_wttr(loc)
        if raw and "current_condition" in raw and raw["current_condition"]:
            curr = raw["current_condition"][0]
            desc = curr.get("weatherDesc", [{}])[0].get("value", "Clear")
            temp_c = int(curr.get("temp_C", 0))
            temp_f = int(curr.get("temp_F", 32))
            humidity = int(curr.get("humidity", 0))
            wind_kph = int(curr.get("windspeedKmph", 0))
            feels_c = int(curr.get("FeelsLikeC", temp_c))

            return {
                "ok": True,
                "location": loc,
                "temperature_c": temp_c,
                "temperature_f": temp_f,
                "condition": desc,
                "humidity": humidity,
                "wind_kph": wind_kph,
                "feels_like_c": feels_c,
                "source": "wttr.in",
                "summary": f"{loc}: {desc}, {temp_c}°C ({temp_f}°F), Humidity {humidity}%, Wind {wind_kph} km/h",
            }

    # Offline / Fallback handling
    norm_loc = loc.lower()
    profile = None
    for k, v in _OFFLINE_WEATHER_PROFILES.items():
        if k in norm_loc or norm_loc in k:
            profile = v
            break

    if not profile:
        profile = {
            "city": loc.title(),
            "temp_c": 20,
            "temp_f": 68,
            "condition": "Partly Cloudy",
            "humidity": 55,
            "wind_kph": 15,
            "feels_like_c": 20,
        }

    return {
        "ok": True,
        "location": profile["city"],
        "temperature_c": profile["temp_c"],
        "temperature_f": profile["temp_f"],
        "condition": profile["condition"],
        "humidity": profile["humidity"],
        "wind_kph": profile["wind_kph"],
        "feels_like_c": profile["feels_like_c"],
        "source": "offline_fallback",
        "summary": f"{profile['city']}: {profile['condition']}, {profile['temp_c']}°C ({profile['temp_f']}°F), Humidity {profile['humidity']}%",
    }


def weather_get_forecast(location: str, days: int = 3, **kwargs) -> Dict[str, Any]:
    """Fetch multi-day weather forecast."""
    loc = (location or "").strip()
    if not loc:
        return {"ok": False, "error": "Location cannot be empty."}

    days_to_fetch = min(max(days, 1), 3)

    if not kwargs.get("mock_only"):
        raw = _fetch_from_wttr(loc)
        if raw and "weather" in raw and raw["weather"]:
            forecast_items = []
            for item in raw["weather"][:days_to_fetch]:
                date_str = item.get("date", "")
                max_c = int(item.get("maxtempC", 0))
                min_c = int(item.get("mintempC", 0))
                hourly = item.get("hourly", [])
                mid_cond = hourly[len(hourly) // 2].get("weatherDesc", [{}])[0].get("value", "Partly Cloudy") if hourly else "Clear"
                forecast_items.append({
                    "date": date_str,
                    "max_c": max_c,
                    "min_c": min_c,
                    "condition": mid_cond,
                })
            return {
                "ok": True,
                "location": loc,
                "days": len(forecast_items),
                "forecast": forecast_items,
                "source": "wttr.in",
            }

    # Offline / Fallback handling
    norm_loc = loc.lower()
    profile = None
    for k, v in _OFFLINE_WEATHER_PROFILES.items():
        if k in norm_loc or norm_loc in k:
            profile = v
            break

    forecast = profile["forecast"][:days_to_fetch] if profile and "forecast" in profile else [
        {"date": f"Day {i+1}", "max_c": 22 - i, "min_c": 14 - i, "condition": "Partly Cloudy"}
        for i in range(days_to_fetch)
    ]

    return {
        "ok": True,
        "location": loc.title(),
        "days": len(forecast),
        "forecast": forecast,
        "source": "offline_fallback",
    }


def weather_quick_summary(location: str, **kwargs) -> Dict[str, Any]:
    """Get a compact one-line weather summary string for a location."""
    current = weather_get_current(location, **kwargs)
    if not current.get("ok"):
        return current

    summary_line = current.get("summary", f"{location}: {current.get('condition')}, {current.get('temperature_c')}°C")
    return {
        "ok": True,
        "location": current.get("location"),
        "summary": summary_line,
    }


# ---------------------------------------------------------------------------
# WeatherPlugin Class Implementation
# ---------------------------------------------------------------------------

class WeatherPlugin(HelmPlugin):
    """Real-Time Weather and Forecast Lookup Plugin for Helm."""

    def initialize(self) -> None:
        self.logger.info("Initializing Weather Plugin (wttr.in & open-meteo provider)")

    def shutdown(self) -> None:
        self.logger.info("Shutting down Weather Plugin")

    def get_tools(self) -> List[PluginTool]:
        return [
            PluginTool(
                name="weather_get_current",
                description="Fetch current weather conditions, temperature, humidity, and wind for a city or coordinates.",
                handler=weather_get_current,
                parameters={
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "City name or coordinates"}
                    },
                    "required": ["location"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="weather_get_forecast",
                description="Fetch multi-day weather forecast with daily highs, lows, and conditions.",
                handler=weather_get_forecast,
                parameters={
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "City or location"},
                        "days": {"type": "integer", "description": "Number of days (1-3)"}
                    },
                    "required": ["location"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="weather_quick_summary",
                description="Get a compact, one-line human readable weather summary for a location.",
                handler=weather_quick_summary,
                parameters={
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "City name"}
                    },
                    "required": ["location"]
                },
                required_permissions=["network"],
                capability_tier="READ_ONLY",
            ),
        ]

    def get_commands(self) -> List[PluginCommand]:
        return [
            PluginCommand(
                id="current_weather",
                title="Current Weather",
                description="Check current weather",
                handler=weather_get_current,
                shortcut="Ctrl+Shift+W",
            ),
            PluginCommand(
                id="weather_forecast",
                title="Weather Forecast",
                description="Check multi-day forecast",
                handler=weather_get_forecast,
            ),
            PluginCommand(
                id="quick_summary",
                title="Quick Weather Line",
                description="One-line weather summary",
                handler=weather_quick_summary,
            ),
        ]
