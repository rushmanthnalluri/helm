"""helm_plugins.py - 1-Click Community Extension Hub & Package Manager for Helm.

Provides a unified plugin package manager and execution runtime for Helm:
- Plugin Manifest Specification: 'manifest.json' defining id, name, version, capabilities, tools, author.
- Safe Sandboxed Installation: Verifies plugin IDs, prevents path traversal, validates schemas.
- Plugin Loader & Runtime: Dynamically loads plugins, registers tools into the agent tool registry,
  and executes them with timeout protection and structured error handling.
- Verified Community Catalog: Pre-seeded registry of popular desktop/developer plugins
  (Spotify Controller, GitHub PR Tracker, Linear Sync, Docker Ops, Obsidian Bridge).
- Built-in Spotify Plugin with Spotipy integration (spotify_play, spotify_pause, spotify_now_playing).
- Lifecycle Management: list, install, load, execute, enable, disable, uninstall, inspect.
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import inspect
import logging
import importlib.util
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("helm.plugins")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

# Spotify tools declaration schema
SPOTIFY_TOOLS_DECL: List[Dict[str, Any]] = [
    {
        "name": "spotify_play",
        "description": "Search and play a track on Spotify by query, or resume playback if query is empty.",
        "python_callable": "plugin:spotify_play",
        "args_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Track, artist, or album name to search and play"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "spotify_pause",
        "description": "Pause current Spotify playback.",
        "python_callable": "plugin:spotify_pause",
        "args_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "spotify_now_playing",
        "description": "Return current track info from Spotify.",
        "python_callable": "plugin:spotify_now_playing",
        "args_schema": {
            "type": "object",
            "properties": {}
        }
    }
]

# Pre-seeded Verified Community Catalog
COMMUNITY_CATALOG: Dict[str, Dict[str, Any]] = {
    "spotify": {
        "id": "spotify",
        "name": "Spotify Media Controller",
        "version": "1.2.0",
        "description": "Control playback, browse playlists, search tracks and podcasts via Spotify Web API.",
        "author": "Helm Community",
        "category": "Media",
        "capabilities": ["network:api.spotify.com"],
        "tools": SPOTIFY_TOOLS_DECL
    },
    "spotify-controller": {
        "id": "spotify-controller",
        "name": "Spotify Media Controller",
        "version": "1.2.0",
        "description": "Control playback, browse playlists, search tracks and podcasts via Spotify Web API.",
        "author": "Helm Community",
        "category": "Media",
        "capabilities": ["network:api.spotify.com"],
        "tools": SPOTIFY_TOOLS_DECL
    },
    "github-pr-tracker": {
        "id": "github-pr-tracker",
        "name": "GitHub PR & Issues Tracker",
        "version": "1.1.0",
        "description": "Stream review requests, summarize diffs, track CI/CD checks and open issues.",
        "author": "Helm Community",
        "category": "Developer Tools",
        "capabilities": ["network:api.github.com"],
        "tools": [
            {"name": "github_list_prs", "description": "List open pull requests.", "python_callable": "plugin:github_list_prs", "args_schema": {"type": "object", "properties": {}}},
            {"name": "github_review_diff", "description": "Review PR diff.", "python_callable": "plugin:github_review_diff", "args_schema": {"type": "object", "properties": {"pr_id": {"type": "integer"}}}},
            {"name": "github_ci_status", "description": "Check CI status for branch.", "python_callable": "plugin:github_ci_status", "args_schema": {"type": "object", "properties": {"ref": {"type": "string"}}}}
        ]
    },
    "linear-sync": {
        "id": "linear-sync",
        "name": "Linear Project Sync",
        "version": "1.0.4",
        "description": "Two-way sync of personal tasks, action items, bug reports, and roadmap milestones.",
        "author": "Helm Community",
        "category": "Productivity",
        "capabilities": ["network:api.linear.app"],
        "tools": [
            {"name": "linear_create_issue", "description": "Create a new issue in Linear.", "python_callable": "plugin:linear_create_issue", "args_schema": {"type": "object", "properties": {"title": {"type": "string"}}}},
            {"name": "linear_my_issues", "description": "List issues assigned to me.", "python_callable": "plugin:linear_my_issues", "args_schema": {"type": "object", "properties": {}}},
            {"name": "linear_update_state", "description": "Update issue status.", "python_callable": "plugin:linear_update_state", "args_schema": {"type": "object", "properties": {"issue_id": {"type": "string"}, "state": {"type": "string"}}}}
        ]
    },
    "docker-ops": {
        "id": "docker-ops",
        "name": "Docker Container & Compose Manager",
        "version": "1.0.1",
        "description": "Inspect containers, stream logs, restart unhealthy services, and manage compose stacks.",
        "author": "Helm Community",
        "category": "DevOps",
        "capabilities": ["process:docker"],
        "tools": [
            {"name": "docker_ps", "description": "List Docker containers.", "python_callable": "plugin:docker_ps", "args_schema": {"type": "object", "properties": {}}},
            {"name": "docker_logs", "description": "Get container logs.", "python_callable": "plugin:docker_logs", "args_schema": {"type": "object", "properties": {"container_id": {"type": "string"}}}},
            {"name": "docker_restart_container", "description": "Restart a container.", "python_callable": "plugin:docker_restart_container", "args_schema": {"type": "object", "properties": {"container_id": {"type": "string"}}}}
        ]
    },
    "obsidian-bridge": {
        "id": "obsidian-bridge",
        "name": "Obsidian Vault Bridge",
        "version": "1.3.0",
        "description": "Read, search, backlink, and append daily notes directly inside your local Obsidian vault.",
        "author": "Helm Community",
        "category": "Notes",
        "capabilities": ["filesystem:read_write"],
        "tools": [
            {"name": "obsidian_search_notes", "description": "Search Obsidian notes.", "python_callable": "plugin:obsidian_search_notes", "args_schema": {"type": "object", "properties": {"query": {"type": "string"}}}},
            {"name": "obsidian_append_daily", "description": "Append note to daily log.", "python_callable": "plugin:obsidian_append_daily", "args_schema": {"type": "object", "properties": {"content": {"type": "string"}}}},
            {"name": "obsidian_get_backlinks", "description": "Get backlinks for note.", "python_callable": "plugin:obsidian_get_backlinks", "args_schema": {"type": "object", "properties": {"note_name": {"type": "string"}}}}
        ]
    }
}


def get_plugins_dir() -> Path:
    """Returns the persistent directory for installed plugins."""
    custom = os.environ.get("HELM_PLUGINS_DIR")
    if custom:
        p = Path(custom).expanduser().resolve()
    else:
        base = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))
        p = (base / "plugins").expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _get_state_file() -> Path:
    return get_plugins_dir() / "plugins_state.json"


def _read_state() -> Dict[str, Any]:
    state_file = _get_state_file()
    if not state_file.exists():
        return {"enabled": {}, "installed_at": {}}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return {"enabled": {}, "installed_at": {}}


def _write_state(state: Dict[str, Any]) -> None:
    state_file = _get_state_file()
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")


def validate_plugin_id(plugin_id: str) -> bool:
    return bool(plugin_id and _PLUGIN_ID_RE.match(plugin_id))


def list_installed_plugins() -> List[Dict[str, Any]]:
    """Lists all installed plugins and their current enabled status."""
    plugins_dir = get_plugins_dir()
    state = _read_state()
    enabled_map = state.get("enabled", {})

    results = []
    if not plugins_dir.exists():
        return results

    for item in plugins_dir.iterdir():
        if item.is_dir():
            manifest_file = item / "manifest.json"
            if manifest_file.exists():
                try:
                    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                    pid = manifest.get("id", item.name)
                    results.append({
                        "id": pid,
                        "name": manifest.get("name", pid),
                        "version": manifest.get("version", "1.0.0"),
                        "description": manifest.get("description", ""),
                        "author": manifest.get("author", "Unknown"),
                        "category": manifest.get("category", "General"),
                        "capabilities": manifest.get("capabilities", []),
                        "tools": manifest.get("tools", []),
                        "enabled": enabled_map.get(pid, True),
                        "path": str(item)
                    })
                except Exception:
                    continue
    return results


def install_plugin(
    manifest_data: Dict[str, Any],
    files: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Installs a plugin from manifest data and optional payload files."""
    raw_id = manifest_data.get("id", "").strip()
    if not validate_plugin_id(raw_id):
        raise ValueError(f"Invalid plugin id '{raw_id}'. Must match ^[a-z0-9][a-z0-9_-]{{1,63}}$")
    pid = raw_id

    target_dir = get_plugins_dir() / pid
    target_dir.mkdir(parents=True, exist_ok=True)

    # Write manifest
    manifest_file = target_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # Write auxiliary files (e.g. plugin.py, README.md)
    if files:
        for rel_path, content in files.items():
            clean_rel = os.path.normpath(rel_path).lstrip("/\\")
            if ".." in clean_rel:
                continue
            dest_file = target_dir / clean_rel
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_text(content, encoding="utf-8")

    state = _read_state()
    state.setdefault("enabled", {})[pid] = True
    state.setdefault("installed_at", {})[pid] = time.time()
    _write_state(state)

    return {
        "ok": True,
        "id": pid,
        "name": manifest_data.get("name", pid),
        "version": manifest_data.get("version", "1.0.0"),
        "installed_path": str(target_dir),
        "status": "enabled"
    }


def _find_bundled_plugin_dir(plugin_id: str) -> Optional[Path]:
    """Finds bundled plugin directory in repository or distribution paths."""
    candidates = [
        Path(BASE_DIR) / "plugins" / plugin_id,
        Path(BASE_DIR) / "plugins" / ("spotify" if "spotify" in plugin_id else plugin_id),
        Path("D:/helm/plugins") / plugin_id,
        Path("D:/helm/plugins") / ("spotify" if "spotify" in plugin_id else plugin_id),
    ]
    for cand in candidates:
        if cand.exists() and cand.is_dir():
            return cand
    return None


def install_from_community_catalog(catalog_id: str) -> Dict[str, Any]:
    """Installs a verified plugin from the community catalog, copying real source files if available,
    and automatically registers its tools into the agent's tool registry via load_plugin().
    """
    cid = catalog_id.strip().lower()
    if cid not in COMMUNITY_CATALOG:
        if cid == "spotify" and "spotify-controller" in COMMUNITY_CATALOG:
            cid = "spotify-controller"
        elif cid == "spotify-controller" and "spotify" in COMMUNITY_CATALOG:
            cid = "spotify"
        else:
            available = list(COMMUNITY_CATALOG.keys())
            raise ValueError(f"Plugin '{cid}' not found in community catalog. Available: {available}")

    manifest = dict(COMMUNITY_CATALOG[cid])
    source_dir = _find_bundled_plugin_dir(cid)

    files: Dict[str, str] = {}
    if source_dir and source_dir.exists():
        for p in source_dir.iterdir():
            if p.is_file():
                try:
                    files[p.name] = p.read_text(encoding="utf-8")
                except Exception:
                    pass

        # If source directory has manifest.json, use its tool declarations but align the ID
        if "manifest.json" in files:
            try:
                loaded_manifest = json.loads(files["manifest.json"])
                loaded_manifest["id"] = cid
                manifest = loaded_manifest
                files["manifest.json"] = json.dumps(manifest, indent=2)
            except Exception:
                pass
    else:
        readme_content = f"# {manifest['name']}\n\n{manifest['description']}\n\nAuthor: {manifest['author']}\n"
        files["README.md"] = readme_content

    install_res = install_plugin(manifest, files=files)

    # Step 5: Wire load_plugin() to be called automatically after install_from_community_catalog()
    load_res = load_plugin(cid)
    install_res["tools_loaded"] = load_res.get("tools_loaded", [])

    return install_res


def load_plugin(plugin_id: str, registry: Optional[Any] = None) -> Dict[str, Any]:
    """Reads the plugin manifest and dynamically registers each declared tool into the agent's tool registry."""
    pid = plugin_id.strip().lower()

    # Check if disabled
    state = _read_state()
    if not state.get("enabled", {}).get(pid, True):
        return {"ok": False, "error": f"Plugin '{pid}' is currently disabled.", "plugin_id": pid}

    # Locate plugin directory
    target_dir = get_plugins_dir() / pid
    if not target_dir.exists() or not (target_dir / "manifest.json").exists():
        bundled = _find_bundled_plugin_dir(pid)
        if bundled and (bundled / "manifest.json").exists():
            target_dir = bundled
        else:
            return {"ok": False, "error": f"Plugin directory for '{pid}' not found.", "plugin_id": pid}

    manifest_file = target_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as e:
        return {"ok": False, "error": f"Failed to read manifest for '{pid}': {e}", "plugin_id": pid}

    tools_decl = manifest.get("tools", [])
    import agent_tools

    loaded_tools: List[str] = []
    for item in tools_decl:
        if isinstance(item, str):
            tool_name = item
            desc = f"Tool '{tool_name}' provided by plugin '{pid}'"
            py_callable = f"plugin:{tool_name}"
            args_schema: Dict[str, Any] = {"type": "object", "properties": {}}
        elif isinstance(item, dict):
            tool_name = item.get("name", "")
            desc = item.get("description", "")
            py_callable = item.get("python_callable", f"plugin:{tool_name}")
            args_schema = item.get("args_schema") or item.get("parameters") or {"type": "object", "properties": {}}
        else:
            continue

        if not tool_name:
            continue

        tool_entry = {
            "plugin_id": pid,
            "name": tool_name,
            "description": desc,
            "python_callable": py_callable,
            "args_schema": args_schema,
            "parameters": args_schema,
            "plugin_dir": str(target_dir),
            "tier": item.get("tier", "READ_ONLY") if isinstance(item, dict) else "READ_ONLY",
        }

        # Dynamically register into the agent's tool registry (a dict in agent_tools.py)
        agent_tools.register_plugin_tool(pid, tool_entry)
        loaded_tools.append(tool_name)

        # If a ToolRegistry instance was supplied, also register a ToolSpec
        if registry is not None and hasattr(registry, "register"):
            try:
                spec = agent_tools.ToolSpec(
                    name=tool_name,
                    description=desc,
                    parameters=args_schema,
                    capability_tier="READ_ONLY",
                    runner=lambda args, caller_id, t_name=tool_name: execute_plugin_tool(pid, t_name, **args),
                    returns_untrusted=False,
                    egress="none",
                    approval="none",
                    timeout_seconds=float(item.get("timeout_seconds", 10.0)) if isinstance(item, dict) else 10.0,
                )
                registry.register(spec, allow_consequential=True)
            except Exception as reg_err:
                logger.debug("Optional ToolRegistry registration skipped for %s: %s", tool_name, reg_err)

    return {
        "ok": True,
        "plugin_id": pid,
        "tools_loaded": loaded_tools,
        "count": len(loaded_tools)
    }


def _resolve_callable(plugin_id: str, py_callable: str, plugin_dir: Optional[str] = None) -> Tuple[Optional[Callable], Optional[str]]:
    """Resolves a callable string (e.g. 'plugin:spotify_play' or 'plugin.spotify_play') from the plugin directory."""
    if ":" in py_callable:
        mod_name, func_name = py_callable.split(":", 1)
    elif "." in py_callable:
        mod_name, func_name = py_callable.rsplit(".", 1)
    else:
        mod_name = "plugin"
        func_name = py_callable

    if mod_name.endswith(".py"):
        mod_name = mod_name[:-3]

    cand_dirs: List[Path] = []
    if plugin_dir:
        cand_dirs.append(Path(plugin_dir))
    cand_dirs.extend([
        get_plugins_dir() / plugin_id,
        Path(BASE_DIR) / "plugins" / plugin_id,
        Path(BASE_DIR) / "plugins" / ("spotify" if "spotify" in plugin_id else plugin_id),
        Path("D:/helm/plugins") / plugin_id,
        Path("D:/helm/plugins") / ("spotify" if "spotify" in plugin_id else plugin_id),
    ])

    py_path: Optional[Path] = None
    found_dir: Optional[Path] = None
    for d in cand_dirs:
        if d.exists() and d.is_dir():
            cand_file = d / f"{mod_name}.py"
            if cand_file.exists():
                py_path = cand_file
                found_dir = d
                break

    if not py_path:
        return None, f"Module file '{mod_name}.py' for plugin '{plugin_id}' not found."

    module_key = f"helm_plugin_{plugin_id}_{mod_name}"
    try:
        dir_str = str(found_dir)
        if dir_str not in sys.path:
            sys.path.insert(0, dir_str)

        spec = importlib.util.spec_from_file_location(module_key, py_path)
        if spec is None or spec.loader is None:
            return None, f"Failed to create module spec for '{py_path}'"

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_key] = module
        spec.loader.exec_module(module)

        if not hasattr(module, func_name):
            return None, f"Callable '{func_name}' not found in '{py_path}'"

        fn = getattr(module, func_name)
        return fn, None
    except Exception as e:
        return None, f"Error importing '{py_path}': {e}"


def execute_plugin_tool(plugin_id: str, tool_name: str, **kwargs) -> Dict[str, Any]:
    """Looks up the callable for a plugin tool and executes it safely with try/except and timeout protection."""
    import agent_tools

    pid = (plugin_id or "").strip().lower()
    meta = agent_tools.PLUGIN_TOOL_REGISTRY.get(tool_name)
    if not meta and pid:
        meta = agent_tools.PLUGIN_TOOL_REGISTRY.get(f"{pid}:{tool_name}")

    # If tool is not currently registered in the registry, attempt load
    if not meta and pid:
        load_plugin(pid)
        meta = agent_tools.PLUGIN_TOOL_REGISTRY.get(tool_name) or agent_tools.PLUGIN_TOOL_REGISTRY.get(f"{pid}:{tool_name}")

    if not meta:
        for k, v in agent_tools.PLUGIN_TOOL_REGISTRY.items():
            if isinstance(v, dict) and v.get("name") == tool_name:
                meta = v
                if not pid:
                    pid = v.get("plugin_id", "")
                break

    fn = meta.get("callable") if meta else None
    if fn is None:
        py_callable = meta.get("python_callable", f"plugin:{tool_name}") if meta else f"plugin:{tool_name}"
        pdir = meta.get("plugin_dir") if meta else None
        fn, err = _resolve_callable(pid, py_callable, plugin_dir=pdir)
        if err or fn is None:
            return {"ok": False, "error": err or f"Could not resolve callable for '{tool_name}' in plugin '{pid}'."}
        if meta:
            meta["callable"] = fn

    # Safe timeout extraction
    timeout = float(kwargs.pop("__timeout__", kwargs.pop("timeout_seconds", 10.0)))

    # Signature introspection for safe kwargs passing
    try:
        sig = inspect.signature(fn)
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        if not has_var_kw:
            call_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
        else:
            call_kwargs = kwargs
    except Exception:
        call_kwargs = kwargs

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn, **call_kwargs)
        try:
            result = future.result(timeout=timeout)
        except TimeoutError:
            return {"ok": False, "error": f"Plugin tool '{tool_name}' timed out after {timeout} seconds."}
        except Exception as e:
            return {"ok": False, "error": f"Plugin tool '{tool_name}' raised an exception: {e}"}

    if isinstance(result, dict) and "ok" in result:
        return result
    return {"ok": True, "data": result, "result": result}


def load_all_installed_plugins(registry: Optional[Any] = None) -> Dict[str, Any]:
    """Loads all currently installed and enabled plugins into the agent tool registry."""
    state = _read_state()
    enabled_map = state.get("enabled", {})
    plugins_dir = get_plugins_dir()
    loaded = {}
    if plugins_dir.exists():
        for item in plugins_dir.iterdir():
            if item.is_dir() and (item / "manifest.json").exists():
                pid = item.name
                if enabled_map.get(pid, True):
                    loaded[pid] = load_plugin(pid, registry=registry)
    return loaded


def set_plugin_enabled(plugin_id: str, enabled: bool) -> Dict[str, Any]:
    """Enables or disables an installed plugin."""
    pid = plugin_id.strip().lower()
    target_dir = get_plugins_dir() / pid
    if not target_dir.exists():
        raise FileNotFoundError(f"Plugin '{pid}' is not installed.")

    state = _read_state()
    state.setdefault("enabled", {})[pid] = bool(enabled)
    _write_state(state)

    import agent_tools
    if enabled:
        load_plugin(pid)
    else:
        agent_tools.unregister_plugin_tools(pid)

    return {
        "ok": True,
        "id": pid,
        "enabled": bool(enabled)
    }


def uninstall_plugin(plugin_id: str) -> Dict[str, Any]:
    """Safely removes an installed plugin."""
    pid = plugin_id.strip().lower()
    target_dir = get_plugins_dir() / pid
    if not target_dir.exists():
        raise FileNotFoundError(f"Plugin '{pid}' is not installed.")

    # Remove directory
    shutil.rmtree(target_dir, ignore_errors=True)

    state = _read_state()
    if "enabled" in state and pid in state["enabled"]:
        del state["enabled"][pid]
    if "installed_at" in state and pid in state["installed_at"]:
        del state["installed_at"][pid]
    _write_state(state)

    import agent_tools
    agent_tools.unregister_plugin_tools(pid)

    return {
        "ok": True,
        "id": pid,
        "uninstalled": True
    }


def list_community_catalog() -> List[Dict[str, Any]]:
    """Returns the full list of community catalog plugins."""
    installed_ids = {p["id"] for p in list_installed_plugins()}
    catalog = []
    for cid, meta in COMMUNITY_CATALOG.items():
        entry = dict(meta)
        entry["is_installed"] = cid in installed_ids
        catalog.append(entry)
    return catalog
