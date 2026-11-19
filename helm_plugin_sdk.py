"""helm_plugin_sdk.py - Official Plugin & Extension SDK for Helm.

Provides a standalone, extensible SDK for third-party and built-in Helm plugins:
- HelmPlugin: Abstract base class with lifecycle hooks (initialize, shutdown, get_tools, get_commands).
- PluginManifest: Manifest parser and validator for 'plugin.json' (metadata, permissions, commands, tools).
- SecuritySandbox: Capability-based sandboxing and permission checks (network, clipboard, filesystem, system).
- PluginContext: Sandboxed execution context providing isolated data directory, logging, and permissions.
- PluginManager: Dynamic registry, discovery, loading, lifecycle control, and agent tool registration.
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
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("helm.plugin_sdk")

_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

# Recognized capability categories
VALID_CAPABILITIES = {"network", "clipboard", "filesystem", "system"}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PluginError(Exception):
    """Base exception for Helm Plugin SDK errors."""
    pass


class ManifestValidationError(PluginError):
    """Raised when a plugin.json manifest fails validation."""
    pass


class PermissionDeniedError(PluginError):
    """Raised when a plugin attempts an action without the required permission."""
    def __init__(self, plugin_id: str, permission: str, granted: Optional[Set[str]] = None):
        self.plugin_id = plugin_id
        self.permission = permission
        self.granted = granted or set()
        super().__init__(
            f"Permission denied: Plugin '{plugin_id}' lacks permission '{permission}'. "
            f"Granted permissions: {sorted(list(self.granted))}"
        )


class PluginExecutionError(PluginError):
    """Raised when a plugin tool or command fails execution."""
    pass


# ---------------------------------------------------------------------------
# Manifest Parser & Specification
# ---------------------------------------------------------------------------

@dataclass
class PluginCommandSpec:
    id: str
    title: str
    description: str = ""
    shortcut: Optional[str] = None
    icon: Optional[str] = None
    handler: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "shortcut": self.shortcut,
            "icon": self.icon,
            "handler": self.handler,
        }


@dataclass
class PluginToolSpec:
    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    python_callable: Optional[str] = None
    required_permissions: List[str] = field(default_factory=list)
    capability_tier: str = "READ_ONLY"
    timeout_seconds: float = 10.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "python_callable": self.python_callable,
            "required_permissions": self.required_permissions,
            "capability_tier": self.capability_tier,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class PluginManifest:
    """Represents a validated plugin manifest (plugin.json)."""
    id: str
    name: str
    version: str
    author: str = "Unknown"
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    commands: List[PluginCommandSpec] = field(default_factory=list)
    tools: List[PluginToolSpec] = field(default_factory=list)
    icon: str = "puzzle"
    entrypoint: str = "plugin.py"
    category: str = "General"
    homepage: Optional[str] = None
    repository: Optional[str] = None
    min_helm_version: Optional[str] = None

    def validate(self) -> None:
        """Validates manifest integrity according to Helm specifications."""
        if not self.id or not isinstance(self.id, str):
            raise ManifestValidationError("Manifest 'id' is required and must be a string.")
        if not _PLUGIN_ID_RE.match(self.id):
            raise ManifestValidationError(
                f"Invalid plugin id '{self.id}'. Must match regex ^[a-z0-9][a-z0-9_-]{{1,63}}$ "
                "(lowercase alphanumeric, hyphen, or underscore)."
            )
        if not self.name or not isinstance(self.name, str):
            raise ManifestValidationError("Manifest 'name' is required and must be a non-empty string.")
        if not self.version or not isinstance(self.version, str):
            raise ManifestValidationError("Manifest 'version' is required and must be a non-empty string.")

        # Permissions validation
        if not isinstance(self.permissions, list):
            raise ManifestValidationError("Manifest 'permissions' must be a list of strings.")
        for perm in self.permissions:
            if not isinstance(perm, str) or not perm.strip():
                raise ManifestValidationError(f"Invalid permission entry '{perm}'. Must be a non-empty string.")

        # Tools validation
        if not isinstance(self.tools, list):
            raise ManifestValidationError("Manifest 'tools' must be a list of tool objects.")
        for tool in self.tools:
            if not tool.name or not isinstance(tool.name, str):
                raise ManifestValidationError(f"Tool in plugin '{self.id}' missing required 'name'.")

        # Commands validation
        if not isinstance(self.commands, list):
            raise ManifestValidationError("Manifest 'commands' must be a list of command objects.")
        for cmd in self.commands:
            if not cmd.id or not isinstance(cmd.id, str):
                raise ManifestValidationError(f"Command in plugin '{self.id}' missing required 'id'.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "permissions": list(self.permissions),
            "commands": [c.to_dict() for c in self.commands],
            "tools": [t.to_dict() for t in self.tools],
            "icon": self.icon,
            "entrypoint": self.entrypoint,
            "category": self.category,
            "homepage": self.homepage,
            "repository": self.repository,
            "min_helm_version": self.min_helm_version,
        }


def parse_manifest(source: Union[str, Path, Dict[str, Any]]) -> PluginManifest:
    """Parses and validates a plugin manifest from a file path, json string, or dictionary."""
    data: Dict[str, Any]

    if isinstance(source, Path):
        if not source.exists():
            raise ManifestValidationError(f"Manifest file not found: {source}")
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except Exception as e:
            raise ManifestValidationError(f"Failed to parse manifest JSON at '{source}': {e}")
    elif isinstance(source, str):
        # Determine if source is a file path or a raw json string
        trimmed = source.strip()
        if trimmed.startswith("{") and trimmed.endswith("}"):
            try:
                data = json.loads(trimmed)
            except Exception as e:
                raise ManifestValidationError(f"Failed to parse manifest JSON string: {e}")
        else:
            p = Path(source)
            if p.exists() and p.is_file():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except Exception as e:
                    raise ManifestValidationError(f"Failed to parse manifest JSON at '{p}': {e}")
            else:
                raise ManifestValidationError(f"Manifest path does not exist: {source}")
    elif isinstance(source, dict):
        data = dict(source)
    else:
        raise ManifestValidationError(f"Unsupported manifest source type: {type(source)}")

    # Parse commands
    commands: List[PluginCommandSpec] = []
    raw_commands = data.get("commands", [])
    if isinstance(raw_commands, list):
        for c in raw_commands:
            if isinstance(c, dict):
                commands.append(
                    PluginCommandSpec(
                        id=str(c.get("id") or c.get("name") or ""),
                        title=str(c.get("title") or c.get("name") or c.get("id") or ""),
                        description=str(c.get("description", "")),
                        shortcut=c.get("shortcut"),
                        icon=c.get("icon"),
                        handler=c.get("handler") or c.get("python_callable"),
                    )
                )

    # Parse tools
    tools: List[PluginToolSpec] = []
    raw_tools = data.get("tools", [])
    if isinstance(raw_tools, list):
        for t in raw_tools:
            if isinstance(t, dict):
                tools.append(
                    PluginToolSpec(
                        name=str(t.get("name", "")),
                        description=str(t.get("description", "")),
                        parameters=t.get("parameters") or t.get("args_schema") or {"type": "object", "properties": {}},
                        python_callable=t.get("python_callable"),
                        required_permissions=list(t.get("required_permissions") or t.get("permissions") or []),
                        capability_tier=t.get("capability_tier") or t.get("tier") or "READ_ONLY",
                        timeout_seconds=float(t.get("timeout_seconds", 10.0)),
                    )
                )

    # Backward compatibility with 'capabilities' field if 'permissions' is omitted
    perms = data.get("permissions")
    if perms is None and "capabilities" in data:
        perms = data.get("capabilities", [])

    manifest = PluginManifest(
        id=str(data.get("id", "")).strip().lower(),
        name=str(data.get("name", "")).strip(),
        version=str(data.get("version", "1.0.0")).strip(),
        author=str(data.get("author", "Unknown")).strip(),
        description=str(data.get("description", "")).strip(),
        permissions=list(perms or []),
        commands=commands,
        tools=tools,
        icon=str(data.get("icon", "puzzle")),
        entrypoint=str(data.get("entrypoint", "plugin.py")),
        category=str(data.get("category", "General")),
        homepage=data.get("homepage"),
        repository=data.get("repository"),
        min_helm_version=data.get("min_helm_version"),
    )

    manifest.validate()
    return manifest


# ---------------------------------------------------------------------------
# Capability-Based Sandboxing & Permission Checks
# ---------------------------------------------------------------------------

class SecuritySandbox:
    """Capability-based permission sandbox for plugin isolation and execution safety."""

    def __init__(self, plugin_id: str, granted_permissions: Optional[Union[List[str], Set[str]]] = None):
        self.plugin_id = plugin_id
        self._granted: Set[str] = set()
        if granted_permissions:
            for p in granted_permissions:
                self.grant(p)

    @property
    def granted_permissions(self) -> Set[str]:
        return set(self._granted)

    def grant(self, permission: str) -> None:
        """Grants a capability permission to this sandbox."""
        if permission:
            self._granted.add(permission.strip().lower())

    def revoke(self, permission: str) -> None:
        """Revokes a capability permission from this sandbox."""
        norm = permission.strip().lower()
        self._granted.discard(norm)
        # Also revoke any scoped permissions under it if category revoked
        to_remove = [p for p in self._granted if p == norm or p.startswith(f"{norm}:")]
        for p in to_remove:
            self._granted.discard(p)

    def has_permission(self, permission: str) -> bool:
        """Checks if the sandbox holds the requested capability permission.

        Supports scoped hierarchy:
        - If '*' is granted, all permissions pass.
        - If 'network' is granted, 'network:api.github.com' passes.
        - If 'network:api.github.com' is granted, 'network' does NOT pass (requires broad network).
        """
        req = permission.strip().lower()
        if "*" in self._granted:
            return True
        if req in self._granted:
            return True

        # Check prefix match for scoped permissions (e.g. granted 'network' checks 'network:api.github.com')
        if ":" in req:
            base_category = req.split(":", 1)[0]
            if base_category in self._granted:
                return True

        return False

    def require(self, permission: str) -> None:
        """Enforces that the requested capability permission is granted, otherwise raises PermissionDeniedError."""
        if not self.has_permission(permission):
            raise PermissionDeniedError(self.plugin_id, permission, self._granted)

    def guard(self, permission: str) -> Callable:
        """Decorator for plugin methods or callables to enforce permission check before invocation."""
        def decorator(fn: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                self.require(permission)
                return fn(*args, **kwargs)
            return wrapper
        return decorator


# ---------------------------------------------------------------------------
# Plugin Tools & Commands Representation
# ---------------------------------------------------------------------------

@dataclass
class PluginTool:
    """Represents a callable agent tool provided by a plugin."""
    name: str
    description: str
    handler: Callable
    parameters: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    required_permissions: List[str] = field(default_factory=list)
    capability_tier: str = "READ_ONLY"
    timeout_seconds: float = 10.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "required_permissions": self.required_permissions,
            "capability_tier": self.capability_tier,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class PluginCommand:
    """Represents a quick action/command registered by a plugin for user shortcuts."""
    id: str
    title: str
    handler: Callable
    description: str = ""
    shortcut: Optional[str] = None
    icon: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "shortcut": self.shortcut,
            "icon": self.icon,
        }


# ---------------------------------------------------------------------------
# Plugin Execution Context
# ---------------------------------------------------------------------------

class PluginContext:
    """Execution context injected into HelmPlugin instances, giving access to sandboxed services."""

    def __init__(
        self,
        manifest: PluginManifest,
        plugin_dir: Path,
        sandbox: SecuritySandbox,
        data_dir: Optional[Path] = None,
    ):
        self.manifest = manifest
        self.plugin_id = manifest.id
        self.plugin_dir = plugin_dir.resolve()
        self.sandbox = sandbox
        self.logger = logging.getLogger(f"helm.plugin.{self.plugin_id}")

        if data_dir:
            self.data_dir = data_dir.resolve()
        else:
            base_data = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))
            self.data_dir = (base_data / "plugin_data" / self.plugin_id).resolve()

    def check_permission(self, permission: str) -> bool:
        """Returns True if the capability permission is granted."""
        return self.sandbox.has_permission(permission)

    def require_permission(self, permission: str) -> None:
        """Raises PermissionDeniedError if the capability permission is not granted."""
        self.sandbox.require(permission)

    def get_storage_path(self, filename: str) -> Path:
        """Returns an isolated, safe path within the plugin's dedicated data directory."""
        clean_name = os.path.basename(filename)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / clean_name


# ---------------------------------------------------------------------------
# HelmPlugin Base Class & Lifecycle Hooks
# ---------------------------------------------------------------------------

class HelmPlugin:
    """Base class for all Helm plugins.

    Subclasses implement lifecycle hooks:
    - initialize(): Lifecycle hook invoked when plugin is loaded.
    - shutdown(): Lifecycle hook invoked when plugin is unloaded or disabled.
    - get_tools(): Returns list of PluginTool objects for agent usage.
    - get_commands(): Returns list of PluginCommand objects for UI commands.
    """

    def __init__(self, context: PluginContext):
        self.context = context
        self.manifest = context.manifest
        self.plugin_id = context.plugin_id
        self.logger = context.logger
        self.is_initialized = False

    def initialize(self) -> None:
        """Lifecycle hook: initialize resources, verify dependencies, set up caches."""
        pass

    def shutdown(self) -> None:
        """Lifecycle hook: cleanly release connections, timers, and active resources."""
        pass

    def get_tools(self) -> List[PluginTool]:
        """Returns the list of agent tools exposed by this plugin."""
        return []

    def get_commands(self) -> List[PluginCommand]:
        """Returns the quick commands exposed by this plugin."""
        return []


# ---------------------------------------------------------------------------
# Dynamic Plugin Registry & Loader (PluginManager)
# ---------------------------------------------------------------------------

class PluginManager:
    """Dynamic plugin registry and loader for Helm.

    Manages plugin discovery across:
    - Repository/distribution built-in directory (`plugins/`)
    - User plugins directory (`~/.config/helm/plugins` or `$HELM_PLUGINS_DIR`)
    - Custom search paths

    Features:
    - Manifest parsing & validation
    - Capability-based sandboxing & permission checks
    - Lifecycle hooks (initialize, shutdown)
    - Thread-safe tool & command execution with timeout protection
    - Integration with agent_tools registry
    """

    def __init__(
        self,
        search_paths: Optional[List[Union[str, Path]]] = None,
        base_data_dir: Optional[Path] = None,
    ):
        self._search_paths: List[Path] = []
        if search_paths:
            for p in search_paths:
                self._search_paths.append(Path(p).resolve())
        else:
            self._search_paths = self._default_search_paths()

        self._base_data_dir = base_data_dir
        self._loaded_plugins: Dict[str, HelmPlugin] = {}
        self._manifests: Dict[str, PluginManifest] = {}
        self._sandboxes: Dict[str, SecuritySandbox] = {}
        self._contexts: Dict[str, PluginContext] = {}
        self._tools: Dict[str, PluginTool] = {}  # qualified tool_name -> tool
        self._commands: Dict[str, PluginCommand] = {}  # qualified cmd_id -> command
        self._enabled_state: Dict[str, bool] = {}

    @staticmethod
    def _default_search_paths() -> List[Path]:
        paths = []
        # 1. Custom env var
        custom = os.environ.get("HELM_PLUGINS_DIR")
        if custom:
            paths.append(Path(custom).resolve())

        # 2. Local workspace plugins directory
        here = Path(__file__).resolve().parent
        local_plugins = here / "plugins"
        if local_plugins.exists() and local_plugins.is_dir():
            paths.append(local_plugins)

        # 3. User config directory
        user_config = Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm")) / "plugins"
        paths.append(user_config.resolve())

        return paths

    def add_search_path(self, path: Union[str, Path]) -> None:
        """Adds an additional plugin search directory."""
        p = Path(path).resolve()
        if p not in self._search_paths:
            self._search_paths.insert(0, p)

    def discover_plugins(self) -> Dict[str, Path]:
        """Scans all search paths for directories containing 'plugin.json' or 'manifest.json'."""
        discovered: Dict[str, Path] = {}
        for base_path in self._search_paths:
            if not base_path.exists() or not base_path.is_dir():
                continue
            for entry in base_path.iterdir():
                if entry.is_dir():
                    manifest_file = entry / "plugin.json"
                    if not manifest_file.exists():
                        manifest_file = entry / "manifest.json"

                    if manifest_file.exists():
                        try:
                            # Read id quickly
                            content = json.loads(manifest_file.read_text(encoding="utf-8"))
                            pid = str(content.get("id") or entry.name).strip().lower()
                            if pid and pid not in discovered:
                                discovered[pid] = entry
                        except Exception as e:
                            logger.warning("Failed reading manifest in %s: %e", entry, e)
        return discovered

    def get_plugin(self, plugin_id: str) -> Optional[HelmPlugin]:
        """Returns loaded plugin instance if currently active."""
        return self._loaded_plugins.get(plugin_id.strip().lower())

    def is_plugin_enabled(self, plugin_id: str) -> bool:
        """Returns whether a plugin is enabled."""
        pid = plugin_id.strip().lower()
        return self._enabled_state.get(pid, True)

    def load_plugin(
        self,
        plugin_id_or_path: Union[str, Path],
        granted_permissions: Optional[List[str]] = None,
    ) -> HelmPlugin:
        """Loads and initializes a plugin by ID or direct directory path.

        1. Locates directory and parses plugin.json (or manifest.json).
        2. Configures SecuritySandbox with manifest permissions (or custom granted_permissions).
        3. Imports entrypoint module and instantiates HelmPlugin subclass.
        4. Calls plugin.initialize().
        5. Registers plugin tools and commands.
        """
        plugin_dir: Optional[Path] = None
        target = str(plugin_id_or_path).strip()

        # If a path was passed directly
        as_path = Path(target)
        if as_path.exists() and as_path.is_dir():
            plugin_dir = as_path.resolve()
        else:
            # Look up via discovery
            discovered = self.discover_plugins()
            norm_id = target.lower()
            if norm_id in discovered:
                plugin_dir = discovered[norm_id]

        if not plugin_dir or not plugin_dir.exists():
            raise FileNotFoundError(f"Plugin '{target}' directory not found in search paths.")

        # Locate manifest
        manifest_path = plugin_dir / "plugin.json"
        if not manifest_path.exists():
            manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            raise ManifestValidationError(f"Neither 'plugin.json' nor 'manifest.json' found in '{plugin_dir}'")

        manifest = parse_manifest(manifest_path)
        pid = manifest.id

        # If already loaded, unload cleanly first
        if pid in self._loaded_plugins:
            self.unload_plugin(pid)

        # Configure SecuritySandbox
        # Default granted permissions come from manifest, can be overridden by caller
        perms_to_grant = granted_permissions if granted_permissions is not None else manifest.permissions
        sandbox = SecuritySandbox(pid, perms_to_grant)

        # Context
        context = PluginContext(
            manifest=manifest,
            plugin_dir=plugin_dir,
            sandbox=sandbox,
            data_dir=(self._base_data_dir / pid) if self._base_data_dir else None,
        )

        # Import entrypoint module
        entrypoint_file = plugin_dir / manifest.entrypoint
        if not entrypoint_file.exists():
            # Try plugin.py fallback
            entrypoint_file = plugin_dir / "plugin.py"
        if not entrypoint_file.exists():
            raise FileNotFoundError(f"Plugin entrypoint '{manifest.entrypoint}' not found in '{plugin_dir}'")

        module_key = f"helm_plugin_{pid}"
        dir_str = str(plugin_dir)
        if dir_str not in sys.path:
            sys.path.insert(0, dir_str)

        spec = importlib.util.spec_from_file_location(module_key, entrypoint_file)
        if spec is None or spec.loader is None:
            raise ImportError(f"Failed to create spec for '{entrypoint_file}'")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_key] = module
        spec.loader.exec_module(module)

        # Search for HelmPlugin subclass
        plugin_instance: Optional[HelmPlugin] = None
        for attr_name in dir(module):
            val = getattr(module, attr_name)
            if inspect.isclass(val) and issubclass(val, HelmPlugin) and val is not HelmPlugin:
                plugin_instance = val(context)
                break

        # If no HelmPlugin subclass found, wrap functional implementation
        if plugin_instance is None:
            plugin_instance = _FunctionalPluginAdapter(module, context)

        # Call initialize hook
        try:
            plugin_instance.initialize()
            plugin_instance.is_initialized = True
        except Exception as e:
            logger.error("Error during initialize() of plugin '%s': %s", pid, e)
            raise PluginExecutionError(f"Plugin '{pid}' initialize() failed: {e}") from e

        # Store state
        self._loaded_plugins[pid] = plugin_instance
        self._manifests[pid] = manifest
        self._sandboxes[pid] = sandbox
        self._contexts[pid] = context
        self._enabled_state[pid] = True

        # Register tools and commands
        self._register_plugin_tools_and_commands(plugin_instance)

        logger.info("Successfully loaded plugin '%s' (version %s)", pid, manifest.version)
        return plugin_instance

    def _register_plugin_tools_and_commands(self, plugin: HelmPlugin) -> None:
        pid = plugin.plugin_id

        # Register tools
        for tool in plugin.get_tools():
            # tool name can be plain e.g. "spotify_play" or qualified "spotify:spotify_play"
            self._tools[tool.name] = tool
            self._tools[f"{pid}:{tool.name}"] = tool

        # Register commands
        for cmd in plugin.get_commands():
            self._commands[cmd.id] = cmd
            self._commands[f"{pid}:{cmd.id}"] = cmd

    def unload_plugin(self, plugin_id: str) -> bool:
        """Unloads a plugin, calls its shutdown hook, and unregisters its tools/commands."""
        pid = plugin_id.strip().lower()
        plugin = self._loaded_plugins.get(pid)
        if not plugin:
            return False

        try:
            plugin.shutdown()
        except Exception as e:
            logger.warning("Error during shutdown() of plugin '%s': %s", pid, e)

        # Clean tools
        tools_to_remove = [k for k, v in self._tools.items() if k.startswith(f"{pid}:") or getattr(v, "_plugin_id", "") == pid]
        for k in tools_to_remove:
            del self._tools[k]

        # Clean commands
        cmds_to_remove = [k for k in self._commands.items() if k[0].startswith(f"{pid}:")]
        for k, _ in cmds_to_remove:
            del self._commands[k]

        # Remove from loaded
        self._loaded_plugins.pop(pid, None)
        self._manifests.pop(pid, None)
        self._sandboxes.pop(pid, None)
        self._contexts.pop(pid, None)

        # Unregister from agent_tools if present
        try:
            import agent_tools
            agent_tools.unregister_plugin_tools(pid)
        except Exception:
            pass

        return True

    def enable_plugin(self, plugin_id: str) -> bool:
        """Enables a loaded or discovered plugin."""
        pid = plugin_id.strip().lower()
        if pid not in self._loaded_plugins:
            self.load_plugin(pid)
        self._enabled_state[pid] = True
        return True

    def disable_plugin(self, plugin_id: str) -> bool:
        """Disables an active plugin, preventing tool execution."""
        pid = plugin_id.strip().lower()
        self._enabled_state[pid] = False
        try:
            import agent_tools
            agent_tools.unregister_plugin_tools(pid)
        except Exception:
            pass
        return True

    def grant_permission(self, plugin_id: str, permission: str) -> None:
        """Grants a permission capability to an active or loaded plugin sandbox."""
        pid = plugin_id.strip().lower()
        sandbox = self._sandboxes.get(pid)
        if sandbox:
            sandbox.grant(permission)

    def revoke_permission(self, plugin_id: str, permission: str) -> None:
        """Revokes a permission capability from an active or loaded plugin sandbox."""
        pid = plugin_id.strip().lower()
        sandbox = self._sandboxes.get(pid)
        if sandbox:
            sandbox.revoke(permission)

    def get_permissions(self, plugin_id: str) -> Set[str]:
        """Gets granted permissions for a plugin."""
        pid = plugin_id.strip().lower()
        sandbox = self._sandboxes.get(pid)
        return sandbox.granted_permissions if sandbox else set()

    def execute_tool(
        self,
        plugin_id_or_tool_name: str,
        tool_name: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Executes a plugin tool with permission gating and timeout protection.

        Can be called as:
        execute_tool("weather", "weather_get_current", city="Tokyo")
        or
        execute_tool("weather_get_current", city="Tokyo")
        """
        if tool_name is None:
            # Single argument passed as tool_name
            t_name = plugin_id_or_tool_name
            tool = self._tools.get(t_name)
            pid = getattr(tool, "_plugin_id", "") if tool else ""
        else:
            pid = plugin_id_or_tool_name.strip().lower()
            t_name = tool_name
            tool = self._tools.get(f"{pid}:{t_name}") or self._tools.get(t_name)

        if not tool:
            # Check if plugin is not loaded yet
            if pid and pid not in self._loaded_plugins:
                try:
                    self.load_plugin(pid)
                    tool = self._tools.get(f"{pid}:{t_name}") or self._tools.get(t_name)
                except Exception as e:
                    return {"ok": False, "error": f"Tool '{t_name}' not found and plugin '{pid}' failed to load: {e}"}

        if not tool:
            return {"ok": False, "error": f"Plugin tool '{t_name}' not found."}

        # Resolve plugin ID if not set
        if not pid:
            for k, p in self._loaded_plugins.items():
                if tool in p.get_tools():
                    pid = k
                    break

        # Check enabled state
        if pid and not self.is_plugin_enabled(pid):
            return {"ok": False, "error": f"Plugin '{pid}' is currently disabled."}

        # Capability-based Permission Check
        sandbox = self._sandboxes.get(pid)
        for req_perm in tool.required_permissions:
            if sandbox and not sandbox.has_permission(req_perm):
                return {
                    "ok": False,
                    "error": f"Permission denied: Tool '{t_name}' requires permission '{req_perm}' which is not granted to plugin '{pid}'."
                }

        # Timeout extraction
        timeout = float(kwargs.pop("__timeout__", kwargs.pop("timeout_seconds", tool.timeout_seconds)))

        # Inspect handler kwargs
        handler = tool.handler
        try:
            sig = inspect.signature(handler)
            has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            call_kwargs = kwargs if has_var_kw else {k: v for k, v in kwargs.items() if k in sig.parameters}
        except Exception:
            call_kwargs = kwargs

        # Execute in threadpool
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(handler, **call_kwargs)
            try:
                res = future.result(timeout=timeout)
            except FutureTimeoutError:
                return {"ok": False, "error": f"Plugin tool '{t_name}' timed out after {timeout} seconds."}
            except Exception as e:
                return {"ok": False, "error": f"Plugin tool '{t_name}' raised an exception: {e}"}

        if isinstance(res, dict) and "ok" in res:
            return res
        return {"ok": True, "result": res, "data": res}

    def execute_command(self, plugin_id: str, command_id: str, **kwargs) -> Dict[str, Any]:
        """Executes a plugin command."""
        pid = plugin_id.strip().lower()
        cmd = self._commands.get(f"{pid}:{command_id}") or self._commands.get(command_id)
        if not cmd:
            return {"ok": False, "error": f"Command '{command_id}' not found in plugin '{pid}'."}

        try:
            sig = inspect.signature(cmd.handler)
            has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            call_kwargs = kwargs if has_var_kw else {k: v for k, v in kwargs.items() if k in sig.parameters}
            res = cmd.handler(**call_kwargs)
            if isinstance(res, dict) and "ok" in res:
                return res
            return {"ok": True, "result": res}
        except Exception as e:
            return {"ok": False, "error": f"Command '{command_id}' failed: {e}"}

    def list_plugins(self) -> List[Dict[str, Any]]:
        """Lists all discovered plugins and their loaded/enabled status."""
        discovered = self.discover_plugins()
        results = []
        all_ids = set(discovered.keys()).union(self._loaded_plugins.keys())

        for pid in sorted(list(all_ids)):
            p = self._loaded_plugins.get(pid)
            manifest = self._manifests.get(pid)
            if not manifest and pid in discovered:
                pdir = discovered[pid]
                mfile = pdir / "plugin.json"
                if not mfile.exists():
                    mfile = pdir / "manifest.json"
                if mfile.exists():
                    try:
                        manifest = parse_manifest(mfile)
                    except Exception:
                        pass

            entry = {
                "id": pid,
                "name": manifest.name if manifest else pid,
                "version": manifest.version if manifest else "1.0.0",
                "author": manifest.author if manifest else "Unknown",
                "description": manifest.description if manifest else "",
                "permissions": list(manifest.permissions) if manifest else [],
                "icon": manifest.icon if manifest else "puzzle",
                "category": manifest.category if manifest else "General",
                "loaded": pid in self._loaded_plugins,
                "enabled": self.is_plugin_enabled(pid),
                "tools_count": len(p.get_tools()) if p else (len(manifest.tools) if manifest else 0),
                "commands_count": len(p.get_commands()) if p else (len(manifest.commands) if manifest else 0),
                "path": str(discovered.get(pid, "")) if pid in discovered else "",
            }
            results.append(entry)
        return results

    def register_tools_with_agent(self, registry: Optional[Any] = None) -> int:
        """Registers all tools from enabled plugins into the agent tool registry."""
        try:
            import agent_tools
        except ImportError:
            return 0

        registered_count = 0
        for pid, plugin in self._loaded_plugins.items():
            if not self.is_plugin_enabled(pid):
                continue

            for tool in plugin.get_tools():
                # Set tag for lookup
                setattr(tool, "_plugin_id", pid)
                tool_entry = {
                    "plugin_id": pid,
                    "name": tool.name,
                    "description": tool.description,
                    "python_callable": f"plugin:{tool.name}",
                    "args_schema": tool.parameters,
                    "parameters": tool.parameters,
                    "plugin_dir": str(plugin.context.plugin_dir),
                    "tier": tool.capability_tier,
                    "required_permissions": tool.required_permissions,
                    "callable": tool.handler,
                }
                agent_tools.register_plugin_tool(pid, tool_entry)
                registered_count += 1

                if registry is not None and hasattr(registry, "register"):
                    try:
                        spec = agent_tools.ToolSpec(
                            name=tool.name,
                            description=tool.description,
                            parameters=tool.parameters,
                            capability_tier=tool.capability_tier,
                            runner=lambda args, caller_id, t=tool.name, p=pid: self.execute_tool(p, t, **(args if isinstance(args, dict) else {})),
                            returns_untrusted=False,
                            egress="none",
                            approval="none",
                            timeout_seconds=tool.timeout_seconds,
                        )
                        registry.register(spec, allow_consequential=True)
                    except Exception as reg_err:
                        logger.debug("ToolRegistry registration skipped for %s: %s", tool.name, reg_err)

        return registered_count

    def shutdown_all(self) -> None:
        """Shuts down all active plugins cleanly."""
        for pid in list(self._loaded_plugins.keys()):
            self.unload_plugin(pid)


# ---------------------------------------------------------------------------
# Functional Plugin Adapter (for legacy or function-based plugins)
# ---------------------------------------------------------------------------

class _FunctionalPluginAdapter(HelmPlugin):
    """Adapts module-level functions into a HelmPlugin instance based on manifest definitions."""

    def __init__(self, module: Any, context: PluginContext):
        super().__init__(context)
        self._module = module
        self._tools: List[PluginTool] = []
        self._commands: List[PluginCommand] = []

    def initialize(self) -> None:
        # If module has an init_plugin or initialize function, call it
        for hook_name in ("initialize", "init_plugin", "setup"):
            if hasattr(self._module, hook_name) and callable(getattr(self._module, hook_name)):
                getattr(self._module, hook_name)(self.context)
                break

        # Map tools from manifest
        for t_spec in self.manifest.tools:
            # Resolve handler
            handler = None
            if t_spec.python_callable:
                fn_name = t_spec.python_callable.split(":")[-1].split(".")[-1]
                handler = getattr(self._module, fn_name, None)
            if handler is None:
                handler = getattr(self._module, t_spec.name, None)

            if handler and callable(handler):
                tool = PluginTool(
                    name=t_spec.name,
                    description=t_spec.description,
                    handler=handler,
                    parameters=t_spec.parameters,
                    required_permissions=t_spec.required_permissions or self.manifest.permissions,
                    capability_tier=t_spec.capability_tier,
                    timeout_seconds=t_spec.timeout_seconds,
                )
                setattr(tool, "_plugin_id", self.plugin_id)
                self._tools.append(tool)

        # Map commands from manifest
        for c_spec in self.manifest.commands:
            handler = None
            if c_spec.handler:
                fn_name = c_spec.handler.split(":")[-1].split(".")[-1]
                handler = getattr(self._module, fn_name, None)
            if handler is None:
                handler = getattr(self._module, c_spec.id, None)

            if handler and callable(handler):
                self._commands.append(
                    PluginCommand(
                        id=c_spec.id,
                        title=c_spec.title,
                        handler=handler,
                        description=c_spec.description,
                        shortcut=c_spec.shortcut,
                        icon=c_spec.icon,
                    )
                )

    def shutdown(self) -> None:
        for hook_name in ("shutdown", "teardown", "cleanup"):
            if hasattr(self._module, hook_name) and callable(getattr(self._module, hook_name)):
                getattr(self._module, hook_name)()
                break

    def get_tools(self) -> List[PluginTool]:
        return self._tools

    def get_commands(self) -> List[PluginCommand]:
        return self._commands


# ---------------------------------------------------------------------------
# Global Singleton Accessor
# ---------------------------------------------------------------------------

_GLOBAL_MANAGER: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Returns the process-wide PluginManager singleton."""
    global _GLOBAL_MANAGER
    if _GLOBAL_MANAGER is None:
        _GLOBAL_MANAGER = PluginManager()
    return _GLOBAL_MANAGER
