"""Typed, least-privilege tool registry for the shared conversational core."""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from typing import Any, Callable


MAX_TOOL_RESULT_CHARS = 8_000
logger = logging.getLogger("homie.agent_tools")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    capability_tier: str
    runner: Callable[[dict[str, Any], str], Any]
    timeout_seconds: float = 5.0


class ToolRegistry:
    """Registry that accepts read-only tools and validates all arguments."""

    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="homie-read-tool")
        self._closed = False

    def register(self, spec: ToolSpec, allow_consequential: bool = False) -> None:
        if spec.capability_tier != "READ_ONLY" and not allow_consequential:
            raise ValueError(f"Tool '{spec.name}' is not read-only; consequential tools are not available in this tier.")
        if not spec.name or spec.name in self._tools:
            raise ValueError(f"Tool name '{spec.name}' is empty or already registered.")
        if spec.timeout_seconds <= 0:
            raise ValueError("Tool timeout must be positive.")
        self._tools[spec.name] = spec

    def schemas(self) -> list[dict[str, Any]]:
        """OpenAI-compatible function schemas for the model request."""
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": {**tool.parameters, "additionalProperties": False},
                },
            }
            for tool in self._tools.values()
        ]

    def execute(
        self,
        name: str,
        arguments: Any,
        caller_id: str = "ai_text_agent",
        approval_token: str | None = None,
    ) -> dict[str, Any]:
        if self._closed:
            return {"ok": False, "error": "The tool registry is closed."}
        tool = self._tools.get(name)
        if tool is None:
            return {"ok": False, "error": f"Tool '{name}' is not available."}
        error = _validate_arguments(tool.parameters, arguments)
        if error:
            return {"ok": False, "error": error}

        # Emergency kill switch check: immediately pauses all tool executions
        import kill_switch
        if kill_switch.is_kill_switch_active():
            return {
                "ok": False,
                "error": "The emergency kill switch is active; tool execution is paused. You can continue speaking with me or disengage the kill switch.",
            }

        import rails_config
        import rails_confirmation
        import rails_audit
        import rails_content_boundary

        cfg = rails_config.get_rails_config()
        gate = rails_confirmation.get_confirmation_gate()
        audit = rails_audit.get_rails_audit()

        is_consequential = cfg.is_confirmation_required(name) or tool.capability_tier in ("CONSEQUENTIAL", "WRITE_EXEC")
        confirmed = False

        if is_consequential:
            if not approval_token:
                req = gate.create_request(name, arguments if isinstance(arguments, dict) else {}, caller_id=caller_id)
                audit.record_confirmation_event(req.request_id, name, "CREATED", req.impact_summary)
                return {
                    "ok": False,
                    "needs_confirmation": True,
                    "request_id": req.request_id,
                    "tool_name": name,
                    "impact_summary": req.impact_summary,
                    "message": f"Confirmation required: {req.impact_summary} (Request ID: {req.request_id})",
                }
            else:
                valid, err_msg = gate.verify_and_consume_token(name, approval_token)
                if not valid:
                    audit.record_confirmation_event(approval_token, name, "DENIED", err_msg)
                    return {"ok": False, "error": f"Confirmation token invalid: {err_msg}"}
                confirmed = True
                audit.record_confirmation_event(approval_token, name, "CONSUMED", "Token verified and consumed")
        else:
            try:
                # Recheck the shared policy classification at execution time. A tool
                # cannot become write-capable by changing the broker registry.
                import homie_supervisor

                allowed_tier = homie_supervisor.get_allowed_tools_map().get(name)
                if allowed_tier != "READ_ONLY":
                    return {"ok": False, "error": "The policy broker does not classify this tool as read-only."}
            except Exception:
                return {"ok": False, "error": "The policy broker is unavailable; the tool was not run."}

        start_time = time.perf_counter()
        future = self._executor.submit(tool.runner, arguments, caller_id)
        try:
            data = future.result(timeout=tool.timeout_seconds)
        except TimeoutError:
            future.cancel()
            return {"ok": False, "error": f"Tool '{name}' timed out after {tool.timeout_seconds:g} seconds."}
        except Exception:
            return {"ok": False, "error": f"Tool '{name}' failed. No result was returned."}

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if isinstance(data, dict) and data.get("ok") is False:
            result = data
        else:
            result = data if isinstance(data, dict) and data.get("ok") is True else {"ok": True, "data": data}

        # Process external content: scan for planted instructions & wrap in untrusted data delimiters
        if isinstance(result.get("data"), str):
            raw_data = result["data"]
            is_json = False
            try:
                parsed = json.loads(raw_data)
                if isinstance(parsed, (dict, list)):
                    is_json = True
                    is_injected, snippet = rails_content_boundary.detect_instruction_injection(raw_data)
                    if is_injected:
                        result["security_flag"] = (
                            f"Security Flag: Content from 'tool_{name}' contains a planted instruction attempt "
                            f"({snippet!r}). Treated strictly as passive data; the instruction will not be executed."
                        )
            except (json.JSONDecodeError, TypeError):
                is_json = False

            if not is_json:
                wrapped, is_injected, warning = rails_content_boundary.process_external_content(
                    raw_data, source=f"tool_{name}"
                )
                result["data"] = wrapped
                if is_injected:
                    result["security_flag"] = warning

        # OpenJarvis Redaction Filter: Redact credentials, API keys, and private keys
        import homie_credential_stripper
        result = homie_credential_stripper.redact_secrets(result)

        try:
            encoded = json.dumps(result, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return {"ok": False, "error": f"Tool '{name}' returned an invalid result."}
        if len(encoded) > MAX_TOOL_RESULT_CHARS:
            return {"ok": False, "error": f"Tool '{name}' returned more data than the allowed limit."}

        audit.record_tool_execution(
            tool_name=name,
            arguments=arguments if isinstance(arguments, dict) else {},
            caller_id=caller_id,
            ok=result.get("ok", False),
            latency_ms=round(latency_ms, 2),
            requires_confirmation=is_consequential,
            confirmed=confirmed,
        )

        return result

    def close(self) -> None:
        """Stop tool workers and cleanly shut down only an unlocked local broker."""
        if self._closed:
            return
        self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=True)
        try:
            import action_broker
            import homie_supervisor

            broker = action_broker._GLOBAL_BROKER
            supervisor = getattr(broker, "supervisor", None) if broker else None
            if supervisor and supervisor.state != homie_supervisor.STATE_LOCKED:
                supervisor.clean_shutdown()
                action_broker._GLOBAL_BROKER = None
        except Exception:
            # Preserve dirty/locked state if shutdown cannot be verified.
            logger.warning("Could not verify a clean ActionBroker shutdown.")


def _validate_arguments(schema: dict[str, Any], arguments: Any) -> str | None:
    if not isinstance(arguments, dict):
        return "Arguments must be a JSON object."
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    extras = set(arguments) - set(properties)
    if extras:
        return f"Unexpected argument(s): {', '.join(sorted(map(str, extras)))}."
    missing = set(required) - set(arguments)
    if missing:
        return f"Missing required argument(s): {', '.join(sorted(missing))}."
    for name, value in arguments.items():
        spec = properties[name]
        expected = spec.get("type")
        if expected == "integer":
            valid_type = isinstance(value, int) and not isinstance(value, bool)
        elif expected == "number":
            valid_type = isinstance(value, (int, float)) and not isinstance(value, bool)
        elif expected == "string":
            valid_type = isinstance(value, str)
        elif expected == "boolean":
            valid_type = isinstance(value, bool)
        elif expected == "array":
            valid_type = isinstance(value, list)
        elif expected == "object":
            valid_type = isinstance(value, dict)
        else:
            return f"Tool schema for '{name}' has an unsupported type."
        if not valid_type:
            return f"Argument '{name}' must be {expected}."
        if "enum" in spec and value not in spec["enum"]:
            return f"Argument '{name}' must be one of: {', '.join(map(str, spec['enum']))}."
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in spec and value < spec["minimum"]:
                return f"Argument '{name}' must be at least {spec['minimum']}."
            if "maximum" in spec and value > spec["maximum"]:
                return f"Argument '{name}' must be at most {spec['maximum']}."
    return None


def _run_broker_tool(tool_name: str, args: dict[str, Any], caller_id: str) -> dict[str, Any]:
    import action_broker

    ok, message, data = action_broker.execute_action(tool_name, args, caller_id=caller_id)
    if not ok:
        return {"ok": False, "error": str(message)[:500]}
    if tool_name == "homie_get_vitals":
        # Keep the tool useful while avoiding sending the foreground window
        # title or other activity details to the configured model.
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                pass
        if isinstance(data, dict):
            allowed_fields = {"ram_pct", "ram_avail_gb", "ram_total_gb", "disk_free_gb", "disk_total_gb", "battery", "uptime_hours"}
            data = {key: value for key, value in data.items() if key in allowed_fields}
    return {"ok": True, "data": data}


def build_default_registry() -> ToolRegistry:
    """Register the initial two low-risk, read-only workstation tools."""
    registry = ToolRegistry()
    registry.register(ToolSpec(
        name="homie_get_vitals",
        description="Read current PC health, including memory, disk, battery, and uptime.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("homie_get_vitals", args, caller_id),
    ))
    registry.register(ToolSpec(
        name="homie_list_downloads",
        description="List recent files in Downloads when the user asks which files they downloaded. Returns file names, paths, sizes, and modification times.",
        parameters={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 10}},
            "required": [],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("homie_list_downloads", args, caller_id),
    ))
    registry.register(ToolSpec(
        name="homie_remember_fact",
        description="Records or updates a durable personal fact about the user (e.g. name, preferences, work habits) that persists across restarts.",
        parameters={
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "fact": {"type": "string"},
            },
            "required": ["key", "fact"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("homie_remember_fact", args, caller_id),
    ))
    registry.register(ToolSpec(
        name="homie_forget_fact",
        description="Deletes a stale or outdated durable fact from the persistent memory store.",
        parameters={
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("homie_forget_fact", args, caller_id),
    ))
    registry.register(ToolSpec(
        name="homie_list_facts",
        description="Lists all durable facts currently saved in the persistent memory store.",
        parameters={"type": "object", "properties": {}, "required": []},
        capability_tier="READ_ONLY",
        runner=lambda args, caller_id: _run_broker_tool("homie_list_facts", args, caller_id),
    ))
    return registry


def add_consequential_tools(registry: ToolRegistry) -> ToolRegistry:
    """Registers consequential tools protected by the Tier 6 hard confirmation gate."""
    registry.register(
        ToolSpec(
            name="homie_set_clipboard",
            description="Copies given text onto the user's system clipboard.",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            capability_tier="CONSEQUENTIAL",
            runner=lambda args, caller_id: _run_broker_tool("homie_set_clipboard", args, caller_id),
        ),
        allow_consequential=True,
    )
    registry.register(
        ToolSpec(
            name="homie_launch_app",
            description="Launches an approved desktop application by name.",
            parameters={
                "type": "object",
                "properties": {"app_name": {"type": "string"}},
                "required": ["app_name"],
            },
            capability_tier="CONSEQUENTIAL",
            runner=lambda args, caller_id: _run_broker_tool("homie_launch_app", args, caller_id),
        ),
        allow_consequential=True,
    )
    return registry


def build_full_registry() -> ToolRegistry:
    """Builds a full registry including read-only tools and gated consequential tools."""
    registry = build_default_registry()
    add_consequential_tools(registry)
    return registry
