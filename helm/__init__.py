"""Helm: The Modular Desktop AI Assistant Platform.

Subpackages:
    helm.core   - OS foundations, security vault, daemon, supervisor, confinement
    helm.gui    - Windows 11 materials, Omnibar, HUDs, Action Pill, app shell
    helm.engine - Caret dictation, deterministic UIA, AI engine, agent tools, workflows
"""

import os
import sys
import importlib
import importlib.abc
import importlib.machinery

__version__ = "1.0.0"
__author__ = "Helm Desktop Team"

# ---------------------------------------------------------------------------
# Dynamic Backward-Compatibility Shim Finder (PEP 451)
# Allows legacy code and tests to `import action_broker` or `from app import ...`
# ---------------------------------------------------------------------------

LEGACY_MODULE_MAP = {
    # helm.gui (7 modules)
    "app": "helm.gui.app",
    "action_pill": "helm.gui.action_pill",
    "helm_canvas": "helm.gui.helm_canvas",
    "helm_hud": "helm.gui.helm_hud",
    "helm_omnibar": "helm.gui.helm_omnibar",
    "helm_style": "helm.gui.helm_style",
    "tray_hud": "helm.gui.tray_hud",

    # helm.core (52 modules)
    "action_broker": "helm.core.action_broker",
    "agent_audit_ledger": "helm.core.agent_audit_ledger",
    "canary_monitor": "helm.core.canary_monitor",
    "client_token_auth": "helm.core.client_token_auth",
    "crypto_vault": "helm.core.crypto_vault",
    "db_utils": "helm.core.db_utils",
    "device_registry": "helm.core.device_registry",
    "durable_memory": "helm.core.durable_memory",
    "event_log": "helm.core.event_log",
    "heartbeat_lease": "helm.core.heartbeat_lease",
    "heartbeat_service": "helm.core.heartbeat_service",
    "helm_core_cli": "helm.core.helm",
    "helm_confinement": "helm.core.helm_confinement",
    "helm_credential_stripper": "helm.core.helm_credential_stripper",
    "helm_episodic_memory": "helm.core.helm_episodic_memory",
    "helm_file_witness": "helm.core.helm_file_witness",
    "helm_hal": "helm.core.helm_hal",
    "helm_hardware_profiler": "helm.core.helm_hardware_profiler",
    "helm_intrusion_watch": "helm.core.helm_intrusion_watch",
    "helm_knowledge_graph": "helm.core.helm_knowledge_graph",
    "helm_layout_profiles": "helm.core.helm_layout_profiles",
    "helm_netstat": "helm.core.helm_netstat",
    "helm_quarantine_reader": "helm.core.helm_quarantine_reader",
    "helm_resource_tracker": "helm.core.helm_resource_tracker",
    "helm_selfheal": "helm.core.helm_selfheal",
    "helm_ssrf": "helm.core.helm_ssrf",
    "helm_structured_approval": "helm.core.helm_structured_approval",
    "helm_supervisor": "helm.core.helm_supervisor",
    "helm_supervisor_daemon": "helm.core.helm_supervisor_daemon",
    "helm_sync": "helm.core.helm_sync",
    "helm_sync_vault": "helm.core.helm_sync_vault",
    "helm_telemetry": "helm.core.helm_telemetry",
    "helm_updater": "helm.core.helm_updater",
    "helm_watchdog": "helm.core.helm_watchdog",
    "key_recovery": "helm.core.key_recovery",
    "kill_switch": "helm.core.kill_switch",
    "locked_recovery": "helm.core.locked_recovery",
    "log_redactor": "helm.core.log_redactor",
    "pipeline_telemetry": "helm.core.pipeline_telemetry",
    "policy_envelope": "helm.core.policy_envelope",
    "rails_audit": "helm.core.rails_audit",
    "rails_config": "helm.core.rails_config",
    "rails_confirmation": "helm.core.rails_confirmation",
    "rails_content_boundary": "helm.core.rails_content_boundary",
    "shadow_mode": "helm.core.shadow_mode",
    "step_up_gate": "helm.core.step_up_gate",
    "taint_tracker": "helm.core.taint_tracker",
    "trust_tiers": "helm.core.trust_tiers",
    "update_verifier": "helm.core.update_verifier",
    "windows_hello": "helm.core.windows_hello",
    "worker_confinement": "helm.core.worker_confinement",
    "workspace_manager": "helm.core.workspace_manager",

    # helm.engine (63 modules)
    "adversarial_red_team": "helm.engine.adversarial_red_team",
    "agent_tools": "helm.engine.agent_tools",
    "ai_engine": "helm.engine.ai_engine",
    "assistant_timeline": "helm.engine.assistant_timeline",
    "autonomous_evoloop": "helm.engine.autonomous_evoloop",
    "chat_cli": "helm.engine.chat_cli",
    "chat_core": "helm.engine.chat_core",
    "clipboard_classifier": "helm.engine.clipboard_classifier",
    "desktop_agent": "helm.engine.desktop_agent",
    "file_indexer": "helm.engine.file_indexer",
    "focus_tracker": "helm.engine.focus_tracker",
    "grounding_tools": "helm.engine.grounding_tools",
    "helm_anticipatory": "helm.engine.helm_anticipatory",
    "helm_apps_catalog": "helm.engine.helm_apps_catalog",
    "helm_attachments": "helm.engine.helm_attachments",
    "helm_briefing": "helm.engine.helm_briefing",
    "helm_briefs": "helm.engine.helm_briefs",
    "helm_browser_broker": "helm.engine.helm_browser_broker",
    "helm_cdp": "helm.engine.helm_cdp",
    "helm_context_search": "helm.engine.helm_context_search",
    "helm_everything_search": "helm.engine.helm_everything_search",
    "helm_focus_mode": "helm.engine.helm_focus_mode",
    "helm_ghost_desktop": "helm.engine.helm_ghost_desktop",
    "helm_ide_bridge": "helm.engine.helm_ide_bridge",
    "helm_lazy": "helm.engine.helm_lazy",
    "helm_learn": "helm.engine.helm_learn",
    "helm_live_voice": "helm.engine.helm_live_voice",
    "helm_mail_calendar": "helm.engine.helm_mail_calendar",
    "helm_mcp": "helm.engine.helm_mcp",
    "helm_memory_extractor": "helm.engine.helm_memory_extractor",
    "helm_plan_envelopes": "helm.engine.helm_plan_envelopes",
    "helm_plugins": "helm.engine.helm_plugins",
    "helm_plugin_sdk": "helm.engine.helm_plugin_sdk",
    "helm_retrospective": "helm.engine.helm_retrospective",
    "helm_session_compression": "helm.engine.helm_session_compression",
    "helm_skills": "helm.engine.helm_skills",
    "helm_snapshot": "helm.engine.helm_snapshot",
    "helm_tts": "helm.engine.helm_tts",
    "helm_vla_agent": "helm.engine.helm_vla_agent",
    "helm_voice_stream": "helm.engine.helm_voice_stream",
    "helm_watchers": "helm.engine.helm_watchers",
    "helm_worker": "helm.engine.helm_worker",
    "helm_workflow_engine": "helm.engine.helm_workflow_engine",
    "helm_writer": "helm.engine.helm_writer",
    "injection_baseline_harness": "helm.engine.injection_baseline_harness",
    "meeting_notes": "helm.engine.meeting_notes",
    "mobile_remote": "helm.engine.mobile_remote",
    "notification_mirror": "helm.engine.notification_mirror",
    "presence_monitor": "helm.engine.presence_monitor",
    "quick_notes": "helm.engine.quick_notes",
    "reminder_scheduler": "helm.engine.reminder_scheduler",
    "screen_ocr_engine": "helm.engine.screen_ocr_engine",
    "semantic_screen_memory": "helm.engine.semantic_screen_memory",
    "skill_compiler": "helm.engine.skill_compiler",
    "startup_bench": "helm.engine.startup_bench",
    "task_manager": "helm.engine.task_manager",
    "telegram_bridge": "helm.engine.telegram_bridge",
    "voice": "helm.engine.voice",
    "voice_inject": "helm.engine.voice_inject",
    "voice_pipeline": "helm.engine.voice_pipeline",
    "wake_word_engine": "helm.engine.wake_word_engine",
    "windows_tools": "helm.engine.windows_tools",
    "workflow_compiler": "helm.engine.workflow_compiler",

    # Compatibility shims for purged modules
    "phone_approval_portal": "helm.core.device_registry",
    "phone_testing_keys": "helm.core.testing_keys",
    "tests.phone_testing_keys": "helm.core.testing_keys",
}

class HelmShimLoader(importlib.abc.Loader):
    def __init__(self, target_module: str):
        self.target_module = target_module

    def create_module(self, spec):
        mod = importlib.import_module(self.target_module)
        sys.modules[spec.name] = mod
        return mod

    def exec_module(self, module):
        pass

class HelmShimFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in LEGACY_MODULE_MAP:
            target_name = LEGACY_MODULE_MAP[fullname]
            return importlib.machinery.ModuleSpec(fullname, HelmShimLoader(target_name))
        return None

def install_shim_hook():
    """Install the Helm dynamic backward-compatibility import hook."""
    for finder in sys.meta_path:
        if isinstance(finder, HelmShimFinder):
            return
    sys.meta_path.insert(0, HelmShimFinder())

# Automatically activate the hook on import
install_shim_hook()

# Subpackage exports
from helm import core
from helm import gui
from helm import engine

# Re-export all 18 top-level CLI and utility functions from helm.core.helm
try:
    from helm.core.helm import (
        get_prefs,
        save_pref,
        get_rules,
        add_rule,
        remove_rule,
        log_event,
        get_macros,
        save_macro,
        delete_macro,
        execute_macro,
        analyze_clipboard,
        try_fast_command,
        web_search,
        web_read,
        is_risky,
        build_system_prompt,
        run_ai,
        run_claude,
        main,
    )
except ImportError:
    pass

def __getattr__(name):
    """Dynamic fallback for any module attributes delegating to helm.core.helm."""
    try:
        import helm.core.helm as _core_helm
        if hasattr(_core_helm, name):
            return getattr(_core_helm, name)
    except ImportError:
        pass
    raise AttributeError(f"module 'helm' has no attribute '{name}'")
