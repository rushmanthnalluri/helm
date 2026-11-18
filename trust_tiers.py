"""
Homie Progressive Trust Authorization System
4-tier model for balancing security and usability.

Tier 0 — Ambient: Pure reads, zero friction, no approval.
Tier 1 — Safe local actions: Non-blocking toast + 5-second undo window.
Tier 2 — Consequential local: Windows Hello / local PIN confirmation (blocking, but on-device).
Tier 3 — High-risk / irreversible: Out-of-band WebAuthn phone approval.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("homie.trust_tiers")

# ---------------------------------------------------------------------------
# Tier constants
# ---------------------------------------------------------------------------
TIER_0_AMBIENT = 0           # Read-only, no approval needed
TIER_1_SAFE = 1              # Safe local actions, non-blocking toast + 5s undo
TIER_2_LOCAL_BIOMETRIC = 2   # Windows Hello / local PIN confirmation
TIER_3_HIGH_RISK = 3         # Out-of-band WebAuthn phone approval (destructive ops)

# ---------------------------------------------------------------------------
# Tool → tier mapping
# Covers the tool names registered in agent_tools.py as well as action_broker
# names used in rails_confirmation._format_impact_summary().
# Unknown tools default to TIER_2_LOCAL_BIOMETRIC (fail-safe).
# ---------------------------------------------------------------------------
TOOL_TIERS: dict[str, int] = {
    # ------------------------------------------------------------------
    # Tier 0: Pure reads — no user impact, no approval needed
    # ------------------------------------------------------------------
    "homie_read_screen":        TIER_0_AMBIENT,
    "homie_get_window_list":    TIER_0_AMBIENT,
    "homie_everything_search":  TIER_0_AMBIENT,
    "homie_recall_screen":      TIER_0_AMBIENT,
    "homie_get_clipboard":      TIER_0_AMBIENT,
    "homie_get_vitals":         TIER_0_AMBIENT,
    "homie_list_downloads":     TIER_0_AMBIENT,
    "homie_list_skills":        TIER_0_AMBIENT,
    "homie_read_skill":         TIER_0_AMBIENT,
    "homie_search_context":     TIER_0_AMBIENT,
    "homie_read_attachment":    TIER_0_AMBIENT,
    "homie_list_watchers":      TIER_0_AMBIENT,
    "homie_check_watcher":      TIER_0_AMBIENT,
    "homie_learn_topic":        TIER_0_AMBIENT,
    "homie_list_apps":          TIER_0_AMBIENT,
    "homie_get_app_info":       TIER_0_AMBIENT,
    "homie_list_plugins":       TIER_0_AMBIENT,
    "homie_instant_file_search": TIER_0_AMBIENT,
    "homie_get_ide_context":    TIER_0_AMBIENT,
    "homie_show_canvas":        TIER_0_AMBIENT,
    "homie_list_facts":         TIER_0_AMBIENT,
    "homie_remember_fact":      TIER_0_AMBIENT,
    "homie_forget_fact":        TIER_0_AMBIENT,
    "homie_generate_briefing":  TIER_0_AMBIENT,
    "homie_generate_eod_narrative": TIER_0_AMBIENT,
    "homie_list_brief_templates": TIER_0_AMBIENT,
    "homie_get_knowledge_dossier": TIER_0_AMBIENT,
    "homie_search_knowledge_graph": TIER_0_AMBIENT,
    "homie_get_pre_meeting_card": TIER_0_AMBIENT,

    # ------------------------------------------------------------------
    # Tier 1: Safe local actions — non-blocking toast + 5s undo window
    # Easily reversible, no data loss, no network egress.
    # ------------------------------------------------------------------
    "homie_launch_app":         TIER_1_SAFE,
    "homie_set_clipboard":      TIER_1_SAFE,
    "homie_window_snap":        TIER_1_SAFE,
    "homie_agent_click":        TIER_1_SAFE,
    "homie_agent_type":         TIER_1_SAFE,
    "homie_agent_mouse_move":   TIER_1_SAFE,
    "homie_press_key":          TIER_1_SAFE,
    "homie_send_hotkey":        TIER_1_SAFE,
    "homie_open_url":           TIER_1_SAFE,
    "homie_volume_control":     TIER_1_SAFE,
    "homie_media_control":      TIER_1_SAFE,
    "homie_close_app":          TIER_1_SAFE,
    "homie_link_knowledge":     TIER_1_SAFE,
    "homie_add_watcher":        TIER_1_SAFE,
    "homie_remove_watcher":     TIER_1_SAFE,

    # ------------------------------------------------------------------
    # Tier 2: Consequential local — Windows Hello PIN / biometric gate
    # Creates/modifies data or sends communications; reversible with effort.
    # ------------------------------------------------------------------
    "homie_send_email":         TIER_2_LOCAL_BIOMETRIC,
    "homie_send_whatsapp":      TIER_2_LOCAL_BIOMETRIC,
    "homie_send_chat":          TIER_2_LOCAL_BIOMETRIC,
    "homie_modify_file":        TIER_2_LOCAL_BIOMETRIC,
    "homie_create_file":        TIER_2_LOCAL_BIOMETRIC,
    "homie_make_document":      TIER_2_LOCAL_BIOMETRIC,
    "homie_make_presentation":  TIER_2_LOCAL_BIOMETRIC,
    "homie_make_spreadsheet":   TIER_2_LOCAL_BIOMETRIC,
    "homie_system_settings":    TIER_2_LOCAL_BIOMETRIC,
    "homie_install_plugin":     TIER_2_LOCAL_BIOMETRIC,
    "homie_uninstall_plugin":   TIER_2_LOCAL_BIOMETRIC,
    "homie_safe_command":       TIER_2_LOCAL_BIOMETRIC,

    # ------------------------------------------------------------------
    # Tier 3: High-risk / irreversible — out-of-band phone WebAuthn
    # Shell exec, process kill, file deletion, financial ops.
    # ------------------------------------------------------------------
    "homie_run_shell":          TIER_3_HIGH_RISK,
    "homie_run_ghost_task":     TIER_3_HIGH_RISK,
    "homie_kill_process":       TIER_3_HIGH_RISK,
    "homie_delete_file":        TIER_3_HIGH_RISK,
    "homie_financial_action":   TIER_3_HIGH_RISK,
    "homie_install_software":   TIER_3_HIGH_RISK,
    "homie_vla_step":           TIER_3_HIGH_RISK,
}


def get_tool_tier(tool_name: str) -> int:
    """Return the trust tier for a tool.

    Unknown tools default to TIER_2_LOCAL_BIOMETRIC (fail-safe: require
    Windows Hello before an unclassified tool can run).
    """
    tier = TOOL_TIERS.get(tool_name, TIER_2_LOCAL_BIOMETRIC)
    logger.debug("Tool '%s' → tier %d", tool_name, tier)
    return tier


def requires_confirmation(tool_name: str) -> bool:
    """Returns True if the tool requires *any* form of user confirmation (Tier 2+)."""
    return get_tool_tier(tool_name) >= TIER_2_LOCAL_BIOMETRIC


def get_tier_label(tier: int) -> str:
    """Human-readable label for a tier constant."""
    tier_labels = {
        TIER_0_AMBIENT:        "Ambient (no approval)",
        TIER_1_SAFE:           "Safe local action (undo available)",
        TIER_2_LOCAL_BIOMETRIC: "Consequential (Windows Hello)",
        TIER_3_HIGH_RISK:      "High-risk (phone approval required)",
    }
    return tier_labels.get(tier, "Unknown")
