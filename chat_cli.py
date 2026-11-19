"""Run Helm's text-first, streaming terminal conversation."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agent_tools import build_default_registry
from chat_core import AgentCore, ProviderError, build_system_prompt


ROOT = Path(__file__).resolve().parent
DEFAULT_PREFS = {
    "provider": "gemini",
    "model": "gemini-flash-lite-latest",
    "apiBase": "",
    "apiKey": "",
    "geminiKey": "",
    "nvidiaKey": "",
    "groqKey": "",
}


def config_dir() -> Path:
    return Path(os.environ.get("HELM_DIR") or (Path.home() / ".config" / "helm"))


def load_preferences() -> dict:
    prefs = DEFAULT_PREFS.copy()
    path = config_dir() / "settings.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            prefs.update(data)
    except FileNotFoundError:
        pass
    except (OSError, json.JSONDecodeError):
        print(f"Warning: could not read {path}; using default provider settings.")
    return prefs


def load_mission() -> str:
    try:
        content = (ROOT / "AGENT.md").read_text(encoding="utf-8")
        section = content.split("## Mission", 1)[1].split("\n## ", 1)[0]
        return " ".join(line.strip() for line in section.splitlines() if line.strip())
    except (OSError, IndexError):
        return "Build a dependable personal assistant that helps the user safely and honestly."


def main() -> int:
    prefs = load_preferences()
    assistant_name = os.environ.get("HELM_NAME") or prefs.get("assistantName") or "Helm"
    registry = build_default_registry()
    import durable_memory
    memory_store = durable_memory.get_default_memory_store()
    facts = memory_store.list_facts()
    core = AgentCore(
        build_system_prompt(str(assistant_name), load_mission(), facts=facts),
        prefs,
        tool_registry=registry,
        memory_store=memory_store,
    )
    print(f"{assistant_name} text chat — type /quit to exit.")
    print("Conversation history lasts for this session only.\n")

    try:
        while True:
            try:
                user_text = input("You> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye.")
                return 0
            if user_text.lower() in {"/quit", "/exit"}:
                print("Goodbye.")
                return 0
            if not user_text:
                continue
            print(f"{assistant_name}> ", end="", flush=True)
            try:
                core.turn(user_text, lambda delta: print(delta, end="", flush=True))
                print("\n")
            except ProviderError as exc:
                print(f"\n[Provider unavailable] {exc}\nYou can try again or change provider settings.\n")
            except Exception as exc:
                print(f"\n[Turn failed] {exc.__class__.__name__}. The conversation is ready for another message.\n")
    finally:
        registry.close()


if __name__ == "__main__":
    raise SystemExit(main())
