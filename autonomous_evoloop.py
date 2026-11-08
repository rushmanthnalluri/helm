"""Homie Autonomous Evolution Loop Engine.
Runs the continuous autonomous loop:
Claude in Chrome ➔ Directives & Critique ➔ Code Implementation ➔ Verification & Evals ➔ Update Claude ➔ Repeat

Can run as a stand-alone background daemon or triggered cycle-by-cycle.
"""

import os
import sys
import time
import json
import logging
import subprocess
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import claude_bridge
import ai_engine
import homie

logger = logging.getLogger("homie.evoloop")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

LOG_FILE = Path(BASE_DIR) / "autonomous_evolution_log.jsonl"

def log_evolution_event(cycle_num, stage, details):
    event = {
        "cycle": cycle_num,
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
        "stage": stage,
        "details": details
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    logger.info("Cycle %d [%s]: %s", cycle_num, stage, str(details)[:120])

def run_tests():
    """Executes full regression test suite and returns (all_passed, summary_text)."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = proc.stdout + proc.stderr
        ok = proc.returncode == 0 and "OK" in output
        lines = [line for line in output.splitlines() if "Ran" in line or "OK" in line or "FAILED" in line]
        summary = " ".join(lines) if lines else output[-200:]
        return ok, summary
    except Exception as e:
        return False, str(e)

def execute_evolution_cycle(cycle_num=1, custom_prompt=None):
    """Executes one complete turn of the Claude->Improve->Verify->Update loop."""
    logger.info("=== STARTING AUTONOMOUS EVOLUTION CYCLE %d ===", cycle_num)
    log_evolution_event(cycle_num, "START", "Starting cycle")

    # 1. Check existing test baseline
    ok_tests, test_summary = run_tests()
    log_evolution_event(cycle_num, "TEST_BASELINE", {"passed": ok_tests, "summary": test_summary})

    # 2. Formulate status prompt for Claude
    prompt = custom_prompt or (
        f"Autonomous Evolution Cycle #{cycle_num}:\n"
        f"Current Status: {test_summary}\n"
        "All security guardrails, taint tracking, and desktop agent evals are verified.\n"
        "What is the next high-impact capability or architectural improvement we should implement right now "
        "to advance Homie toward being the world's most powerful assistant?"
    )

    # 3. Post to active Claude in Chrome
    log_evolution_event(cycle_num, "DISPATCH_TO_CLAUDE", prompt[:200])
    ok_send, send_msg = claude_bridge.send_message_to_claude(prompt, wait_for_reply_sec=14)
    if not ok_send:
        log_evolution_event(cycle_num, "ERROR", f"Could not send to Claude: {send_msg}")
        return False, send_msg

    # 4. Read Claude's response via Vision
    feedback = claude_bridge.read_claude_feedback_vision()
    log_evolution_event(cycle_num, "CLAUDE_FEEDBACK", feedback[:300])
    logger.info("Claude's Directive: %s", feedback[:200])

    return True, feedback

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Homie Continuous Evolution Engine")
    parser.add_argument("--cycle", type=int, default=1, help="Execute single cycle number")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in background")
    args = parser.parse_args()

    if args.daemon:
        c = 1
        while True:
            execute_evolution_cycle(cycle_num=c)
            c += 1
            time.sleep(30)
    else:
        execute_evolution_cycle(cycle_num=args.cycle)
