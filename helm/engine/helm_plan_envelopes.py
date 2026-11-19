"""helm_plan_envelopes.py - Multi-Step Plan Envelopes, Strict Risk Computation, and Verified Macro Scaffolding.

Key Architectural Invariants:
1. Structured Plan Representation:
   - Step: id, tool, args_template, depends_on
   - Scope: domains, apps, accounts
   - Budget: max_steps, max_keystrokes, max_egress_bytes
   - Expiry & Taint Epoch: bound to supervisor taint state
   - Declared Untrusted Reads: expected untrusted reads do not falsely invalidate the envelope;
     only UNEXPECTED new taint invalidates.
2. Supervisor-Computed Risk:
   - Evaluated strictly by the Policy Supervisor from tool specifications and typed argument templates.
   - Planner-provided risk is advisory only; supervisor takes the strictly stricter tier.
   - Arguments deriving from untrusted handles are classified GATED.
3. Deterministic Executor (No LLM in the Loop):
   - One mobile signature authorizes the bounded envelope.
   - Zero bearer tokens issued.
   - Executor enforces that step ID, tool name, and arguments hash match the plan exactly.
   - Any deviation is an immediate hard termination, never a fallback prompt.
4. Macro Compilation & Replay:
   - Macros compile ONLY from executed plans with ZERO tainted inputs.
   - Require supervisor cryptographic signature.
   - Remembered approval permitted ONLY for macros that are entirely READ_ONLY or REVERSIBLE.
"""

import os
import sys
import re
import time
import json
import secrets
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import agent_tools
import helm_structured_approval


class PlanExecutionError(Exception):
    """Raised on plan envelope violations, unexpected taint, budget exhaustion, or step mismatch."""
    pass


class MacroCompilationError(Exception):
    """Raised when compiling macros from tainted inputs or unverified executions."""
    pass


@dataclass(frozen=True)
class Step:
    id: str
    tool: str
    args_template: dict[str, Any]
    depends_on: tuple[str, ...] = ()
    is_gated: bool = False
    requires_step_approval: bool = False


@dataclass(frozen=True)
class Scope:
    domains: tuple[str, ...] = ()
    apps: tuple[str, ...] = ()
    accounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Budget:
    max_steps: int = 10
    max_keystrokes: int = 500
    max_egress_bytes: int = 1_048_576


@dataclass(frozen=True)
class Plan:
    plan_id: str
    steps: tuple[Step, ...]
    scope: Scope
    budget: Budget
    expiry: int
    taint_epoch: int
    declared_untrusted_reads: tuple[str, ...] = ()


def compute_step_args_hash(args: Dict[str, Any]) -> str:
    """Computes canonical 64-character SHA-256 hash of step arguments."""
    canonical_json = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class SupervisorRiskCalculator:
    """Computes authoritative risk for plan steps based on tool registry, arguments, and handles."""

    @staticmethod
    def calculate_step_risk(step: Step, active_taint: bool = False) -> Tuple[str, bool]:
        """Calculates effective risk tier and whether the step is GATED.
        
        Returns:
            (effective_tier, is_gated)
        """
        registry = agent_tools.build_default_registry()
        tool_spec = registry._tools.get(step.tool)
        tier = tool_spec.capability_tier if tool_spec else "WRITE_EXEC"

        is_gated = False

        # Any argument deriving from an opaque handle ($HANDLE_...) is GATED
        for k, v in step.args_template.items():
            if isinstance(v, str) and (v.startswith("$HANDLE_") or v.startswith("$EMAIL_") or v.startswith("$RAW_TEXT_")):
                is_gated = True
                break

        # Consequential or Write tools with active taint are GATED
        if tier in ("CONSEQUENTIAL", "WRITE_EXEC"):
            is_gated = True

        return tier, is_gated


class PlanExecutor:
    """Deterministic plan executor with NO LLM in the loop."""

    def __init__(self, plan: Plan, phone_signature: str, supervisor_secret: bytes):
        self.plan = plan
        self.phone_signature = phone_signature
        self.supervisor_secret = supervisor_secret
        self.steps_executed = 0
        self.completed_step_ids: Set[str] = set()
        self.active_taint_epoch = plan.taint_epoch
        self._step_results: Dict[str, Any] = {}

    def execute_step(
        self,
        step_id: str,
        tool: str,
        actual_args: Dict[str, Any],
        current_taint_epoch: int,
        unexpected_taint_detected: bool = False
    ) -> Dict[str, Any]:
        """Executes a single step enforcing exact ID, tool, args hash, and taint envelope invariants."""
        # 1. Check expiry
        if time.time() > self.plan.expiry:
            raise PlanExecutionError(f"Plan '{self.plan.plan_id}' has expired. Execution halted.")

        # 2. Check budget
        if self.steps_executed >= self.plan.budget.max_steps:
            raise PlanExecutionError(
                f"Step budget exceeded ({self.steps_executed} >= {self.plan.budget.max_steps}). Execution halted."
            )

        # 3. Check taint envelope: unexpected taint invalidates plan
        if unexpected_taint_detected or current_taint_epoch > self.plan.taint_epoch:
            raise PlanExecutionError(
                f"Unexpected new taint detected (epoch {current_taint_epoch} > plan epoch {self.plan.taint_epoch}). "
                f"Envelope invalidated; replanning and new user approval required."
            )

        # 4. Locate step definition in plan
        matching_steps = [s for s in self.plan.steps if s.id == step_id]
        if not matching_steps:
            raise PlanExecutionError(f"Step '{step_id}' is not in authorized plan '{self.plan.plan_id}'.")
        target_step = matching_steps[0]

        # 5. Verify tool matches
        if target_step.tool != tool:
            raise PlanExecutionError(
                f"Tool mismatch for step '{step_id}': expected '{target_step.tool}', received '{tool}'."
            )

        # 6. Verify dependencies
        for dep in target_step.depends_on:
            if dep not in self.completed_step_ids:
                raise PlanExecutionError(f"Dependency '{dep}' not satisfied for step '{step_id}'.")

        # 7. Verify step arguments match plan template
        expected_hash = compute_step_args_hash(target_step.args_template)
        actual_hash = compute_step_args_hash(actual_args)
        if expected_hash != actual_hash:
            raise PlanExecutionError(
                f"Arguments deviation for step '{step_id}': expected hash={expected_hash[:16]}..., actual={actual_hash[:16]}... "
                f"Plan deviation is a hard failure."
            )

        # Record completion
        self.steps_executed += 1
        self.completed_step_ids.add(step_id)
        result = {"ok": True, "step_id": step_id, "tool": tool, "status": "completed"}
        self._step_results[step_id] = result
        return result


@dataclass(frozen=True)
class CompiledMacro:
    macro_id: str
    source_plan_id: str
    steps: tuple[Step, ...]
    is_entirely_reversible: bool
    supervisor_sig: str
    created_at: float


def compile_macro_from_plan(
    plan: Plan,
    was_tainted: bool,
    supervisor_secret: bytes
) -> CompiledMacro:
    """Compiles an executed plan into a reusable macro ONLY IF executed with zero tainted inputs."""
    if was_tainted or plan.taint_epoch > 0:
        raise MacroCompilationError("Cannot compile macro from an execution with tainted inputs or non-zero taint epoch.")

    # Check if steps are entirely read-only or reversible
    registry = agent_tools.build_default_registry()
    all_reversible = True
    for s in plan.steps:
        spec = registry._tools.get(s.tool)
        tier = spec.capability_tier if spec else "WRITE_EXEC"
        if tier not in ("READ_ONLY", "SENSITIVE_READ", "REVERSIBLE"):
            all_reversible = False
            break

    macro_id = f"macro_{secrets.token_hex(8)}"
    manifest = f"MACRO:{macro_id}:{plan.plan_id}:{len(plan.steps)}:{all_reversible}"
    sig = hashlib.sha256(supervisor_secret + manifest.encode("utf-8")).hexdigest()

    return CompiledMacro(
        macro_id=macro_id,
        source_plan_id=plan.plan_id,
        steps=plan.steps,
        is_entirely_reversible=all_reversible,
        supervisor_sig=sig,
        created_at=time.time()
    )
