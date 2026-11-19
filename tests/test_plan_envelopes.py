"""tests/test_plan_envelopes.py - Acceptance Tests for Plan Envelopes, Risk Scoping, and Macros."""

import unittest
import time
from helm_plan_envelopes import (
    Step,
    Scope,
    Budget,
    Plan,
    PlanExecutor,
    SupervisorRiskCalculator,
    compile_macro_from_plan,
    PlanExecutionError,
    MacroCompilationError
)


class TestPlanEnvelopes(unittest.TestCase):

    def setUp(self):
        self.supervisor_secret = b"test_supervisor_secret_32_bytes_len"
        self.step1 = Step(id="s1", tool="helm_get_vitals", args_template={})
        self.step2 = Step(
            id="s2",
            tool="helm_search_context",
            args_template={"query": "meeting summary"},
            depends_on=("s1",)
        )
        self.step3_write = Step(
            id="s3",
            tool="helm_remember_fact",
            args_template={"key": "project_lead", "fact": "Priya"},
            depends_on=("s2",)
        )

        self.plan = Plan(
            plan_id="plan_test_01",
            steps=(self.step1, self.step2, self.step3_write),
            scope=Scope(domains=("example.com",), apps=("chrome.exe",)),
            budget=Budget(max_steps=5, max_keystrokes=200, max_egress_bytes=50000),
            expiry=int(time.time() + 3600),
            taint_epoch=0,
            declared_untrusted_reads=("helm_search_context",)
        )

    def test_1_supervisor_risk_calculation(self):
        """Supervisor computes risk and marks opaque handles or write tools as GATED."""
        # Step 1: read-only vitals -> not gated
        tier1, gated1 = SupervisorRiskCalculator.calculate_step_risk(self.step1)
        self.assertEqual(tier1, "READ_ONLY")
        self.assertFalse(gated1)

        # Step with untrusted handle argument is strictly GATED
        step_handle = Step(
            id="s_handle",
            tool="helm_send_email",
            args_template={"body_handle": "$EMAIL_abc123"}
        )
        tier_h, gated_h = SupervisorRiskCalculator.calculate_step_risk(step_handle)
        self.assertTrue(gated_h)

    def test_2_deterministic_execution_and_dependency_ordering(self):
        """Executor deterministically runs steps when ID, tool, and args hash match."""
        executor = PlanExecutor(self.plan, phone_signature="sig_test", supervisor_secret=self.supervisor_secret)

        # Attempting step 2 before step 1 fails dependency check
        with self.assertRaises(PlanExecutionError) as ctx:
            executor.execute_step("s2", "helm_search_context", {"query": "meeting summary"}, current_taint_epoch=0)
        self.assertIn("Dependency 's1' not satisfied", str(ctx.exception))

        # Execute step 1 -> succeeds
        res1 = executor.execute_step("s1", "helm_get_vitals", {}, current_taint_epoch=0)
        self.assertTrue(res1["ok"])

        # Execute step 2 -> succeeds
        res2 = executor.execute_step("s2", "helm_search_context", {"query": "meeting summary"}, current_taint_epoch=0)
        self.assertTrue(res2["ok"])

    def test_3_argument_deviation_is_hard_failure(self):
        """Any deviation in arguments template causes hard failure without prompting."""
        executor = PlanExecutor(self.plan, phone_signature="sig_test", supervisor_secret=self.supervisor_secret)
        executor.execute_step("s1", "helm_get_vitals", {}, current_taint_epoch=0)

        # Worker supplies altered argument for s2
        altered_args = {"query": "attacker query inject"}
        with self.assertRaises(PlanExecutionError) as ctx:
            executor.execute_step("s2", "helm_search_context", altered_args, current_taint_epoch=0)
        self.assertIn("Arguments deviation for step 's2'", str(ctx.exception))

    def test_4_unexpected_taint_invalidates_plan(self):
        """Unexpected new taint halts execution and requires replanning."""
        executor = PlanExecutor(self.plan, phone_signature="sig_test", supervisor_secret=self.supervisor_secret)
        executor.execute_step("s1", "helm_get_vitals", {}, current_taint_epoch=0)

        # Session acquires unexpected new taint (epoch bumped to 1)
        with self.assertRaises(PlanExecutionError) as ctx:
            executor.execute_step("s2", "helm_search_context", {"query": "meeting summary"}, current_taint_epoch=1)
        self.assertIn("Unexpected new taint detected", str(ctx.exception))

    def test_5_macro_compilation_blocks_tainted_plans(self):
        """Compiling a macro from a plan with tainted inputs is strictly rejected."""
        # 1. Tainted plan compilation fails
        with self.assertRaises(MacroCompilationError):
            compile_macro_from_plan(self.plan, was_tainted=True, supervisor_secret=self.supervisor_secret)

        # 2. Clean plan compilation succeeds
        clean_read_plan = Plan(
            plan_id="plan_clean_01",
            steps=(self.step1,),
            scope=Scope(),
            budget=Budget(),
            expiry=int(time.time() + 3600),
            taint_epoch=0
        )
        macro = compile_macro_from_plan(clean_read_plan, was_tainted=False, supervisor_secret=self.supervisor_secret)
        self.assertTrue(macro.macro_id.startswith("macro_"))
        self.assertTrue(macro.is_entirely_reversible)
        self.assertEqual(len(macro.supervisor_sig), 64)



    def test_6_envelope_creation_denied_from_ui_worker_and_forged_blob(self):
        """Directive: Attempting to create an envelope from UI, from worker, or with a forged blob fails."""
        import policy_envelope
        from policy_envelope import PolicyEnvelope, create_supervisor_verified_envelope

        # 1. Constructor called from UI role fails closed
        with self.assertRaises(PermissionError) as ctx1:
            PolicyEnvelope(
                envelope_id="env_ui",
                allowed_process_images=["notepad.exe"],
                allowed_action_types=["helm_agent_type"],
                step_budget=5,
                keystroke_cap=100,
                expiry=time.time() + 300,
                taint_epoch=0,
                caller_role="ui"
            )
        self.assertIn("cannot be instantiated directly by 'ui'", str(ctx1.exception))

        # 2. Constructor called from worker role fails closed
        with self.assertRaises(PermissionError) as ctx2:
            PolicyEnvelope(
                envelope_id="env_worker",
                allowed_process_images=["notepad.exe"],
                allowed_action_types=["helm_agent_type"],
                step_budget=5,
                keystroke_cap=100,
                expiry=time.time() + 300,
                taint_epoch=0,
                caller_role="worker"
            )
        self.assertIn("cannot be instantiated directly by 'worker'", str(ctx2.exception))

        # 3. Forged signature blob is rejected by supervisor factory
        mock_supervisor = type("MockSupervisor", (), {"verify_and_consume_intent_token": lambda *a: True})()
        forged_blob = {"signature": "forged_signature_hex", "forged": True}
        with self.assertRaises(ValueError) as ctx3:
            create_supervisor_verified_envelope(mock_supervisor, self.plan, forged_blob)
        self.assertIn("Invalid or forged mobile approval blob", str(ctx3.exception))


if __name__ == "__main__":
    unittest.main()
