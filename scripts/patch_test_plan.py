with open("tests/test_plan_envelopes.py", "r", encoding="utf-8") as f:
    text = f.read()

test6 = '''
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
'''

insert_target = 'if __name__ == "__main__":'
assert insert_target in text
text = text.replace(insert_target, test6 + "\n\n" + insert_target)

with open("tests/test_plan_envelopes.py", "w", encoding="utf-8") as f:
    f.write(text)

print("test_plan_envelopes.py updated with test_6!")
