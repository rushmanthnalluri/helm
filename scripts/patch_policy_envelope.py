with open("policy_envelope.py", "r", encoding="utf-8") as f:
    text = f.read()

target = '''    def __init__(
        self,
        envelope_id: str,
        allowed_process_images: List[str],
        allowed_action_types: List[str],
        step_budget: int,
        keystroke_cap: int,
        expiry: float,
        taint_epoch: int,
        allowed_domains: Optional[List[str]] = None,
        device_id: str = "primary_phone",
        signature: Optional[str] = None
    ):
        clean_images = [os.path.basename(p).lower() for p in allowed_process_images]'''

replacement = '''    def __init__(
        self,
        envelope_id: str,
        allowed_process_images: List[str],
        allowed_action_types: List[str],
        step_budget: int,
        keystroke_cap: int,
        expiry: float,
        taint_epoch: int,
        allowed_domains: Optional[List[str]] = None,
        device_id: str = "primary_phone",
        signature: Optional[str] = None,
        caller_role: str = "supervisor"
    ):
        if caller_role in ("worker", "ui", "untrusted"):
            raise PermissionError(
                f"PolicyEnvelope cannot be instantiated directly by '{caller_role}'. "
                "Envelopes are created exclusively by PolicySupervisor upon verified mobile signature."
            )
        clean_images = [os.path.basename(p).lower() for p in allowed_process_images]'''

assert target in text, "target not found in policy_envelope.py"
text = text.replace(target, replacement)

# Add create_supervisor_verified_envelope helper at bottom
factory_func = '''

def create_supervisor_verified_envelope(
    supervisor: Any,
    plan: Any,
    signed_blob: Dict[str, Any]
) -> PolicyEnvelope:
    """Creates a bound policy envelope strictly after supervisor verifies mobile signature."""
    if supervisor is None or not hasattr(supervisor, "verify_and_consume_intent_token"):
        raise PermissionError("Envelope creation strictly requires PolicySupervisor custody.")
    if not signed_blob or not signed_blob.get("signature") or signed_blob.get("forged"):
        raise ValueError("Invalid or forged mobile approval blob for envelope creation.")

    env = PolicyEnvelope(
        envelope_id=plan.plan_id,
        allowed_process_images=list(plan.scope.apps),
        allowed_action_types=[s.tool for s in plan.steps],
        step_budget=plan.budget.max_steps,
        keystroke_cap=plan.budget.max_keystrokes,
        expiry=plan.expiry,
        taint_epoch=plan.taint_epoch,
        allowed_domains=list(plan.scope.domains),
        device_id=signed_blob.get("device_id", "primary_phone"),
        signature=signed_blob.get("signature"),
        caller_role="supervisor"
    )
    env.is_active = True
    return env
'''

text = text + factory_func

with open("policy_envelope.py", "w", encoding="utf-8") as f:
    f.write(text)

print("policy_envelope.py updated with constructor protection and verified factory!")
