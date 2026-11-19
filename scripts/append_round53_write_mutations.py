"""scripts/append_round53_write_mutations.py - Appends mutations 111 and 112 to run_mutation_tests.py.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUT_FILE = os.path.join(BASE_DIR, "scripts", "run_mutation_tests.py")

with open(MUT_FILE, "r", encoding="utf-8") as f:
    text = f.read()

target = '''        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_injection_baseline_harness.TestInjectionBaselineHarness.test_3_zero_policy_asr_invariant"]
    }
]'''

addition = '''        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_injection_baseline_harness.TestInjectionBaselineHarness.test_3_zero_policy_asr_invariant"]
    },
    {
        "id": "MUTATION_111_MAIL_SEND_WEBAUTHN_BYPASS",
        "name": "Bypass WebAuthn Assertion Check in MailConnector.send",
        "file": os.path.join(BASE_DIR, "helm_mail_calendar.py"),
        "target": '        webauthn_verifier.verify_assertion(rp, cred, assertion_response, challenge_bytes, challenge_store)',
        "replacement": '        pass # MUTATION_111_BYPASS_MAIL_SEND_WEBAUTHN',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_mail_calendar.TestMailCalendarWorkflows.test_10_send_denied_with_wrong_challenge_or_forged_assertion"]
    },
    {
        "id": "MUTATION_112_BROWSER_TOCTOU_WEBAUTHN_BYPASS",
        "name": "Bypass Gated Submit TOCTOU Check in helm_browser_broker.py",
        "file": os.path.join(BASE_DIR, "helm_browser_broker.py"),
        "target": '        if current_snap.snapshot_hash != prior_snapshot.snapshot_hash:',
        "replacement": '        if False: # MUTATION_112_BYPASS_TOCTOU',
        "test_cmd": [sys.executable, "-m", "unittest", "tests.test_browser_broker.TestBrowserBroker.test_7_browser_gated_submit_with_webauthn_and_toctou"]
    }
]'''

if target in text:
    new_text = text.replace(target, addition, 1)
    with open(MUT_FILE, "w", encoding="utf-8") as f:
        f.write(new_text)
    print("Successfully appended mutations 111-112!")
elif "MUTATION_111" in text:
    print("Mutations 111-112 already present.")
else:
    print("ERROR: Target anchor not found!")
    sys.exit(1)
