"""tests/test_structured_approval.py - Unit tests for Canonical Structured Approvals."""

import unittest
from helm_structured_approval import (
    compute_canonical_approval_hash,
    verify_phone_hash_rebuild,
    build_send_approval_object,
    build_form_submit_approval_object,
    build_plan_approval_object,
    StructuredApprovalSecurityError
)


class TestStructuredApprovals(unittest.TestCase):

    def test_1_canonical_hash_and_rebuild_verification(self):
        """Verifies deterministic hash calculation and phone-side rebuild equality."""
        obj = build_send_approval_object(
            account="user@example.com",
            to=["colleague@example.com"],
            cc=[],
            bcc=[],
            subject="Status Report",
            body_text="All systems operational.",
            attachments=[{"name": "report.pdf", "sha256": "abcdef1234567890"}],
            nonce="fixed_nonce_123"
        )

        h1, bytes1 = compute_canonical_approval_hash(obj)
        self.assertEqual(len(h1), 64)

        # Phone receives obj and verifies rebuild
        self.assertTrue(verify_phone_hash_rebuild(obj, h1))

        # Re-keyed order should produce the exact same canonical hash
        reordered_obj = {
            "nonce": "fixed_nonce_123",
            "subject": "Status Report",
            "approval_type": "send",
            "body_text": "All systems operational.",
            "to": ["colleague@example.com"],
            "cc": [],
            "bcc": [],
            "account": "user@example.com",
            "thread_id": "",
            "attachments": [{"name": "report.pdf", "sha256": "abcdef1234567890"}]
        }
        h2, _ = compute_canonical_approval_hash(reordered_obj)
        self.assertEqual(h1, h2)

    def test_2_prohibits_bidi_override_characters(self):
        """Verifies rejection of Right-to-Left Override (RLO) and other bidi manipulation characters."""
        # \u202E is Right-to-Left Override
        spoofed_subject = "Invoice from Alice \u202E exe.pdf"
        obj = build_send_approval_object(
            account="user@example.com",
            to=["alice@corp.com"],
            cc=[],
            bcc=[],
            subject=spoofed_subject,
            body_text="Hello",
            attachments=[],
            nonce="nonce_bidi"
        )

        with self.assertRaises(StructuredApprovalSecurityError) as ctx:
            compute_canonical_approval_hash(obj)
        self.assertIn("Prohibited visual spoofing character", str(ctx.exception))
        self.assertIn("U+202E", str(ctx.exception))

    def test_3_prohibits_zero_width_characters(self):
        """Verifies rejection of zero-width spaces (\u200B) and zero-width joiners (\u200D)."""
        spoofed_recipient = "admin\u200B@corp.com"
        obj = build_send_approval_object(
            account="user@example.com",
            to=[spoofed_recipient],
            cc=[],
            bcc=[],
            subject="Hello",
            body_text="Hello",
            attachments=[],
            nonce="nonce_zwsp"
        )

        with self.assertRaises(StructuredApprovalSecurityError) as ctx:
            compute_canonical_approval_hash(obj)
        self.assertIn("U+200B", str(ctx.exception))

    def test_4_rejects_unapproved_approval_type(self):
        """Only 'send', 'form_submit', and 'plan' approval types are permitted."""
        with self.assertRaisesRegex(StructuredApprovalSecurityError, "Invalid approval_type"):
            compute_canonical_approval_hash({"approval_type": "arbitrary_execute", "cmd": "format c:"})

    def test_5_form_submit_and_plan_approval_builders(self):
        """Verifies form_submit and plan approval canonical serialization."""
        form_obj = build_form_submit_approval_object(
            origin="https://checkout.stripe.com",
            action_url="https://checkout.stripe.com/api/pay",
            method="POST",
            field_names_and_values={"amount": "100.00", "currency": "USD"},
            button_text="Pay $100.00",
            parsed_total="$100.00",
            dom_snapshot_hash="f0e1d2c3b4a5",
            nonce="nonce_form"
        )
        h_form, _ = compute_canonical_approval_hash(form_obj)
        self.assertTrue(verify_phone_hash_rebuild(form_obj, h_form))

        plan_obj = build_plan_approval_object(
            plan_id="plan_001",
            steps_summary=[{"id": "step1", "tool": "browser_scrape", "target": "https://example.com"}],
            scope_domains=["example.com"],
            scope_apps=["chrome.exe"],
            budget_max_steps=5,
            budget_max_keystrokes=100,
            budget_max_egress_bytes=10240,
            expiry_epoch=1700000000,
            taint_epoch=1,
            declared_untrusted_reads=["https://example.com/pricing"],
            nonce="nonce_plan"
        )
        h_plan, _ = compute_canonical_approval_hash(plan_obj)
        self.assertTrue(verify_phone_hash_rebuild(plan_obj, h_plan))

    def test_6_verify_webauthn_transaction_approval(self):
        """Verifies end-to-end binding between canonical approval object and WebAuthn verifier."""
        import hashlib, struct, json, cbor2
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        import webauthn_verifier as wv
        from helm_structured_approval import verify_webauthn_transaction_approval

        rp = wv.RelyingParty(rp_id="approval.helm.internal", origins=frozenset({"https://approval.helm.internal"}))
        store = wv.ChallengeStore()
        device_id = "phone_pixel_9"

        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_numbers()
        cose_map = {1: 2, 3: wv.COSE_ES256, -1: 1, -2: pub.x.to_bytes(32, "big"), -3: pub.y.to_bytes(32, "big")}
        cred = wv.Credential(
            credential_id=b"cred_001",
            cose_key_cbor=cbor2.dumps(cose_map),
            alg=wv.COSE_ES256,
            sign_count=0,
            device_id=device_id,
            backup_eligible=False,
            aaguid=b"\x00" * 16,
            attestation_fmt="none",
            attestation_trust="none"
        )

        plan_obj = build_plan_approval_object(
            plan_id="plan_webauthn_001",
            steps_summary=[{"id": "s1", "tool": "helm_agent_type", "text": "hello"}],
            scope_domains=["corp.internal"],
            scope_apps=["notepad.exe"],
            budget_max_steps=1,
            budget_max_keystrokes=10,
            budget_max_egress_bytes=0,
            expiry_epoch=1800000000,
            taint_epoch=0,
            declared_untrusted_reads=[],
            nonce="nonce_webauthn_test"
        )

        hash_hex, _ = compute_canonical_approval_hash(plan_obj)
        challenge = bytes.fromhex(hash_hex)
        store.register(challenge, device_id)

        cd_bytes = json.dumps({
            "type": "webauthn.get",
            "challenge": wv.b64u_encode(challenge),
            "origin": "https://approval.helm.internal"
        }).encode("utf-8")
        flags = wv.FLAG_UP | wv.FLAG_UV
        auth_data = hashlib.sha256(b"approval.helm.internal").digest() + bytes([flags]) + struct.pack(">I", 1)
        sig = priv.sign(auth_data + hashlib.sha256(cd_bytes).digest(), ec.ECDSA(hashes.SHA256()))

        assertion_resp = {
            "clientDataJSON": wv.b64u_encode(cd_bytes),
            "authenticatorData": wv.b64u_encode(auth_data),
            "signature": wv.b64u_encode(sig)
        }

        result = verify_webauthn_transaction_approval(plan_obj, assertion_resp, rp, cred, store)
        self.assertEqual(result.new_sign_count, 1)
        self.assertTrue(result.user_verified)


if __name__ == "__main__":
    unittest.main()
