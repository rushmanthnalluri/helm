"""tests/test_browser_broker.py - Unit and Security Tests for Tier C Dedicated Browser Automation."""

import unittest
import os
import shutil
from helm_browser_broker import (
    BrowserBroker,
    is_dot_boundary_domain_match,
    is_ip_literal,
    validate_navigation_url,
    BrowserBrokerSecurityError,
    DOMMovedTOCTOUError,
    ALLOWED_DOWNLOAD_EXTENSIONS
)


class TestBrowserBroker(unittest.TestCase):

    def setUp(self):
        self.broker = BrowserBroker()

    def test_1_dot_boundary_domain_matching(self):
        """Dot-boundary matching permits subdomains but strictly blocks prefix lookalikes."""
        self.assertTrue(is_dot_boundary_domain_match("github.com", "github.com"))
        self.assertTrue(is_dot_boundary_domain_match("api.github.com", "github.com"))
        self.assertTrue(is_dot_boundary_domain_match("gist.github.com", "github.com"))
        # Must not match lookalike without dot boundary
        self.assertFalse(is_dot_boundary_domain_match("notgithub.com", "github.com"))
        self.assertFalse(is_dot_boundary_domain_match("evil-github.com", "github.com"))

    def test_2_ip_literals_strictly_rejected(self):
        """IP literals (IPv4 and IPv6) are recognized and rejected."""
        self.assertTrue(is_ip_literal("127.0.0.1"))
        self.assertTrue(is_ip_literal("169.254.169.254"))
        self.assertTrue(is_ip_literal("::1"))
        self.assertTrue(is_ip_literal("fe80::1"))
        self.assertFalse(is_ip_literal("example.com"))
        self.assertFalse(is_ip_literal("sub.domain.local"))

    def test_3_https_only_and_navigation_scoping(self):
        """Insecure protocols and out-of-scope domains are blocked."""
        allowed = ("stripe.com", "github.com")

        # 1. Plain HTTP is rejected
        v1, _, err1 = validate_navigation_url("http://stripe.com/pay", allowed)
        self.assertFalse(v1)
        self.assertIn("Only HTTPS is permitted", err1)

        # 2. IP literal is rejected
        v2, _, err2 = validate_navigation_url("https://169.254.169.254/metadata", allowed)
        self.assertFalse(v2)
        self.assertIn("IP literal destination", err2)

        # 3. Out-of-scope domain is rejected
        v3, _, err3 = validate_navigation_url("https://evil.com/steal", allowed)
        self.assertFalse(v3)
        self.assertIn("outside allowed task scope", err3)

        # 4. Valid HTTPS within allowed domain succeeds
        v4, host4, _ = validate_navigation_url("https://api.stripe.com/v1/charges", allowed)
        self.assertTrue(v4)
        self.assertEqual(host4, "api.stripe.com")

    def test_4_browser_session_and_page_snapshots(self):
        """Session isolates profile directory and wraps page elements in cryptographic nonces."""
        session = self.broker.open_session("task_buy_item", allowed_domains=("amazon.com",))
        self.assertTrue(os.path.exists(session.user_data_dir))
        self.assertTrue(os.path.exists(session.download_dir))
        self.assertIn("amazon.com", session.allowed_domains)

        page = self.broker.navigate(session, "https://www.amazon.com/dp/B08N5WRWNW")
        self.assertEqual(page.domain, "www.amazon.com")

        elements = [
            {"name": "Buy Now", "role": "button", "selector": "#buy-now-button"},
            {"name": "Add to Cart", "role": "button", "selector": "#add-to-cart-button"}
        ]
        snap = self.broker.capture_snapshot(
            page=page,
            raw_text="Product: Wireless Headphones. Price: $99.99. In Stock.",
            elements=elements,
            schema_data={"price": 99.99, "currency": "USD", "availability": "in_stock"}
        )

        self.assertTrue(snap.quarantined_text_handle.startswith("$RAW_TEXT_"))
        self.assertEqual(len(snap.enveloped_elements), 2)
        self.assertIn("[[[ELEM nonce=", snap.enveloped_elements[0])
        self.assertIn("Buy Now", snap.enveloped_elements[0])

    def test_5_form_submission_anti_toctou_defense(self):
        """DOM mutation between phone approval and execution triggers DOMMovedTOCTOUError."""
        session = self.broker.open_session("task_checkout", allowed_domains=("store.com",))
        page = self.broker.navigate(session, "https://store.com/checkout")

        initial_fields = {"recipient": "Alice", "amount": "$50.00", "shipping": "standard"}
        form_snap, approval_obj, canonical_hash = self.broker.prepare_form_approval(
            page=page,
            action_url="https://store.com/api/order",
            method="POST",
            fields=initial_fields,
            button_text="Submit Order",
            parsed_total="$50.00"
        )
        self.assertEqual(approval_obj["approval_type"], "form_submit")
        self.assertEqual(approval_obj["parsed_total"], "$50.00")

        # Case A: DOM is unchanged -> execution succeeds
        ok = self.broker.execute_gated_submit(page, form_snap, initial_fields, signed_hash=canonical_hash)
        self.assertTrue(ok)

        # Case B: Attacker script modified amount to $500.00 before click -> TOCTOU detected & aborted!
        tampered_fields = {"recipient": "Alice", "amount": "$500.00", "shipping": "standard"}
        with self.assertRaises(DOMMovedTOCTOUError) as ctx:
            self.broker.execute_gated_submit(page, form_snap, tampered_fields, signed_hash=canonical_hash)
        self.assertIn("TOCTOU violation detected: DOM moved or mutated", str(ctx.exception))

    def test_6_download_quarantine_and_file_type_allowlist(self):
        """Downloads enforce extension allowlist and generate sha256 hashes."""
        session = self.broker.open_session("task_dl", allowed_domains=("reports.org",))

        # 1. Allowed extension: .pdf
        pdf_res = self.broker.process_download(session, "annual_report.pdf", b"%PDF-1.4 test report")
        self.assertTrue(pdf_res["tainted"])
        self.assertEqual(len(pdf_res["sha256"]), 64)
        self.assertTrue(os.path.exists(pdf_res["path"]))

        # 2. Blocked dangerous extension: .exe or .bat
        with self.assertRaises(BrowserBrokerSecurityError):
            self.broker.process_download(session, "payload.exe", b"MZ...")

    def test_7_browser_gated_submit_with_webauthn_and_toctou(self):
        """Directive: Gated browser form submissions verify Windows Hello biometric approval and anti-TOCTOU DOM integrity."""
        from helm_browser_broker import DOMMovedTOCTOUError
        import windows_hello
        from unittest.mock import patch

        session = self.broker.open_session("task_bank_transfer", allowed_domains=("bank.corp",))
        page = self.broker.navigate(session, "https://bank.corp/transfer")

        initial_fields = {"to_account": "123456", "amount": "$100.00"}
        form_snap, approval_obj, canonical_hash = self.broker.prepare_form_approval(
            page=page,
            action_url="https://bank.corp/api/submit",
            method="POST",
            fields=initial_fields,
            button_text="Confirm Transfer",
            parsed_total="$100.00"
        )

        with patch.object(windows_hello.WindowsHello, "is_available", return_value=True), \
             patch.object(windows_hello.WindowsHello, "verify_sync", return_value=True):
            # 1. Unchanged DOM -> Windows Hello verified & form submit permitted
            ok = self.broker.execute_gated_submit_with_windows_hello(page, form_snap, initial_fields)
            self.assertTrue(ok)

            # Backward compatibility check: legacy method works too
            ok_legacy = self.broker.execute_gated_submit_with_webauthn(page, form_snap, initial_fields)
            self.assertTrue(ok_legacy)

            # 2. TOCTOU mutation -> even with approval, mutated DOM is blocked
            tampered_fields = {"to_account": "123456", "amount": "$10,000.00"}
            with self.assertRaises(DOMMovedTOCTOUError):
                self.broker.execute_gated_submit_with_windows_hello(page, form_snap, tampered_fields)


if __name__ == "__main__":
    unittest.main()
