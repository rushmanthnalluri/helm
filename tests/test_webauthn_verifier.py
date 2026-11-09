"""tests/test_webauthn_verifier.py - Unit test suite for WebAuthn transaction approval verification.
Verifies all security boundaries in webauthn_verifier.py:
- ES256 and Ed25519 signature verification
- Atomic single-use challenge store (replay defense)
- Origin and cross-origin confinement
- Hardware device-bound enforcement (rejection of Backup-Eligible synced passkeys)
- User presence (UP) and user verification (UV) requirements
- Sign count monotonic rollback detection
- Attestation handling (none and packed self-attestation)
"""

import unittest
import hashlib
import struct
import json
import time
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes

import webauthn_verifier as wv
from webauthn_verifier import (
    RelyingParty,
    Credential,
    ChallengeStore,
    WebAuthnError,
    verify_assertion,
    verify_registration,
    parse_authenticator_data,
    b64u_encode,
    b64u_decode,
    FLAG_UP,
    FLAG_UV,
    FLAG_BE,
    FLAG_BS,
    FLAG_AT,
    FLAG_ED,
    COSE_ES256,
    COSE_EDDSA,
)


class TestWebAuthnVerifier(unittest.TestCase):
    def setUp(self):
        self.rp_id = "approval.homie.internal"
        self.origin = "https://approval.homie.internal"
        self.rp = RelyingParty(
            rp_id=self.rp_id,
            origins=frozenset({self.origin}),
            allowed_algs=frozenset({COSE_ES256, COSE_EDDSA}),
            require_uv=True,
            require_device_bound=True,
        )
        self.store = ChallengeStore()
        self.device_id = "pixel_9_pro_hw"

        # Generate standard ES256 testing keypair
        self.es256_priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.es256_priv.public_key().public_numbers()
        self.es256_x = pub.x.to_bytes(32, "big")
        self.es256_y = pub.y.to_bytes(32, "big")
        self.es256_cose = {1: 2, 3: COSE_ES256, -1: 1, -2: self.es256_x, -3: self.es256_y}
        self.es256_cose_cbor = cbor2.dumps(self.es256_cose)

        self.cred_id = b"cred_phone_device_001"
        self.cred = Credential(
            credential_id=self.cred_id,
            cose_key_cbor=self.es256_cose_cbor,
            alg=COSE_ES256,
            sign_count=10,
            device_id=self.device_id,
            backup_eligible=False,
            aaguid=b"\x01" * 16,
            attestation_fmt="none",
            attestation_trust="none",
        )

    def _make_client_data(self, challenge: bytes, c_type: str = "webauthn.get", origin: str = None, extra: dict = None):
        cd = {
            "type": c_type,
            "challenge": b64u_encode(challenge),
            "origin": origin or self.origin,
        }
        if extra:
            cd.update(extra)
        raw = json.dumps(cd).encode("utf-8")
        return raw, b64u_encode(raw)

    def _make_auth_data(self, flags: int, sign_count: int, rp_id: str = None):
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        raw = rp_hash + bytes([flags]) + struct.pack(">I", sign_count)
        return raw, b64u_encode(raw)

    def _sign_assertion(self, priv_key, auth_data_raw: bytes, client_data_raw: bytes, alg: int = COSE_ES256):
        to_sign = auth_data_raw + hashlib.sha256(client_data_raw).digest()
        if alg == COSE_ES256:
            sig = priv_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
        else:
            sig = priv_key.sign(to_sign)
        return sig, b64u_encode(sig)

    def test_1_valid_es256_assertion(self):
        """Happy path: valid ES256 assertion verifies cleanly and increments sign count."""
        challenge = hashlib.sha256(b"canonical_approval_send_001").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        sig_raw, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": sig_b64,
        }

        result = verify_assertion(self.rp, self.cred, response, challenge, self.store)
        self.assertEqual(result.new_sign_count, 11)
        self.assertTrue(result.user_verified)
        self.assertEqual(result.flags, FLAG_UP | FLAG_UV)

    def test_2_replay_attack_rejected(self):
        """Replaying the same assertion fails because single-use challenge was consumed."""
        challenge = hashlib.sha256(b"canonical_approval_send_002").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": sig_b64,
        }

        # First verification succeeds and consumes challenge
        verify_assertion(self.rp, self.cred, response, challenge, self.store)

        # Second verification (replay) fails closed
        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, response, challenge, self.store)
        self.assertEqual(ctx.exception.code, "CHALLENGE_UNKNOWN_OR_EXPIRED")

    def test_3_forged_signature_rejected(self):
        """Tampered signature or client data raises BAD_SIGNATURE."""
        challenge = hashlib.sha256(b"canonical_approval_send_003").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        sig_raw, _ = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)

        # Corrupt the signature bytes
        corrupted_sig = bytes([sig_raw[0] ^ 0xFF]) + sig_raw[1:]
        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": b64u_encode(corrupted_sig),
        }

        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, response, challenge, self.store)
        self.assertEqual(ctx.exception.code, "BAD_SIGNATURE")

    def test_4_challenge_mismatch_rejected(self):
        """Mismatched challenge in clientDataJSON raises CHALLENGE_MISMATCH."""
        chal_sup = hashlib.sha256(b"canonical_approval_send_004").digest()
        chal_attacker = hashlib.sha256(b"canonical_approval_forged").digest()
        self.store.register(chal_sup, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(chal_attacker)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": sig_b64,
        }

        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, response, chal_sup, self.store)
        self.assertEqual(ctx.exception.code, "CHALLENGE_MISMATCH")

    def test_5_origin_and_cross_origin_rejected(self):
        """Mismatched origin or crossOrigin: True fails closed."""
        challenge = hashlib.sha256(b"canonical_approval_send_005").digest()
        self.store.register(challenge, self.device_id)

        # 1. Hostile origin
        cd_raw, cd_b64 = self._make_client_data(challenge, origin="https://attacker.evil.com")
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)
        with self.assertRaises(WebAuthnError) as ctx1:
            verify_assertion(self.rp, self.cred, {"clientDataJSON": cd_b64, "authenticatorData": ad_b64, "signature": sig_b64}, challenge, self.store)
        self.assertEqual(ctx1.exception.code, "ORIGIN_MISMATCH")

        # 2. crossOrigin flag set
        cd_raw, cd_b64 = self._make_client_data(challenge, extra={"crossOrigin": True})
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)
        with self.assertRaises(WebAuthnError) as ctx2:
            verify_assertion(self.rp, self.cred, {"clientDataJSON": cd_b64, "authenticatorData": ad_b64, "signature": sig_b64}, challenge, self.store)
        self.assertEqual(ctx2.exception.code, "CROSS_ORIGIN")

    def test_6_user_presence_and_verification_enforced(self):
        """Missing UP or UV raises USER_NOT_PRESENT or USER_NOT_VERIFIED."""
        challenge = hashlib.sha256(b"canonical_approval_send_006").digest()
        self.store.register(challenge, self.device_id)

        # 1. Missing UP
        cd_raw, cd_b64 = self._make_client_data(challenge)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UV, sign_count=11) # no UP
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)
        with self.assertRaises(WebAuthnError) as ctx1:
            verify_assertion(self.rp, self.cred, {"clientDataJSON": cd_b64, "authenticatorData": ad_b64, "signature": sig_b64}, challenge, self.store)
        self.assertEqual(ctx1.exception.code, "USER_NOT_PRESENT")

        # 2. Missing UV when require_uv=True
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP, sign_count=11) # no UV
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)
        with self.assertRaises(WebAuthnError) as ctx2:
            verify_assertion(self.rp, self.cred, {"clientDataJSON": cd_b64, "authenticatorData": ad_b64, "signature": sig_b64}, challenge, self.store)
        self.assertEqual(ctx2.exception.code, "USER_NOT_VERIFIED")

    def test_7_synced_passkey_backup_eligible_rejected(self):
        """Device-bound policy strictly rejects Backup-Eligible (BE) passkeys."""
        challenge = hashlib.sha256(b"canonical_approval_send_007").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge)
        # BE bit set (0x08)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV | FLAG_BE, sign_count=11)
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": sig_b64,
        }

        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, response, challenge, self.store)
        self.assertEqual(ctx.exception.code, "SYNCED_CREDENTIAL_REJECTED")

    def test_8_sign_count_rollback_detected(self):
        """Non-increasing sign counter indicates cloned authenticator and fails closed."""
        challenge = hashlib.sha256(b"canonical_approval_send_008").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge)
        # Cred has sign_count=10, we submit sign_count=10 (not strictly greater)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=10)
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw, cd_raw)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": sig_b64,
        }

        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, response, challenge, self.store)
        self.assertEqual(ctx.exception.code, "SIGN_COUNT_ROLLBACK")

    def test_9_valid_eddsa_assertion(self):
        """Ed25519 (OKP EdDSA) keys verify cleanly."""
        ed_priv = ed25519.Ed25519PrivateKey.generate()
        ed_pub_bytes = ed_priv.public_key().public_bytes_raw()
        ed_cose = {1: 1, 3: COSE_EDDSA, -1: 6, -2: ed_pub_bytes}
        ed_cred = Credential(
            credential_id=b"cred_eddsa_001",
            cose_key_cbor=cbor2.dumps(ed_cose),
            alg=COSE_EDDSA,
            sign_count=5,
            device_id="yubikey_bio",
            backup_eligible=False,
            aaguid=b"\x02" * 16,
            attestation_fmt="none",
            attestation_trust="none",
        )

        challenge = hashlib.sha256(b"canonical_approval_send_009").digest()
        self.store.register(challenge, "yubikey_bio")

        cd_raw, cd_b64 = self._make_client_data(challenge)
        ad_raw, ad_b64 = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=6)
        _, sig_b64 = self._sign_assertion(ed_priv, ad_raw, cd_raw, alg=COSE_EDDSA)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": ad_b64,
            "signature": sig_b64,
        }

        result = verify_assertion(self.rp, ed_cred, response, challenge, self.store)
        self.assertEqual(result.new_sign_count, 6)
        self.assertTrue(result.user_verified)

    def test_10_registration_ceremony_none_and_packed(self):
        """Registration ceremony parses attested credential data and verifies self-attestation."""
        # 1. Format 'none'
        challenge = hashlib.sha256(b"enrollment_ceremony_001").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge, c_type="webauthn.create")
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        flags = FLAG_UP | FLAG_UV | FLAG_AT
        cred_id = b"new_device_cred_001"
        ad_raw = rp_hash + bytes([flags]) + struct.pack(">I", 0) + (b"\x01" * 16) + struct.pack(">H", len(cred_id)) + cred_id + self.es256_cose_cbor

        att_obj = {"fmt": "none", "attStmt": {}, "authData": ad_raw}
        resp = {
            "clientDataJSON": cd_b64,
            "attestationObject": b64u_encode(cbor2.dumps(att_obj)),
            "credentialId": b64u_encode(cred_id),
        }

        cred = verify_registration(self.rp, resp, challenge, self.store, self.device_id)
        self.assertEqual(cred.device_id, self.device_id)
        self.assertEqual(cred.alg, COSE_ES256)
        self.assertEqual(cred.attestation_fmt, "none")
        self.assertEqual(cred.attestation_trust, "none")

        # 2. Format 'packed' self-attestation
        chal_packed = hashlib.sha256(b"enrollment_ceremony_002").digest()
        self.store.register(chal_packed, self.device_id)
        cd_raw2, cd_b64_2 = self._make_client_data(chal_packed, c_type="webauthn.create")
        cred_id2 = b"new_device_cred_002"
        ad_raw2 = rp_hash + bytes([flags]) + struct.pack(">I", 0) + (b"\x01" * 16) + struct.pack(">H", len(cred_id2)) + cred_id2 + self.es256_cose_cbor

        client_hash = hashlib.sha256(cd_raw2).digest()
        self_sig = self.es256_priv.sign(ad_raw2 + client_hash, ec.ECDSA(hashes.SHA256()))
        att_packed = {
            "fmt": "packed",
            "attStmt": {"alg": COSE_ES256, "sig": self_sig},
            "authData": ad_raw2,
        }
        resp2 = {
            "clientDataJSON": cd_b64_2,
            "attestationObject": b64u_encode(cbor2.dumps(att_packed)),
            "credentialId": b64u_encode(cred_id2),
        }
        cred2 = verify_registration(self.rp, resp2, chal_packed, self.store, self.device_id)
        self.assertEqual(cred2.attestation_fmt, "packed")
        self.assertEqual(cred2.attestation_trust, "self")

    def test_11_revoked_credential_denied(self):
        """Revoked credential fails closed before checking challenge or signature."""
        self.cred.revoked = True
        challenge = hashlib.sha256(b"canonical_approval_send_011").digest()
        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, {}, challenge, self.store)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_REVOKED")

    def test_12_malformed_auth_data_trailing_bytes_rejected(self):
        """AuthenticatorData with trailing junk bytes raises BAD_AUTH_DATA."""
        challenge = hashlib.sha256(b"canonical_approval_send_012").digest()
        self.store.register(challenge, self.device_id)

        cd_raw, cd_b64 = self._make_client_data(challenge)
        ad_raw, _ = self._make_auth_data(FLAG_UP | FLAG_UV, sign_count=11)
        ad_raw_trailing = ad_raw + b"extra_trailing_junk"
        _, sig_b64 = self._sign_assertion(self.es256_priv, ad_raw_trailing, cd_raw)

        response = {
            "clientDataJSON": cd_b64,
            "authenticatorData": b64u_encode(ad_raw_trailing),
            "signature": sig_b64,
        }

        with self.assertRaises(WebAuthnError) as ctx:
            verify_assertion(self.rp, self.cred, response, challenge, self.store)
        self.assertEqual(ctx.exception.code, "BAD_AUTH_DATA")


if __name__ == "__main__":
    unittest.main()
