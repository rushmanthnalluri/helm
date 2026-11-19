"""scripts/sign_release.py - Offline Publisher Signing Tool for Helm Updates.

This script resides strictly in release tooling and NEVER ships on user workstations.
Uses the publisher's offline private Ed25519 key to generate signed update manifests.
"""

import os
import sys
import json
import base64
from typing import Dict, Any
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import update_verifier


def sign_update_manifest_offline(manifest: Dict[str, Any], private_key_pem: str) -> str:
    """Publisher utility: Signs manifest with offline private Ed25519 key."""
    key = ECC.import_key(private_key_pem)
    if not key.has_private():
        raise ValueError("sign_update_manifest_offline requires a private Ed25519 key")
    signer = eddsa.new(key, 'rfc8032')
    data = update_verifier.compute_manifest_canonical_bytes(manifest)
    sig_bytes = signer.sign(data)
    return base64.b64encode(sig_bytes).decode("ascii")
