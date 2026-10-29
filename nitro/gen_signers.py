"""Create the approval signing keys and the enclave config (run once, on the HARNESS side).
Private keys stay in output/signers/ (mode 600). Only the PUBLIC keys and limits go into nitro/enclave_config.json, which is baked into the image."""
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
SIG = ROOT / "output" / "signers"
RAW_PRIV = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
RAW_PUB = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_or_create(name: str) -> Ed25519PrivateKey:
    f = SIG / f"{name}.key"
    if f.exists():
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read_text().strip()))
    k = Ed25519PrivateKey.generate()
    SIG.mkdir(parents=True, exist_ok=True)
    f.write_text(k.private_bytes(*RAW_PRIV).hex() + "\n"); f.chmod(0o600)
    return k


def main():
    pol = json.loads((ROOT / "config" / "policy.interview.json").read_text())
    user, policy = load_or_create("user"), load_or_create("policy")
    cfg = {"user_pub": user.public_key().public_bytes(*RAW_PUB).hex(), "policy_pub": policy.public_key().public_bytes(*RAW_PUB).hex(),
           "auto_limit_cents": pol["auto_approve_under_cents"], "max_single_cents": pol["max_single_cents"],
           "allowed_hosts": ["api.stripe.com"], "allowed_paths": ["/v1/payment_methods"]}
    (ROOT / "nitro" / "enclave_config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    print("signers in", SIG, "| wrote nitro/enclave_config.json (public keys + limits only)")


if __name__ == "__main__":
    sys.exit(main())
