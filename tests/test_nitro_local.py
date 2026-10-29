"""The packaged enclave image, run as a container and used by the harness over a socket. Needs Docker, the image, a Kernel key and a Stripe TEST key.
Everything except vsock, attestation and KMS is exercised here; those need real AWS Nitro."""
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from vault_harness import enclave as E
from vault_harness.cardstore import CardStore
from vault_harness.enclave_rpc import EnclaveClient
from vault_harness.hosted_checkout import HostedCheckoutVault
from vault_harness.policy import Intent

from tests.test_hosted_checkout import PAGE, _pk

ROOT = Path(__file__).resolve().parent.parent
PAN = "4242424242424242"
I = Intent("buy.stripe.com", 100, "usd")


def _docker_ready():
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "image", "inspect", "vault-enclave"], capture_output=True)
    return r.returncode == 0


pytestmark = pytest.mark.skipif(not (os.environ.get("RUN_LIVE") and _docker_ready()), reason="needs RUN_LIVE=1, Docker and the vault-enclave image")


@pytest.fixture
def container():
    subprocess.run(["docker", "rm", "-f", "vh-enclave-test"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", "vh-enclave-test", "-p", "127.0.0.1:5015:5005", "vault-enclave"], check=True, capture_output=True)
    for _ in range(60):                                                    # docker's port proxy accepts early: wait for a real reply
        try:
            EnclaveClient("tcp://127.0.0.1:5015", timeout=2).attest(); break
        except Exception:
            time.sleep(0.25)
    yield "tcp://127.0.0.1:5015"
    logs = subprocess.run(["docker", "logs", "vh-enclave-test"], capture_output=True, text=True)
    subprocess.run(["docker", "rm", "-f", "vh-enclave-test"], capture_output=True)
    assert PAN not in logs.stdout + logs.stderr, "the enclave's logs must never contain a card number"


def keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    load = lambda n: Ed25519PrivateKey.from_private_bytes(bytes.fromhex((ROOT / "output" / "signers" / f"{n}.key").read_text().strip()))
    return load("user"), load("policy")


def test_container_attests_enrolls_and_revokes_over_the_socket(container, tmp_path):
    user, pol = keys()
    c = EnclaveClient(container, timeout=20)
    att = c.attest()
    assert len(att["pubkey"]) == 64 and att["mock"] is True                                  # no attestation document: this is not a real enclave
    cid = CardStore.new_id()
    box = E.seal(bytes.fromhex(att["pubkey"]), {"number": PAN, "exp_month": 12, "exp_year": 2030}, aad=cid.encode())
    assert c.enroll(box, cid)["last4"] == "4242"
    with pytest.raises(E.EnclaveRefused, match="signature invalid"):                         # the baked-in public key rejects any other signer
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        c.revoke("all", "n1", Ed25519PrivateKey.generate().sign(b"revoke:all:n1").hex())
    c.revoke("all", "n2", user.sign(b"revoke:all:n2").hex())
    c.lift("all", "n3", user.sign(b"lift:all:n3").hex())


def test_live_payment_through_the_container_in_stripe_test_mode(container, tmp_path):
    pk = _pk()
    if not pk.startswith("pk_test_"):
        pytest.skip("needs STRIPE_PUBLISHABLE_KEY=pk_test_ in .env")
    user, pol = keys()
    c = EnclaveClient(container, timeout=90)
    v = HostedCheckoutVault(c, checkout_url="https://checkout-rehearsal.test/", page_html=PAGE.replace("__PK__", pk), user_key=user, policy_key=pol,
                            card_store=CardStore(tmp_path / "c.json"), cvc_source=lambda: "123", auto_limit_cents=200, make_browser=None, make_page=None,
                            billing={"email": "t@example.com", "name": "Test User", "country": "US", "zip": "94107"}, say=lambda m: None)
    v.enroll({"number": PAN, "exp_month": 12, "exp_year": 2030})
    out = v.pay(c.issue_placeholder(I), I)
    assert out["status"] == "done" and out["charge_id"].startswith("pm_") and out["card_last4"] == "4242"
    assert PAN not in json.dumps(out) and PAN not in json.dumps(v.last)
