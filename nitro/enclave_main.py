"""Entry point INSIDE the enclave (or a local container for testing).
  VAULT_LISTEN   tcp://0.0.0.0:5005 (local/Docker)  |  vsock://5005 (real Nitro)           default tcp://0.0.0.0:5005
  NITRO=1        inside a real enclave: map api.stripe.com to a local forwarder that pipes to the parent over vsock, and attach attestation
The enclave logic is vault_harness/enclave.py (named MockEnclave: on its own it isolates nothing; the ENCLAVE VM around it does).
The config (signer PUBLIC keys, limits, host/path allowlists) is baked into the image, so it is covered by the PCR0 image measurement."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vault_harness import enclave as E  # noqa: E402
from vault_harness.enclave_rpc import EnclaveServer, listen_tcp, listen_vsock  # noqa: E402
from vault_harness.forward import ForwardProcessor  # noqa: E402


def main():
    cfg = json.loads(Path(os.environ.get("VAULT_ENCLAVE_CONFIG", Path(__file__).resolve().parent / "enclave_config.json")).read_text())
    enc = E.MockEnclave(user_pub=bytes.fromhex(cfg["user_pub"]), policy_pub=bytes.fromhex(cfg["policy_pub"]), processor=ForwardProcessor(),
                        auto_limit_cents=cfg["auto_limit_cents"], max_single_cents=cfg["max_single_cents"],
                        allowed_hosts=tuple(cfg["allowed_hosts"]), allowed_paths=tuple(cfg["allowed_paths"]),
                        webauthn_origin=cfg.get("webauthn_origin", "http://localhost:8765"), webauthn_rp_id=cfg.get("webauthn_rp_id", "localhost"))
    att = None
    if os.environ.get("NITRO") == "1":
        from vault_harness import nsm
        from vault_harness.vsock_forward import forward
        with open("/etc/hosts", "a") as f:
            f.write("127.0.0.1 api.stripe.com\n")                              # TLS still verifies api.stripe.com; the bytes just ride vsock
        forward("127.0.0.1", 443, os.environ.get("VAULT_EGRESS", "vsock://3:8443"))
        att = nsm.attestation_fn()
    where = os.environ.get("VAULT_LISTEN", "tcp://0.0.0.0:5005")
    scheme, rest = where.split("://", 1)
    ls = listen_vsock(int(rest)) if scheme == "vsock" else listen_tcp(*(lambda h, p: (h, int(p)))(*rest.rsplit(":", 1)))
    print(f"enclave listening on {where}  (nitro={os.environ.get('NITRO') == '1'}, pubkey {enc.attest()['pubkey'][:16]}…)", flush=True)
    EnclaveServer(enc, attestation=att).serve_forever(ls)


if __name__ == "__main__":
    main()
