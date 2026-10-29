# Moving the enclave onto real AWS Nitro

**Status.** Everything here is *prepared*. Nothing has been run on AWS (no AWS access was available). What **is** tested locally is listed in the first table; the second table is what only a real Nitro instance can prove.

| Tested locally (no AWS needed) | How |
|---|---|
| The enclave runs as a **separate program** behind a socket; the harness uses it through `EnclaveClient` | `tests/test_enclave_rpc.py` (no card number on the wire) |
| The **packaged image** builds (259 MB, six source files, no `.env`, no private keys) and runs as a container | `docker build -f nitro/Dockerfile`, `tests/test_nitro_local.py` |
| Harness → container → real Stripe **test-mode** PaymentMethod, with a real Kernel browser; the container's logs hold no card number | `RUN_LIVE=1 pytest tests/test_nitro_local.py` |
| The **attestation verifier** accepts a genuine synthetic document and rejects: wrong image, tampered bytes, untrusted CA, expired cert, wrong key, replayed nonce, stale timestamp, debug-mode zero PCRs | `tests/test_attestation.py` |
| The harness **fails closed**: if verification fails, no public key is handed out | `tests/test_enclave_rpc.py` |
| Shell scripts parse; JSON templates are valid | `bash -n`, `json.tool` |

| Needs real Nitro to verify (UNVERIFIED) |
|---|
| vsock transport (`socket.AF_VSOCK`) between parent and enclave |
| Fetching a real attestation document through `libnsm` (`vault_harness/nsm.py`, written from the documented C API) |
| `libnsm` compiling in `Dockerfile.nitro` (not test-built: it fetches third-party source, so it requires a commit you have reviewed) |
| The enclave reaching `api.stripe.com` through the vsock proxy, with TLS verified end to end |
| Whether the enclave clock is correct for TLS certificate validation (a known gotcha: if handshakes fail with "certificate not yet valid", sync the clock from the parent) |
| The `nitro-cli build-enclave` output format that `build.sh` parses for the PCRs |
| The KMS key policy (phase 2) |

## Cost
No charge for Nitro Enclaves itself. You pay for the instance (a `c5.xlarge` is about USD 0.15–0.20/hour from memory; check the live price), plus about USD 1/month for a KMS key if you create one. The free-tier micro instance is **not** supported. Set a USD 5 billing alarm first. Terminate when done.

## Steps
1. **Billing alarm** (Billing → Budgets → USD 5). Check Billing → Credits.
2. **Sign in from your terminal, never in chat:** `aws configure sso`, then `aws sts get-caller-identity` to confirm the account.
3. **Review** `nitro/aws_launch.sh`, then run it. It creates an IAM role (SSM only), a security group with **no inbound rules**, and one `c5.xlarge` with Nitro Enclaves enabled and IMDSv2 required. It asks you to type `YES`.
4. **Connect with SSM** (no SSH, no open ports): `aws ssm start-session --target $(cat nitro/.instance_id)`.
5. **Copy the repository** to the instance (for example `git clone` your repo, or `aws ssm` file transfer) and run `bash nitro/parent_setup.sh`. Log out and back in so the `ne` and `docker` groups apply.
6. **Choose and review a libnsm commit** from `github.com/aws/aws-nitro-enclaves-nsm-api` (read the diff since the last release you trust). Then:
   `NSM_REF=<that commit sha> bash nitro/build.sh`. This generates the signing keys (private keys stay on the instance in `output/signers`), builds the image, builds the EIF, and writes `nitro/pcrs.json`. **Write down PCR0.**
7. `bash nitro/run.sh` starts the Stripe vsock proxy and the enclave (**not** in debug mode: debug zeroes the PCRs and the verifier rejects it).
8. **Download the AWS Nitro root certificate** from AWS's documentation page for attestation, and check its SHA-256 fingerprint against the value AWS publishes there. Save it as `nitro/aws_root.pem`.
9. **Start the web app on the instance**, pointing it at the enclave, and requiring a verified attestation:
   ```
   export VAULT_ENCLAVE=vsock://16:5005
   export VAULT_EXPECT_PCR0=$(python3.11 -c "import json;print(json.load(open('nitro/pcrs.json'))['PCR0'])")
   export VAULT_ROOT_PEM=nitro/aws_root.pem
   python3.11 webapp.py --no-open
   ```
   The page header should read **"enclave: NITRO, attestation verified · PCR0 …"**. If verification fails the page cannot seal a card at all.
10. **View it from your laptop through SSM** (still no open port):
    `aws ssm start-session --target <id> --document-name AWS-StartPortForwardingSession --parameters portNumber=8765,localPortNumber=8765`, then open `http://127.0.0.1:8765`.
11. Add the card in the page, then run a payment. Compare: the image you built and the PCR0 you wrote down are the only code that can open the card.
12. **Terminate:** `bash nitro/aws_teardown.sh`. Schedule deletion of any KMS key.

## Phase 2 (not built): key persistence with KMS
Today the enclave generates its key at boot, so cards must be re-added after an enclave restart. Phase 2 seals the key to KMS with `nitro/kms_key_policy.json.tmpl` (decrypt allowed only when `kms:RecipientAttestation:ImageSha384` equals your PCR0), using `kmstool_enclave_cli` inside the enclave. Not implemented.

## What this still does not make safe
- The user signing key is held by the harness process (the weakest link). The passkey design replaces it.
- A Nitro enclave protects the card from the parent instance and its operators; it does not remove PCI DSS obligations.
- The parent can refuse to relay or can drop traffic (availability), but cannot read the card or the Stripe session.
