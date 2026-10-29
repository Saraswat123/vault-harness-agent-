#!/usr/bin/env bash
# On the instance. Starts the Stripe vsock proxy and the enclave. NEVER pass --debug-mode: it zeroes the PCRs and the verifier rejects it.
# UNTESTED against real Nitro.
set -euo pipefail
nitro-cli terminate-enclave --all 2>/dev/null || true
pkill -f "vsock-proxy 8443" 2>/dev/null || true
nohup vsock-proxy 8443 api.stripe.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml > nitro/vsock-proxy.log 2>&1 &
nitro-cli run-enclave --eif-path nitro/vault.eif --cpu-count 2 --memory 1024 --enclave-cid 16
echo "enclave CID 16; the harness connects with:  VAULT_ENCLAVE=vsock://16:5005"
echo "attestation check needs:  VAULT_EXPECT_PCR0=\$(python -c \"import json;print(json.load(open('nitro/pcrs.json'))['PCR0'])\")  VAULT_ROOT_PEM=<AWS Nitro root cert .pem>"
