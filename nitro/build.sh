#!/usr/bin/env bash
# On the instance, from the repository root. Builds the image, then the enclave image file (EIF), and saves the measurements.
# UNTESTED against real Nitro. PCR0 is a hash of the exact image INCLUDING the baked-in config: any change to the code or the config changes it.
set -euo pipefail
PY=.venv/bin/python
$PY nitro/gen_signers.py                        # keys stay in output/signers; only public keys enter the image
: "${NSM_REF:?set NSM_REF to a commit of aws/aws-nitro-enclaves-nsm-api that you have reviewed}"
docker build --build-arg NSM_REF="$NSM_REF" -f nitro/Dockerfile.nitro -t vault-enclave-nitro .
nitro-cli build-enclave --docker-uri vault-enclave-nitro:latest --output-file nitro/vault.eif | tee nitro/build.out
$PY - <<'PY'
import json, re
t = open("nitro/build.out").read()
pcrs = json.loads(t[t.index("{"): t.rindex("}") + 1])["Measurements"]
json.dump({k: v for k, v in pcrs.items() if k.startswith("PCR")}, open("nitro/pcrs.json", "w"), indent=2)
print("saved nitro/pcrs.json; PCR0 =", pcrs["PCR0"])
PY
