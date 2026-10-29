#!/usr/bin/env bash
# Run ON THE EC2 INSTANCE (Amazon Linux 2023) via SSM. UNTESTED against real Nitro. Installs the enclave tooling and the Stripe vsock proxy config.
set -euo pipefail
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git python3.11 python3.11-pip
sudo usermod -aG ne,docker "$USER"
# memory/CPU reserved for enclaves (the enclave below uses 2 vCPU, 1024 MiB)
sudo sed -i 's/^memory_mib:.*/memory_mib: 1280/; s/^cpu_count:.*/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
sudo cp "$(dirname "$0")/vsock-proxy.yaml" /etc/nitro_enclaves/vsock-proxy.yaml
sudo systemctl enable --now docker nitro-enclaves-allocator.service
cd "$(dirname "$0")/.."
python3.11 -m venv .venv
.venv/bin/pip install --quiet -r requirements.lock playwright cbor2        # harness + web app + attestation verifier run on the instance too
echo "log out and back in (group membership), then run nitro/build.sh and nitro/run.sh"
