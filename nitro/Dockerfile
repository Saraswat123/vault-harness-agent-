# Build context = repository root:  docker build -f nitro/Dockerfile -t vault-enclave .
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY nitro/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vault_harness/__init__.py vault_harness/policy.py vault_harness/enclave.py vault_harness/enclave_rpc.py vault_harness/forward.py \
     vault_harness/vsock_forward.py vault_harness/nsm.py ./vault_harness/
COPY nitro/enclave_main.py nitro/enclave_config.json ./
CMD ["python", "-u", "/app/enclave_main.py"]
