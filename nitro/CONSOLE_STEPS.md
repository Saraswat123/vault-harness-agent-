# AWS Nitro, tonight: browser-console checklist
Everything below uses the AWS console in your browser, except the last port-forward step. **Nothing here has been run by the assistant**; each step says what you should see. Stop and paste any error (never keys).
Cost ≈ USD 0.15–0.20 per hour for a `c5.xlarge` (check the live price). Terminate at the end (step 14).

## On your Mac
1. Commit and push the code to a **private** GitHub repo (the repo audit found no secrets; `.env`, `output/` and the signing keys are git-ignored):
   ```
   cd ~/vault-harness && git add -A && git commit -m "vault harness and nitro prep"
   ```
   Create an empty **private** repo on GitHub, then `git remote add origin git@github.com:<you>/vault-harness.git && git push -u origin HEAD`.
2. Install the CLI pieces needed only for the final port-forward: `brew install awscli session-manager-plugin`.

## AWS console
3. **Billing → Budgets → Create budget**: monthly cost budget USD 5, with your email. (Check Billing → Credits too.)
4. **IAM → Roles → Create role**: trusted entity *AWS service → EC2*; attach `AmazonSSMManagedInstanceCore`; name it `vault-enclave-role`.
5. **IAM → Users → Create user** `vault-cli` (no console access); attach `AmazonSSMFullAccess`; then *Security credentials → Create access key → CLI*. On the Mac run `aws configure` and paste them there (never in chat). Delete this key in step 14.
6. **EC2 → Launch instance**:
   - Name `vault-enclave`; AMI **Amazon Linux 2023**, 64-bit **x86**
   - Instance type **c5.xlarge** (not `.large`, not `t3`)
   - Key pair: **Proceed without a key pair**
   - Network settings → Edit: create a security group and **delete every inbound rule** (remove the default SSH rule)
   - Storage: 20 GiB gp3, **encrypted**
   - Advanced details: IAM instance profile `vault-enclave-role`; **Nitro Enclave: Enable**; Metadata version **V2 only**
   - Launch. Expect "Instance state: running" in about a minute.
7. Select the instance → **Connect → Session Manager → Connect**. If the tab is greyed out, wait 3–5 minutes for the agent to register, then refresh. You get a terminal in the browser.

## In the browser terminal (the instance)
8. Fetch the code with a **read-only deploy key** (nothing secret leaves the instance):
   ```
   sudo dnf install -y git
   ssh-keygen -t ed25519 -f ~/.ssh/deploy -N "" && cat ~/.ssh/deploy.pub
   ```
   Copy that line into GitHub → your repo → *Settings → Deploy keys → Add* (leave "write access" **off**). Then:
   ```
   GIT_SSH_COMMAND="ssh -i ~/.ssh/deploy -o StrictHostKeyChecking=accept-new" git clone git@github.com:<you>/vault-harness.git
   cd vault-harness && bash nitro/parent_setup.sh
   ```
   Then **close and reopen the Session Manager terminal** so the new groups apply.
9. **Choose the libnsm version.** The latest tag is `v0.5.2` (commit `1993eeb0620d35f5cefc50b17638b432325328f9`). Skim what changed since `v0.5.1` at `github.com/aws/aws-nitro-enclaves-nsm-api/compare/v0.5.1...v0.5.2` and decide you trust it. Then:
   ```
   cd ~/vault-harness && NSM_REF=1993eeb0620d35f5cefc50b17638b432325328f9 bash nitro/build.sh
   ```
   Expect `saved nitro/pcrs.json; PCR0 = …`. **Write PCR0 down.** (First build downloads Rust and compiles libnsm; it can take several minutes.)
10. `bash nitro/run.sh`. Expect an enclave with CID 16 and no `--debug-mode`. Check `nitro-cli describe-enclaves` shows `"State": "RUNNING"` and `"Flags": "NONE"`.
11. **Get the AWS Nitro root certificate** from AWS's attestation documentation page, **check its SHA-256 fingerprint against the one AWS publishes there**, and save it as `nitro/aws_root.pem`.
12. Start the app, requiring a verified attestation:
    ```
    cd ~/vault-harness
    export VAULT_ENCLAVE=vsock://16:5005
    export VAULT_EXPECT_PCR0=$(.venv/bin/python -c "import json;print(json.load(open('nitro/pcrs.json'))['PCR0'])")
    export VAULT_ROOT_PEM=nitro/aws_root.pem
    .venv/bin/python webapp.py --no-open
    ```
    It asks for a passphrase (not used with a remote enclave; press Enter). It should print "listening…". **If it refuses to start or the page cannot seal a card, attestation did not verify: that is the safety check working. Paste me the message.**

## Back on your Mac
13. View it through an SSM port-forward (still no open port on the instance):
    `aws ssm start-session --target <instance-id> --document-name AWS-StartPortForwardingSession --parameters portNumber=8765,localPortNumber=8765`
    Open `http://127.0.0.1:8765`. The header should read **enclave: NITRO, attestation verified · PCR0 …** and match the PCR0 you wrote down. Add the card in the page and run a payment; watch the live view.

## Clean up (do not skip)
14. **EC2 → terminate the instance**; IAM → delete user `vault-cli` and its access key, and the role `vault-enclave-role`; delete the security group. Any KMS key: schedule deletion.

## If something fails
- `nitro-cli run-enclave` fails: usually memory/CPU in `/etc/nitro_enclaves/allocator.yaml` or the instance isn't enclave-enabled (step 6).
- The enclave starts but cannot reach Stripe: check `nitro/vsock-proxy.log`, and the enclave clock (TLS says "not yet valid").
- Attestation fails with "PCRs are all zero": the enclave was started in debug mode.
- Paste the exact message, never keys or card details.
