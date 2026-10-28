# vault-harness (flow style)

Scaffolded by `/agent-new`. Runs offline with a scripted model until you add a key to `.env`.

    .venv/bin/python -m pytest -q tests                                  # offline, no key
    <venv>/bin/python ~/agent-kit/draw_graph.py . vault_harness.graph:graph    # flowchart (same as /langchain graph)
    langgraph dev                                                        # serve it (needs the sandbox off for the port)

First edits, in order: (1) the prompt or `SYSTEM` in `vault_harness/graph.py`, (2) the tools or rules,
(3) the offline script in `fake_model.py`, (4) real test data and golden answers.

Not scaffolded: an eval runner. Copy the pattern from `~/deepagent-lab/evals/` once you have golden data.
Keys: `.env` only (gitignored and dockerignored). Never paste a key into chat.

## Guarded by default (agent kernel)
Every step runs through `~/agent-kit/agent_kernel.py`: halt switch -> step/time budget -> hash-chained ledger ->
screening of untrusted text -> post-check of the world. See `vault_harness/kernel_setup.py` for the switches.

    python3 -m blackbox halt --agent vault-harness --reason "why"      # from ~/agent-blackbox; stops the next step
    python3 -m blackbox resume --agent vault-harness                   # only after you looked at why
    python3 -m blackbox verify                                    # is the ledger intact

Edit `vault_harness/checks.py` when you add a tool or replace the real action: a check that reads the world (file exists, row
exists, message id logged) beats trusting what the step says. `tests/test_kernel.py` proves the guards hold; keep it green.

Limits: stops a cooperating loop at the next step, not a call in flight. Fails closed: if the kernel cannot be loaded the
agent refuses to run (`AGENT_KERNEL=off` runs unguarded on purpose). Needs `~/agent-kit` and `~/agent-blackbox`, so a
container must bundle them. Deep style guards your own tools; deepagents' built-in `write_file` is covered by the approval gate.
