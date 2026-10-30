# vendor/

The safety kernel used by every graph step: a halt switch (a file outside the agent), a step/time budget, a hash-chained ledger with secret
redaction, screening of untrusted text, and post-conditions that check the world after an irreversible step.

- `agent_kernel.py`, `egress.py`, `blackbox/` are the author's own code, copied unchanged from his `agent-kit` and `agent-blackbox` projects
  except for one line in `agent_kernel.py`: the `blackbox` import path now points at this directory instead of `~/agent-blackbox`.
- Pure standard library. Total about 700 lines, short enough to read in one sitting.
- `kernel_setup.py` fails **closed**: if this kernel cannot be loaded the agent refuses to run (`AGENT_KERNEL=off` disables it on purpose).
- Override locations with `AGENT_KIT_SRC` / `AGENT_BLACKBOX_SRC`.
