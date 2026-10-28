"""Opens the agent kernel (~/agent-kit/agent_kernel.py): halt switch, step/time budget, hash-chained ledger,
screening of untrusted text, and post-checks of the world. Scaffolded agents are guarded by default.

FAILS CLOSED: if the kernel cannot be loaded (for example in a container without ~/agent-kit and ~/agent-blackbox)
this raises. It never falls back to running unguarded. To run unguarded ON PURPOSE set AGENT_KERNEL=off.

  AGENT_KERNEL=off            run without the kernel (tests of your own logic, throwaway runs)
  AGENT_KIT_SRC=<dir>         where agent_kernel.py lives (default ~/agent-kit)
  BLACKBOX_DIR=<dir>          ledger location (default ~/.blackbox/ledger)
  AGENT_CONTROL_DIR=<dir>     halt files (default ~/.agent-control).  Stop me:  python3 -m blackbox halt --agent vault-harness --reason "..."
"""
import functools
import os
import sys
from pathlib import Path

AGENT = "vault-harness"
_kernel = None


def off() -> bool:
    return os.environ.get("AGENT_KERNEL", "on").lower() == "off"


def get_kernel():
    """The shared Kernel for this process, or None when AGENT_KERNEL=off. Checks come from vault_harness/checks.py."""
    global _kernel
    if off():
        return None
    if _kernel is None:
        kit = Path(os.environ.get("AGENT_KIT_SRC", str(Path.home() / "agent-kit")))
        if kit.exists() and str(kit) not in sys.path:
            sys.path.insert(0, str(kit))
        try:
            from agent_kernel import Kernel
        except Exception as e:
            raise RuntimeError(
                f"agent kernel not loadable ({type(e).__name__}: {e}). Refusing to run unguarded. "
                "Fix AGENT_KIT_SRC / the agent-blackbox install, or set AGENT_KERNEL=off to run without it on purpose.") from e
        from vault_harness import checks
        _kernel = Kernel(AGENT, postconditions=checks.POSTCONDITIONS, screens=checks.SCREENS)
    return _kernel


def reset():
    """Forget the kernel (tests do this so each test gets a fresh ledger and budget)."""
    global _kernel
    _kernel = None


def guarded(name: str):
    """Decorator for a tool function: every call goes through the kernel. Put it UNDER @tool."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            kern = get_kernel()
            return fn(*a, **k) if kern is None else kern.call(name, fn, *a, **k)
        return wrapper
    return deco
