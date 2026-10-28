import pytest
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tempfile
_boot = tempfile.mkdtemp(prefix="agent-kernel-test-")      # import-time kernel must not touch the real ledger or halt files
os.environ.setdefault("BLACKBOX_DIR", _boot + "/ledger")
os.environ.setdefault("AGENT_CONTROL_DIR", _boot + "/control")
for k in ("OPENROUTER_API_KEY", "GROQ_API_KEY", "LLM_PROVIDER", "PHOENIX_COLLECTOR_ENDPOINT"):
    os.environ[k] = ""          # tests are offline and never spend model calls


@pytest.fixture(autouse=True)
def fresh_kernel(tmp_path, monkeypatch):
    """Each test gets its own ledger, halt directory and budget."""
    from vault_harness import kernel_setup
    monkeypatch.setenv("BLACKBOX_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("AGENT_CONTROL_DIR", str(tmp_path / "control"))
    kernel_setup.reset()
    yield
    kernel_setup.reset()
