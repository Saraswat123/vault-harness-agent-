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


@pytest.fixture(autouse=True)
def hermetic_stripe_keys(monkeypatch):
    """Unit tests never read real Stripe keys from .env or the environment."""
    from vault_harness import stripe_processor
    monkeypatch.setattr(stripe_processor, "_env", lambda name: None)


@pytest.fixture(autouse=True)
def isolated_guard_state(tmp_path, monkeypatch):
    """Events DB, freezes, alerts and the card store live in each test's own tmp dir, never in the real output/."""
    monkeypatch.setenv("VAULT_EVENTS_DB", str(tmp_path / "events.db"))
    monkeypatch.setenv("VAULT_FREEZE_FILE", str(tmp_path / "freezes.json"))
    monkeypatch.setenv("VAULT_ALERTS_FILE", str(tmp_path / "alerts.jsonl"))
    monkeypatch.setenv("VAULT_CARD_STORE", str(tmp_path / "cards.json"))
