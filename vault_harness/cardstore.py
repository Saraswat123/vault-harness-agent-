"""Card-on-file store: CIPHERTEXT ONLY. Each record is the sealed box the enclave can open (and nobody else), plus display fields.
Never stored: the card number in clear, the CVC (PCI DSS forbids keeping it after authorization, even encrypted), any key.
A copied or stolen store file is useless without the enclave's private key (in the real build: KMS key released only to the attested enclave)."""
import json
import os
import secrets
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CardStore:
    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("VAULT_CARD_STORE", ROOT / "output" / "cards.json"))

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def _save(self, d: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(d))
        self.path.chmod(0o600)

    @staticmethod
    def new_id() -> str:
        return "vc_" + secrets.token_hex(10)

    def add(self, card_id: str, display: dict, sealed: dict):
        d = self._load()
        d[card_id] = {"display": display, "sealed": sealed, "status": "active", "created": time.time()}
        self._save(d)

    def sealed(self, card_id: str) -> dict:
        r = self._load().get(card_id)
        if not r or r["status"] != "active":
            raise KeyError(f"card {card_id} not found or not active")
        return r["sealed"]

    def list_display(self) -> list:
        return [{"id": k, **v["display"], "status": v["status"]} for k, v in self._load().items()]

    def set_status(self, card_id: str, status: str):
        d = self._load(); d[card_id]["status"] = status; self._save(d)

    def delete(self, card_id: str):
        d = self._load(); d.pop(card_id, None); self._save(d)
