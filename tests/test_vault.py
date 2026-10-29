import re
import time

from vault_harness.policy import Intent
from vault_harness.vault import MockVault

I = Intent("buy.stripe.com", 100, "usd")


def test_placeholder_is_single_use():
    v = MockVault()
    ph = v.issue_placeholder(I)
    assert v.pay(ph, I)["status"] == "done"
    assert v.pay(ph, I)["status"] == "refused"


def test_placeholder_bound_to_the_exact_payment():
    v = MockVault()
    ph = v.issue_placeholder(I)
    assert v.pay(ph, Intent("buy.stripe.com", 101, "usd"))["reason"] == "placeholder not bound to this payment"
    assert v.pay(ph, Intent("other.com", 100, "usd"))["status"] == "refused"


def test_placeholder_expires(monkeypatch):
    v = MockVault()
    ph = v.issue_placeholder(I)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 3600)
    assert v.pay(ph, I)["reason"] == "placeholder expired"


def test_placeholder_carries_no_card_data():
    ph = MockVault().issue_placeholder(I)
    assert "4242424242424242" not in repr(ph) and re.fullmatch(r"ph_[0-9a-f]{24}", ph.token)
