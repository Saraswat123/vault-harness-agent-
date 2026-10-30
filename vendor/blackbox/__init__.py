"""agent-blackbox: a flight recorder for agents. Stdlib only.

ledger   tamper-evident, hash-chained, human-readable evidence, stored as sealed segments (chunks)
halt     containment: a global or per-agent stop that any agent loop checks before each step
incident structured incident reports, linked into the ledger
"""
from blackbox.halt import Halted, Halt
from blackbox.incident import create_incident
from blackbox.ledger import Ledger, verify

__all__ = ["Ledger", "verify", "Halt", "Halted", "create_incident"]
