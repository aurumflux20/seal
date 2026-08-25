"""Seal — exactly-once admission for irreversible agent actions, across processes.

Public surface: `Seal`, `Admission`, `intent_id`.
The honesty boundary is in the cert itself: `world: "unconfirmed"` until a
provider adapter confirms settlement. Admission and settlement are different
claims; Seal never conflates them.
"""
from .core import (
    Admission,
    DomainFrozen,
    NotFenceHolder,
    PayloadConflict,
    Seal,
    SealError,
    StaleWorldRead,
    intent_id,
)

__all__ = [
    "Seal", "Admission", "intent_id",
    "SealError", "PayloadConflict", "DomainFrozen", "NotFenceHolder",
    "StaleWorldRead",
]
__version__ = "0.3.0"
