"""An append-only, hash-chained log in one SQLite file."""

from evidence_chain.core import (
    GENESIS,
    Chain,
    ChainError,
    Checkpoint,
    Entry,
    VerifyResult,
    canonical_json,
    compute_entry_hash,
    read_file,
    verify_entries,
    verify_file,
)

__all__ = [
    "GENESIS",
    "Chain",
    "ChainError",
    "Checkpoint",
    "Entry",
    "VerifyResult",
    "canonical_json",
    "compute_entry_hash",
    "read_file",
    "verify_entries",
    "verify_file",
]
__version__ = "0.1.0"
