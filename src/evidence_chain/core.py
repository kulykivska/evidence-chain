"""An append-only log where every entry hashes the one before it.

The point is not that the hashes are clever - it is that nobody, including the
process that owns the database, can quietly change what was already written.
Rows are protected by SQLite triggers, the chain refuses to fork, and a second
process appending at the same moment cannot read the same head twice.

entry_hash = sha256(prev_hash + occurred_at + event_type + canonical_json(payload))
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

# How long a writer waits for another writer before giving up. Generous,
# because the caller may be holding the lock across real work.
BUSY_TIMEOUT_MS = 30_000

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS evidence_log (
         seq         INTEGER PRIMARY KEY AUTOINCREMENT,
         occurred_at TEXT NOT NULL,
         event_type  TEXT NOT NULL,
         payload     TEXT NOT NULL,
         -- Unique: one successor per entry, so a fork cannot be written even
         -- by a process that is trying to write one.
         prev_hash   TEXT NOT NULL UNIQUE,
         entry_hash  TEXT NOT NULL UNIQUE
       )""",
    """CREATE TABLE IF NOT EXISTS chain_checkpoints (
         seq         INTEGER PRIMARY KEY,
         entry_hash  TEXT NOT NULL,
         verified_at TEXT NOT NULL
       )""",
)

APPEND_ONLY_TRIGGERS = (
    """CREATE TRIGGER IF NOT EXISTS evidence_log_no_update
       BEFORE UPDATE ON evidence_log
       BEGIN SELECT RAISE(ABORT, 'evidence_log is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS evidence_log_no_delete
       BEFORE DELETE ON evidence_log
       BEGIN SELECT RAISE(ABORT, 'evidence_log is append-only'); END""",
    # A checkpoint says how much of the chain has been verified, so a forged one
    # silences the routine check. Same protection as the log itself.
    """CREATE TRIGGER IF NOT EXISTS chain_checkpoints_no_update
       BEFORE UPDATE ON chain_checkpoints
       BEGIN SELECT RAISE(ABORT, 'chain_checkpoints is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS chain_checkpoints_no_delete
       BEFORE DELETE ON chain_checkpoints
       BEGIN SELECT RAISE(ABORT, 'chain_checkpoints is append-only'); END""",
)


# The columns this library knows how to fill. Anything else that a foreign
# schema demands is a column it cannot write.
LOG_COLUMNS = frozenset(
    {"seq", "occurred_at", "event_type", "payload", "prev_hash", "entry_hash"}
)
CHECKPOINT_COLUMNS = frozenset({"seq", "entry_hash", "verified_at"})


def _unfillable_columns(
    conn: sqlite3.Connection, table: str, known: frozenset[str]
) -> list[str]:
    """Columns that are required, have no default, and are not ours to fill.

    A primary key counts as required even when SQLite reports it nullable -
    a long-standing quirk lets a non-INTEGER primary key hold NULL, and a
    checkpoint row keyed on NULL is worse than no checkpoint at all.
    """
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [
        str(row[1])
        for row in rows
        if str(row[1]) not in known
        and row[4] is None
        and (int(row[3]) == 1 or int(row[5]) > 0)
    ]


class ChainError(Exception):
    """Something about this chain is wrong in a way the caller must handle."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json(payload: dict[str, Any]) -> str:
    """The exact bytes that get hashed. Key order and spacing are part of the
    hash, so they are fixed here and never left to the json defaults."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_entry_hash(
    prev_hash: str, occurred_at: str, event_type: str, payload: dict[str, Any]
) -> str:
    material = prev_hash + occurred_at + event_type + canonical_json(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Entry:
    seq: int
    occurred_at: str
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def recomputed(self) -> str:
        return compute_entry_hash(
            self.prev_hash, self.occurred_at, self.event_type, self.payload
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "occurred_at": self.occurred_at,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_row(cls, row: tuple[Any, ...]) -> Entry:
        return cls(
            seq=int(row[0]),
            occurred_at=str(row[1]),
            event_type=str(row[2]),
            payload=json.loads(row[3]),
            prev_hash=str(row[4]),
            entry_hash=str(row[5]),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        if not isinstance(data, dict) or not isinstance(data.get("payload"), dict):
            raise ChainError(f"not an entry: {data!r}")
        try:
            return cls(
                seq=int(data["seq"]),
                occurred_at=str(data["occurred_at"]),
                event_type=str(data["event_type"]),
                payload=data["payload"],
                prev_hash=str(data["prev_hash"]),
                entry_hash=str(data["entry_hash"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ChainError(f"not an entry: {data!r}") from exc


@dataclass(frozen=True)
class Checkpoint:
    seq: int
    entry_hash: str
    verified_at: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    reason: str | None = None
    # Set when only part of the chain was walked: where the walk started, and
    # when everything below it was last checked in full.
    checked_from: int | None = None
    checkpoint_at: str | None = None

    def __bool__(self) -> bool:
        return self.ok

    def describe(self) -> str:
        if not self.ok:
            return f"chain BROKEN at seq {self.first_bad_seq}: {self.reason}"
        if self.checked_from is None:
            return f"chain valid: {self.entries} entries"
        return (
            f"chain valid: {self.entries} entries (seq {self.checked_from} onwards; "
            f"earlier verified in full at {self.checkpoint_at})"
        )


class Chain:
    """An append-only log in one SQLite file.

    Opening it creates the schema and the triggers if they are not there, and
    re-installs the triggers if someone dropped them - which is the first thing
    anyone does who wants to edit the log.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if self.path.parent != Path():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: pysqlite otherwise opens the transaction at the
        # first write, after this process has already read the chain head.
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # FULL, not NORMAL: an entry the caller was told was written must still
        # be there after the machine loses power.
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        with self.writing() as conn:
            for statement in (*SCHEMA, *APPEND_ONLY_TRIGGERS):
                conn.execute(statement)
        # A chain written by another tool can be read and exported here even if
        # its tables carry columns of their own; writing into them is what this
        # library cannot do, and it says so when asked rather than at open.
        self._unfillable = {
            table: _unfillable_columns(self._conn, table, known)
            for table, known in (
                ("evidence_log", LOG_COLUMNS),
                ("chain_checkpoints", CHECKPOINT_COLUMNS),
            )
        }

    def _refuse_foreign_writes(self, table: str) -> None:
        columns = self._unfillable.get(table) or []
        if columns:
            raise ChainError(
                f"{self.path} was created by another tool: {table} requires "
                f"{', '.join(columns)}, which this library does not fill. "
                "It can still be verified and exported."
            )

    def __enter__(self) -> Chain:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def writing(self) -> Iterator[sqlite3.Connection]:
        """A write transaction, held from before the head is read.

        BEGIN IMMEDIATE is the whole difference between one chain and two: with
        a deferred transaction, two processes read the same head, compute the
        same prev_hash, and the second one only finds out at COMMIT.
        """
        if self._conn.in_transaction:
            # SQLite would say "cannot start a transaction within a
            # transaction", which does not tell the caller what they did.
            raise ChainError(
                "this chain is already in a transaction - finish iterating "
                "entries(), or leave the writing() block, before writing"
            )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    @contextmanager
    def reading(self) -> Iterator[sqlite3.Connection]:
        """A consistent snapshot, so a long read cannot see half of a writer.

        Deferred, not immediate: readers must not queue behind each other, and
        under WAL they do not have to.
        """
        if self._conn.in_transaction:
            yield self._conn
            return
        self._conn.execute("BEGIN DEFERRED")
        try:
            yield self._conn
        finally:
            # A read changes nothing, so ending it can never fail the caller.
            self._conn.execute("COMMIT")

    # --- writing ----------------------------------------------------------

    def append(self, event_type: str, payload: dict[str, Any]) -> Entry:
        """Append one entry and commit it."""
        with self.writing() as conn:
            return self._append(conn, event_type, payload)

    def append_many(self, events: list[tuple[str, dict[str, Any]]]) -> list[Entry]:
        """Append several entries in one transaction: all of them or none."""
        with self.writing() as conn:
            return [self._append(conn, event_type, payload) for event_type, payload in events]

    def _append(
        self, conn: sqlite3.Connection, event_type: str, payload: dict[str, Any]
    ) -> Entry:
        if not isinstance(payload, dict):
            raise ChainError(f"payload must be a dict, not {type(payload).__name__}")
        self._refuse_foreign_writes("evidence_log")
        head = self._head(conn)
        prev_hash = head.entry_hash if head else GENESIS
        occurred_at = now_iso()
        try:
            body = canonical_json(payload)
        except (TypeError, ValueError) as exc:
            # A datetime or a set in the payload. Say so as a chain error, not
            # as whatever json raised from three frames down.
            raise ChainError(f"payload is not JSON-serialisable: {exc}") from exc
        entry_hash = compute_entry_hash(prev_hash, occurred_at, event_type, payload)
        cursor = conn.execute(
            "INSERT INTO evidence_log (occurred_at, event_type, payload, prev_hash, entry_hash)"
            " VALUES (?, ?, ?, ?, ?)",
            (occurred_at, event_type, body, prev_hash, entry_hash),
        )
        return Entry(
            seq=int(cursor.lastrowid or 0),
            occurred_at=occurred_at,
            event_type=event_type,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def checkpoint(self) -> Checkpoint | None:
        """Record that the head has been verified in full.

        One row per advance, not one per check: a daily verification on a chain
        that has not moved writes nothing.
        """
        with self.writing() as conn:
            return self._checkpoint(conn)

    def _checkpoint(self, conn: sqlite3.Connection) -> Checkpoint | None:
        self._refuse_foreign_writes("chain_checkpoints")
        head = self._head(conn)
        if head is None:
            return None
        current = self._latest_checkpoint(conn)
        if current is not None and current.seq >= head.seq:
            return current
        row = Checkpoint(seq=head.seq, entry_hash=head.entry_hash, verified_at=now_iso())
        conn.execute(
            "INSERT INTO chain_checkpoints (seq, entry_hash, verified_at) VALUES (?, ?, ?)",
            (row.seq, row.entry_hash, row.verified_at),
        )
        return row

    # --- reading ----------------------------------------------------------

    def head(self) -> Entry | None:
        return self._head(self._conn)

    def _head(self, conn: sqlite3.Connection) -> Entry | None:
        row = conn.execute(
            "SELECT seq, occurred_at, event_type, payload, prev_hash, entry_hash"
            " FROM evidence_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return Entry.from_row(row) if row else None

    def entries(self, since: int | None = None) -> Iterator[Entry]:
        """Every entry in order, streamed - the log is expected to outgrow memory."""
        query = (
            "SELECT seq, occurred_at, event_type, payload, prev_hash, entry_hash"
            " FROM evidence_log"
        )
        params: tuple[Any, ...] = ()
        if since is not None:
            query += " WHERE seq >= ?"
            params = (since,)
        with self.reading() as conn:
            for row in conn.execute(query + " ORDER BY seq ASC", params):
                yield Entry.from_row(row)

    def count(self) -> int:
        row = self._conn.execute("SELECT count(*) FROM evidence_log").fetchone()
        return int(row[0])

    def latest_checkpoint(self) -> Checkpoint | None:
        return self._latest_checkpoint(self._conn)

    def _latest_checkpoint(self, conn: sqlite3.Connection) -> Checkpoint | None:
        row = conn.execute(
            "SELECT seq, entry_hash, verified_at FROM chain_checkpoints"
            " ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return Checkpoint(int(row[0]), str(row[1]), str(row[2])) if row else None

    # --- verifying --------------------------------------------------------

    def verify(self) -> VerifyResult:
        """Re-hash every entry from the genesis and report the first break."""
        return verify_entries(self.entries(), GENESIS, None, 0)

    def verify_since_checkpoint(self, *, record: bool = True) -> VerifyResult:
        """Check what was appended since the last full verification.

        A routine check that re-hashes the whole log grows without bound while
        telling nobody anything new. What is below the checkpoint was verified
        in full when that checkpoint was written - and the checkpoint itself is
        checked against the log first, so a truncated chain cannot hide under it.
        """
        checkpoint = self.latest_checkpoint()
        if checkpoint is None:
            result = self.verify()
        else:
            broken = self._checkpoint_broken(checkpoint)
            # `broken or ...` would be wrong here: a failing result is falsy by
            # design, so the fallback would run and report the chain clean.
            if broken is not None:
                result = broken
            else:
                result = verify_entries(
                    self.entries(since=checkpoint.seq + 1),
                    checkpoint.entry_hash,
                    checkpoint.seq + 1,
                    self._count_to(checkpoint.seq),
                    checked_from=checkpoint.seq + 1,
                    checkpoint_at=checkpoint.verified_at,
                )
        if result.ok and record:
            self.checkpoint()
        return result

    def _count_to(self, seq: int) -> int:
        row = self._conn.execute(
            "SELECT count(*) FROM evidence_log WHERE seq <= ?", (seq,)
        ).fetchone()
        return int(row[0])

    def _checkpoint_broken(self, checkpoint: Checkpoint) -> VerifyResult | None:
        """Check the checkpoint against the log before trusting it. None means it holds.

        Without this, a check that starts above the checkpoint cannot see that
        the entries it skipped are gone, or that the head was cut back to below
        it: a truncated chain reported as valid, which is exactly the tampering
        this table would otherwise invite.
        """
        below = self._count_to(checkpoint.seq)
        row = self._conn.execute(
            "SELECT seq, occurred_at, event_type, payload, prev_hash, entry_hash"
            " FROM evidence_log WHERE seq = ?",
            (checkpoint.seq,),
        ).fetchone()
        if row is None:
            return VerifyResult(False, below, checkpoint.seq, "the checkpointed entry is gone")
        anchor = Entry.from_row(row)
        if anchor.entry_hash != checkpoint.entry_hash:
            return VerifyResult(
                False, below, checkpoint.seq, "checkpoint does not match its entry"
            )
        if anchor.recomputed() != anchor.entry_hash:
            return VerifyResult(
                False, below, checkpoint.seq, "entry_hash does not match content"
            )
        first_row = self._conn.execute("SELECT min(seq) FROM evidence_log").fetchone()
        first = first_row[0]
        if first is None or below != checkpoint.seq - int(first) + 1:
            return VerifyResult(
                False, below, checkpoint.seq, "entries below the checkpoint are gone"
            )
        head = self.head()
        if head is None or head.seq < checkpoint.seq:
            return VerifyResult(
                False, below, checkpoint.seq, "the chain is shorter than the checkpoint"
            )
        return None

    # --- handing it to someone else ---------------------------------------

    def export(self, destination: Path | str) -> int:
        """Write the chain as JSONL, one entry per line, in order.

        The file verifies on its own with `verify_file`: whoever you hand it to
        does not need your database, your schema, or your code path.
        """
        path = Path(destination)
        written = 0
        with path.open("w", encoding="utf-8") as handle:
            for entry in self.entries():
                handle.write(json.dumps(entry.as_dict(), ensure_ascii=False) + "\n")
                written += 1
        return written


def verify_entries(  # noqa: PLR0913 - a walk needs its whole starting position
    entries: Iterator[Entry],
    expected_prev: str,
    expected_seq: int | None,
    count: int,
    *,
    checked_from: int | None = None,
    checkpoint_at: str | None = None,
) -> VerifyResult:
    """Walk entries in order, checking each link. The one place that decides
    what "valid" means, so the database and an exported file cannot disagree."""
    for entry in entries:
        count += 1
        if expected_seq is None:
            expected_seq = entry.seq
        if entry.seq != expected_seq:
            return VerifyResult(False, count, entry.seq, f"gap: expected seq {expected_seq}")
        if entry.prev_hash != expected_prev:
            return VerifyResult(
                False, count, entry.seq, "prev_hash does not match the previous entry"
            )
        if entry.recomputed() != entry.entry_hash:
            return VerifyResult(False, count, entry.seq, "entry_hash does not match content")
        expected_prev = entry.entry_hash
        expected_seq = entry.seq + 1
    return VerifyResult(True, count, checked_from=checked_from, checkpoint_at=checkpoint_at)


def read_file(path: Path | str) -> Iterator[Entry]:
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ChainError(f"{path}:{number} is not JSON: {exc}") from exc
            yield Entry.from_dict(data)


def verify_file(path: Path | str) -> VerifyResult:
    """Verify an exported chain with no database involved."""
    return verify_entries(read_file(path), GENESIS, None, 0)
