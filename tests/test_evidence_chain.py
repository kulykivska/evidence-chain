"""What the chain must survive.

Not "does it hash things" - it does. The tests that matter are the ones where
someone with write access to the database tries to change what it says.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from evidence_chain import Chain, ChainError, verify_file
from evidence_chain.cli import main
from evidence_chain.core import GENESIS, compute_entry_hash


@pytest.fixture
def chain(tmp_path: Path) -> Chain:
    with Chain(tmp_path / "evidence.db") as opened:
        yield opened


def raw(path: Path) -> sqlite3.Connection:
    """A connection with no chain code in the way: this is the attacker."""
    return sqlite3.connect(str(path), isolation_level=None)


def test_the_first_entry_starts_from_the_genesis(chain: Chain) -> None:
    entry = chain.append("captured", {"url": "https://example.com"})
    assert entry.prev_hash == GENESIS
    assert entry.seq == 1
    assert chain.verify().ok


def test_each_entry_hashes_the_one_before_it(chain: Chain) -> None:
    first = chain.append("captured", {"n": 1})
    second = chain.append("captured", {"n": 2})
    assert second.prev_hash == first.entry_hash
    result = chain.verify()
    assert result.ok
    assert result.entries == 2


def test_the_hash_covers_the_payload_whatever_order_it_was_written_in() -> None:
    """Key order must not change the hash, or the same event hashes two ways."""
    one = compute_entry_hash(GENESIS, "t", "e", {"a": 1, "b": 2})
    two = compute_entry_hash(GENESIS, "t", "e", {"b": 2, "a": 1})
    assert one == two


def test_a_changed_payload_breaks_the_chain(chain: Chain, tmp_path: Path) -> None:
    """The whole point: an edit made outside this library is visible."""
    chain.append("captured", {"url": "https://example.com"})
    chain.append("captured", {"url": "https://example.org"})
    with raw(tmp_path / "evidence.db") as conn:
        conn.execute("DROP TRIGGER evidence_log_no_update")
        conn.execute("UPDATE evidence_log SET payload = ? WHERE seq = 1", ('{"url":"edited"}',))
    result = chain.verify()
    assert not result.ok
    assert result.first_bad_seq == 1
    assert result.reason == "entry_hash does not match content"


def test_a_deleted_entry_breaks_the_chain(chain: Chain, tmp_path: Path) -> None:
    for n in range(3):
        chain.append("captured", {"n": n})
    with raw(tmp_path / "evidence.db") as conn:
        conn.execute("DROP TRIGGER evidence_log_no_delete")
        conn.execute("DELETE FROM evidence_log WHERE seq = 2")
    result = chain.verify()
    assert not result.ok
    assert result.first_bad_seq == 3


def test_updating_an_entry_is_refused_by_the_database(chain: Chain, tmp_path: Path) -> None:
    chain.append("captured", {"n": 1})
    with raw(tmp_path / "evidence.db") as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE evidence_log SET payload = '{}' WHERE seq = 1")


def test_deleting_an_entry_is_refused_by_the_database(chain: Chain, tmp_path: Path) -> None:
    chain.append("captured", {"n": 1})
    with raw(tmp_path / "evidence.db") as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM evidence_log")


def test_dropped_triggers_are_back_the_next_time_it_is_opened(
    chain: Chain, tmp_path: Path
) -> None:
    """Dropping the triggers is the first thing anyone does who wants to edit
    the log; it must not be a permanent win."""
    chain.append("captured", {"n": 1})
    with raw(tmp_path / "evidence.db") as conn:
        conn.execute("DROP TRIGGER evidence_log_no_delete")
    with (
        Chain(tmp_path / "evidence.db"),
        raw(tmp_path / "evidence.db") as conn,
        pytest.raises(sqlite3.IntegrityError),
    ):
        conn.execute("DELETE FROM evidence_log")


def test_a_second_entry_after_the_same_one_cannot_be_written(
    chain: Chain, tmp_path: Path
) -> None:
    """The fork: two successors to one entry. The unique prev_hash refuses it
    even when the triggers are gone."""
    first = chain.append("captured", {"n": 1})
    chain.append("captured", {"n": 2})
    with raw(tmp_path / "evidence.db") as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO evidence_log (occurred_at, event_type, payload, prev_hash, entry_hash)"
            " VALUES ('t', 'forged', '{}', ?, 'deadbeef')",
            (first.entry_hash,),
        )


def test_append_many_is_all_or_nothing(chain: Chain) -> None:
    chain.append("captured", {"n": 0})
    with pytest.raises(ChainError):
        chain.append_many([("captured", {"n": 1}), ("captured", "not a dict")])  # type: ignore[list-item]
    assert chain.count() == 1
    assert chain.verify().ok


def test_two_processes_appending_do_not_fork_the_chain(tmp_path: Path) -> None:
    """The reason the write transaction is IMMEDIATE. With a deferred one both
    processes read the same head and the loser finds out at COMMIT."""
    db = tmp_path / "evidence.db"
    with Chain(db) as chain:
        chain.append("start", {})
    script = (
        "import sys; from evidence_chain import Chain\n"
        "chain = Chain(sys.argv[1])\n"
        "[chain.append('captured', {'who': sys.argv[2], 'n': n}) for n in range(20)]\n"
    )
    workers = [
        subprocess.Popen([sys.executable, "-c", script, str(db), name])  # noqa: S603
        for name in ("a", "b")
    ]
    assert [w.wait(timeout=60) for w in workers] == [0, 0]
    with Chain(db) as chain:
        assert chain.count() == 41
        assert chain.verify().ok


# --- checkpoints ----------------------------------------------------------


def test_a_checkpoint_lets_the_routine_check_skip_what_it_already_verified(
    chain: Chain,
) -> None:
    for n in range(5):
        chain.append("captured", {"n": n})
    chain.checkpoint()
    chain.append("captured", {"n": 5})
    result = chain.verify_since_checkpoint(record=False)
    assert result.ok
    assert result.checked_from == 6
    assert result.entries == 6


def test_a_checkpoint_is_written_once_per_advance_not_once_per_check(
    chain: Chain, tmp_path: Path
) -> None:
    chain.append("captured", {"n": 0})
    for _ in range(3):
        chain.verify_since_checkpoint()
    with raw(tmp_path / "evidence.db") as conn:
        assert conn.execute("SELECT count(*) FROM chain_checkpoints").fetchone()[0] == 1


def test_a_truncated_chain_is_not_hidden_by_its_checkpoint(
    chain: Chain, tmp_path: Path
) -> None:
    """The failure this whole anchor exists for: cut the log back below the
    checkpoint and a naive "check only what is new" reports it clean."""
    for n in range(5):
        chain.append("captured", {"n": n})
    chain.checkpoint()
    with raw(tmp_path / "evidence.db") as conn:
        conn.execute("DROP TRIGGER evidence_log_no_delete")
        conn.execute("DELETE FROM evidence_log WHERE seq > 2")
    result = chain.verify_since_checkpoint(record=False)
    assert not result.ok
    assert "shorter" in (result.reason or "") or "gone" in (result.reason or "")


def test_entries_deleted_below_the_checkpoint_are_caught(chain: Chain, tmp_path: Path) -> None:
    for n in range(5):
        chain.append("captured", {"n": n})
    chain.checkpoint()
    with raw(tmp_path / "evidence.db") as conn:
        conn.execute("DROP TRIGGER evidence_log_no_delete")
        conn.execute("DELETE FROM evidence_log WHERE seq = 2")
    result = chain.verify_since_checkpoint(record=False)
    assert not result.ok
    assert result.reason == "entries below the checkpoint are gone"


def test_a_forged_checkpoint_is_refused(chain: Chain, tmp_path: Path) -> None:
    """A checkpoint naming an entry it does not match would otherwise vouch for
    a chain nobody checked."""
    for n in range(3):
        chain.append("captured", {"n": n})
    with raw(tmp_path / "evidence.db") as conn:
        conn.execute(
            "INSERT INTO chain_checkpoints (seq, entry_hash, verified_at)"
            " VALUES (3, 'not-the-hash', 't')"
        )
    result = chain.verify_since_checkpoint(record=False)
    assert not result.ok
    assert result.reason == "checkpoint does not match its entry"


def test_checkpoints_cannot_be_updated_or_deleted(chain: Chain, tmp_path: Path) -> None:
    chain.append("captured", {"n": 0})
    chain.checkpoint()
    with raw(tmp_path / "evidence.db") as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE chain_checkpoints SET entry_hash = 'x'")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM chain_checkpoints")


def test_an_empty_chain_verifies_and_checkpoints_nothing(chain: Chain) -> None:
    assert chain.verify().ok
    assert chain.checkpoint() is None
    assert chain.verify_since_checkpoint().ok


# --- handing it to someone else -------------------------------------------


def test_an_exported_file_verifies_without_the_database(chain: Chain, tmp_path: Path) -> None:
    for n in range(4):
        chain.append("captured", {"n": n})
    out = tmp_path / "chain.jsonl"
    assert chain.export(out) == 4
    result = verify_file(out)
    assert result.ok
    assert result.entries == 4


def test_an_edited_export_does_not_verify(chain: Chain, tmp_path: Path) -> None:
    for n in range(3):
        chain.append("captured", {"n": n})
    out = tmp_path / "chain.jsonl"
    chain.export(out)
    lines = out.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["payload"] = {"n": "edited"}
    lines[1] = json.dumps(tampered)
    out.write_text("\n".join(lines) + "\n")
    assert not verify_file(out).ok


def test_a_line_removed_from_the_export_does_not_verify(chain: Chain, tmp_path: Path) -> None:
    for n in range(3):
        chain.append("captured", {"n": n})
    out = tmp_path / "chain.jsonl"
    chain.export(out)
    lines = out.read_text().splitlines()
    out.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = verify_file(out)
    assert not result.ok
    assert result.first_bad_seq == 3


def test_a_file_that_is_not_a_chain_says_so(tmp_path: Path) -> None:
    bad = tmp_path / "notes.jsonl"
    bad.write_text('{"hello": "world"}\n')
    with pytest.raises(ChainError, match="not an entry"):
        verify_file(bad)


# --- the CLI --------------------------------------------------------------


def test_the_cli_appends_verifies_and_exports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = str(tmp_path / "evidence.db")
    assert main(["--db", db, "append", "captured", '{"url": "https://example.com"}']) == 0
    assert main(["--db", db, "append", "captured", '{"url": "https://example.org"}']) == 0
    capsys.readouterr()
    assert main(["--db", db, "verify"]) == 0
    assert "2 entries" in capsys.readouterr().out
    out = tmp_path / "chain.jsonl"
    assert main(["--db", db, "export", str(out)]) == 0
    capsys.readouterr()
    assert main(["check", str(out)]) == 0
    assert "valid" in capsys.readouterr().out


def test_the_cli_exits_one_on_a_broken_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "evidence.db"
    with Chain(db) as chain:
        chain.append("captured", {"n": 1})
        chain.append("captured", {"n": 2})
    with raw(db) as conn:
        conn.execute("DROP TRIGGER evidence_log_no_update")
        conn.execute("UPDATE evidence_log SET payload = '{}' WHERE seq = 1")
    assert main(["--db", str(db), "verify"]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_a_payload_that_is_not_an_object_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, not 0: the caller must not read "could not append" as "appended"."""
    assert main(["--db", str(tmp_path / "e.db"), "append", "captured", "[1, 2]"]) == 2
    assert "must be a JSON object" in capsys.readouterr().err


def test_log_prints_entries_as_json_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = str(tmp_path / "evidence.db")
    main(["--db", db, "append", "captured", '{"n": 1}'])
    main(["--db", db, "append", "captured", '{"n": 2}'])
    capsys.readouterr()
    assert main(["--db", db, "log", "--since", "2"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["payload"] == {"n": 2}


def test_a_payload_that_cannot_be_json_is_a_chain_error(chain: Chain) -> None:
    """Not a TypeError from three frames inside json."""
    with pytest.raises(ChainError, match="not JSON-serialisable"):
        chain.append("captured", {"when": object()})
    assert chain.count() == 0


def test_writing_inside_a_write_says_what_went_wrong(chain: Chain) -> None:
    with chain.writing(), pytest.raises(ChainError, match="already in a transaction"):
        chain.append("captured", {"n": 1})


def test_a_failed_append_leaves_nothing_behind(chain: Chain, tmp_path: Path) -> None:
    chain.append("captured", {"n": 0})
    with pytest.raises(ChainError):
        chain.append("captured", {"bad": {1, 2}})
    assert chain.count() == 1
    assert chain.verify().ok
    # And the next real append still chains onto the last good entry.
    assert chain.append("captured", {"n": 1}).seq == 2
    assert chain.verify().ok


def test_a_chain_from_another_tool_can_be_read_but_not_checkpointed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real case: brand-evidence writes the same evidence_log through
    SQLAlchemy, with a chain_checkpoints table that carries its own id column."""
    db = tmp_path / "foreign.db"
    with raw(db) as conn:
        conn.execute(
            "CREATE TABLE evidence_log ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,"
            " event_type TEXT NOT NULL, payload TEXT NOT NULL,"
            " prev_hash TEXT NOT NULL UNIQUE, entry_hash TEXT NOT NULL UNIQUE)"
        )
        conn.execute(
            "CREATE TABLE chain_checkpoints (id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE,"
            " entry_hash TEXT NOT NULL, verified_at TEXT NOT NULL)"
        )
    with Chain(db) as chain:
        chain.append("captured", {"n": 1})
        assert chain.verify().ok
        with pytest.raises(ChainError, match="created by another tool"):
            chain.checkpoint()
    assert main(["--db", str(db), "verify", "--since-checkpoint"]) == 2
    assert "another tool" in capsys.readouterr().err
