# evidence-chain

[![ci](https://github.com/kulykivska/evidence-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/kulykivska/evidence-chain/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An append-only log in one SQLite file, where every entry hashes the one before
it. Change a row and the file says so. Delete one and the file says so. Do it
with the database open in front of you and the file still says so.

```bash
pip install evidence-chain
```

No dependencies.

```python
from evidence_chain import Chain

with Chain("evidence.db") as chain:
    chain.append("captured", {"url": "https://example.com", "sha256": digest})
    chain.append("archived", {"url": "https://example.com", "wayback_id": ref})

    print(chain.verify().describe())
    # chain valid: 2 entries
```

## What it is for

A log you will one day have to defend. Trademark evidence, model provenance,
consent records, an audit trail a regulator will read — anywhere the question
is not "what does the log say" but "why should anyone believe it".

It is not a blockchain and there is no network. It is the smallest thing that
makes tampering **visible**: the hash chain shows an edit, the SQLite triggers
refuse one, and a unique `prev_hash` means the chain cannot fork even if the
triggers are gone.

## What an attacker with write access has to get past

They have the file. They can run any SQL they like. Every column is theirs.

```python
conn.execute("UPDATE evidence_log SET payload = '{}' WHERE seq = 1")
# sqlite3.IntegrityError: evidence_log is append-only
```

The triggers are the first fence, and they are the easy one — the attacker
drops them. So the next time the chain is opened they are back, and meanwhile:

```python
chain.verify().describe()
# chain BROKEN at seq 1: entry_hash does not match content
```

Deleting an entry breaks the chain at the next one. Rewriting an entry *and*
re-hashing every entry above it means rewriting the whole log — at which point
an exported copy someone else is holding no longer matches.

Writing a second entry after an existing one — a fork, the one shape a naive
chain accepts happily — is refused by the database itself:

```python
conn.execute("INSERT INTO evidence_log (...) VALUES (..., prev_hash, ...)")
# sqlite3.IntegrityError: UNIQUE constraint failed: evidence_log.prev_hash
```

## Two processes, one chain

```python
chain.append("captured", payload)   # BEGIN IMMEDIATE, read head, insert, COMMIT
```

The write transaction takes SQLite's write lock **before** it reads the chain
head. That is the entire difference between one chain and two: with a deferred
transaction, two processes read the same head, compute the same `prev_hash`,
and the loser only finds out at `COMMIT`.

The test suite runs two real processes appending twenty entries each and
verifies the result.

## Checkpoints, for a log that keeps growing

Re-hashing every entry ever written is fine at ten thousand and silly at ten
million, and the daily check learns nothing new about what it already verified.

```python
chain.verify_since_checkpoint()   # walks only what came after the last full check
```

The trap in that idea is the reason for the interesting half of this library:
if the check starts *above* the checkpoint, it cannot see that everything below
was deleted, or that the head was cut back. So the checkpoint is verified
against the log first — its entry must exist, hash correctly, and have the
right number of entries beneath it — and checkpoints get the same append-only
triggers as the log, because a forged checkpoint would otherwise silence the
check entirely.

`verify()` still walks everything. Use it before you hand the log to anyone.

## Handing it to someone else

```python
chain.export("chain.jsonl")
```

```bash
evidence-chain check chain.jsonl
# chain valid: 1284 entries
```

The exported file verifies on its own — no database, no schema, no access to
your system. That is what makes it evidence rather than a claim: the person
checking it does not have to trust the machine it came from.

## The CLI

```bash
evidence-chain --db evidence.db append captured '{"url": "https://example.com"}'
evidence-chain --db evidence.db verify
evidence-chain --db evidence.db verify --since-checkpoint
evidence-chain --db evidence.db log --since 500
evidence-chain --db evidence.db export chain.jsonl
evidence-chain check chain.jsonl
```

Exit 1 means the chain is broken. Exit 2 means the check could not run — a
missing file, a locked database, a payload that is not JSON. They are separate
because "could not check" must never be read as "the chain holds".

## What it does not do

It does not stop someone from deleting the whole file, and it does not prove
*when* an entry was written. A hash chain proves order and integrity, not time.
If you need time, put the head's `entry_hash` somewhere you do not control —
a timestamping authority, a public repository, an email to yourself — and keep
the receipt. `chain.head().entry_hash` is the one value that commits to
everything below it.

It does not encrypt anything. Payloads are stored as JSON, and anyone who can
read the file can read them.

## Where it comes from

Extracted from [brand-evidence], a tool that records trademark-infringement
evidence and has to be able to defend every row it holds years later. That one
writes the same log through SQLAlchemy; this one uses the standard library and
nothing else.

The two agree on the same file, in both directions — this library verifies and
exports a chain brand-evidence wrote, brand-evidence verifies an entry this
library appended, and the definition of "valid" lives in one function so the
database and an exported file cannot drift apart.

Where a foreign schema carries columns of its own, `Chain` says so instead of
guessing:

```
evidence-chain: evidence.db was created by another tool: chain_checkpoints
requires id, which this library does not fill. It can still be verified and
exported.
```

[brand-evidence]: https://github.com/kulykivska/brand-evidence

## License

MIT.
