# solana-slot-audit

`solana-slot-audit` measures whether a Solana RPC provider is missing finalized
blocks, and says so in a form somebody else can re-perform. Solana returns the
same `-32007` for a protocol-skipped slot and for data discarded during a ledger
jump, so an error message is never evidence of provider loss.

> ### Status: the instrument is complete; no real measurement has been made
>
> **`LIVE FULL-EPOCH RUN: NOT EXECUTED`.** No epoch-100 audit has been performed
> against mainnet or against the real Old Faithful archive. Every number in this
> repository's example output comes from a 32-slot deterministic fixture whose
> purpose is to test the instrument, not to measure any provider.
>
> The code, the validation gates and the offline tests are finished and green.
> The inputs are not available here: the 62.9 GB archive, credentials for two
> genuinely distinct archive-capable providers, and a provider able to serve
> account state at an exact historical slot. See
> [What this does not prove](#what-this-does-not-prove) for the full list and for
> the one assumption that still needs checking against the real archive.
>
> Do not cite this repository as evidence about any provider.

The repository contains two things:

* **Pass A** (`enumerate`) — a cheap, resumable cross-provider diff. Useful for
  reconnaissance; it cannot tell a protocol skip from a hole unless another
  provider happens to have the block.
* **The single-epoch audit** (`audit`) — a fail-closed instrument scoped to
  exactly one complete epoch, exactly two genuinely distinct RPC providers, and
  exactly one legacy SPL Token mint, anchored to a verified Old Faithful CAR.

The canonical package is `src/slot_audit/` (see `pyproject.toml`). The
distribution is named `solana-slot-audit`; the importable module is `slot_audit`.

## The single-epoch audit

```bash
PYTHONPATH=src python3 -m slot_audit audit \
  --config config.epoch-100.yaml \
  --results-dir results/epoch-100
```

It writes `results/epoch-100/evidence/` (raw bytes, sanitized request metadata,
derived artifacts, provenance and a manifest), plus `summary.md` and
`result.json` beside it.

### A zero-finding result is only meaningful if the instrument passed

The run produces exactly one authoritative
`InstrumentAssessment`. `RunConclusion` is derived from it and `summary.md`
renders it; neither recomputes a gate. Any failed mandatory gate forces
`NO_CONCLUSION` **even when there are zero findings**:

| Gate | What it asserts |
| --- | --- |
| `negative_control_provider_hole` | Removing a block known to exist yields `PROVIDER_HOLE`, never `PROTOCOL_SKIPPED` |
| `negative_control_token_truncation` | A dropped account under-reports supply by exactly its balance |
| `negative_control_previous_blockhash` | A corrupted `previousBlockhash` surfaces as `PREVIOUS_BLOCKHASH_MISMATCH` |
| `ground_truth_provenance_binding` | The archive is the pinned one, structurally and by digest |
| `ground_truth_full_epoch_coverage` | Every scheduled position of the epoch is accounted for |
| `per_provider_agreement` | Each provider separately meets the configured minimum |
| `indeterminate_threshold` | Indeterminate positions stay within the configured exact-decimal threshold |
| `exact_pinned_slot_support` | Both providers served the exact pinned context slot |
| `distinct_endpoints` | The two providers, and the anchor, are independent sources |
| `finding_evidence_completeness` | Every conclusive finding carries what a reviewer needs to re-perform it |
| `manifest_provenance_completeness` | Evidence is complete, unmodified and fully attributed |

`hash_link_continuity` and `token_supply_reconciliation` are reported but are
**not** mandatory: their failure is a *finding about the providers*, not a
malfunction of the instrument, and conflating the two would make every real
finding suppress its own result.

### The ground-truth trust chain

The anchor answers the one question two providers cannot answer between them:
when both omit a slot, was it skipped by the protocol or lost by both? An anchor
that an arbitrary file can satisfy answers nothing, so the binding is narrow.

1. **The pinned constants live in `src/slot_audit/groundtruth.py`**, not in
   configuration. For epoch 100: first slot 43,200,000; last slot 43,631,999;
   432,000 scheduled positions; 402,076 produced blocks; 29,924 skipped slots;
   predecessor boundary row 43,199,999; CAR root CID
   `bafyreibqt2nvroysxlxctgb52xxn27ectsllv2xyka4qar7ga6vupmbs3i`; CAR SHA-256
   `9f6d631833a8dfe0a4253ceede8e4af18a63603f0131a71ca5e947ba77eaec5a`; Old
   Faithful source commit `a69a0d2e189006608e3b73b7659a957b00b3567e`.
   `config.epoch-100.yaml` must restate every one of them — an unstated
   assumption is not auditable — but restating a *wrong* value fails the run
   rather than redefining the constant. **A digest a user typed can never bless
   a file.**
2. **The archive must be the archive.** It must hash to the pinned digest, parse
   as CAR v1, declare exactly the pinned root CID, contain that root block, and
   every block must be addressed by its own CID. A single flipped byte anywhere
   is fatal (`car_block_integrity`).
3. **Records come from a pinned extractor.** `CarBlockHeaderExtractor` reads
   block-header nodes directly from the verified archive. Its name, version,
   pinned commit, command and node schema are retained, and the derived record
   file is written into evidence with its own SHA-256 and byte length, so the
   derivation is re-performable without the 62.9 GB archive.

   Both the digest pass and the parse pass **stream**. The archive is never
   loaded into memory, so anchoring a 62.9 GB CAR needs disk, not RAM.

   The extractor reads a *declared* node shape. Whether the published archive
   actually uses it is a question about the file, and `probe-car` answers it
   factually against a prefix, in one command, before you commit to a full run:

   ```bash
   PYTHONPATH=src python3 -m slot_audit probe-car \
     --car "$OLD_FAITHFUL_EPOCH_100_CAR" --max-blocks 5000
   ```

   It reports the codecs, node `kind` values and map key signatures actually
   present, and says plainly whether the shape this build derives from is among
   them. It asserts nothing about what *should* be there.
4. **Coverage is asserted, not assumed.** The predecessor boundary row 43,199,999
   is filtered *explicitly* and counted (it is retained separately so the epoch's
   first block can still be hash-link validated against its real parent). The
   number of in-range produced blocks must equal 402,076 exactly, and the implied
   skip count must equal 29,924 exactly.

Nothing in that chain can be satisfied by an RPC endpoint returning a version
string, by a text file containing the expected substrings, or by a slot list
that happens to match. Derivation never contacts a network at all.

### Freeze before you compare

The providers' own answer is written to
`evidence/artifacts/provider-only-inference.json` **before** the anchor is read.
The manifest records `write_order`, so a reviewer can confirm the inference was
frozen before the result it is compared against existed. The encoding is
run-length but lossless.

### Agreement is reported four ways, never merged

Per provider: **classification agreement** (how often that endpoint's unaided
"present, so produced / missing, so skipped" inference matched the anchor, over
the audit population) and **availability agreement** (how often it matched over
its own successful coverage). Separately, the **combined two-provider existence
inference agreement**, which is a different quantity and is labelled as one.
Each is reported with numerator, denominator, rate, indeterminate count and the
declared denominator policy.

### Evidence

Every supporting RPC call retains the exact response bytes plus a sanitized
request record holding an endpoint *fingerprint* — never a URL. Two providers
differing only by API key produce different endpoint fingerprints but the same
host fingerprint, and a shared host is rejected: that is one upstream wearing two
names.

A conclusive `PROVIDER_HOLE` additionally requires the provider to **answer**
that it has no block: a null result, or `-32007`/`-32009`. A direct `getBlock`
that failed for any other reason — an exhausted request budget, a transport
fault, a node that never became healthy, or `-32001` "below retention" — is the
audit failing to ask, not the provider failing to serve. Those record an
indeterminate matter instead. Not asking is not evidence of absence.

Every conclusive block finding carries non-null `slot`, `blockhash`,
`previousBlockhash`, `parentSlot`, `source` and `inference`, and references the
`getBlocks` batch that demonstrated the omission, the direct `getBlock`
response, the ground-truth header, and the peer and parent responses where used.
If a required ground-truth header cannot be retrieved or derived, the run records
an indeterminate matter and concludes nothing — it never emits a hole with null
hashes.

Manifest verification is closed-world (missing, modified **and** unexpected
unmanifested files), and a store refuses to open on a directory that already
holds a run, so evidence is never silently overwritten:

```bash
PYTHONPATH=src python3 -m slot_audit verify-evidence \
  --evidence-dir results/epoch-100/evidence
```

### Request policy

Each provider gets its own token bucket, concurrency semaphore, bounded retry
and hard request budget, all required in `limits:`. They are configuration
because each one changes what the run can observe: a throttled run manufactures
false indeterminates, an unbounded retry produces coverage nobody can
characterise, and a budget cut-off leaves gaps that are the audit's doing rather
than the provider's — which the run records explicitly and reports in
`## Request cost and limits`.

Retries are retained individually. A call that succeeded on its fourth attempt
is a different observation from one that succeeded immediately, and the evidence
store keeps both attempts so it cannot be presented as the latter.

### No silent defaults

Every scoping and judgment value is required in configuration and echoed into
`result.json` and `summary.md`: population definition, epoch and inclusive slot
bounds, commitment, pinned slot, exact-context policy, indeterminate threshold
and denominator policy, materiality threshold, minimum provider agreement, token
program id, account size, mint/amount/state/supply offsets, included account
states, zero-balance policy, duplicate-pubkey policy, hash-link validation
population, request limits, and the ground-truth source and expected hashes.
Unknown keys fail; missing keys fail.

Thresholds must be quoted (`"0.01"`). An unquoted YAML `0.01` is a binary float
and is rejected: comparisons use `Decimal` and exact `Fraction` arithmetic
end-to-end, and a configured threshold is never converted to `float`.

## Install

Python 3.11 or newer.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp config.example.yaml config.yaml          # Pass A
cp .env.example .env
```

## Tests

Deterministic and fully offline — no network access is required, and the shipped
negative controls run against generated fixtures whose archive bytes, digest and
root CID are identical on every machine.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Pass A

```bash
PYTHONPATH=src python3 -m slot_audit enumerate --config config.yaml --results-dir results
```

Writes `raw.jsonl` / `raw-cross-provider-diff.jsonl` (one conclusive omission per
`(provider, slot)`), `enumeration-summary.json`, a resumable checkpoint, and
`run.log`. Retention is checked before and after enumeration; slots below the
later `getFirstAvailableBlock` boundary are excluded, never called holes. Result
files contain provider names, not credential-bearing URLs.

## What this does not prove

**LIVE FULL-EPOCH RUN: NOT EXECUTED.** No epoch-100 measurement has been
performed. The code, the gates and the deterministic integration tests are
complete; the inputs are not. To run it for real you need:

1. the Old Faithful epoch-100 CAR (62.9 GB) whose SHA-256 is
   `9f6d631833a8dfe0a4253ceede8e4af18a63603f0131a71ca5e947ba77eaec5a`, at
   `$OLD_FAITHFUL_EPOCH_100_CAR`;
2. credentials for two genuinely distinct archive-capable providers whose
   retention covers slots 43,200,000–43,631,999, in `$PROVIDER_A_URL` and
   `$PROVIDER_B_URL` — different hosts, not two keys on one host;
3. a provider that can serve `getProgramAccounts` at an **exact** context slot.
   Standard mainnet RPC answers against its current bank, so
   `exact_context_policy: require_exact_pinned_slot` will fail against ordinary
   endpoints and the run will correctly conclude nothing. This is deliberate: an
   account-state figure measured at an unknown slot is not a measurement;
4. permission to spend the request budget: with
   `hash_link_validation_population: all_produced_blocks`, the run issues
   402,076 `getBlock` calls **per provider**.

Additionally, `CarBlockHeaderExtractor` reads a declared block-header node shape
(`slot-audit/oldfaithful-block-header-v1`). That shape has **not** been validated
against the published epoch-100 CAR in this environment, and the run records
`validated_against_published_car: false` in its own trust chain. Run `probe-car`
against the real archive first: it will say factually whether the shape is
present. If it is not, this build cannot anchor that archive, the produced-block
count gate fails, and the run correctly concludes nothing.

Beyond that: measuring block presence does not establish that anyone was harmed
by a missing block. This audit does not prove transaction-level completeness,
fork or reorg semantics, market-wide provider quality, or anything about
endpoints other than the two configured ones.
