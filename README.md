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

The tool is a fail-closed instrument scoped to exactly one complete epoch,
exactly two genuinely distinct RPC providers, and exactly one legacy SPL Token
mint, anchored to a verified Old Faithful CAR.

It used to ship a second, cheaper pass as well: a cross-provider diff with no
anchor and no direct confirmation. That pass could only ever produce candidates,
but it shared this one's vocabulary, and sharing a vocabulary across two
evidence standards is how a mere discrepancy came to be labelled a proven
`PROVIDER_HOLE`. Renaming fixed the symptom; removing the pass fixed the cause.
An unanchored run of this audit produces the same reconnaissance as indeterminate
matters, correctly labelled.

The canonical package is `src/slot_audit/` (see `pyproject.toml`). The
distribution is named `solana-slot-audit`; the importable module is `slot_audit`.

## Running an audit

```bash
PYTHONPATH=src python3 -m slot_audit audit \
  --config config.epoch-100.yaml \
  --results-dir results/epoch-100
```

It writes `results/epoch-100/evidence/` (raw bytes, sanitized request metadata,
derived artifacts, provenance and a manifest), plus `summary.md` and
`result.json` beside it.

### Re-performance is a command, not an adjective

Every call's exact bytes are retained, and `replay` is the path that consumes
them. It does not reimplement anything — reimplementing would only prove the
copy agrees with itself. It runs the same `run_epoch_audit`, with a transport
that serves recorded responses instead of a socket and an anchor rebuilt from
the retained derived records, then compares the recomputed conclusion against
the sealed one:

```bash
PYTHONPATH=src python3 -m slot_audit replay \
  --evidence-dir results/epoch-100/evidence \
  --output-dir results/epoch-100-replay
```

Four things are checked rather than promised: a call the original never made is
refused, a recorded call the replay never consumed is reported, the result and
every gate *status* must match, and so must every gate *metric* — comparing only
statuses would let a forged agreement figure through as long as it stayed on the
passing side of a threshold. Two metric families are exempt, listed with their
reasons in `replay.VOLATILE_GATE_METRICS`; the list was derived by diffing an
honest replay, not by guessing.

The negative controls are re-run rather than taken from the sealed verdicts, and
the two are compared: the sealed values say what the code did that day, a fresh
run says what today's code does, and both answers are worth having.

Not every retained record is a response. A call that could not be sent — a
dropped socket, a spent budget — leaves a synthetic record so the gap is
explicable. Replay recognises those and re-walks the identical retry path
instead of serving them as bodies. A 400,000-call run will contain several
transient faults, and an earlier version of replay reported every such honest
run as unreproducible — which, in this tool's vocabulary, reads as an accusation
of forgery.

This is also the practical answer to the unsigned manifest. A forger who edits a
response, its meta digest and the manifest passes `verify-evidence` — and then
has to make the forged bytes reproduce the sealed conclusion. Forging a finding
*in* fails immediately, because replay asks for the confirming `getBlock` the
original never made. Forging one *out* fails too, because the confirming calls
the original did make are left unconsumed. Both are tested.

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
| `ground_truth_constants_provenance` | The pinned constants trace to an authority — **currently fails for epoch 100** |
| `ground_truth_provenance_binding` | The archive is the pinned one, structurally and by digest |
| `ground_truth_full_epoch_coverage` | Every scheduled position of the epoch is accounted for |
| `per_provider_agreement` | Each provider separately meets the configured minimum |
| `indeterminate_threshold` | Indeterminate positions stay within the configured exact-decimal threshold |
| `exact_pinned_slot_support` | Both providers served the exact pinned context slot |
| `distinct_endpoints` | The two providers, and the anchor, are independent sources |
| `finding_evidence_completeness` | Every conclusive finding carries what a reviewer needs to re-perform it |
| `manifest_provenance_completeness` | Evidence is complete, unmodified and fully attributed |

Gates are declared in `assessment.GATE_REGISTRY`, which is the only source of
`MANDATORY_GATES`; a gate cannot be constructed outside it, nor against its
registered status. `tests/test_gate_coverage.py` then requires that **every
mandatory gate has a scenario that executes and observes it failing**, and
records whether that scenario drives the full orchestration or re-assesses a
crafted input. Adding a mandatory gate without a failure test breaks the build —
which is the specific gap that shipped once and had to be caught by review.

The same question is asked of the controls themselves. A control reporting
`detected=True` could be right for the wrong reason, so
`tests/test_negative_controls.py::ControlSensitivityTests` breaks
`classify_epoch`, `reconcile_mint` and `validate_hash_links` in turn — the way a
plausible regression would — and requires the matching control to go blind and
to name the sabotage in what it observed. A control that has quietly stopped
depending on the code it claims to exercise fails there.

`hash_link_continuity`, `token_supply_reconciliation` and `materiality_assessment`
are reported but are **not** mandatory: their failure is a *finding about the
providers*, not a malfunction of the instrument, and conflating the two would
make every real finding suppress its own result. `materiality_assessment` in
particular will fail on any run that reports something — that is it doing its
job, and it does not block the conclusion.

### The ground-truth trust chain

The anchor answers the one question two providers cannot answer between them:
when both omit a slot, was it skipped by the protocol or lost by both? An anchor
that an arbitrary file can satisfy answers nothing, so the binding is narrow.

1. **The pinned constants live in `src/slot_audit/groundtruth.py`**, not in
   configuration. `config.epoch-100.yaml` must restate every one of them — an
   unstated assumption is not auditable — but restating a *wrong* value fails the
   run rather than redefining the constant. **A digest a user typed can never
   bless a file.**

   > **The epoch-100 constants are not verified, and the run is blocked because
   > of it.** The values in this build (402,076 produced blocks, 29,924 skipped,
   > CAR SHA-256 `9f6d63…ec5a`, root CID `bafyrei…mbs3i`, source commit
   > `a69a0d2e…`) were supplied by the specification that commissioned the tool.
   > No citation to an Old Faithful release or index came with them, and nobody
   > here has held the archive, so the digest cannot have been measured. They are
   > recorded as `verified_against_archive: false`, the mandatory
   > `ground_truth_constants_provenance` gate fails, and **an epoch-100 run
   > concludes nothing today.**
   >
   > The fix is to reconcile the values against a published Old Faithful source
   > and set the provenance. Editing the constants to match a file you already
   > hold is *not* the fix — it inverts the check and turns the anchor into
   > whatever archive you started with.
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

### Agreement, reported once per provider

Each provider gets **one** agreement figure: how often its unaided
"present, so produced / missing, so skipped" inference matched the anchor, over
positions where both were determinate. Against a binary ground truth there is
only one such quantity — a provider is right about availability exactly when
that inference is right — so reporting an "availability agreement" beside it
would be one measurement printed twice. An earlier version of this tool did
exactly that; it was corrected.

Alongside it, **coverage completeness**: how much of the epoch the provider
successfully enumerated at all, over every scheduled position, independent of
the anchor. That is genuinely different — a provider can agree perfectly about
the tenth of the epoch it managed to answer for.

Separately again, the **combined two-provider existence inference agreement**,
a different quantity and labelled as one. Each figure carries numerator,
denominator, rate, indeterminate count and the declared denominator policy.

### Evidence

Every supporting RPC call retains the exact response bytes plus a sanitized
request record holding an endpoint *fingerprint* — never a URL. Two providers
differing only by API key produce different endpoint fingerprints but the same
host fingerprint, and a shared host is rejected: that is one upstream wearing two
names.

A conclusive `PROVIDER_HOLE` additionally requires the provider to **answer**
that it has no block: `-32007`/`-32009`, or a null result confirmed by a re-read.
A bare null is a *successful* response, so the transport never retries it, and
gateway layers have been observed returning one for an edge-cache miss on a slot
they do hold — one unreplicated null is not enough. The re-read is **in-band**:
same client, same endpoint, seconds later. It catches a transient miss; it cannot
catch an endpoint that *consistently* returns null for a slot it holds, and no
same-endpoint check could. Each finding's `inference` text says so. A direct
`getBlock` that failed for any other reason — an exhausted request budget, a
transport fault, a node that never became healthy, or `-32001` "below retention"
— is the audit failing to ask, not the provider failing to serve. Those record an
indeterminate matter instead. Not asking is not evidence of absence.

Every conclusive block finding carries non-null `slot`, `blockhash`,
`previousBlockhash`, `parentSlot`, `source` and `inference`, and references the
`getBlocks` batch that demonstrated the omission, the direct `getBlock`
response, the ground-truth header, and the peer and parent responses where used.
If a required ground-truth header cannot be retrieved or derived, the run records
an indeterminate matter and concludes nothing — it never emits a hole with null
hashes.

`summary.md` and `result.json` are themselves manifested artifacts. The copies
beside the evidence directory are byte-identical to the sealed ones, so editing
the readable conclusion is detectable — `verify-evidence` compares them and
distinguishes a modified copy (a failure) from a deleted one (recoverable from
the sealed original, but reported). Because sealing must happen before the
manifest closes, the sealed `result.json` necessarily carries a null `manifest`
and a null `provenance.run_completed_at`; it says so in its own `sealing_note`,
and the completed values live in `provenance.json` and `manifest.json`.

Manifest verification is closed-world (missing, modified **and** unexpected
unmanifested files), and a store refuses to open on a directory that already
holds a run, so evidence is never silently overwritten. The manifest is
**unsigned**: it rules out damage, partial loss and naive editing, but not an
editor who also recomputes the affected digest and rewrites the manifest. It is
an integrity check, not an authenticity one.

```bash
PYTHONPATH=src python3 -m slot_audit verify-evidence \
  --evidence-dir results/epoch-100/evidence
```

### Request policy

Each provider gets its own token bucket, bounded retry and hard request budget,
required in `limits:`. They are configuration because each one changes what the
run can observe: a throttled run manufactures false indeterminates, an unbounded
retry produces coverage nobody can characterise, and a budget cut-off leaves
gaps that are the audit's doing rather than the provider's — which the run
records explicitly and reports in `## Request cost and limits`.

**Calls are issued one at a time, and there is no concurrency setting.** The
audit is rate-limited rather than latency-bound, so concurrency would buy
little, and it would cost two things the instrument argues from: the evidence
store's write order is what shows the provider-only inference was frozen before
the anchor was read, and replay matches recorded responses to requests in order.
Deterministic sequencing is what makes that matching sound rather than lucky.

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
Unknown keys fail; missing keys fail. `materiality_threshold` is applied by the
`materiality_assessment` gate, which weighs the finding rate and the token
discrepancy against it.

Thresholds must be quoted (`"0.01"`). An unquoted YAML `0.01` is a binary float
and is rejected: comparisons use `Decimal` and exact `Fraction` arithmetic
end-to-end, and a configured threshold is never converted to `float`.

## Install

Python 3.11 or newer.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp .env.example .env
```

## Review history

`REVIEW-LOG.md` records four rounds of adversarial review: thirty-four claims
and design decisions examined, twenty-four changed, ten that held, eight limits
that remain — the log states how those numbers are counted so they can be
checked against its own headings. It is organised by finding, and every entry
cites the commit, test name or command that substantiates it; statements
traceable only to correspondence are marked pending rather than written as
fact. The error log records both sides.

## Fixtures are deliberately messy

Three defects reached review because every fixture answered perfectly on the
first attempt: the conclusive-`FINDINGS` path was unreachable, the constants gate
had no failure test, and replay could not survive one transient blip. The
fixtures were not wrong, they were *tidy*, and a tidy fixture only exercises the
path its author already had in mind.

`tests/epoch_support.realistic_noise()` injects seeded, retryable faults, and the
end-to-end test classes each carry a noisy variant. A run under noise must reach
the same conclusion, with the same counts, as the clean one.

## Tests

Deterministic and fully offline — no network access is required, and the shipped
negative controls run against generated fixtures whose archive bytes, digest and
root CID are identical on every machine.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## What this does not prove

**LIVE FULL-EPOCH RUN: NOT EXECUTED.** No epoch-100 measurement has been
performed. The code, the gates and the deterministic integration tests are
complete; the inputs are not. To run it for real you need:

0. **provenance for the pinned constants** — a citation to a published Old
   Faithful source establishing the epoch-100 digest, root CID and block counts.
   Without it the mandatory `ground_truth_constants_provenance` gate fails and
   nothing else matters;
1. the Old Faithful epoch-100 CAR reported to be 62.9 GB, at
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

Residual assumptions worth knowing before citing any future finding:

- The null confirmation re-read is in-band. An endpoint that consistently
  returns null for a slot it holds would still produce a conclusive finding.
- The evidence manifest is unsigned. It detects damage and naive edits, not a
  forger with write access who also rewrites the manifest.

Beyond that: measuring block presence does not establish that anyone was harmed
by a missing block. This audit does not prove transaction-level completeness,
fork or reorg semantics, market-wide provider quality, or anything about
endpoints other than the two configured ones.
