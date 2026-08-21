# Review log

This tool exists to keep claims inside the evidence that supports them. This
document applies the same rule to the tool's own development.

Four rounds of adversarial review ran against this repository between
2026-08-20 and 2026-08-21. Thirty-four claims and design decisions were
examined. Twenty-four did not survive and were changed; ten were attacked and
held; eight limits remain, stated rather than removed.

**How those numbers are counted**, so a reader can check them against the
headings rather than take them on trust. The twenty-four are the labels in
[section 1](#1-claims-that-did-not-hold): `F1`–`F10` from the first round,
`R1`–`R5` from the second, `H1`–`H3` from the third round's re-verification,
and `A1`–`A6`. The A entries are architectural findings rather than falsified
claims — nothing the code said was untrue, but each named a design that cost
the instrument something and each was changed, so they are counted and kept
alongside the rest. `R2`–`R5` share one heading, which is why section 1 carries
21 headings for 24 labels, and `F10` is one label covering four smaller
defects, listed individually in its table. The ten that held are the ten rows
of the table in [section 2](#2-claims-that-were-attacked-and-held). The eight
limits are `L1`–`L8` in [section 3](#3-limits-that-remain).

## How to read an entry

Entries are organised by **finding**, not by round, because the question a
reader has is "does this claim hold *now*", not "what happened on Thursday". A
thin chronology is in [Appendix A](#appendix-a--chronology) for the patterns
that are only visible on a timeline.

Every entry carries:

| Field | Meaning |
| --- | --- |
| **Claim** | What the code or documentation asserted, quoted from the artifact that asserted it |
| **Attacked** | `executed` (a test or command was run) or `read` (source inspection), with the artifact |
| **Failure** | The concrete scenario: specific inputs or state, and the specific wrong output |
| **Fixed** | The commit |
| **Residual** | What is still true afterwards that a reader must know |
| **Verdict** | `Held` · `Fixed` · `Accepted limit` · `Not fixed` |

### Sourcing rule

**Every statement here must be reconstructible from this repository** — a
commit, a test name, or a command anyone can re-run. Statements that trace only
to review correspondence are marked **⚠ PENDING** and are not written as
established fact. That mark is not a doubt about the reviewer; it is the same
standard the code is held to, applied to its own history.

Five marks remain. The list names them rather than counting them, so a reader
checks it by reading the entries, not by trusting a number:

- `F3` and `H1` — a demonstration the review ran by hand whose script is not in
  this repository. In both cases the repository carries a stronger equivalent,
  named in the entry itself.
- `E5` — a statement about the correspondence, which cannot be anything else.
- One specimen listed in [`P3`](#p3--output-that-looks-right-is-not-evidence-the-thing-happened)
  — a drafting error caught before it was committed, so no artifact of it
  exists.
- The attribution on the [preflight acceptance criteria](#acceptance-criteria-for-the-live-preflight)
  — the criteria themselves are now an artifact; who proposed them is not.

Two earlier marks are closed rather than explained. The construction behind
`F7` is reproducible in
[Appendix B](#appendix-b--reproducing-the-checks-cited-here), and the control
kill-tests behind [section 2](#2-claims-that-were-attacked-and-held) are now
`tests/test_negative_controls.py::ControlSensitivityTests`.

Commands used below assume `PYTHONPATH=src` and the project's virtualenv.

---

## 1. Claims that did not hold

### F1 — The reconnaissance pass reported unconfirmed omissions as proven holes

**Claim.** The class was documented as "Conclusive Pass-A evidence that one
provider omitted a real block", carried `verdict = Verdict.PROVIDER_HOLE`, and
emitted reasoning ending "proving that the block existed and that this omission
is a provider data hole".

*Sources.* `git show 9af7707:src/slot_audit/enumerate.py` — the docstring at
line 306, the verdict default at line 312, the reasoning at lines 519-523. The
reasoning is split across two source lines, so the full phrase is greppable only
in the assertion that pinned it:
`git show 9af7707:tests/test_enumerate.py | sed -n '141p'`.

**Attacked.** `read` — the emitting path issued no direct `getBlock` and
obtained no denial from the provider.

**Failure.** From `c768982`: "on the strength of cross-provider presence alone
— no direct getBlock, no explicit denial, no anchor. Silent gateway truncation
produces an identical signature, so a truncating proxy would have yielded
thousands of rows reading as proven data loss." This was the only output the
tool could then produce against a real provider.

**Fixed.** `c768982` renamed the verdict to `UNCONFIRMED_OMISSION`, put
`confirmed: false`, `conclusive: false` and `direct_getblock_issued: false` at
the top level of every row, and added an `unexcluded_explanations` list naming
truncation first. `b5f64da` removed the `CrossProviderHole` alias. `0439147`
removed the pass entirely.

**Residual.** None in this repository — the subsystem is gone. `Verdict` now
has no member reachable without an anchor
(`src/slot_audit/verdict.py` module docstring).

**Verdict.** `Fixed`

### F2 — The anchor's pinned constants were presented as published figures

**Claim.** The epoch-100 constants (402,076 produced blocks, CAR SHA-256
`9f6d63…ec5a`, root CID `bafyrei…mbs3i`, source commit `a69a0d2e…`) were
described in the module's trust-chain docstring as "the published epoch
constants", against which coverage "must equal the published figure exactly",
and the test that restated them was named
`test_pinned_constants_match_the_published_epoch_100_figures`.
*Sources: `git show 9af7707:src/slot_audit/groundtruth.py` lines 20 and 22;
`git show 9af7707:tests/test_groundtruth.py`.*

**Attacked.** `read` — no citation to any Old Faithful release, index or
announcement appears anywhere in the repository, and the test restated the same
literals, which is tautology rather than verification.

**Failure.** From `c768982`: "The epoch-100 constants came from the
commissioning specification with no citation, and nobody here has held the
archive, so the pinned SHA-256 cannot have been measured." The consequence is
worse than a documentation slip: an operator whose real archive disagrees has
no move except to edit the constant, at which point the anchor becomes whatever
file they already had.

**Fixed.** `c768982` added `ConstantProvenance`, marked epoch 100
`verified_against_archive=False`, and added the mandatory gate
`ground_truth_constants_provenance`. The test was renamed
`test_pinned_constants_are_unchanged` with a docstring stating it is a change
detector, not verification. `b5f64da` added the gate's FAIL-path tests.

Verify: `tests/test_groundtruth.py::PublishedEpoch100Tests::test_the_constants_declare_that_nobody_verified_them`
and `tests/test_epoch_audit.py::ConstantProvenanceGateTests` (six tests).

**Residual.** **An epoch-100 run concludes nothing today.** The gate fails, and
that is intended. See [Accepted limit L2](#l2--the-epoch-100-constants-are-unverified).

**Verdict.** `Fixed` (the defect was presenting them as established; the
underlying unverifiability is L2)

### F3 — Two "independent" agreement metrics were one measurement twice

**Claim.** The report presented per-provider "classification agreement" and
"availability agreement" as separate figures, with a source comment asserting
"Keeping the denominators distinct is the point."
*Source: `git show 9af7707:src/slot_audit/audit.py`.*

**Attacked.** `executed` — the review reported running clean, dropped-block,
failed-range, no-anchor and `all_scheduled_positions` scenarios and observing
identical numerator/denominator pairs in every one. ⚠ PENDING — that run is not
in this repository. What *is* reconstructible: the two predicates are provably
equal over the nine-cell input domain, tabulated in
`tests/test_classification.py::ClassificationTableTests`.

**Failure.** From `c768982`: "Against a binary ground truth, availability
agreement and classification agreement are provably the same quantity, and a
reader could have cited both as corroboration."

**Fixed.** `c768982` reports agreement once, beside **coverage completeness**
(positions successfully enumerated over all scheduled positions), which does not
depend on the anchor. `cbb81ab` extracted `classify_position` so the definition
has an identity a test can address.

Verify: `tests/test_epoch_audit.py::AgreementReportingTests::test_agreement_is_reported_once_not_as_two_lookalike_metrics`,
`::test_coverage_and_agreement_diverge_when_a_provider_cannot_answer`, and
`tests/test_classification.py::ClassificationTableTests::test_agreement_and_coverage_are_not_the_same_column`.

**Residual.** Agreement against a binary ground truth remains a single quantity.
Any future second agreement figure must show, in a table test, that it differs.

**Verdict.** `Fixed`

### F4 — One unretried null result founded a conclusive denial

**Claim.** `confirms_absence` accepted a `null` `getBlock` result as the
provider denying the block exists.
*Source: `src/slot_audit/audit.py`, `confirms_absence`.*

**Attacked.** `read` — a null is a *successful* response, so the transport's
retry policy never applies to it.

**Failure.** From `c768982`: "gateways return one for an edge-cache miss on a
slot they hold." A provider returning null for fifty slots it holds would, with
agreement still above threshold, have produced fifty conclusive findings that
vanish on re-query.

**Fixed.** `c768982` requires a confirming re-read; disagreement records an
indeterminate matter.

Verify: `tests/test_epoch_audit.py::AbsenceConfirmationTests::test_a_single_unreplicated_null_is_not_enough`
and `::test_a_null_block_answer_confirms_absence_only_after_a_second_read`.

**Residual.** The re-read is **in-band** — same client, same endpoint, seconds
later. See [L5](#l5--the-null-confirmation-re-read-is-in-band).

**Verdict.** `Fixed`

### F5 — The documents a human reads were outside the closed world

**Claim.** "Manifest verification is closed-world (missing, modified **and**
unexpected unmanifested files)".
*Source: `git show 9af7707:README.md`.*

**Attacked.** `executed` — rewriting `summary.md` beside the evidence directory
and re-running `verify-evidence` returned `ok`.

**Failure.** From `c768982`: "Rewriting the conclusion beside the evidence used
to pass verification." The closed world covered the raw material but not the
conclusion drawn from it.

**Fixed.** `c768982` seals `summary.md` and `result.json` as manifested
artifacts before the manifest closes; the readable copies are byte-copies of the
sealed ones. `b5f64da` made a deleted copy report differently from a modified
one.

Verify: `tests/test_epoch_cli.py::ReportSealingTests` (four tests).

**Residual.** Sealing must precede the manifest closing, so the sealed
`result.json` necessarily carries a null `manifest` and null
`provenance.run_completed_at`. It says so in its own `sealing_note`
(`b5f64da`), verified by
`tests/test_epoch_cli.py::ReportSealingTests::test_the_sealed_result_explains_its_own_null_provenance`.

**Verdict.** `Fixed`

### F6 — A required judgment value was never consumed

**Claim.** `materiality_threshold` was required in configuration, validated,
and printed in the summary.

**Attacked.** `read` — no gate, comparison or branch referenced it.

**Failure.** From `c768982`: "materiality_threshold was required, validated,
printed and never consumed." It was rendered in the summary's threshold block
between `indeterminate_threshold` and `minimum_provider_agreement`, both of
which did drive gates, so its presence in that list implied a judgment that no
code made. A required-but-ignored value is the mirror image of a silent
default.

*Sources.* `git show 9af7707:src/slot_audit/report.py | sed -n '84,87p'` for the
print; at that commit the name appeared in no module that could consume it
(Appendix B carries the traversal).

**Fixed.** `c768982` added the `materiality_assessment` gate over the finding
rate and the token discrepancy.

**Residual.** The gate is advisory. It fails on any run that reports something,
which is it working, and it does not block the conclusion
(`README.md`, gate table).

**Verdict.** `Fixed`

### F7 — A mandatory gate could be constructed as advisory

**Claim.** `InstrumentAssessment.__post_init__` enforced that all mandatory
gates were present.

**Attacked.** `executed` — an assessment whose `per_provider_agreement` gate is
`FAIL` but `mandatory=False` constructs without complaint at `9af7707` and
reports `status: PASS result: FINDINGS`. The review found this by hand; the
reproduction in [Appendix B](#appendix-b--reproducing-the-checks-cited-here)
builds that assessment in a worktree at `9af7707`, and the same script run
against `HEAD` raises instead.

**Failure.** Presence was checked; the flag was not. A refactor could have
demoted a gate and left the suite green.

**Fixed.** `c768982` rejects a mandatory gate constructed as advisory.
`cbb81ab` moved gate identity into `GATE_REGISTRY` and made `build_gate` refuse
both an unregistered id and a status contradicting the registry.

Verify: `tests/test_epoch_audit.py::SingleAssessmentTests::test_a_mandatory_gate_cannot_be_relabelled_advisory`
and `tests/test_gate_coverage.py::GateCoverageMetaTests::test_a_gate_cannot_be_built_against_its_registered_status`.

**Verdict.** `Fixed`

### F8 — The manifest's guarantee was stated absolutely

**Claim.** "detect missing, modified and unexpected" — without qualification.
*Source: `git show 9af7707:src/slot_audit/evidence.py`.*

**Attacked.** `executed` — editing a retained file and recomputing its manifest
entry passes verification.

**Failure.** An unsigned manifest cannot distinguish the run's own record from a
consistent rewrite of it.

**Fixed.** `c768982` states the limit precisely in the module docstring and in
`ManifestVerification.describe()`, and **added a test asserting the limit
exists** rather than only documenting it:
`tests/test_evidence.py::ClosedWorldManifestTests::test_a_recomputed_manifest_is_not_detected_and_this_is_documented`.

`cbb81ab` addressed it in practice: a forger must also make the forged bytes
reproduce the sealed conclusion under `replay`. See
[A1](#a1--replay-re-performance-as-a-command).

**Residual.** Still unsigned. See [L4](#l4--the-evidence-manifest-is-unsigned).

**Verdict.** `Accepted limit`, with the overclaim `Fixed`

### F9 — One code path decided trustworthiness with a float

**Claim.** "thresholds are exact Decimal/Fraction comparisons, never float"
(`9af7707` commit message).

**Attacked.** `read` — the reconnaissance path used a float literal
`INDETERMINATE_TRUST_THRESHOLD = 0.01` and float division.

**Failure.** The claim was true of the audit path and false of the shipped
package.

**Fixed.** `c768982` made both exact. `0439147` removed the path entirely.

**Residual.** None. `tests/test_epoch_audit.py::SingleAssessmentTests::test_the_report_module_evaluates_no_thresholds`
enforces that the renderer contains no threshold symbols at all.

**Verdict.** `Fixed`

### F10 — Four smaller defects

All `read`, all fixed in `c768982`.

| Defect | Failure | Verify |
| --- | --- | --- |
| A batch failing validation mid-response left already-read slots in the frozen inference artifact | The frozen artifact disagreed with its own coverage ranges | `src/slot_audit/audit.py`, `collect_provider` scratch set |
| CAR header length unbounded; deep CBOR nesting escaped as `RecursionError` | A hostile archive could crash the probe outside the error taxonomy | `tests/test_car.py::HostileInputTests` |
| A hash-link population with zero links reported "all validated links matched" | True and misleading | `tests/test_epoch_audit.py::VacuousChainTests` |
| Dead `epoch_override` parameter | — | removed |

**Verdict.** `Fixed`

### R1 — The gate that blocks every epoch-100 run had no failure test

**Claim.** `ground_truth_constants_provenance` blocks a run whose constants are
unverified (added in `c768982`).

**Attacked.** `executed` — a suite-wide search found the gate id only in a name
list and a docstring. No test observed it failing.

**Failure.** From `b5f64da`: "a typo in its `passed=` expression or a flipped
default on ConstantProvenance would have silently unblocked a run whose anchor
traces to nothing, with the suite still green."

**Fixed.** `b5f64da` added `ConstantProvenanceGateTests` (six tests), including
a complete, defensible `PROVIDER_HOLE` on a clean archive that still cannot be
reported. `cbb81ab` generalised the guard: every mandatory gate must now have a
scenario that executes and observes it failing —
`tests/test_gate_coverage.py`.

**Residual.** Two of the twelve scenarios are assessment-level rather than
orchestration-level, and each declares which
(`tests/test_gate_coverage.py`, `GateFailScenario.level`).

**Verdict.** `Fixed`

### R2–R5 — Residual findings from the second round

All fixed in `b5f64da`.

| # | Claim | Failure | Verify |
| --- | --- | --- | --- |
| R2 | `verify_reports` checks the readable copies | A *deleted* copy was silent; deletion and tampering are different events | `tests/test_epoch_cli.py::ReportSealingTests::test_a_deleted_copy_is_reported_distinctly_and_does_not_fail` |
| R3 | The sealed `result.json` is the record | Its null `manifest` and null `run_completed_at` read to a parser as an unfinished run | `::test_the_sealed_result_explains_its_own_null_provenance` |
| R4 | "a second **independent** read" | Same client, same endpoint, seconds apart — not independent | `tests/test_epoch_audit.py::AbsenceConfirmationTests::test_a_null_block_answer_confirms_absence_only_after_a_second_read` asserts the finding text states the limit |
| R5 | `CrossProviderHole` alias retained for compatibility | Kept the over-claiming name importable | alias removed |

**Verdict.** `Fixed`

### H1 — Replay reported every honest run containing a transient fault as unreproducible

The most serious defect found after the tool's core was considered sound.

**Claim.** `replay` distinguishes a faithful record from a forged one
(`cbb81ab`).

**Attacked.** `executed` — an otherwise clean 512-position run with one
simulated connection reset, retried and successful, concluding `FINDINGS/PASS`.

**Failure.** Quoted from `0963ebd`: "one simulated connection reset in an
otherwise clean 512-position run turned FINDINGS/PASS into NO_CONCLUSION/FAIL,
with unconsumed calls and finding differences — the same output shape, and the
same wording, as a detected forgery."

Mechanism, from the same commit: "A failed send leaves a synthetic record with
http_status 0 so the gap is explicable; ReplayTransport served that record as if
it were a response, the replaying client read HTTP 0 as a hard error, and the
classification cascaded."

Why it mattered: "A real 400,000-call epoch will contain several such faults, so
as shipped, every honest production run would have failed its own replay. In
this tool's vocabulary 'NOT reproduced' reads as an accusation of forgery, which
makes this the family of error the whole project exists to avoid: a confident
wrong answer, aimed at an honest operator."

**Fixed.** `0963ebd`. `ReplayTransport` recognises synthetic records: a
transport-error record is re-raised so the client walks the identical retry
path; a budget-exhausted record is excluded from the queue and from unconsumed
accounting. Replay also stops sleeping through the original's backoff.

Verify: `tests/test_replay.py::MessyButHonestRunTests` — four tests covering a
transient failure, seeded noise, an exhausted budget, and the recognition of a
synthetic record itself.

**Residual.** None known. The reviewer reported re-running their original attack
script against the fix and observing reproduction. ⚠ PENDING — that script is
not in this repository; the equivalent is
`::test_a_run_containing_a_transient_failure_reproduces`.

**Verdict.** `Fixed`

### H2 — Replay compared gate status but not gate metrics

**Claim.** Replay compares "result, every gate status and every finding field"
(`cbb81ab`).

**Attacked.** `read` — a forged agreement figure that stayed on the passing side
of its threshold would not change any status.

**Fixed.** `0963ebd`. Metrics are compared, with a two-family exemption list in
`replay.VOLATILE_GATE_METRICS` **derived by diffing an honest replay rather than
guessed** — the first run of the new comparison found a third volatile family
(control `evidence_refs`, which carry meta digests containing timestamps), which
was added with its reason.

Verify: `tests/test_replay.py::ForgeryTests::test_forging_an_agreement_metric_is_caught`.

**Residual.** Three metric families are exempt from comparison, each with a
stated reason in `VOLATILE_GATE_METRICS`.

**Verdict.** `Fixed`

### H3 — Replay took the sealed negative-control verdicts on trust

**Claim.** Replay re-performs the run.

**Attacked.** `read` — controls were read from `negative-control-*.json` rather
than re-run, so replay inherited the day's verdict without checking today's code.

**Fixed.** `0963ebd`. Controls are re-run and compared against the sealed
verdicts, which answers both questions instead of choosing one. They are offline
and deterministic, so this costs nothing.

**Verdict.** `Fixed`

### A1 — Replay: re-performance as a command

**Claim.** "re-performable" (`README.md`, `9af7707`).

**Attacked.** `read` — the raw bytes of every call were retained and *nothing
consumed them*. Checking a conclusion meant 400,000 fresh RPC calls.

**Fixed.** `cbb81ab` added `slot_audit replay`. It does not reimplement
collection, classification or assessment — from the commit: "that would only
prove the copy agrees with itself" — but drives the same `run_epoch_audit`
through a transport serving recorded responses.

Verify: `tests/test_replay.py::ReproductionTests` (five tests) and
`::ForgeryTests` (six tests). The two forgery directions:

* forging a finding **in** fails because replay asks for the confirming
  `getBlock` the original never made
  (`::test_forging_a_finding_in_demands_evidence_that_does_not_exist`);
* forging one **out** fails because the confirming calls the original did make
  go unconsumed
  (`::test_forging_a_finding_out_fails_to_reproduce_the_conclusion`).

**Residual.** Replay does not re-read the archive. See [L6](#l6--replay-does-not-re-read-the-archive).

**Verdict.** `Fixed`

### A2 — Gates had no addressable identity

**Claim.** Gate names lived in `assessment.py`; their fourteen evaluations lived
inside a 450-line builder in `audit.py`, tied together only by a runtime check.

**Attacked.** `read`. From `cbb81ab`: "the missing FAIL-path test was not an
oversight but a structural certainty — nobody could ask which gates lacked one."

**Fixed.** `cbb81ab`. `GATE_REGISTRY` is the single source of
`MANDATORY_GATES`; `build_gate` refuses an unregistered id or a contradicting
status; the suite requires every mandatory gate to have an executing failure
scenario.

Verify: `tests/test_gate_coverage.py` (eight tests). The meta-test bites: adding
an unregistered mandatory gate fails
`::test_every_mandatory_gate_has_a_failure_scenario`.

**Verdict.** `Fixed`

### A3 — Solana error-code semantics were scattered across three modules

**Claim.** Which code is a denial, which is transient, which is a storage limit
— the most safety-critical domain knowledge in the tool.

**Attacked.** `read` — `confirms_absence` in `audit.py`, `RETRYABLE_RPC_CODES`
in `rpc.py`, and `-32001` message parsing in a third place, with no statement of
the reasoning.

**Fixed.** `cbb81ab` created `src/slot_audit/solana_codes.py`: sixteen codes,
mutually exclusive semantics enforced in `__post_init__`, exhaustive test.
`c764757` completed the wiring — see [E3](#e3--an-inaccurate-self-report-about-the-code-table).

Verify: `tests/test_classification.py::CodeSemanticsTableTests` (six tests).

**Residual.** The table is transcribed from Solana's `RpcCustomError`, not
verified against a live node. See [L7](#l7--the-error-code-table-is-transcribed-not-verified).

**Verdict.** `Fixed`

### A4 — The definition of agreement was buried in a counting loop

**Claim.** See F3.

**Attacked.** `read`. From `cbb81ab`: "F3 survived two review rounds because the
definition of agreement lived inside a 432,000-iteration accumulator where two
identical predicates were invisible."

**Fixed.** `cbb81ab` extracted `classify_position` as a pure nine-cell function.
The input domain is small enough to tabulate exhaustively, so a duplicated
definition appears as two identical columns.

Verify: `tests/test_classification.py::ClassificationTableTests` (seven tests).

**Verdict.** `Fixed`

### A5 — Two evidence standards shared one vocabulary

**Claim.** The package shipped a reconnaissance pass and an anchored audit
sharing one `Verdict` enum, one README and one name.

**Attacked.** `read`. Renaming the verdict (F1) fixed the symptom; the structure
that produced it remained.

**Fixed.** `0439147` removed the pass: 4,927 deletions across 28 files, 22 files
removed outright, `cli.py` reduced by 976 of 1,236 lines. Merged in `e58a056`.

The reconnaissance is not lost: an unanchored run of the audit produces the same
list as indeterminate matters, correctly labelled
(`tests/test_epoch_audit.py::UnverifiableAnchorTests`).

**Residual.** None. Every `Verdict` member is now anchored
(`src/slot_audit/verdict.py` module docstring).

**Verdict.** `Fixed`

### A6 — Async was half-used

**Claim.** The transport carried a semaphore and a concurrency parameter.

**Attacked.** `read` — collection was sequential regardless, so the complexity
bought nothing.

**Fixed.** `0963ebd` removed the semaphore and removed `max_concurrency` from
configuration entirely rather than leaving it required-but-ignored, which is the
defect F6 already had once.

**Residual.** Sequential issue is now load-bearing, not incidental: the evidence
write order is what shows the frozen inference preceded the anchor, and replay's
in-order matching is sound only because ordering is deterministic
(`src/slot_audit/transport.py`, `AuditRpcClient` docstring).

**Verdict.** `Fixed`

---

## 2. Claims that were attacked and held

A log of only the falsified claims reads as though the tool was entirely broken.
These were attacked and did not break.

| Claim | Attacked | Verify | Verdict |
| --- | --- | --- | --- |
| An arbitrary file cannot satisfy the anchor — not by matching a user-supplied digest, not by containing the expected substrings, not by any RPC response | `executed` | `tests/test_groundtruth.py::RejectedAnchorTests` (ten tests) | `Held` |
| The negative controls traverse the production path, not a parallel one | `executed` | `tests/test_negative_controls.py::ShippedControlSuiteTests::test_a_full_run_gates_on_its_own_controls`, and `::ControlSensitivityTests` — three mutation tests that break `classify_epoch`, `reconcile_mint` and `validate_hash_links` in turn and require the matching control to report `detected=False` *and* to name the sabotage in its observed payload. The reviewer ran the equivalent by hand during round 4; the repository now carries it as a standing regression guard | `Held` |
| Any failed mandatory gate forces `NO_CONCLUSION`, even with zero findings | `executed` | `tests/test_epoch_audit.py::SingleAssessmentTests::test_zero_findings_with_a_failed_gate_is_still_no_conclusion`; `tests/test_gate_coverage.py::GateFailureExecutionTests` drives all twelve to `FAIL` | `Held` |
| No credential reaches any output | `executed` | `tests/test_epoch_cli.py::AuditCommandRefusalTests::test_a_refusal_never_echoes_the_credential`; `tests/test_evidence.py::FingerprintTests`; `tests/test_transport.py::ScriptedTransportTests::test_the_request_record_never_holds_the_url` | `Held` |
| Threshold arithmetic is exact — a configured threshold never becomes a float | `executed` | `tests/test_epoch_audit.py::DecimalThresholdBoundaryTests` — `1/32` against `"0.03125"` passes and against `"0.031249999999999999"` fails, while both convert to the same float | `Held` |
| The provider-only inference is frozen before the anchor is read | `executed` | `tests/test_epoch_audit.py::ScopeAndOrderingTests::test_provider_inference_is_frozen_before_the_anchor_is_read`, using the manifest's `write_order` | `Held` |
| One assessment object produces both the conclusion and the summary | `executed` | `tests/test_epoch_audit.py::SingleAssessmentTests::test_the_summary_renders_the_assessment_it_is_given` and `::test_the_report_module_evaluates_no_thresholds` | `Held` |
| Every scoping value is required; unknown keys fail | `executed` | `tests/test_epoch_config.py::NoSilentDefaultsTests` — a leaf-by-leaf traversal deleting each field | `Held` |
| Two providers differing only by credential are rejected as one source | `executed` | `tests/test_epoch_config.py::ProviderDistinctnessTests` (nine tests) | `Held` |
| Not asking is not evidence of absence | `executed` | `tests/test_epoch_audit.py::AbsenceConfirmationTests` (seven tests) and `::RequestCostTests::test_a_starved_run_never_reports_a_provider_hole` | `Held` |

---

## 3. Limits that remain

These are stated, not solved. Each is enforced or disclosed in the code.

### L1 — No real measurement has been made

`LIVE FULL-EPOCH RUN: NOT EXECUTED`. Every number in this repository's example
output comes from a deterministic fixture whose purpose is to test the
instrument. *Source: `README.md` status block.* **Do not cite this repository as
evidence about any provider.**

### L2 — The epoch-100 constants are unverified

`verified_against_archive=False`. The mandatory gate
`ground_truth_constants_provenance` fails, so an epoch-100 run concludes nothing.
Pinned by `tests/test_epoch_audit.py::ConstantProvenanceGateTests::test_the_shipped_epoch_100_constants_are_unverified_today`,
whose failure message says that flipping it means updating the README status
block in the same change.

**Editing the constants to match a file you already hold is not the fix** — it
inverts the check (`src/slot_audit/groundtruth.py`, `EPOCH_100_GROUND_TRUTH`
provenance note).

### L3 — The extractor's node schema is unvalidated against the real archive

`validated_against_published_car: false`, recorded in the run's own trust chain.
`slot_audit probe-car` answers the question factually against a prefix of the
real file in one command.

### L4 — The evidence manifest is unsigned

It detects damage, partial loss and naive editing. It does not detect an editor
who also recomputes the affected digest and rewrites the manifest. This is
asserted, not merely documented:
`tests/test_evidence.py::ClosedWorldManifestTests::test_a_recomputed_manifest_is_not_detected_and_this_is_documented`.

`replay` narrows it in practice (A1): a forger must also make the forged bytes
reproduce the conclusion.

### L5 — The null confirmation re-read is in-band

Same client, same endpoint, seconds later. It catches a transient miss. It
cannot catch an endpoint that *consistently* returns null for a slot it holds,
and no same-endpoint check could. Each finding's `inference` text says so.

### L6 — Replay does not re-read the archive

The anchor is rebuilt from the retained derived records, whose digest is
re-verified against the derivation record. The CAR-level trust steps are carried
over from the original run rather than re-established. Replay reports this in
its own notes (`tests/test_replay.py::ReproductionTests::test_the_replay_records_what_it_could_not_re_establish`).

### L7 — The error-code table is transcribed, not verified

`src/slot_audit/solana_codes.py` transcribes Solana's `RpcCustomError`; the
semantic classifications are this project's reading. Asserted by
`tests/test_classification.py::CodeSemanticsTableTests::test_the_table_states_that_it_is_unverified`.
A live preflight probe would close this; none exists.

### L8 — The exact-context policy needs a provider with as-of-slot support

Standard mainnet RPC answers `getProgramAccounts` against its current bank, so
`exact_context_policy: require_exact_pinned_slot` fails against ordinary
endpoints and the run correctly concludes nothing. Deliberate: account state
measured at an unknown slot is not a measurement (`README.md`).

---

## 4. Findings assessed and deferred

Raised in review, not built. Recorded so the reasoning is inspectable.

| # | Finding | Why deferred |
| --- | --- | --- |
| Anchor bundle | Derive the anchor once into a cacheable, sealed bundle so `audit` consumes the bundle rather than the archive | Depends on L2. Caching an anchor that cannot currently conclude buys nothing |
| Summary as a pure function | Seal only `result.json`; define `summary.md` as `render(result.json)` and have `verify-evidence` re-render and diff | Cleaner than the current sealing, but would redo the just-verified F5 fix. The `.get()`-chain fragility it also names is a real separate defect and is **not fixed** |
| Live preflight | A fourth control that probes real endpoints for the behaviours `confirms_absence` assumes, and gates on the result | The next item of work. It closes L7 and narrows L5. It cannot self-verify without a real endpoint. Its acceptance criteria are fixed below |

### Acceptance criteria for the live preflight

Written before the work starts, which is the whole of their value. Criteria
written afterwards are not criteria; they are a description of whatever got
built. That is the shape of `F2` — reconciling a figure against a file you
already hold inverts the check rather than satisfying it.

1. **Probe responses are evidence, not log lines.** Every observation the
   preflight makes enters the same evidence store under the same discipline as
   an audit run: raw bytes retained, hashed, manifested, endpoint recorded as a
   fingerprint and never as a URL.
2. **Behaviour outside the code table fails closed.** An observed response the
   table does not describe blocks the conclusion. It is not recorded as a
   warning and carried past.
3. **The provenance upgrade is scoped to what was probed.** `solana_codes` may
   move from "transcribed" to "observed consistent against endpoints X and Y on
   a stated date". It may not move to "verified against Solana". Two endpoints
   are not the protocol, and `L7` narrows rather than closes.
4. **Noise and kill-tests ship in the preflight's first commit.** The
   tidy-fixture pattern in [`P1`](#p1--tidy-fixtures-hide-the-defects-that-matter)
   has hit this repository three times. A new subsystem gets no grace period.

⚠ PENDING — these came from the review, and that attribution traces only to
correspondence. The ordering is verifiable: this entry precedes any preflight
commit in this history.

---

## 5. Patterns

### P1 — Tidy fixtures hide the defects that matter

Three successive gaps had the same shape, visible only on the timeline
([Appendix A](#appendix-a--chronology)):

1. `c768982` — no test had ever asserted a successful conclusive run. A 32-slot
   fixture *cannot* produce one: a single finding drags agreement below the 0.99
   minimum. The case the instrument exists for was structurally unreachable.
2. `b5f64da` — the gate that blocks every epoch-100 run had no failure test.
3. `0963ebd` — replay could not survive a single transient fault.

From `0963ebd`: "Every one answered perfectly on the first attempt, so every
test exercised the path its author already had in mind."

**Countermeasure.** `tests/epoch_support.realistic_noise(seed=…)` injects seeded
retryable faults; the end-to-end classes each carry a noisy variant asserting the
same conclusion and the same counts as the clean run.

### P2 — A claim's wording drifts ahead of its evidence in small steps

F1 and F2 were large overclaims. R4 was the same error at small scale: "a second
**independent** read" describing a same-endpoint retry seconds apart. It reads
as entirely reasonable, which is why it is harder to catch than a large one.

**Countermeasure.** The residual limit is written into the artifact that carries
the claim — each finding's `inference` text states what the re-read cannot
establish — rather than only into documentation a reader may not reach.

### P3 — Output that looks right is not evidence the thing happened

During the merge of `0439147`, `git merge -F -` failed with
`error: could not read file '-'`; `git merge` does not read a message from
stdin. The merge did not occur. The surrounding verification output looked
normal, and the failure was detected only because the test count printed
afterwards was 293 rather than the expected 243.

Three more specimens followed, all inside this document, and they get finer:

- **The front-matter arithmetic.** "Twenty-four claims tested. Fourteen did not
  hold; ten held" could not be derived from the sections beneath it: section 1
  carries 24 labels, section 2 carries 10, and no stated rule produced 14.
  `git show 7810f80:REVIEW-LOG.md | sed -n '6,9p'`, corrected in `f09401f`.
- **A count that counted itself.** The tally of remaining marks in the sourcing
  rule was first written as a `grep -c` command whose own line contained the
  string it searched for, so it returned one more than the sentence claimed.
  ⚠ PENDING — caught in draft and never committed, so this description is the
  only record of it.
- **Its replacement, wrong in the other direction.** The prose that replaced it
  said a search for the mark "also finds this paragraph and the one above it".
  That paragraph names the mark without using it, so only one of the two hits
  it claimed exists. Shipped in `f09401f` and found by review:
  `git show f09401f:REVIEW-LOG.md | grep -n "and the one above it"`.

**Countermeasure.** Verify by observing the state that should have changed, not
by the absence of an error message.

A sentence about a count is the hardest sentence in a document, because it can
change what it counts. The review proposed an accurate one-line repair for the
third specimen; the sentence was removed instead. Any sentence counting
occurrences of a string inside the document that contains it becomes false the
moment someone adds one — as the second bullet above did, which is why the
sourcing rule's tally went from three to four in the same commit that recorded
this pattern. The rule now lists the marks by name instead. A count that
enumerates its members can be checked by reading; a count that asserts the
result of a search cannot.

### P4 — Structural absence of identity produces structural absence of tests

R1 was not an oversight. Gates had no addressable identity, so "which gates lack
a failure test?" was not a question anyone could answer (A2).

**Countermeasure.** `tests/test_gate_coverage.py` makes the question mechanical:
adding a mandatory gate without a failure scenario breaks the build.

---

## 6. Error log

Both sides. A log recording only the author's errors is the reviewer's
autobiography, not a review record.

### Author

| # | Error | Where | Correction |
| --- | --- | --- | --- |
| E1 | The sign-off inventory for the Pass A removal listed 42 removed tests across five files and omitted `test_config.py` entirely, which held nine more. The real figure is 51 removed and one added | Merge commit `e58a056` records the correction | Deletion plans are reconciled against a `discover` run before and after, not tallied by hand per file. Verify: `git show c764757:tests/test_config.py \| grep -c "def test"` → 9 |
| E2 | The share of `cli.py` belonging to the reconnaissance pass was estimated at "about half the module", and that estimate is preserved in the body of `0439147` itself. The actual figure was 976 lines deleted of 1,236, leaving 274 | `git show 0439147 --format="" --numstat -- src/slot_audit/cli.py` → `14  976`; the erroneous estimate: `git log -1 0439147 --format=%B \| grep "about half"` | The commit body is not amended — history is forward-only, and this row is the correction |
| E3 | A commit message claimed `transport.py` read the Solana code table directly. It read it through a re-export in `rpc.py`, because the patch making the import direct sat after an assertion that aborted the script | Self-corrected in `c764757` | Behaviour was already right; the coupling was not. `c764757` also extracted `TokenBucket` so the two subsystems shared no module |
| E4 | `git merge -F -` was used to supply a merge message from stdin, which `git merge` does not support. The merge silently did not happen | See [P3](#p3--output-that-looks-right-is-not-evidence-the-thing-happened) | Detected by the test count, not by the error line |
| E7 | A sentence in the sourcing rule claimed that searching for the pending mark "also finds this paragraph and the one above it". Only the paragraph above contains the mark; the sentence describing it does not. This was the second consecutive wrong answer to the same count | `git show f09401f:REVIEW-LOG.md \| grep -n "and the one above it"`; the pattern and its three siblings are in [P3](#p3--output-that-looks-right-is-not-evidence-the-thing-happened) | Found by review. The sentence was removed rather than repaired, because the class of sentence is fragile, not just this instance |
| E8 | This log quoted a sentence as coming "from `c768982`" that `c768982` does not contain, and that no commit message in the history at the time contained. It came from a review report. `F6` carried it from `7810f80` until `f09401f`. Misattribution is worse than an unmarked claim: it manufactures provenance rather than merely lacking it | `git show 7810f80:REVIEW-LOG.md \| grep -n "naturally infers"` → line 207, and it appears in no commit message that existed when it was written: `git log 7810f80 --format=%H \| while read h; do git log -1 --format=%B "$h" \| grep -q "naturally infers" && echo "$h"; done` → no output. The sweep must be scoped to `7810f80`: run over all history it now returns `f09401f`, which quotes the sentence in order to describe this defect | Found by review. Fixed in `f09401f` by quoting what the commit actually says and sourcing the reader-facing half of the defect separately. This row was added after the fix shipped rather than with it — a smaller instance of the same lapse. The commit that added it: `git log -S"naturally infers" --oneline -- REVIEW-LOG.md` |

### Reviewer

| # | Error | Correction |
| --- | --- | --- |
| E5 | A review report stated that `test_config.py` held 8 tests. The figure was an unverified estimate written in the register of fact; the file held 9. ⚠ PENDING — the reviewer records the sequence as: the author's accounting contradicted the figure first, and the reviewer then verified and acknowledged it. That ordering is a statement about correspondence and is not reconstructible here — "self-corrected", written without it, credited more than the record supports. What is reconstructible: the contradicting accounting, `git log -1 e58a056 --format=%B \| grep "nine more"`, and the true count, `git show c764757:tests/test_config.py \| grep -c "def test"` → 9 | The reviewer identified this as the same class of error the review had been finding in the code: a claim exceeding its observation |
| E6 | Two review reports cite commits `8cf09d7` and `a14e1b8`, which are not resolvable in this repository. **This is the author's fault, not the reviewer's**: those commits were rewritten to change an author email address after the reports were written. History has been forward-only since `cbb81ab` | Review reports must cite resolvable hashes; published history is not rewritten |

---

## Appendix A — Chronology

| Round | Reviewed | Fix | Date | Size | Tests after |
| --- | --- | --- | --- | --- | --- |
| — | — | `9af7707` initial | 2026-08-20 16:32 | +15,863 | 225 |
| 1 | `9af7707` | `c768982` F1–F10 | 2026-08-20 17:00 | +1,046 −167 | 241 |
| 2 | `c768982` | `b5f64da` R1–R5 | 2026-08-20 17:19 | +330 −45 | 251 |
| 3 | `b5f64da` | `cbb81ab` A1–A4 | 2026-08-20 20:56 | +1,999 −74 | 286 |
| 3 | `cbb81ab` | `0963ebd` H1–H3, P1 countermeasure, A6 | 2026-08-20 21:21 | +519 −75 | 293 |
| — | — | `c764757` E3 correction | 2026-08-20 21:25 | +66 −46 | 293 |
| 4 | `c764757` | `0439147` A5 | 2026-08-21 06:26 | +65 −4,927 | 243 |
| 4 | `0439147` | `e58a056` merge, review record | 2026-08-21 06:38 | merge | 243 |

Round 4 was a sign-off on a change proposed in round 3 rather than a new attack
surface. The reviewed commit in each row is the state the round's report was
written against.

## Appendix B — Reproducing the checks cited here

Tests:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m unittest tests.test_replay.ForgeryTests -v
PYTHONPATH=src python3 -m unittest tests.test_replay.MessyButHonestRunTests -v
PYTHONPATH=src python3 -m unittest tests.test_gate_coverage -v
PYTHONPATH=src python3 -m unittest tests.test_groundtruth.RejectedAnchorTests -v
PYTHONPATH=src python3 -m unittest tests.test_epoch_audit.ConstantProvenanceGateTests -v
PYTHONPATH=src python3 -m unittest tests.test_negative_controls.ControlSensitivityTests -v
```

Historical claims quoted in section 1, each against the commit that carried it:

```bash
# F1 the over-claim, and the assertion that pinned it
git show 9af7707:src/slot_audit/enumerate.py | sed -n '305,312p;519,523p'
git show 9af7707:tests/test_enumerate.py     | sed -n '141p'

# F2 the constants described as published, and the tautological test name
git show 9af7707:src/slot_audit/groundtruth.py | grep -n published
git show 9af7707:tests/test_groundtruth.py     | grep -n "def test_pinned_constants"

# F3 the comment asserting the two denominators differed
git show 9af7707:src/slot_audit/audit.py | grep -n "denominators distinct"

# F6 the threshold printed among thresholds that did drive gates, and the
# traversal showing no module that could consume it ever named it
git show 9af7707:src/slot_audit/report.py | sed -n '84,87p'
for f in $(git ls-tree -r --name-only 9af7707 -- src | grep '\.py$'); do
  n=$(git show "9af7707:$f" | grep -ci materiality); [ "$n" -gt 0 ] && echo "$f: $n"
done   # config.py, report.py, negative_controls.py only -- never audit or assessment

# F5 the unqualified closed-world claim
git show 9af7707:README.md | grep -n "closed-world"

# F9 the float threshold literal
git show 9af7707:src/slot_audit/cli.py | grep -n "^INDETERMINATE_TRUST_THRESHOLD"

# E1 and E5 the disputed test count
git show c764757:tests/test_config.py | grep -c "def test"      # 9

# E2 the cli.py share
git show 0439147 --format="" --numstat -- src/slot_audit/cli.py  # 14  976

# E6 the two unresolvable hashes cited in early review reports
git cat-file -e 8cf09d7 2>/dev/null || echo "8cf09d7 unresolvable, as recorded"
git cat-file -e a14e1b8 2>/dev/null || echo "a14e1b8 unresolvable, as recorded"
```

`F7` — the mandatory gate that could be built advisory. The hole is rebuilt at
the commit that carried it; the same script against `HEAD` raises
`ValueError: these gates are mandatory and may not be marked advisory`:

```bash
git worktree add --detach /tmp/slot-audit-9af7707 9af7707
cat > /tmp/f7.py <<'EOF'
from slot_audit.assessment import (
    MANDATORY_GATES, Gate, GateStatus, InstrumentAssessment, RunConclusion)
gates = tuple(
    Gate(gate_id=g, title=g, status=GateStatus.PASS, detail="ok")
    for g in MANDATORY_GATES if g != "per_provider_agreement"
) + (Gate(gate_id="per_provider_agreement", title="agreement",
          status=GateStatus.FAIL, detail="below minimum", mandatory=False),)
a = InstrumentAssessment(gates=gates)
print("status:", a.status.value,
      "result:", RunConclusion(assessment=a, finding_count=1,
                               indeterminate_count=0).result.value)
EOF
PYTHONPATH=/tmp/slot-audit-9af7707/src python3 /tmp/f7.py   # status: PASS result: FINDINGS
PYTHONPATH=src                              python3 /tmp/f7.py   # ValueError
git worktree remove --force /tmp/slot-audit-9af7707
```

Every test named in this document is in that suite. A claim in this file that
cannot be traced to a commit, a test name or a command in this appendix is a
defect in this file.
