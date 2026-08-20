"""Render a run.  Render, not re-decide.

``summary.md`` and ``result.json`` are two views of one
:class:`~slot_audit.assessment.InstrumentAssessment` and one
:class:`~slot_audit.assessment.RunConclusion`.  This module contains no
threshold, no comparison and no policy: if the summary and the machine-readable
result could ever disagree, it would be because something here recomputed a
judgment instead of printing it.  Nothing here recomputes a judgment.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .assessment import GateStatus
from .audit import AuditRun
from .evidence import MANIFEST_NAME, EvidenceRef

SUMMARY_NAME = "summary.md"
RESULT_NAME = "result.json"


def _describe(refs: Iterable[EvidenceRef]) -> list[str]:
    return [
        f"`{ref.relative_path}` — sha256 `{ref.sha256}`, {ref.byte_length} bytes"
        for ref in refs
    ]


def _status_word(status: GateStatus) -> str:
    return "PASS" if status is GateStatus.PASS else "FAIL"


def render_summary(run: AuditRun, *, results_dir: str | Path) -> str:
    """Render ``summary.md`` from the authoritative assessment and conclusion."""

    assessment = run.assessment
    conclusion = run.conclusion
    scope = run.scope
    evidence_rel = Path(run.evidence_root).name
    lines: list[str] = []
    add = lines.append

    add("# Solana single-epoch audit summary")
    add("")
    add(f"- **Instrument validation status:** `{_status_word(assessment.status)}`")
    add(f"- **Result:** `{conclusion.result.value}`")
    add(f"- **Conclusive findings:** {conclusion.finding_count}")
    add(f"- **Indeterminate positions:** {conclusion.indeterminate_count}")
    if conclusion.blocked_by:
        add(
            "- **Blocked by failed mandatory gate(s):** "
            + ", ".join(f"`{name}`" for name in conclusion.blocked_by)
        )
    add("")
    add(
        "The result above is derived from the single self-assessment object below. "
        "No threshold is evaluated a second time when rendering this document."
    )
    add("")

    add("## Scope and filters")
    add("")
    population = scope.get("population", {})
    scope_block = scope.get("scope", {})
    thresholds = scope.get("thresholds", {})
    token = scope.get("token", {})
    continuity = scope.get("continuity", {})
    ground_truth = scope.get("ground_truth", {})
    collection = scope.get("collection", {})
    add(f"- Population: {population.get('definition')}")
    add(f"- Population unit: {population.get('unit')}")
    add(f"- Epoch: {scope_block.get('epoch')}")
    add(
        f"- Inclusive slot bounds: {scope_block.get('first_slot')}–"
        f"{scope_block.get('last_slot')} "
        f"({scope_block.get('scheduled_slot_positions')} scheduled positions)"
    )
    add(f"- Commitment: `{scope_block.get('commitment')}`")
    add(f"- Pinned slot: {scope_block.get('pinned_slot')}")
    add(f"- Exact-context policy: `{scope_block.get('exact_context_policy')}`")
    add(f"- Indeterminate threshold: `{thresholds.get('indeterminate_threshold')}`")
    add(f"- Denominator policy: `{thresholds.get('denominator_policy')}`")
    add(
        f"- Materiality threshold: `{thresholds.get('materiality_threshold')}` "
        "(applied by the `materiality_assessment` gate)"
    )
    add(f"- Minimum provider agreement: `{thresholds.get('minimum_provider_agreement')}`")
    add(f"- Token mint: `{token.get('mint')}`")
    add(f"- Token program id: `{token.get('program_id')}`")
    add(f"- Token account size: {token.get('account_size')} bytes")
    add(
        f"- Offsets: mint={token.get('mint_offset')}, amount={token.get('amount_offset')}, "
        f"state={token.get('state_offset')}, supply={token.get('supply_offset')}"
    )
    add(f"- Included account states: {', '.join(token.get('included_account_states', []))}")
    add(f"- Zero-balance inclusion policy: `{token.get('zero_balance_policy')}`")
    add(f"- Duplicate-pubkey policy: `{token.get('duplicate_pubkey_policy')}`")
    add(
        "- Hash-link validation population: "
        f"`{continuity.get('hash_link_validation_population')}`"
    )
    add(f"- getBlocks chunk size: {collection.get('getblocks_chunk_size')}")
    add(f"- Ground-truth source: `{ground_truth.get('source')}`")
    add(f"- Expected CAR sha256: `{ground_truth.get('car_sha256')}`")
    add(f"- Expected CAR root CID: `{ground_truth.get('car_root_cid')}`")
    add(f"- Pinned Old Faithful source commit: `{ground_truth.get('source_commit')}`")
    add(f"- Slot list filtered at predecessor row: {ground_truth.get('predecessor_boundary_slot')}")
    add("")
    add("Providers are identified by endpoint fingerprint; no URL is reproduced here.")
    add("")
    for provider in scope.get("providers", []):
        add(
            f"- `{provider.get('name')}` — env `{provider.get('url_env')}`, "
            f"endpoint fingerprint `{provider.get('endpoint_fingerprint')}`, "
            f"host fingerprint `{provider.get('host_fingerprint')}`"
        )
    add("")

    add("## Instrument self-assessment")
    add("")
    add("| Gate | Mandatory | Status | Detail |")
    add("| --- | --- | --- | --- |")
    for gate in assessment.gates:
        detail = gate.detail.replace("|", "\\|")
        add(
            f"| `{gate.gate_id}` | {'yes' if gate.mandatory else 'no'} | "
            f"`{_status_word(gate.status)}` | {detail} |"
        )
    add("")
    for gate in assessment.gates:
        if not gate.metrics and not gate.evidence:
            continue
        add(f"### `{gate.gate_id}` — {gate.title}")
        add("")
        add(f"Status: `{_status_word(gate.status)}`")
        add("")
        for key, value in sorted(gate.metrics.items()):
            add(f"- {key}: `{value}`")
        for line in _describe(gate.evidence):
            add(f"- evidence: {line}")
        add("")

    add("## Agreement")
    add("")
    add(
        "Per-provider agreement and the combined two-provider existence inference are "
        "different measurements and are never merged. A provider's own agreement says "
        "how often that single endpoint matched the anchor; the combined inference says "
        "how often the pair, taken together, inferred existence correctly."
    )
    add("")
    add(
        "**Each provider has exactly one agreement figure.** Against a binary ground "
        "truth, a provider is right about availability exactly when its unaided "
        "present-or-skipped inference is right, so an \"availability agreement\" "
        "column would be this same number printed twice. Coverage completeness below "
        "is a different quantity: how much of the epoch the provider could answer for "
        "at all, independent of the anchor."
    )
    add("")
    add("### Per-provider agreement")
    add("")
    add(
        "| Provider | Classification agreement | Numerator/Denominator | "
        "Coverage completeness | Covered/Scheduled | Indeterminate | "
        "Denominator policy |"
    )
    add("| --- | --- | --- | --- | --- | --- | --- |")
    for agreement in run.provider_agreements:
        payload = agreement.to_payload()
        classification = payload["classification_agreement"]
        coverage = payload["coverage_completeness"]
        add(
            f"| `{agreement.provider}` | {classification['percent']} | "
            f"{classification['numerator']}/{classification['denominator']} | "
            f"{coverage['percent']} | "
            f"{coverage['numerator']}/{coverage['denominator']} | "
            f"{agreement.indeterminate_count} | `{agreement.denominator_policy}` |"
        )
    add("")
    add("### Combined two-provider existence inference agreement")
    add("")
    combined = run.combined_agreement.to_payload()
    add(f"- Scope: `{combined['scope']}` (not a per-provider number)")
    add(f"- Numerator: {combined['numerator']}")
    add(f"- Denominator: {combined['denominator']}")
    add(f"- Rate: {combined['rate']} ({combined['percent']})")
    add(f"- Indeterminate: {combined['indeterminate_count']}")
    add(f"- Denominator policy: `{combined['denominator_policy']}`")
    add("")

    add("## Negative controls")
    add("")
    if not run.negative_controls:
        add("No negative controls were executed for this run.")
    else:
        add("| Control | Detected | Detail |")
        add("| --- | --- | --- |")
        for control in run.negative_controls:
            detail = control.detail.replace("|", "\\|")
            add(
                f"| `{control.control_id}` | {'yes' if control.detected else 'NO'} | {detail} |"
            )
        add("")
        for control in run.negative_controls:
            add(f"### `{control.control_id}` — {control.title}")
            add("")
            for key, value in sorted(control.observed.items()):
                add(f"- {key}: `{value}`")
            for line in _describe(control.evidence):
                add(f"- evidence: {line}")
            add("")
    add("")

    add("## Ground-truth trust chain")
    add("")
    truth = run.ground_truth
    add(f"- Source: Old Faithful CAR for epoch {truth.spec.epoch}")
    provenance = truth.spec.provenance
    if not provenance.verified_against_archive:
        add("")
        add(
            f"> **The pinned constants below are unverified.** {provenance.note} "
            f"Stated source: {provenance.source}."
        )
        add("")
    else:
        add(f"- Constants provenance: verified — {provenance.source}")
    add(f"- Pinned CAR sha256: `{truth.spec.car_sha256}`")
    add(f"- Observed CAR sha256: `{truth.car_sha256}`")
    add(f"- Pinned CAR root CID: `{truth.spec.car_root_cid}`")
    add(f"- Pinned Old Faithful source commit: `{truth.spec.source_commit}`")
    add(f"- Extractor: `{truth.extractor.name}` version `{truth.extractor.version}`")
    add(f"- Extractor command: `{truth.extractor.command}`")
    add(f"- Extractor node schema: `{truth.extractor.node_schema}`")
    add(
        "- Extractor validated against the published epoch-100 CAR: "
        f"`{truth.extractor.validated_against_published_car}`"
    )
    add(
        f"- Derived produced blocks: {truth.produced_count} "
        f"(expected {truth.spec.produced_blocks})"
    )
    add(f"- Derived skipped slots: {truth.skipped_count} (expected {truth.spec.skipped_slots})")
    add(
        f"- Predecessor boundary rows filtered explicitly: "
        f"{truth.filtered_predecessor_rows} at slot {truth.spec.predecessor_boundary_slot}"
    )
    add("")
    add("| Step | Passed | Detail |")
    add("| --- | --- | --- |")
    for step in truth.trust_chain:
        add(f"| `{step.step}` | {'yes' if step.passed else 'NO'} | {step.detail} |")
    add("")
    for line in _describe(truth.evidence_refs):
        add(f"- {line}")
    add("")

    add("## Frozen provider-only inference")
    add("")
    add(
        "The providers' own answer was retained before the anchor was read, so the "
        "comparison below cannot have been shaped by its own result."
    )
    add("")
    for line in _describe([run.frozen_inference]):
        add(f"- {line}")
    add("")

    add("## Findings")
    add("")
    if not run.findings:
        add("No conclusive findings were produced.")
        add("")
    for finding in run.findings:
        add(f"### Slot {finding.slot} — `{finding.verdict.value}` at `{finding.provider}`")
        add("")
        add(f"- slot: `{finding.slot}`")
        add(f"- blockhash: `{finding.blockhash}`")
        add(f"- previousBlockhash: `{finding.previous_blockhash}`")
        add(f"- parentSlot: `{finding.parent_slot}`")
        add(f"- source: `{finding.source}`")
        add(f"- inference: {finding.inference}")
        if finding.corroborating_providers:
            add(f"- corroborating providers: {', '.join(finding.corroborating_providers)}")
        add("- evidence:")
        for name, ref in sorted(finding.evidence.items()):
            add(
                f"  - **{name}**: `{ref.relative_path}` — sha256 `{ref.sha256}`, "
                f"{ref.byte_length} bytes"
            )
        add("")

    add("## Token reconciliation")
    add("")
    add(
        "| Provider | Context slot | Accounts included | Enumerated total | Mint supply | "
        "Signed difference |"
    )
    add("| --- | --- | --- | --- | --- | --- |")
    for name, result in sorted(run.token_results.items()):
        add(
            f"| `{name}` | {result.context_slot} | {result.included_accounts} | "
            f"{result.enumerated_total} | {result.mint_supply} | "
            f"{result.signed_difference} |"
        )
    add("")

    add("## Request cost and limits")
    add("")
    add("| Provider | Logical calls | Attempts | Retries | Budget | Budget exhausted |")
    add("| --- | --- | --- | --- | --- | --- |")
    for stats in run.request_stats:
        add(
            f"| `{stats.provider}` | {stats.logical_calls} | {stats.attempts} | "
            f"{stats.retries} | {stats.budget_limit} | "
            f"{'YES' if stats.budget_exhausted else 'no'} |"
        )
    add("")
    add(
        "Attempts exceed logical calls when a retryable failure was retried. Every "
        "attempt is retained separately in the evidence store, so a retried answer "
        "cannot be mistaken for a clean first one."
    )
    add("")

    add("## Hash-link continuity")
    add("")
    add("| Population | Links checked | Mismatches | Outcomes |")
    add("| --- | --- | --- | --- |")
    for result in run.continuity:
        add(
            f"| `{result.population}` | {result.checked} | {len(result.mismatches)} | "
            f"{', '.join(result.outcomes) or 'none'} |"
        )
    add("")

    add("## What this run could not determine")
    add("")
    if not run.indeterminate and conclusion.indeterminate_count == 0:
        add("Nothing was left indeterminate.")
    else:
        add(f"- Indeterminate scheduled positions: {conclusion.indeterminate_count}")
        for matter in run.indeterminate[:200]:
            location = "run-wide" if matter.slot is None else f"slot {matter.slot}"
            add(f"- {location} — `{matter.subject}`: {matter.reason}")
        if len(run.indeterminate) > 200:
            add(f"- … and {len(run.indeterminate) - 200} further indeterminate matters")
    add("")
    add(
        "This audit measures block presence, hash-link continuity for the declared "
        "population, and one mint's token-account reconciliation at one pinned slot. "
        "It does not establish transaction-level completeness, fork or reorg semantics, "
        "economic harm, or the behaviour of any provider outside the two audited "
        "endpoints."
    )
    add("")

    add("## Provenance")
    add("")
    provenance = run.provenance
    add(f"- Package version: `{provenance.package_version}`")
    add(f"- Source-tree sha256: `{provenance.source_tree_sha256}`")
    add(f"- Runtime: `{provenance.python_version}` on `{provenance.platform}`")
    add(f"- Resolved-config sha256: `{provenance.resolved_config_sha256}`")
    add(f"- Run started (UTC): `{provenance.run_started_at}`")
    add(f"- Run completed (UTC): `{provenance.run_completed_at}`")
    if run.manifest is not None:
        add(
            f"- Manifest: `{run.manifest.relative_path}` — sha256 "
            f"`{run.manifest.sha256}`, {run.manifest.byte_length} bytes"
        )
    else:
        add(
            "- Manifest: sealed after this document was recorded. This summary is "
            "itself a manifested artifact (`artifacts/summary.md`), so tampering "
            "with the copy beside the evidence directory is detectable by "
            "comparing it against the sealed one."
        )
    add("")

    add("## Re-performance")
    add("")
    add("Verify the evidence manifest (closed-world: missing, modified and unexpected files):")
    add("")
    add("```bash")
    add(
        "PYTHONPATH=src python3 -m slot_audit verify-evidence "
        f"--evidence-dir {results_dir}/{evidence_rel}"
    )
    add("```")
    add("")
    add("Recompute any evidence digest directly:")
    add("")
    add("```bash")
    add(f"shasum -a 256 {results_dir}/{evidence_rel}/{MANIFEST_NAME}")
    add(f"find {results_dir}/{evidence_rel} -type f -print0 | xargs -0 shasum -a 256")
    add("```")
    add("")
    add("Re-run the audit into a fresh directory (an existing evidence run is never overwritten):")
    add("")
    add("```bash")
    add("PYTHONPATH=src python3 -m slot_audit audit \\")
    add("  --config config.epoch-100.yaml \\")
    add("  --results-dir results/epoch-100-rerun")
    add("```")
    add("")
    add("Run the instrument's own tests:")
    add("")
    add("```bash")
    add("PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v")
    add("```")
    add("")
    return "\n".join(lines) + "\n"


def render_result_bytes(run: AuditRun) -> bytes:
    """Serialize the machine-readable result deterministically."""

    return (
        json.dumps(run.to_payload(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def write_reports(run: AuditRun, *, results_dir: str | Path) -> tuple[Path, Path]:
    """Place readable copies of the sealed reports beside the evidence directory.

    The bytes are *copied* from the manifested artifacts rather than re-rendered,
    so the convenience copy and the sealed record are byte-identical and any edit
    to the copy is detectable. If a run predates sealing (or was constructed by
    hand in a test), rendering falls back to generating them directly.
    """

    directory = Path(results_dir)
    directory.mkdir(parents=True, exist_ok=True)
    summary_path = directory / SUMMARY_NAME
    result_path = directory / RESULT_NAME

    sealed_summary = _sealed_bytes(run, run.summary_evidence)
    sealed_result = _sealed_bytes(run, run.result_evidence)
    summary_path.write_bytes(
        sealed_summary
        if sealed_summary is not None
        else render_summary(run, results_dir=directory).encode("utf-8")
    )
    result_path.write_bytes(
        sealed_result if sealed_result is not None else render_result_bytes(run)
    )
    return summary_path, result_path


def _sealed_bytes(run: AuditRun, ref: EvidenceRef | None) -> bytes | None:
    if ref is None:
        return None
    path = Path(run.evidence_root) / ref.relative_path
    return path.read_bytes() if path.is_file() else None


@dataclass(frozen=True, slots=True)
class ReportVerification:
    """The state of each readable report against its sealed original.

    A missing copy and an edited copy are different events and are reported as
    such. Only an edited or unsealed copy is a failure: a copy that was never
    written, or was deleted, leaves the sealed original untouched and is
    recoverable -- but a reader still needs to be told which happened.
    """

    matched: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()
    absent: tuple[str, ...] = ()
    unsealed: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not (self.modified or self.unsealed)

    def describe(self) -> list[str]:
        lines: list[str] = []
        for name in self.matched:
            lines.append(f"{name}: matches its sealed copy")
        for name in self.absent:
            lines.append(
                f"{name}: NOT PRESENT beside the evidence; the sealed copy in "
                f"artifacts/{name} is intact and can be restored from it"
            )
        for name in self.modified:
            lines.append(
                f"{name}: DIFFERS from the sealed artifacts/{name}; the readable "
                "copy has been modified"
            )
        for name in self.unsealed:
            lines.append(
                f"{name}: present beside the evidence but never sealed; it cannot "
                "be checked against anything"
            )
        return lines


def verify_reports(
    results_dir: str | Path, evidence_dir: str | Path
) -> ReportVerification:
    """Compare the readable copies against the sealed originals."""

    matched: list[str] = []
    modified: list[str] = []
    absent: list[str] = []
    unsealed: list[str] = []
    results = Path(results_dir)
    evidence = Path(evidence_dir)
    for name in (SUMMARY_NAME, RESULT_NAME):
        copy = results / name
        sealed = evidence / "artifacts" / name
        if not sealed.is_file():
            if copy.is_file():
                unsealed.append(name)
            continue
        if not copy.is_file():
            absent.append(name)
        elif copy.read_bytes() != sealed.read_bytes():
            modified.append(name)
        else:
            matched.append(name)
    return ReportVerification(
        matched=tuple(matched),
        modified=tuple(modified),
        absent=tuple(absent),
        unsealed=tuple(unsealed),
    )


__all__ = [
    "RESULT_NAME",
    "SUMMARY_NAME",
    "ReportVerification",
    "render_result_bytes",
    "render_summary",
    "verify_reports",
    "write_reports",
]
