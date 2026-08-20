"""Single-epoch orchestration: collect, freeze, anchor, classify, conclude.

This module is the production path.  The shipped negative controls call
:func:`run_epoch_audit` exactly as a live run does -- same collection, same
classification, same finding construction, same assessment -- so a control that
passes is evidence about *this* code rather than about a helper written to make
the control pass.

Order matters and is enforced here:

1. Collect from both providers and retain the raw bytes of every call.
2. **Freeze** the provider-only inference into an artifact.  It is written
   before the anchor is read, so nobody can later claim the inference was shaped
   by the answer it is about to be compared against.
3. Derive ground truth from the verified archive.
4. Classify, and only then construct findings.
5. Assess the instrument, and derive the conclusion from that assessment alone.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from .assessment import (
    CombinedInferenceAgreement,
    Gate,
    InstrumentAssessment,
    ProviderAgreement,
    RunConclusion,
    at_least,
    build_gate,
    exact_rate,
    format_percent,
    format_rate,
    within_threshold,
)
from .config import ResolvedEpochAuditConfig, ResolvedProvider
from .continuity import (
    BlockHeader,
    ContinuityResult,
    HeaderDecodeError,
    decode_block_header,
    validate_hash_links,
)
from .evidence import EvidenceRef, EvidenceStore, ToolProvenance, build_provenance, utc_now
from .groundtruth import (
    CarBlockHeaderExtractor,
    EpochGroundTruthSpec,
    GroundTruth,
    GroundTruthExtractor,
    derive_ground_truth,
    pinned_spec,
)
from .token import (
    DuplicatePubkeyPolicy,
    TokenError,
    TokenReconciliation,
    TokenScope,
    ZeroBalancePolicy,
    parse_account_states,
    reconcile_mint,
)
from .transport import AuditRpcClient, RecordedCall
from .verdict import ExistenceInference, GroundTruthState, ProviderSlotState, Verdict

DEFAULT_GETBLOCKS_CHUNK = 500_000

ClientFactory = Callable[[ResolvedProvider], AuditRpcClient]


class AuditError(RuntimeError):
    """The audit could not be run at all (as distinct from concluding nothing)."""


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RangeResponse:
    """One ``getBlocks`` batch, kept so a finding can cite the exact answer."""

    provider: str
    start_slot: int
    end_slot: int
    succeeded: bool
    present_count: int
    raw: EvidenceRef
    request: EvidenceRef
    error: str | None = None

    def covers(self, slot: int) -> bool:
        return self.start_slot <= slot <= self.end_slot

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "start_slot": self.start_slot,
            "end_slot": self.end_slot,
            "succeeded": self.succeeded,
            "present_count": self.present_count,
            "error": self.error,
            "raw_response": self.raw.to_payload(),
            "request": self.request.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class ProviderCollection:
    """Everything one provider said about the epoch, plus where it is stored."""

    provider: str
    endpoint_fingerprint: str
    ranges: tuple[RangeResponse, ...]
    present_slots: frozenset[int]
    version_evidence: EvidenceRef | None
    version_text: str | None
    errors: tuple[str, ...] = ()

    def covers(self, slot: int) -> bool:
        return any(item.succeeded and item.covers(slot) for item in self.ranges)

    def range_response_for(self, slot: int) -> RangeResponse | None:
        for item in self.ranges:
            if item.covers(slot):
                return item
        return None

    def state_at(self, slot: int) -> ProviderSlotState:
        if not self.covers(slot):
            return ProviderSlotState.UNCOVERED
        return ProviderSlotState.PRESENT if slot in self.present_slots else ProviderSlotState.ABSENT

    @property
    def covered_count(self) -> int:
        return sum(
            item.end_slot - item.start_slot + 1 for item in self.ranges if item.succeeded
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "endpoint_fingerprint": self.endpoint_fingerprint,
            "version": self.version_text,
            "version_evidence": (
                None if self.version_evidence is None else self.version_evidence.to_payload()
            ),
            "present_slots": len(self.present_slots),
            "covered_positions": self.covered_count,
            "range_responses": [item.to_payload() for item in self.ranges],
            "errors": list(self.errors),
        }


def _chunks(first: int, last: int, size: int) -> list[tuple[int, int]]:
    if size < 1:
        raise AuditError("getBlocks chunk size must be at least one")
    out: list[tuple[int, int]] = []
    cursor = first
    while cursor <= last:
        end = min(last, cursor + size - 1)
        out.append((cursor, end))
        cursor = end + 1
    return out


async def collect_provider(
    client: AuditRpcClient,
    *,
    endpoint_fingerprint: str,
    first_slot: int,
    last_slot: int,
    chunk_size: int = DEFAULT_GETBLOCKS_CHUNK,
) -> ProviderCollection:
    """Enumerate one provider across the epoch, retaining every batch answer."""

    version_call = await client.get_version()
    version_text: str | None = None
    if isinstance(version_call.result, Mapping):
        raw_version = version_call.result.get("solana-core")
        version_text = str(raw_version) if raw_version is not None else None

    ranges: list[RangeResponse] = []
    present: set[int] = set()
    errors: list[str] = []
    for start, end in _chunks(first_slot, last_slot, chunk_size):
        call = await client.get_blocks(start, end)
        succeeded = not call.failed and isinstance(call.result, list)
        count = 0
        error = call.error_message
        # Accumulate into a scratch set. A batch that fails validation half-way
        # through must contribute nothing, or the slots read before the failure
        # would survive into the frozen inference artifact while the range itself
        # is excluded from coverage -- an internally inconsistent record.
        batch_present: set[int] = set()
        if succeeded:
            for slot in call.result:
                if isinstance(slot, bool) or not isinstance(slot, int):
                    succeeded = False
                    error = "getBlocks returned a non-integer slot"
                    break
                if start <= slot <= end:
                    batch_present.add(slot)
                    count += 1
                else:
                    succeeded = False
                    error = f"getBlocks returned slot {slot} outside the requested range"
                    break
        elif error is None:
            error = "getBlocks did not return a list"
        if succeeded:
            present |= batch_present
        else:
            count = 0
            errors.append(f"{start}-{end}: {error}")
        ranges.append(
            RangeResponse(
                provider=client.provider,
                start_slot=start,
                end_slot=end,
                succeeded=succeeded,
                present_count=count,
                raw=call.raw_ref,
                request=call.request_ref,
                error=None if succeeded else error,
            )
        )
    if version_call.failed:
        errors.append(f"getVersion: {version_call.error_message}")

    return ProviderCollection(
        provider=client.provider,
        endpoint_fingerprint=endpoint_fingerprint,
        ranges=tuple(ranges),
        present_slots=frozenset(present),
        version_evidence=version_call.raw_ref,
        version_text=version_text,
        errors=tuple(errors),
    )


def _run_length_encode(slots: Iterable[int]) -> list[list[int]]:
    runs: list[list[int]] = []
    for slot in sorted(slots):
        if runs and slot == runs[-1][1] + 1:
            runs[-1][1] = slot
        else:
            runs.append([slot, slot])
    return runs


def freeze_provider_inference(
    collections: Sequence[ProviderCollection],
    *,
    first_slot: int,
    last_slot: int,
    evidence: EvidenceStore,
    name: str = "provider-only-inference.json",
) -> EvidenceRef:
    """Retain the providers' own answer before ground truth is consulted.

    The encoding is run-length but lossless: the exact present-slot set and the
    exact successfully covered ranges are both recoverable, so the frozen
    artifact can be replayed against any later anchor.
    """

    combined_exists: set[int] = set()
    for collection in collections:
        combined_exists |= collection.present_slots
    payload = {
        "kind": "provider_only_inference",
        "note": (
            "Frozen before the ground-truth anchor was read. Encoding is run-length "
            "but lossless: [start, end] pairs are inclusive."
        ),
        "first_slot": first_slot,
        "last_slot": last_slot,
        "providers": [
            {
                "provider": collection.provider,
                "endpoint_fingerprint": collection.endpoint_fingerprint,
                "present_slot_runs": _run_length_encode(collection.present_slots),
                "covered_ranges": [
                    [item.start_slot, item.end_slot]
                    for item in collection.ranges
                    if item.succeeded
                ],
                "failed_ranges": [
                    [item.start_slot, item.end_slot]
                    for item in collection.ranges
                    if not item.succeeded
                ],
                "present_slot_count": len(collection.present_slots),
            }
            for collection in collections
        ],
        "combined_existence_runs": _run_length_encode(combined_exists),
        "combined_existence_count": len(combined_exists),
    }
    return evidence.record_json_artifact(name, payload)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SlotOutcome:
    """A materialized classification for one interesting slot position."""

    slot: int
    ground_truth: GroundTruthState
    provider_states: Mapping[str, ProviderSlotState]
    combined_inference: ExistenceInference
    verdicts: Mapping[str, Verdict]

    def to_payload(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "ground_truth": self.ground_truth.value,
            "provider_states": {
                name: state.value for name, state in self.provider_states.items()
            },
            "combined_inference": self.combined_inference.value,
            "verdicts": {name: verdict.value for name, verdict in self.verdicts.items()},
        }


@dataclass(frozen=True, slots=True)
class ClassificationTally:
    """Counters over all scheduled positions, plus the positions worth naming."""

    scheduled_positions: int
    ground_truth_produced: int
    ground_truth_skipped: int
    ground_truth_unknown: int
    verdict_counts: Mapping[str, Mapping[str, int]]
    inference_counts: Mapping[str, int]
    indeterminate_positions: int
    candidate_holes: tuple[SlotOutcome, ...]
    conflicts: tuple[SlotOutcome, ...]
    indeterminate_outcomes: tuple[SlotOutcome, ...]
    provider_coverage: Mapping[str, int]
    provider_classification: Mapping[str, tuple[int, int]]
    combined_agreement: tuple[int, int]

    def to_payload(self) -> dict[str, object]:
        return {
            "scheduled_positions": self.scheduled_positions,
            "ground_truth": {
                "produced": self.ground_truth_produced,
                "skipped": self.ground_truth_skipped,
                "unknown": self.ground_truth_unknown,
            },
            "verdict_counts": {
                provider: dict(counts) for provider, counts in self.verdict_counts.items()
            },
            "combined_inference_counts": dict(self.inference_counts),
            "indeterminate_positions": self.indeterminate_positions,
            "candidate_holes": [item.to_payload() for item in self.candidate_holes],
            "ground_truth_conflicts": [item.to_payload() for item in self.conflicts],
        }


def classify_epoch(
    *,
    spec: EpochGroundTruthSpec,
    ground_truth: GroundTruth,
    collections: Sequence[ProviderCollection],
    denominator_policy: str,
) -> ClassificationTally:
    """Classify every scheduled position of the epoch.

    Counters are accumulated rather than materialized: an epoch has 432,000
    positions and only a handful of them are ever individually interesting.
    """

    names = [collection.provider for collection in collections]
    verdict_counts: dict[str, dict[str, int]] = {
        name: {verdict.value: 0 for verdict in Verdict} for name in names
    }
    inference_counts = {value.value: 0 for value in ExistenceInference}
    covered_positions = {name: 0 for name in names}
    classification_hits = {name: 0 for name in names}
    classification_total = {name: 0 for name in names}
    combined_hits = 0
    combined_total = 0
    produced = skipped = unknown = 0
    indeterminate_positions = 0
    candidate_holes: list[SlotOutcome] = []
    conflicts: list[SlotOutcome] = []
    indeterminate_outcomes: list[SlotOutcome] = []
    anchored = ground_truth.verified
    count_all = denominator_policy == "all_scheduled_positions"

    for slot in range(spec.first_slot, spec.last_slot + 1):
        if not anchored:
            truth = GroundTruthState.UNKNOWN
        elif ground_truth.is_produced(slot):
            truth = GroundTruthState.PRODUCED
        else:
            truth = GroundTruthState.SKIPPED
        if truth is GroundTruthState.PRODUCED:
            produced += 1
        elif truth is GroundTruthState.SKIPPED:
            skipped += 1
        else:
            unknown += 1

        states = {
            collection.provider: collection.state_at(slot) for collection in collections
        }
        present_anywhere = any(state is ProviderSlotState.PRESENT for state in states.values())
        all_covered = all(state is not ProviderSlotState.UNCOVERED for state in states.values())
        if present_anywhere:
            inference = ExistenceInference.EXISTS
        elif all_covered:
            inference = ExistenceInference.ABSENT
        else:
            inference = ExistenceInference.INDETERMINATE
        inference_counts[inference.value] += 1

        verdicts: dict[str, Verdict] = {}
        position_indeterminate = False
        for name, state in states.items():
            if state is ProviderSlotState.UNCOVERED or truth is GroundTruthState.UNKNOWN:
                verdict = Verdict.INDETERMINATE
            elif state is ProviderSlotState.PRESENT:
                verdict = (
                    Verdict.PRESENT
                    if truth is GroundTruthState.PRODUCED
                    else Verdict.GROUND_TRUTH_CONFLICT
                )
            elif truth is GroundTruthState.PRODUCED:
                verdict = Verdict.PROVIDER_HOLE
            else:
                verdict = Verdict.PROTOCOL_SKIPPED
            verdicts[name] = verdict
            verdict_counts[name][verdict.value] += 1
            if verdict is Verdict.INDETERMINATE:
                position_indeterminate = True

            # Coverage is about this provider alone: did it successfully answer
            # for this position at all? It has no dependence on the anchor, which
            # is what makes it a different measurement from agreement rather than
            # the same one relabelled.
            if state is not ProviderSlotState.UNCOVERED:
                covered_positions[name] += 1

            # A provider on its own can only infer "present" or "missing, so
            # presumably skipped".  Classification agreement measures how often
            # that unaided inference matches the anchored label. This is the only
            # agreement figure; see ProviderAgreement for why there is not a
            # second one.
            if verdict is not Verdict.INDETERMINATE:
                classification_total[name] += 1
                naive = (
                    Verdict.PRESENT
                    if state is ProviderSlotState.PRESENT
                    else Verdict.PROTOCOL_SKIPPED
                )
                if naive is verdict:
                    classification_hits[name] += 1
            elif count_all:
                classification_total[name] += 1

        if inference is not ExistenceInference.INDETERMINATE and (
            truth is not GroundTruthState.UNKNOWN
        ):
            combined_total += 1
            if (inference is ExistenceInference.EXISTS) == (
                truth is GroundTruthState.PRODUCED
            ):
                combined_hits += 1
        elif count_all:
            combined_total += 1

        if position_indeterminate:
            indeterminate_positions += 1

        outcome: SlotOutcome | None = None
        if any(verdict is Verdict.PROVIDER_HOLE for verdict in verdicts.values()):
            outcome = SlotOutcome(slot, truth, states, inference, verdicts)
            candidate_holes.append(outcome)
        if any(verdict is Verdict.GROUND_TRUTH_CONFLICT for verdict in verdicts.values()):
            outcome = outcome or SlotOutcome(slot, truth, states, inference, verdicts)
            conflicts.append(outcome)
        if position_indeterminate and len(indeterminate_outcomes) < 1000:
            indeterminate_outcomes.append(
                outcome or SlotOutcome(slot, truth, states, inference, verdicts)
            )

    return ClassificationTally(
        scheduled_positions=spec.scheduled_slot_positions,
        ground_truth_produced=produced,
        ground_truth_skipped=skipped,
        ground_truth_unknown=unknown,
        verdict_counts=verdict_counts,
        inference_counts=inference_counts,
        indeterminate_positions=indeterminate_positions,
        candidate_holes=tuple(candidate_holes),
        conflicts=tuple(conflicts),
        indeterminate_outcomes=tuple(indeterminate_outcomes),
        provider_coverage=dict(covered_positions),
        provider_classification={
            name: (classification_hits[name], classification_total[name]) for name in names
        },
        combined_agreement=(combined_hits, combined_total),
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

REQUIRED_FINDING_EVIDENCE = (
    "range_response",
    "direct_response",
    "ground_truth_header",
)

#: Codes in which the provider is actually *answering* that it has no block at
#: this slot. Solana returns -32007/-32009 for a slot that was skipped or is
#: missing after a ledger jump; a null result says the same thing.
SLOT_ABSENT_RPC_CODES = frozenset({-32007, -32009})

#: The provider pruned the block. That is a retention limitation, and a
#: retention limitation is not the same claim as a data hole.
BELOW_RETENTION_RPC_CODE = -32001


#: A bare ``null`` is a *successful* response, so the transport never retries it.
#: Solana defines it as "block not confirmed", but gateway layers have been known
#: to return it for an edge-cache miss on a slot they do hold. One unretried read
#: is therefore not enough, and a confirming re-read is required before a null is
#: accepted as a denial.
#:
#: The re-read is **in-band**: same client, same endpoint, seconds later. It
#: catches a transient miss, which is the failure mode it exists for. It cannot
#: catch a gateway that consistently returns null for a slot it holds -- no
#: same-endpoint check can. That residual assumption is stated in the finding's
#: own inference text so a reader is not left to infer a stronger check than was
#: performed.
NULL_CONFIRMATION_READS = 2


def confirms_absence(call: RecordedCall) -> tuple[bool, str, str | None]:
    """Does this direct answer actually assert that no block exists?

    A failure caused by *us* -- an exhausted request budget, a transport fault, a
    node that never became healthy -- is not the provider saying "no block". It
    is the audit failing to ask. Treating the two alike is how an instrument
    manufactures findings out of its own limitations, so this function only
    accepts a semantically meaningful denial.
    """

    if not call.failed and call.result is None:
        return True, "the provider returned a null block for this slot", "null"
    if call.error_code in SLOT_ABSENT_RPC_CODES:
        return (
            True,
            f"the provider answered {call.error_code} "
            f"({call.error_message}) for this slot",
            "explicit_denial",
        )
    if call.error_code == BELOW_RETENTION_RPC_CODE:
        return (
            False,
            "the provider reports the slot is below its retention boundary "
            f"({call.error_message}); that is a retention limitation, not a "
            "demonstrated data hole",
            None,
        )
    if call.failed:
        return (
            False,
            f"the direct getBlock did not produce a usable answer "
            f"({call.error_message}) after {call.attempts} attempt(s); this run "
            "could not establish that the provider lacks the block",
            None,
        )
    return (
        False,
        "the direct getBlock returned a block, contradicting the batch omission",
        None,
    )


@dataclass(frozen=True, slots=True)
class BlockFinding:
    """A conclusive block-level finding.  Every field below must be populated."""

    slot: int
    provider: str
    verdict: Verdict
    blockhash: str
    previous_blockhash: str
    parent_slot: int
    source: str
    inference: str
    evidence: Mapping[str, EvidenceRef]
    corroborating_providers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("blockhash", "previous_blockhash", "source", "inference"):
            if not getattr(self, name):
                raise AuditError(
                    f"a conclusive finding must not have a null {name}; record an "
                    "indeterminate matter instead"
                )
        if self.parent_slot is None or self.parent_slot < 0:
            raise AuditError("a conclusive finding must have a real parentSlot")

    @property
    def missing_evidence(self) -> tuple[str, ...]:
        return tuple(name for name in REQUIRED_FINDING_EVIDENCE if name not in self.evidence)

    @property
    def complete(self) -> bool:
        return not self.missing_evidence

    def to_payload(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "provider": self.provider,
            "verdict": self.verdict.value,
            "blockhash": self.blockhash,
            "previousBlockhash": self.previous_blockhash,
            "parentSlot": self.parent_slot,
            "source": self.source,
            "inference": self.inference,
            "corroborating_providers": list(self.corroborating_providers),
            "evidence": {
                name: ref.to_payload() for name, ref in sorted(self.evidence.items())
            },
            "evidence_complete": self.complete,
            "missing_evidence": list(self.missing_evidence),
        }


@dataclass(frozen=True, slots=True)
class IndeterminateMatter:
    """Something the run could not determine, recorded rather than guessed."""

    slot: int | None
    subject: str
    reason: str
    evidence: tuple[EvidenceRef, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "subject": self.subject,
            "reason": self.reason,
            "evidence": [ref.to_payload() for ref in self.evidence],
        }


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NegativeControlResult:
    """The outcome of one shipped, end-to-end negative control."""

    control_id: str
    title: str
    detected: bool
    detail: str
    observed: Mapping[str, object] = field(default_factory=dict)
    evidence: tuple[EvidenceRef, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "detected": self.detected,
            "detail": self.detail,
            "observed": dict(self.observed),
            "evidence": [ref.to_payload() for ref in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class RequestStats:
    """How much work a provider actually cost, and whether it was cut short."""

    provider: str
    logical_calls: int
    attempts: int
    retries: int
    budget_limit: int | None
    budget_exhausted: bool

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "logical_calls": self.logical_calls,
            "attempts": self.attempts,
            "retries": self.retries,
            "budget_limit": self.budget_limit,
            "budget_exhausted": self.budget_exhausted,
        }


@dataclass(frozen=True, slots=True)
class AuditRun:
    """Everything one run produced, including its own self-assessment."""

    scope: Mapping[str, object]
    spec: EpochGroundTruthSpec
    ground_truth: GroundTruth
    collections: tuple[ProviderCollection, ...]
    frozen_inference: EvidenceRef
    tally: ClassificationTally
    findings: tuple[BlockFinding, ...]
    indeterminate: tuple[IndeterminateMatter, ...]
    token_results: Mapping[str, TokenReconciliation]
    continuity: tuple[ContinuityResult, ...]
    provider_agreements: tuple[ProviderAgreement, ...]
    combined_agreement: CombinedInferenceAgreement
    negative_controls: tuple[NegativeControlResult, ...]
    request_stats: tuple[RequestStats, ...]
    assessment: InstrumentAssessment
    conclusion: RunConclusion
    provenance: ToolProvenance
    evidence_root: Path
    manifest: EvidenceRef | None = None
    summary_evidence: EvidenceRef | None = None
    result_evidence: EvidenceRef | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "conclusion": self.conclusion.to_payload(),
            "scope": dict(self.scope),
            "provenance": self.provenance.to_payload(),
            "ground_truth": self.ground_truth.to_payload(),
            "providers": [item.to_payload() for item in self.collections],
            "frozen_provider_only_inference": self.frozen_inference.to_payload(),
            "classification": self.tally.to_payload(),
            "agreement": {
                "per_provider": [item.to_payload() for item in self.provider_agreements],
                "combined_two_provider_existence_inference": (
                    self.combined_agreement.to_payload()
                ),
            },
            "findings": [item.to_payload() for item in self.findings],
            "indeterminate_matters": [item.to_payload() for item in self.indeterminate],
            "token": {
                name: result.to_payload() for name, result in sorted(self.token_results.items())
            },
            "continuity": [item.to_payload() for item in self.continuity],
            "negative_controls": [item.to_payload() for item in self.negative_controls],
            "request_stats": [item.to_payload() for item in self.request_stats],
            "assessment": self.assessment.to_payload(),
            "manifest": None if self.manifest is None else self.manifest.to_payload(),
            "sealing_note": (
                "This copy was serialized before the evidence manifest closed -- "
                "which is precisely what allows it to be sealed inside that "
                "manifest. `manifest` and `provenance.run_completed_at` are "
                "therefore null here by construction, not by omission. The "
                "completed provenance is in provenance.json and the manifest "
                "digest in manifest.json, both alongside this file."
                if self.manifest is None
                else "This copy was serialized after the manifest closed."
            ),
            "sealed_reports": {
                "summary": (
                    None if self.summary_evidence is None
                    else self.summary_evidence.to_payload()
                ),
                "result": (
                    None if self.result_evidence is None
                    else self.result_evidence.to_payload()
                ),
            },
        }


def _token_scope(resolved: ResolvedEpochAuditConfig) -> TokenScope:
    token = resolved.config.token
    return TokenScope(
        program_id=token.program_id,
        account_size=token.account_size,
        mint_offset=token.mint_offset,
        amount_offset=token.amount_offset,
        state_offset=token.state_offset,
        supply_offset=token.supply_offset,
        included_account_states=parse_account_states(token.included_account_states),
        zero_balance_policy=ZeroBalancePolicy(token.zero_balance_policy),
        duplicate_pubkey_policy=DuplicatePubkeyPolicy(token.duplicate_pubkey_policy),
    )


def _context_slot(result: object) -> int | None:
    if isinstance(result, Mapping):
        context = result.get("context")
        if isinstance(context, Mapping):
            slot = context.get("slot")
            if isinstance(slot, int) and not isinstance(slot, bool):
                return slot
    return None


async def _audit_token(
    client: AuditRpcClient,
    *,
    resolved: ResolvedEpochAuditConfig,
    scope: TokenScope,
) -> TokenReconciliation:
    token = resolved.config.token
    pinned = resolved.config.scope.pinned_slot
    accounts_call = await client.get_program_accounts(
        scope.program_id,
        mint=token.mint,
        account_size=scope.account_size,
        mint_offset=scope.mint_offset,
        min_context_slot=pinned,
    )
    mint_call = await client.get_account_info(token.mint, min_context_slot=pinned)

    reasons: list[str] = []
    if accounts_call.failed:
        reasons.append(f"getProgramAccounts failed: {accounts_call.error_message}")
    if mint_call.failed:
        reasons.append(f"getAccountInfo failed: {mint_call.error_message}")

    context_slot = _context_slot(accounts_call.result)
    value = (
        accounts_call.result.get("value")
        if isinstance(accounts_call.result, Mapping)
        else accounts_call.result
    )
    mint_value = (
        mint_call.result.get("value")
        if isinstance(mint_call.result, Mapping)
        else mint_call.result
    )
    mint_context = _context_slot(mint_call.result)
    if mint_context is not None and mint_context != pinned:
        reasons.append(
            f"mint account context slot {mint_context} is not the pinned slot {pinned}"
        )

    try:
        return reconcile_mint(
            mint=token.mint,
            pinned_slot=pinned,
            scope=scope,
            program_accounts=value if value is not None else [],
            mint_account=mint_value,
            context_slot=context_slot,
            evidence=(
                accounts_call.raw_ref,
                accounts_call.request_ref,
                mint_call.raw_ref,
                mint_call.request_ref,
            ),
            indeterminate_reasons=reasons,
        )
    except TokenError as exc:
        reasons.append(str(exc))
        return TokenReconciliation(
            mint=token.mint,
            pinned_slot=pinned,
            context_slot=context_slot,
            scope=scope,
            returned_accounts=0,
            included_accounts=0,
            excluded_accounts=0,
            duplicate_pubkeys=(),
            enumerated_total=0,
            mint_supply=None,
            evidence=(accounts_call.raw_ref, mint_call.raw_ref),
            indeterminate_reasons=tuple(reasons),
        )


def _hash_link_population(
    *,
    policy: str,
    ground_truth: GroundTruth,
    candidate_slots: Sequence[int],
) -> tuple[int, ...]:
    if policy == "all_produced_blocks":
        return tuple(sorted(ground_truth.headers))
    wanted: set[int] = set()
    produced = sorted(ground_truth.headers)
    index = {slot: position for position, slot in enumerate(produced)}
    for slot in candidate_slots:
        for neighbour in (slot - 1, slot, slot + 1):
            if neighbour in index:
                wanted.add(neighbour)
        position = index.get(slot)
        if position is not None:
            if position > 0:
                wanted.add(produced[position - 1])
            if position + 1 < len(produced):
                wanted.add(produced[position + 1])
    return tuple(sorted(wanted))


async def run_epoch_audit(
    resolved: ResolvedEpochAuditConfig,
    *,
    evidence: EvidenceStore,
    client_factory: ClientFactory,
    results_dir: str | Path,
    spec: EpochGroundTruthSpec | None = None,
    extractor: GroundTruthExtractor | None = None,
    negative_controls: Sequence[NegativeControlResult] | None = None,
    run_negative_controls: bool = True,
    chunk_size: int = DEFAULT_GETBLOCKS_CHUNK,
    now: Callable[[], str] = utc_now,
) -> AuditRun:
    """Run one complete single-epoch audit and self-assess it."""

    started_at = now()
    model = resolved.config
    chosen_spec = spec if spec is not None else pinned_spec(model.scope.epoch)
    _assert_config_matches_spec(resolved, chosen_spec)
    chosen_extractor = (
        extractor
        if extractor is not None
        else CarBlockHeaderExtractor(source_commit=chosen_spec.source_commit)
    )
    scope_payload = resolved.scope_payload()
    scope_payload["collection"] = {
        "getblocks_chunk_size": chunk_size,
        "hash_link_validation_population": model.continuity.hash_link_validation_population,
    }
    provenance = build_provenance(
        resolved_config_sha256=resolved.config_sha256(), started_at=started_at
    )
    evidence.set_provenance(provenance)
    evidence.record_json_artifact("scope.json", scope_payload)

    controls: tuple[NegativeControlResult, ...]
    if negative_controls is not None:
        controls = tuple(negative_controls)
    elif run_negative_controls:
        from .negative_controls import run_all_negative_controls

        controls = await run_all_negative_controls(
            results_dir=Path(results_dir) / "negative-controls", now=now
        )
    else:
        controls = ()
    # Re-bind each control to the artifact in *this* store, so a gate never cites
    # an evidence path that only exists inside the control's own directory.
    rebound: list[NegativeControlResult] = []
    for control in controls:
        ref = evidence.record_json_artifact(
            f"negative-control-{control.control_id}.json", control.to_payload()
        )
        rebound.append(replace(control, evidence=(ref,)))
    controls = tuple(rebound)

    clients = {provider.name: client_factory(provider) for provider in resolved.providers}
    collections: list[ProviderCollection] = []
    token_results: dict[str, TokenReconciliation] = {}
    token_scope = _token_scope(resolved)
    provider_headers: dict[str, dict[int, BlockHeader]] = {}
    indeterminate: list[IndeterminateMatter] = []

    try:
        for provider in resolved.providers:
            client = clients[provider.name]
            collections.append(
                await collect_provider(
                    client,
                    endpoint_fingerprint=provider.endpoint_fingerprint,
                    first_slot=model.scope.first_slot,
                    last_slot=model.scope.last_slot,
                    chunk_size=chunk_size,
                )
            )

        frozen = freeze_provider_inference(
            collections,
            first_slot=model.scope.first_slot,
            last_slot=model.scope.last_slot,
            evidence=evidence,
        )

        ground_truth = derive_ground_truth(
            resolved.car_path,
            spec=chosen_spec,
            extractor=chosen_extractor,
            evidence=evidence,
        )
        if not ground_truth.verified:
            for step in ground_truth.failures:
                indeterminate.append(
                    IndeterminateMatter(
                        slot=None,
                        subject="ground_truth",
                        reason=f"{step.step}: {step.detail}",
                        evidence=ground_truth.evidence_refs,
                    )
                )

        tally = classify_epoch(
            spec=chosen_spec,
            ground_truth=ground_truth,
            collections=collections,
            denominator_policy=model.thresholds.denominator_policy,
        )

        population = _hash_link_population(
            policy=model.continuity.hash_link_validation_population,
            ground_truth=ground_truth,
            candidate_slots=[item.slot for item in tally.candidate_holes],
        )
        for provider in resolved.providers:
            client = clients[provider.name]
            headers: dict[int, BlockHeader] = {}
            for slot in population:
                call = await client.get_block(slot)
                try:
                    headers[slot] = decode_block_header(
                        call.result,
                        slot=slot,
                        source=f"provider:{provider.name}",
                        evidence=(call.raw_ref, call.request_ref),
                    )
                except HeaderDecodeError as exc:
                    indeterminate.append(
                        IndeterminateMatter(
                            slot=slot,
                            subject=f"provider_header:{provider.name}",
                            reason=str(exc),
                            evidence=(call.raw_ref,),
                        )
                    )
            provider_headers[provider.name] = headers

        findings, more_indeterminate = await build_findings(
            tally=tally,
            ground_truth=ground_truth,
            collections=collections,
            clients=clients,
            evidence=evidence,
        )
        indeterminate.extend(more_indeterminate)

        for provider in resolved.providers:
            token_results[provider.name] = await _audit_token(
                clients[provider.name], resolved=resolved, scope=token_scope
            )
    finally:
        request_stats = tuple(
            RequestStats(
                provider=name,
                logical_calls=getattr(client, "call_count", 0),
                attempts=getattr(client, "attempt_count", 0),
                retries=getattr(client, "retry_count", 0),
                budget_limit=getattr(client, "max_requests", None),
                budget_exhausted=bool(getattr(client, "budget_exhausted", False)),
            )
            for name, client in clients.items()
        )
        for client in clients.values():
            await client.aclose()

    for stats in request_stats:
        if stats.budget_exhausted:
            # A budget cut-off leaves real coverage gaps. Saying so is the
            # difference between "the provider had nothing" and "we stopped
            # asking", and only one of those is a statement about the provider.
            indeterminate.append(
                IndeterminateMatter(
                    slot=None,
                    subject=f"request_budget:{stats.provider}",
                    reason=(
                        f"the configured request budget of {stats.budget_limit} was "
                        f"exhausted after {stats.attempts} attempts; any coverage gap "
                        "beyond that point is this run's doing, not the provider's"
                    ),
                )
            )

    continuity = _validate_continuity(
        ground_truth=ground_truth,
        provider_headers=provider_headers,
        population=population,
        population_name=model.continuity.hash_link_validation_population,
    )

    evidence.record_json_artifact(
        "classification.json",
        {
            "tally": tally.to_payload(),
            "findings": [item.to_payload() for item in findings],
            "indeterminate_matters": [item.to_payload() for item in indeterminate],
            "continuity": [item.to_payload() for item in continuity],
            "token": {
                name: result.to_payload() for name, result in sorted(token_results.items())
            },
        },
    )

    provider_agreements, combined_agreement = _build_agreements(
        tally=tally,
        collections=collections,
        denominator_policy=model.thresholds.denominator_policy,
    )
    assessment = build_assessment(
        resolved=resolved,
        spec=chosen_spec,
        ground_truth=ground_truth,
        tally=tally,
        findings=findings,
        continuity=continuity,
        token_results=token_results,
        collections=collections,
        controls=controls,
        provider_agreements=provider_agreements,
        combined_agreement=combined_agreement,
        evidence=evidence,
        provenance=provenance,
        frozen_inference=frozen,
    )
    reasons = tuple(
        f"{gate.gate_id}: {gate.detail}" for gate in assessment.failed_mandatory_gates
    )
    conclusion = RunConclusion(
        assessment=assessment,
        finding_count=len(findings),
        indeterminate_count=tally.indeterminate_positions,
        reasons=reasons,
    )
    evidence.record_json_artifact("assessment.json", assessment.to_payload())
    evidence.record_json_artifact("conclusion.json", conclusion.to_payload())

    draft = AuditRun(
        scope=scope_payload,
        spec=chosen_spec,
        ground_truth=ground_truth,
        collections=tuple(collections),
        frozen_inference=frozen,
        tally=tally,
        findings=findings,
        indeterminate=tuple(indeterminate),
        token_results=token_results,
        continuity=continuity,
        provider_agreements=provider_agreements,
        combined_agreement=combined_agreement,
        negative_controls=controls,
        request_stats=request_stats,
        assessment=assessment,
        conclusion=conclusion,
        provenance=provenance,
        evidence_root=evidence.root,
    )

    # The two documents a human actually reads are sealed inside the manifest,
    # not left beside it. Rendering them before finalize is what lets the
    # closed-world check cover the conclusion as well as the raw material.
    from .report import render_result_bytes, render_summary

    summary_bytes = render_summary(draft, results_dir=results_dir).encode("utf-8")
    result_bytes = render_result_bytes(draft)
    summary_ref = evidence.record_artifact("summary.md", summary_bytes)
    result_ref = evidence.record_artifact("result.json", result_bytes)

    completed = provenance.completed(now())
    manifest = evidence.finalize(provenance=completed)

    return replace(
        draft,
        provenance=completed,
        manifest=manifest,
        summary_evidence=summary_ref,
        result_evidence=result_ref,
    )


def _assert_config_matches_spec(
    resolved: ResolvedEpochAuditConfig, spec: EpochGroundTruthSpec
) -> None:
    """Configuration must *restate* the pinned constants, never redefine them."""

    model = resolved.config
    mismatches: list[str] = []
    checks = (
        ("scope.epoch", model.scope.epoch, spec.epoch),
        ("scope.first_slot", model.scope.first_slot, spec.first_slot),
        ("scope.last_slot", model.scope.last_slot, spec.last_slot),
        (
            "scope.scheduled_slot_positions",
            model.scope.scheduled_slot_positions,
            spec.scheduled_slot_positions,
        ),
        ("ground_truth.car_sha256", model.ground_truth.car_sha256, spec.car_sha256),
        ("ground_truth.car_root_cid", model.ground_truth.car_root_cid, spec.car_root_cid),
        ("ground_truth.source_commit", model.ground_truth.source_commit, spec.source_commit),
        (
            "ground_truth.slots_file_name",
            model.ground_truth.slots_file_name,
            spec.slots_file_name,
        ),
        (
            "ground_truth.predecessor_boundary_slot",
            model.ground_truth.predecessor_boundary_slot,
            spec.predecessor_boundary_slot,
        ),
        ("ground_truth.produced_blocks", model.ground_truth.produced_blocks, spec.produced_blocks),
        ("ground_truth.skipped_slots", model.ground_truth.skipped_slots, spec.skipped_slots),
    )
    for name, configured, pinned in checks:
        if configured != pinned:
            mismatches.append(f"{name}: config says {configured!r}, this build pins {pinned!r}")
    if mismatches:
        raise AuditError(
            "Configuration disagrees with the pinned ground-truth specification. The "
            "pinned values are authoritative; restating them wrongly cannot change them. "
            + "; ".join(mismatches)
        )


async def build_findings(
    *,
    tally: ClassificationTally,
    ground_truth: GroundTruth,
    collections: Sequence[ProviderCollection],
    clients: Mapping[str, AuditRpcClient],
    evidence: EvidenceStore,
) -> tuple[tuple[BlockFinding, ...], list[IndeterminateMatter]]:
    """Turn candidate holes into findings, or into honest indeterminate matters."""

    by_name = {collection.provider: collection for collection in collections}
    findings: list[BlockFinding] = []
    indeterminate: list[IndeterminateMatter] = []

    for outcome in tally.candidate_holes:
        slot = outcome.slot
        header = ground_truth.header_for(slot)
        for provider, verdict in outcome.verdicts.items():
            if verdict is not Verdict.PROVIDER_HOLE:
                continue
            collection = by_name[provider]
            range_response = collection.range_response_for(slot)
            direct = await clients[provider].get_block(slot)
            refs: dict[str, EvidenceRef] = {"direct_response": direct.raw_ref}
            if range_response is not None:
                refs["range_response"] = range_response.raw
                refs["range_request"] = range_response.request
            refs["direct_request"] = direct.request_ref

            peers = [
                name
                for name, state in outcome.provider_states.items()
                if name != provider and state is ProviderSlotState.PRESENT
            ]
            for peer in peers:
                peer_call = await clients[peer].get_block(slot)
                refs["peer_response"] = peer_call.raw_ref
                break

            confirmed, absence_detail, basis = confirms_absence(direct)
            if confirmed and basis == "null":
                # A null is not retried by the transport, so a single one is a
                # single unreplicated observation. Re-read before founding a
                # conclusive finding on it. In-band only; see the note on
                # NULL_CONFIRMATION_READS for what that cannot establish.
                second = await clients[provider].get_block(slot)
                refs["direct_response_confirmation"] = second.raw_ref
                again, second_detail, second_basis = confirms_absence(second)
                if not again:
                    confirmed = False
                    absence_detail = (
                        "the first direct read returned null but a confirming "
                        f"re-read did not agree ({second_detail}); a single "
                        "unreplicated null is not evidence that the provider lacks "
                        "the block"
                    )
                else:
                    absence_detail = (
                        f"{absence_detail}, and a confirming re-read against the "
                        f"same endpoint agreed ({second_basis}). Both reads are "
                        "in-band, so this rules out a transient miss but not an "
                        "endpoint that consistently returns null for a slot it holds"
                    )
            if not confirmed:
                indeterminate.append(
                    IndeterminateMatter(
                        slot=slot,
                        subject=f"provider_hole:{provider}",
                        reason=absence_detail,
                        evidence=tuple(refs.values()),
                    )
                )
                continue

            if header is None:
                indeterminate.append(
                    IndeterminateMatter(
                        slot=slot,
                        subject=f"provider_hole:{provider}",
                        reason=(
                            "the ground-truth header for this slot could not be retrieved or "
                            "derived, so no conclusive PROVIDER_HOLE may be emitted"
                        ),
                        evidence=tuple(refs.values()),
                    )
                )
                continue
            refs["ground_truth_header"] = evidence.record_json_artifact(
                f"ground-truth-header-{slot}.json", header.to_payload()
            )
            parent_header = ground_truth.header_for(header.parent_slot)
            if parent_header is not None:
                refs["parent_response"] = evidence.record_json_artifact(
                    f"ground-truth-parent-{slot}.json", parent_header.to_payload()
                )
            inference = (
                "ground truth derived from the verified Old Faithful CAR shows a produced "
                f"block at slot {slot}"
            )
            if peers:
                inference += f"; peer provider(s) {', '.join(sorted(peers))} returned it"
            inference += (
                f"; {provider} successfully enumerated the range containing slot {slot} "
                f"and omitted it, and {absence_detail}"
            )
            findings.append(
                BlockFinding(
                    slot=slot,
                    provider=provider,
                    verdict=Verdict.PROVIDER_HOLE,
                    blockhash=header.blockhash,
                    previous_blockhash=header.previous_blockhash,
                    parent_slot=header.parent_slot,
                    source="old_faithful_car_derived_ground_truth",
                    inference=inference,
                    evidence=refs,
                    corroborating_providers=tuple(sorted(peers)),
                )
            )

    for outcome in tally.conflicts:
        for provider, verdict in outcome.verdicts.items():
            if verdict is Verdict.GROUND_TRUTH_CONFLICT:
                collection = by_name[provider]
                range_response = collection.range_response_for(outcome.slot)
                indeterminate.append(
                    IndeterminateMatter(
                        slot=outcome.slot,
                        subject=f"ground_truth_conflict:{provider}",
                        reason=(
                            f"{provider} returned a block at slot {outcome.slot} but the "
                            "anchor classifies that position as skipped"
                        ),
                        evidence=() if range_response is None else (range_response.raw,),
                    )
                )
    return tuple(findings), indeterminate


def _validate_continuity(
    *,
    ground_truth: GroundTruth,
    provider_headers: Mapping[str, Mapping[int, BlockHeader]],
    population: Sequence[int],
    population_name: str,
) -> tuple[ContinuityResult, ...]:
    """Validate the anchor's own chain, then each provider's headers against it."""

    anchor_headers: dict[int, BlockHeader] = {}
    for slot, header in ground_truth.headers.items():
        anchor_headers[slot] = BlockHeader(
            slot=header.slot,
            blockhash=header.blockhash,
            previous_blockhash=header.previous_blockhash,
            parent_slot=header.parent_slot,
            source="ground_truth",
            evidence=ground_truth.evidence_refs,
        )
    predecessor = ground_truth.predecessor_header
    if predecessor is not None:
        anchor_headers[predecessor.slot] = BlockHeader(
            slot=predecessor.slot,
            blockhash=predecessor.blockhash,
            previous_blockhash=predecessor.previous_blockhash,
            parent_slot=predecessor.parent_slot,
            source="ground_truth_predecessor",
            evidence=ground_truth.evidence_refs,
        )
    expected_parents = {
        slot: header.parent_slot for slot, header in ground_truth.headers.items()
    }

    results = [
        validate_hash_links(
            anchor_headers,
            population=sorted(ground_truth.headers),
            population_name=f"anchor_chain::{population_name}",
        )
    ]
    for provider, headers in sorted(provider_headers.items()):
        merged = dict(anchor_headers)
        merged.update(headers)
        results.append(
            validate_hash_links(
                merged,
                population=[slot for slot in population if slot in headers],
                population_name=f"provider_chain:{provider}::{population_name}",
                expected_parents=expected_parents,
            )
        )
    return tuple(results)


def _build_agreements(
    *,
    tally: ClassificationTally,
    collections: Sequence[ProviderCollection],
    denominator_policy: str,
) -> tuple[tuple[ProviderAgreement, ...], CombinedInferenceAgreement]:
    agreements: list[ProviderAgreement] = []
    for collection in collections:
        name = collection.provider
        classification_hits, classification_total = tally.provider_classification[name]
        indeterminate = tally.verdict_counts[name][Verdict.INDETERMINATE.value]
        agreements.append(
            ProviderAgreement(
                provider=name,
                classification_numerator=classification_hits,
                classification_denominator=classification_total,
                covered_positions=tally.provider_coverage[name],
                scheduled_positions=tally.scheduled_positions,
                indeterminate_count=indeterminate,
                denominator_policy=denominator_policy,
            )
        )
    hits, total = tally.combined_agreement
    combined = CombinedInferenceAgreement(
        numerator=hits,
        denominator=total,
        indeterminate_count=tally.inference_counts[ExistenceInference.INDETERMINATE.value],
        denominator_policy=denominator_policy,
    )
    return tuple(agreements), combined


def build_assessment(
    *,
    resolved: ResolvedEpochAuditConfig,
    spec: EpochGroundTruthSpec,
    ground_truth: GroundTruth,
    tally: ClassificationTally,
    findings: Sequence[BlockFinding],
    continuity: Sequence[ContinuityResult],
    token_results: Mapping[str, TokenReconciliation],
    collections: Sequence[ProviderCollection],
    controls: Sequence[NegativeControlResult],
    provider_agreements: Sequence[ProviderAgreement],
    combined_agreement: CombinedInferenceAgreement,
    evidence: EvidenceStore,
    provenance: ToolProvenance,
    frozen_inference: EvidenceRef,
) -> InstrumentAssessment:
    """Build the one assessment object the conclusion and summary both consume."""

    thresholds = resolved.config.thresholds
    gates: list[Gate] = []
    control_by_id = {control.control_id: control for control in controls}

    for gate_id, control_id, title in (
        (
            "negative_control_provider_hole",
            "removed_known_block",
            "Removing a known block yields PROVIDER_HOLE, not PROTOCOL_SKIPPED",
        ),
        (
            "negative_control_token_truncation",
            "truncated_token_enumeration",
            "A truncated token enumeration under-reports supply by exactly the dropped balance",
        ),
        (
            "negative_control_previous_blockhash",
            "corrupted_previous_blockhash",
            "A corrupted previousBlockhash surfaces as PREVIOUS_BLOCKHASH_MISMATCH",
        ),
    ):
        control = control_by_id.get(control_id)
        if control is None:
            gates.append(
                build_gate(
                    gate_id,
                    title,
                    passed=False,
                    detail=f"negative control {control_id!r} was not run",
                )
            )
        else:
            gates.append(
                build_gate(
                    gate_id,
                    title,
                    passed=control.detected,
                    detail=control.detail,
                    evidence=control.evidence,
                    metrics={
                        key: str(value) for key, value in sorted(control.observed.items())
                    },
                )
            )

    constants = spec.provenance
    gates.append(
        build_gate(
            "ground_truth_constants_provenance",
            "The pinned constants trace to an authority",
            passed=constants.verified_against_archive,
            detail=(
                f"source: {constants.source}. {constants.note}"
                if not constants.verified_against_archive
                else f"verified; source: {constants.source}"
            ),
            metrics={
                "source": constants.source,
                "verified_against_archive": str(constants.verified_against_archive),
                "car_sha256": spec.car_sha256,
                "produced_blocks": str(spec.produced_blocks),
            },
        )
    )

    binding_failures = [f"{step.step}: {step.detail}" for step in ground_truth.failures]
    gates.append(
        build_gate(
            "ground_truth_provenance_binding",
            "Ground truth is bound to the pinned Old Faithful archive",
            passed=ground_truth.verified,
            detail=(
                "every link of the trust chain passed"
                if ground_truth.verified
                else "; ".join(binding_failures)
            ),
            evidence=ground_truth.evidence_refs,
            metrics={
                "car_sha256_expected": spec.car_sha256,
                "car_sha256_observed": str(ground_truth.car_sha256),
                "car_root_cid": spec.car_root_cid,
                "extractor_commit": ground_truth.extractor.source_commit,
                "extractor": ground_truth.extractor.name,
            },
        )
    )

    coverage_ok = (
        ground_truth.verified
        and ground_truth.produced_count == spec.produced_blocks
        and ground_truth.skipped_count == spec.skipped_slots
        and tally.ground_truth_unknown == 0
        and ground_truth.filtered_predecessor_rows >= 1
    )
    gates.append(
        build_gate(
            "ground_truth_full_epoch_coverage",
            "Ground truth covers every scheduled position of the epoch",
            passed=coverage_ok,
            detail=(
                f"derived {ground_truth.produced_count} produced and "
                f"{ground_truth.skipped_count} skipped positions across "
                f"{spec.scheduled_slot_positions} scheduled positions; "
                f"{ground_truth.filtered_predecessor_rows} predecessor boundary row(s) "
                f"filtered at slot {spec.predecessor_boundary_slot}"
            ),
            evidence=ground_truth.evidence_refs,
            metrics={
                "produced_expected": str(spec.produced_blocks),
                "produced_derived": str(ground_truth.produced_count),
                "skipped_expected": str(spec.skipped_slots),
                "skipped_derived": str(ground_truth.skipped_count),
                "positions_without_ground_truth": str(tally.ground_truth_unknown),
                "filtered_predecessor_rows": str(ground_truth.filtered_predecessor_rows),
            },
        )
    )

    minimum = thresholds.minimum_provider_agreement
    agreement_metrics: dict[str, str] = {}
    agreement_ok = bool(provider_agreements)
    for agreement in provider_agreements:
        classification = agreement.classification_rate
        agreement_metrics[f"{agreement.provider}.classification_agreement"] = format_rate(
            classification
        )
        agreement_metrics[f"{agreement.provider}.classification_numerator"] = str(
            agreement.classification_numerator
        )
        agreement_metrics[f"{agreement.provider}.classification_denominator"] = str(
            agreement.classification_denominator
        )
        agreement_metrics[f"{agreement.provider}.coverage_completeness"] = format_rate(
            agreement.coverage_rate
        )
        agreement_metrics[f"{agreement.provider}.covered_positions"] = str(
            agreement.covered_positions
        )
        agreement_metrics[f"{agreement.provider}.indeterminate"] = str(
            agreement.indeterminate_count
        )
        if not at_least(classification, minimum):
            agreement_ok = False
    agreement_metrics["combined_inference_agreement"] = format_rate(combined_agreement.rate)
    agreement_metrics["combined_inference_numerator"] = str(combined_agreement.numerator)
    agreement_metrics["combined_inference_denominator"] = str(combined_agreement.denominator)
    agreement_metrics["denominator_policy"] = combined_agreement.denominator_policy
    agreement_metrics["minimum_provider_agreement"] = str(minimum)
    gates.append(
        build_gate(
            "per_provider_agreement",
            "Each provider separately meets the configured minimum agreement",
            passed=agreement_ok,
            detail=(
                "; ".join(
                    f"{item.provider} classification agreement="
                    f"{format_percent(item.classification_rate)} "
                    f"({item.classification_numerator}/{item.classification_denominator}), "
                    f"coverage={format_percent(item.coverage_rate)} "
                    f"({item.covered_positions}/{item.scheduled_positions})"
                    for item in provider_agreements
                )
                or "no provider agreement could be computed"
            ),
            evidence=(frozen_inference,),
            metrics=agreement_metrics,
        )
    )

    indeterminate_rate = exact_rate(
        tally.indeterminate_positions, spec.scheduled_slot_positions
    )
    indeterminate_ok = within_threshold(
        indeterminate_rate, thresholds.indeterminate_threshold
    )
    gates.append(
        build_gate(
            "indeterminate_threshold",
            "Indeterminate positions stay within the configured threshold",
            passed=indeterminate_ok,
            detail=(
                f"{tally.indeterminate_positions}/{spec.scheduled_slot_positions} positions "
                f"({format_percent(indeterminate_rate)}) are indeterminate against a "
                f"threshold of {thresholds.indeterminate_threshold}"
            ),
            metrics={
                "numerator": str(tally.indeterminate_positions),
                "denominator": str(spec.scheduled_slot_positions),
                "rate": format_rate(indeterminate_rate),
                "threshold": str(thresholds.indeterminate_threshold),
                "denominator_policy": thresholds.denominator_policy,
            },
        )
    )

    pinned = resolved.config.scope.pinned_slot
    context_details: list[str] = []
    exact_ok = bool(token_results) and len(token_results) == len(collections)
    for name, result in sorted(token_results.items()):
        context_details.append(f"{name} context slot {result.context_slot}")
        if not result.exact_context:
            exact_ok = False
    gates.append(
        build_gate(
            "exact_pinned_slot_support",
            f"Both providers served the exact pinned slot {pinned}",
            passed=exact_ok,
            detail=(
                "; ".join(context_details) or "no provider returned a response context slot"
            ),
            metrics={
                "pinned_slot": str(pinned),
                "exact_context_policy": resolved.config.scope.exact_context_policy,
                **{
                    f"{name}.context_slot": str(result.context_slot)
                    for name, result in sorted(token_results.items())
                },
            },
            evidence=tuple(
                ref for result in token_results.values() for ref in result.evidence[:1]
            ),
        )
    )

    fingerprints = {provider.endpoint_fingerprint for provider in resolved.providers}
    hosts = {provider.host_fingerprint for provider in resolved.providers}
    anchor_fingerprint = resolved.anchor_endpoint_fingerprint
    distinct_ok = (
        len(fingerprints) == len(resolved.providers)
        and len(hosts) == len(resolved.providers)
        and (anchor_fingerprint is None or anchor_fingerprint not in fingerprints)
    )
    gates.append(
        build_gate(
            "distinct_endpoints",
            "The two providers, and the anchor, are genuinely distinct sources",
            passed=distinct_ok,
            detail=(
                f"{len(fingerprints)} distinct endpoint fingerprint(s) and {len(hosts)} "
                f"distinct host fingerprint(s) across {len(resolved.providers)} providers"
            ),
            metrics={
                **{
                    f"{provider.name}.endpoint_fingerprint": provider.endpoint_fingerprint
                    for provider in resolved.providers
                },
                **{
                    f"{provider.name}.host_fingerprint": provider.host_fingerprint
                    for provider in resolved.providers
                },
                "anchor.endpoint_fingerprint": str(anchor_fingerprint),
            },
        )
    )

    incomplete = [finding for finding in findings if not finding.complete]
    null_fields = [
        finding
        for finding in findings
        if not (finding.blockhash and finding.previous_blockhash and finding.source)
    ]
    evidence_ok = not incomplete and not null_fields
    gates.append(
        build_gate(
            "finding_evidence_completeness",
            "Every conclusive finding carries the evidence needed to re-perform it",
            passed=evidence_ok,
            detail=(
                f"{len(findings)} conclusive finding(s); "
                f"{len(incomplete)} missing required evidence; "
                f"{len(null_fields)} with a null header field"
            ),
            metrics={
                "findings": str(len(findings)),
                "incomplete": str(len(incomplete)),
                "required_evidence": ", ".join(REQUIRED_FINDING_EVIDENCE),
                **{
                    f"slot_{finding.slot}.missing": ", ".join(finding.missing_evidence)
                    for finding in incomplete
                },
            },
        )
    )

    integrity_failures: list[str] = []
    for relative, ref in sorted(evidence.entries.items()):
        path = evidence.root / relative
        if not path.is_file():
            integrity_failures.append(f"missing {relative}")
            continue
        data = path.read_bytes()
        from .evidence import sha256_hex

        if sha256_hex(data) != ref.sha256 or len(data) != ref.byte_length:
            integrity_failures.append(f"modified {relative}")
    declared = set(evidence.entries)
    from .evidence import MANIFEST_NAME, PROVENANCE_NAME

    on_disk = {
        path.relative_to(evidence.root).as_posix()
        for path in evidence.root.rglob("*")
        if path.is_file()
    }
    unexpected = sorted(on_disk - declared - {MANIFEST_NAME, PROVENANCE_NAME})
    provenance_ok = provenance.package_version and provenance.run_started_at
    manifest_ok = not integrity_failures and not unexpected and bool(provenance_ok)
    gates.append(
        build_gate(
            "manifest_provenance_completeness",
            "Evidence is complete, unmodified and fully attributed",
            passed=manifest_ok,
            detail=(
                f"{len(declared)} manifested artifact(s); "
                f"{len(integrity_failures)} integrity failure(s); "
                f"{len(unexpected)} unexpected file(s)"
            ),
            metrics={
                "manifested_entries": str(len(declared)),
                "integrity_failures": ", ".join(integrity_failures) or "none",
                "unexpected_files": ", ".join(unexpected) or "none",
                "package_version": provenance.package_version,
                "source_tree_sha256": provenance.source_tree_sha256,
                "python_version": provenance.python_version,
                "resolved_config_sha256": provenance.resolved_config_sha256,
                "run_started_at": provenance.run_started_at,
            },
        )
    )

    # Materiality. Previously this configured value was validated, echoed and
    # printed but never consumed, which invited a reader to assume the numbers
    # below had been weighed against it. They now are.
    materiality = thresholds.materiality_threshold
    finding_rate = exact_rate(len(findings), spec.scheduled_slot_positions)
    material_reasons: list[str] = []
    if finding_rate is not None and not within_threshold(finding_rate, materiality):
        material_reasons.append(
            f"{len(findings)} finding(s) over {spec.scheduled_slot_positions} "
            f"scheduled positions ({format_percent(finding_rate)}) exceeds the "
            f"materiality threshold {materiality}"
        )
    token_rates: dict[str, str] = {}
    for name, result in sorted(token_results.items()):
        difference = result.signed_difference
        if difference is None or not result.mint_supply:
            token_rates[f"{name}.token_discrepancy_rate"] = "n/a"
            continue
        rate = exact_rate(abs(difference), result.mint_supply)
        token_rates[f"{name}.token_discrepancy_rate"] = format_rate(rate)
        if not within_threshold(rate, materiality):
            material_reasons.append(
                f"{name} token discrepancy of {difference} base units "
                f"({format_percent(rate)} of supply) exceeds the materiality "
                f"threshold {materiality}"
            )
    gates.append(
        build_gate(
            "materiality_assessment",
            "Observed discrepancies weighed against the configured materiality",
            passed=not material_reasons,
            detail=(
                "; ".join(material_reasons)
                if material_reasons
                else f"nothing observed exceeds the materiality threshold {materiality}"
            ),
            mandatory=False,
            metrics={
                "materiality_threshold": str(materiality),
                "finding_count": str(len(findings)),
                "finding_rate": format_rate(finding_rate),
                "material": str(bool(material_reasons)),
                **token_rates,
            },
        )
    )

    chain_failures = [
        result for result in continuity if not (result.clean or result.vacuous)
    ]
    vacuous = [result for result in continuity if result.vacuous]
    checked = sum(result.checked for result in continuity)
    gates.append(
        build_gate(
            "hash_link_continuity",
            "Validated hash links are consistent with the anchor",
            passed=not chain_failures,
            detail=(
                "; ".join(
                    f"{result.population}: {sorted(result.outcomes)}"
                    for result in chain_failures
                )
                or (
                    f"all {checked} validated link(s) matched"
                    if checked
                    else "NO links were validated; this gate establishes nothing"
                )
            ),
            mandatory=False,
            metrics={
                "links_checked": str(checked),
                "vacuous_populations": ", ".join(item.population for item in vacuous)
                or "none",
                **{
                    result.population: (
                        f"{result.checked} checked, {len(result.mismatches)} mismatched"
                    )
                    for result in continuity
                },
            },
        )
    )

    token_ok = bool(token_results) and all(
        result.reconciled for result in token_results.values()
    )
    gates.append(
        build_gate(
            "token_supply_reconciliation",
            "Enumerated token accounts reconcile with the mint supply",
            passed=token_ok,
            detail="; ".join(
                f"{name}: signed difference {result.signed_difference} base units"
                for name, result in sorted(token_results.items())
            )
            or "no token reconciliation was produced",
            mandatory=False,
            metrics={
                f"{name}.signed_difference_base_units": str(result.signed_difference)
                for name, result in sorted(token_results.items())
            },
        )
    )
    return InstrumentAssessment(gates=tuple(gates))


__all__ = [
    "DEFAULT_GETBLOCKS_CHUNK",
    "BELOW_RETENTION_RPC_CODE",
    "REQUIRED_FINDING_EVIDENCE",
    "SLOT_ABSENT_RPC_CODES",
    "AuditError",
    "AuditRun",
    "BlockFinding",
    "ClassificationTally",
    "IndeterminateMatter",
    "NegativeControlResult",
    "ProviderCollection",
    "RangeResponse",
    "RequestStats",
    "SlotOutcome",
    "build_assessment",
    "build_findings",
    "classify_epoch",
    "collect_provider",
    "confirms_absence",
    "freeze_provider_inference",
    "run_epoch_audit",
]
