"""The single authoritative self-assessment for a run.

There is exactly one of these objects per run.  The final
:class:`RunConclusion` is derived from it, and ``summary.md`` renders it.
Nothing recomputes a gate, because two implementations of the same threshold is
precisely how a run ends up reporting ``NO_CONCLUSION`` in one file and ``PASS``
in another.

Threshold arithmetic is exact.  Counts are integers and configured thresholds
are :class:`~decimal.Decimal`, compared as :class:`~fractions.Fraction` values;
no configured threshold is ever converted to ``float``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from fractions import Fraction

from .evidence import EvidenceRef


class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


class RunResult(StrEnum):
    """The audit's answer, kept separate from the instrument's own health."""

    NO_FINDINGS = "NO_FINDINGS"
    FINDINGS = "FINDINGS"
    NO_CONCLUSION = "NO_CONCLUSION"


@dataclass(frozen=True, slots=True)
class GateSpec:
    """A gate's declared identity, independent of the code that evaluates it.

    Gate identity used to be implicit: the names lived in one module and the
    fourteen evaluations lived inside a 450-line builder in another, with only a
    runtime check tying them together. Nothing had a handle you could point a
    test at, which is why the most consequential gate in the tool shipped
    without a FAIL-path test and nobody noticed for a review round.

    Declaring gates here gives each one an addressable identity, makes this
    module the single source of truth for what is mandatory, and lets the test
    suite assert -- mechanically -- that every mandatory gate has a test which
    actually observes it failing.
    """

    gate_id: str
    title: str
    mandatory: bool
    rationale: str


GATE_REGISTRY: tuple[GateSpec, ...] = (
    GateSpec(
        "negative_control_provider_hole",
        "Removing a block known to exist yields PROVIDER_HOLE",
        True,
        "an instrument that cannot detect a planted hole cannot report a real one",
    ),
    GateSpec(
        "negative_control_token_truncation",
        "A truncated enumeration under-reports supply by exactly the dropped balance",
        True,
        "the reconciliation must be sensitive to the defect it exists to find",
    ),
    GateSpec(
        "negative_control_previous_blockhash",
        "A corrupted previousBlockhash surfaces as PREVIOUS_BLOCKHASH_MISMATCH",
        True,
        "a chain check that cannot see a break is not a chain check",
    ),
    GateSpec(
        "ground_truth_constants_provenance",
        "The pinned constants trace to an authority",
        True,
        "an anchor whose root is unsourced verifies a file against a typed number",
    ),
    GateSpec(
        "ground_truth_provenance_binding",
        "The archive is the pinned one, structurally and by digest",
        True,
        "the classification is only as good as the archive it was made against",
    ),
    GateSpec(
        "ground_truth_full_epoch_coverage",
        "Ground truth covers every scheduled position of the epoch",
        True,
        "a partial anchor silently converts unknowns into skips",
    ),
    GateSpec(
        "per_provider_agreement",
        "Each provider separately meets the configured minimum agreement",
        True,
        "a provider that disagrees wholesale is not being measured, it is broken",
    ),
    GateSpec(
        "indeterminate_threshold",
        "Indeterminate positions stay within the configured threshold",
        True,
        "a run that could not determine most of the epoch has not audited it",
    ),
    GateSpec(
        "exact_pinned_slot_support",
        "Both providers served the exact pinned slot",
        True,
        "account state measured at an unknown slot is not a measurement",
    ),
    GateSpec(
        "distinct_endpoints",
        "The two providers, and the anchor, are genuinely distinct sources",
        True,
        "one upstream answering twice is not corroboration",
    ),
    GateSpec(
        "finding_evidence_completeness",
        "Every conclusive finding carries the evidence needed to re-perform it",
        True,
        "a finding nobody else can check is an assertion, not a finding",
    ),
    GateSpec(
        "manifest_provenance_completeness",
        "Evidence is complete, unmodified and fully attributed",
        True,
        "an incomplete record cannot support any conclusion drawn from it",
    ),
    GateSpec(
        "hash_link_continuity",
        "Validated hash links are consistent with the anchor",
        False,
        "a broken link is a finding about the providers, not a malfunction here",
    ),
    GateSpec(
        "token_supply_reconciliation",
        "Enumerated token accounts reconcile with the mint supply",
        False,
        "a discrepancy is the result, and must not suppress its own reporting",
    ),
    GateSpec(
        "materiality_assessment",
        "Observed discrepancies weighed against the configured materiality",
        False,
        "materiality qualifies a result; it does not decide instrument health",
    ),
)

GATE_SPECS: Mapping[str, GateSpec] = {spec.gate_id: spec for spec in GATE_REGISTRY}

#: Derived, not restated. Adding a mandatory gate to the registry is the only
#: way to add one, so the two can never drift apart.
MANDATORY_GATES: tuple[str, ...] = tuple(
    spec.gate_id for spec in GATE_REGISTRY if spec.mandatory
)


def exact_rate(numerator: int, denominator: int) -> Fraction | None:
    """Return an exact rate, or ``None`` when the denominator is zero."""

    if denominator == 0:
        return None
    return Fraction(int(numerator), int(denominator))


def format_rate(rate: Fraction | None, *, places: int = 6) -> str:
    if rate is None:
        return "n/a"
    quantum = Decimal(1).scaleb(-places)
    value = (Decimal(rate.numerator) / Decimal(rate.denominator)).quantize(quantum)
    return f"{value}"


def format_percent(rate: Fraction | None, *, places: int = 4) -> str:
    if rate is None:
        return "n/a"
    quantum = Decimal(1).scaleb(-places)
    value = (Decimal(rate.numerator) * 100 / Decimal(rate.denominator)).quantize(quantum)
    return f"{value}%"


def within_threshold(rate: Fraction | None, threshold: Decimal) -> bool:
    """Exact ``rate <= threshold`` with no floating-point conversion."""

    if rate is None:
        return True
    return rate <= Fraction(threshold)


def at_least(rate: Fraction | None, threshold: Decimal) -> bool:
    """Exact ``rate >= threshold`` with no floating-point conversion."""

    if rate is None:
        return False
    return rate >= Fraction(threshold)


@dataclass(frozen=True, slots=True)
class Gate:
    """One mandatory or advisory validation gate and the evidence behind it."""

    gate_id: str
    title: str
    status: GateStatus
    detail: str
    mandatory: bool = True
    evidence: tuple[EvidenceRef, ...] = ()
    metrics: Mapping[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status is GateStatus.PASS

    def to_payload(self) -> dict[str, object]:
        return {
            "gate_id": self.gate_id,
            "title": self.title,
            "status": self.status.value,
            "mandatory": self.mandatory,
            "detail": self.detail,
            "metrics": dict(self.metrics),
            "evidence": [ref.to_payload() for ref in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class ProviderAgreement:
    """One provider's agreement with the anchor, plus how much it could answer.

    There is deliberately only **one** agreement number here. Against a binary
    ground truth (produced / skipped) a provider's "availability agreement" and
    its "classification agreement" are the same quantity computed twice: the
    provider is right about availability exactly when its unaided
    present-or-skipped inference matches the anchor. An earlier version of this
    class reported both, and a reader could have cited two independent-looking
    figures that were one measurement. Reporting it once is the correction.

    ``coverage_completeness`` is a genuinely different quantity: it is how much
    of the epoch this provider successfully enumerated at all, scored over every
    scheduled position and independent of what the anchor says. A provider can
    have perfect agreement over the tenth of the epoch it managed to answer for.
    """

    provider: str
    classification_numerator: int
    classification_denominator: int
    covered_positions: int
    scheduled_positions: int
    indeterminate_count: int
    denominator_policy: str

    @property
    def classification_rate(self) -> Fraction | None:
        return exact_rate(self.classification_numerator, self.classification_denominator)

    @property
    def coverage_rate(self) -> Fraction | None:
        return exact_rate(self.covered_positions, self.scheduled_positions)

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "classification_agreement": {
                "definition": (
                    "positions where this provider's unaided present-or-skipped "
                    "inference matched the anchor, over positions where both were "
                    "determinate"
                ),
                "numerator": self.classification_numerator,
                "denominator": self.classification_denominator,
                "rate": format_rate(self.classification_rate),
                "percent": format_percent(self.classification_rate),
            },
            "coverage_completeness": {
                "definition": (
                    "scheduled positions this provider successfully enumerated, "
                    "over all scheduled positions; independent of the anchor"
                ),
                "numerator": self.covered_positions,
                "denominator": self.scheduled_positions,
                "rate": format_rate(self.coverage_rate),
                "percent": format_percent(self.coverage_rate),
            },
            "indeterminate_count": self.indeterminate_count,
            "denominator_policy": self.denominator_policy,
            "note": (
                "Agreement is reported once. Against a binary ground truth, "
                "availability agreement and classification agreement are the same "
                "quantity; presenting both would be one measurement counted twice."
            ),
        }


@dataclass(frozen=True, slots=True)
class CombinedInferenceAgreement:
    """Agreement of the *two-provider existence inference* with ground truth.

    This is a different quantity from any single provider's agreement and is
    always labelled as such: it answers "did the pair, taken together, infer
    existence correctly", not "was provider A right".
    """

    numerator: int
    denominator: int
    indeterminate_count: int
    denominator_policy: str

    @property
    def rate(self) -> Fraction | None:
        return exact_rate(self.numerator, self.denominator)

    def to_payload(self) -> dict[str, object]:
        return {
            "scope": "combined_two_provider_existence_inference",
            "numerator": self.numerator,
            "denominator": self.denominator,
            "rate": format_rate(self.rate),
            "percent": format_percent(self.rate),
            "indeterminate_count": self.indeterminate_count,
            "denominator_policy": self.denominator_policy,
        }


@dataclass(frozen=True, slots=True)
class InstrumentAssessment:
    """The one object that decides whether this run may conclude anything."""

    gates: tuple[Gate, ...]

    def __post_init__(self) -> None:
        seen = [gate.gate_id for gate in self.gates]
        if len(set(seen)) != len(seen):
            raise ValueError("gate ids must be unique within an assessment")
        missing = [name for name in MANDATORY_GATES if name not in set(seen)]
        if missing:
            raise ValueError(f"assessment is missing mandatory gate(s): {', '.join(missing)}")
        # Presence is not enough. A gate named in MANDATORY_GATES but carrying
        # mandatory=False would be silently advisory, and a failing one would no
        # longer force NO_CONCLUSION -- a downgrade that reads as a passing run.
        demoted = [
            gate.gate_id
            for gate in self.gates
            if gate.gate_id in MANDATORY_GATES and not gate.mandatory
        ]
        if demoted:
            raise ValueError(
                "these gates are mandatory and may not be marked advisory: "
                + ", ".join(sorted(demoted))
            )

    def gate(self, gate_id: str) -> Gate:
        for gate in self.gates:
            if gate.gate_id == gate_id:
                return gate
        raise KeyError(gate_id)

    @property
    def failed_gates(self) -> tuple[Gate, ...]:
        return tuple(gate for gate in self.gates if not gate.passed)

    @property
    def failed_mandatory_gates(self) -> tuple[Gate, ...]:
        return tuple(gate for gate in self.gates if gate.mandatory and not gate.passed)

    @property
    def status(self) -> GateStatus:
        return GateStatus.FAIL if self.failed_mandatory_gates else GateStatus.PASS

    @property
    def passed(self) -> bool:
        return self.status is GateStatus.PASS

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "gate_count": len(self.gates),
            "passed_gates": sum(1 for gate in self.gates if gate.passed),
            "failed_mandatory_gates": [gate.gate_id for gate in self.failed_mandatory_gates],
            "gates": [gate.to_payload() for gate in self.gates],
        }


@dataclass(frozen=True, slots=True)
class RunConclusion:
    """The run's result, derived from -- never alongside -- the assessment."""

    assessment: InstrumentAssessment
    finding_count: int
    indeterminate_count: int
    reasons: tuple[str, ...] = ()

    @property
    def result(self) -> RunResult:
        if not self.assessment.passed:
            return RunResult.NO_CONCLUSION
        return RunResult.FINDINGS if self.finding_count else RunResult.NO_FINDINGS

    @property
    def blocked_by(self) -> tuple[str, ...]:
        return tuple(gate.gate_id for gate in self.assessment.failed_mandatory_gates)

    def to_payload(self) -> dict[str, object]:
        return {
            "result": self.result.value,
            "instrument_validation_status": self.assessment.status.value,
            "blocked_by_failed_gates": list(self.blocked_by),
            "finding_count": self.finding_count,
            "indeterminate_count": self.indeterminate_count,
            "reasons": list(self.reasons),
        }


def build_gate(
    gate_id: str,
    title: str,
    *,
    passed: bool,
    detail: str,
    mandatory: bool | None = None,
    evidence: Sequence[EvidenceRef] = (),
    metrics: Mapping[str, str] | None = None,
) -> Gate:
    """Construct a gate, taking its mandatory status from the registry.

    ``mandatory`` may be passed only to restate what the registry already says.
    Disagreeing with it raises: a caller must not be able to downgrade a gate at
    the point of construction, which is the one place such a change would look
    like an ordinary keyword argument.
    """

    spec = GATE_SPECS.get(gate_id)
    if spec is None:
        raise ValueError(
            f"gate {gate_id!r} is not in GATE_REGISTRY; declare it there so it "
            "gains an identity the test suite can require coverage for"
        )
    if mandatory is not None and mandatory != spec.mandatory:
        raise ValueError(
            f"gate {gate_id!r} is registered as "
            f"{'mandatory' if spec.mandatory else 'advisory'} and cannot be "
            "constructed as the opposite"
        )
    return Gate(
        gate_id=gate_id,
        title=title,
        status=GateStatus.PASS if passed else GateStatus.FAIL,
        detail=detail,
        mandatory=spec.mandatory,
        evidence=tuple(evidence),
        metrics=dict(metrics or {}),
    )


__all__ = [
    "GATE_REGISTRY",
    "GATE_SPECS",
    "MANDATORY_GATES",
    "GateSpec",
    "CombinedInferenceAgreement",
    "Gate",
    "GateStatus",
    "InstrumentAssessment",
    "ProviderAgreement",
    "RunConclusion",
    "RunResult",
    "at_least",
    "build_gate",
    "exact_rate",
    "format_percent",
    "format_rate",
    "within_threshold",
]
