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


#: Every gate below must pass before the run is allowed to conclude anything.
MANDATORY_GATES: tuple[str, ...] = (
    "negative_control_provider_hole",
    "negative_control_token_truncation",
    "negative_control_previous_blockhash",
    "ground_truth_provenance_binding",
    "ground_truth_full_epoch_coverage",
    "per_provider_agreement",
    "indeterminate_threshold",
    "exact_pinned_slot_support",
    "distinct_endpoints",
    "finding_evidence_completeness",
    "manifest_provenance_completeness",
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
    """Per-provider agreement, reported separately from the combined inference."""

    provider: str
    classification_numerator: int
    classification_denominator: int
    availability_numerator: int
    availability_denominator: int
    indeterminate_count: int
    denominator_policy: str

    @property
    def classification_rate(self) -> Fraction | None:
        return exact_rate(self.classification_numerator, self.classification_denominator)

    @property
    def availability_rate(self) -> Fraction | None:
        return exact_rate(self.availability_numerator, self.availability_denominator)

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "classification_agreement": {
                "numerator": self.classification_numerator,
                "denominator": self.classification_denominator,
                "rate": format_rate(self.classification_rate),
                "percent": format_percent(self.classification_rate),
            },
            "availability_agreement": {
                "numerator": self.availability_numerator,
                "denominator": self.availability_denominator,
                "rate": format_rate(self.availability_rate),
                "percent": format_percent(self.availability_rate),
            },
            "indeterminate_count": self.indeterminate_count,
            "denominator_policy": self.denominator_policy,
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
    mandatory: bool = True,
    evidence: Sequence[EvidenceRef] = (),
    metrics: Mapping[str, str] | None = None,
) -> Gate:
    return Gate(
        gate_id=gate_id,
        title=title,
        status=GateStatus.PASS if passed else GateStatus.FAIL,
        detail=detail,
        mandatory=mandatory,
        evidence=tuple(evidence),
        metrics=dict(metrics or {}),
    )


__all__ = [
    "MANDATORY_GATES",
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
