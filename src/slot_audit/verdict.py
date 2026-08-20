"""The closed verdict taxonomy used by every audit pass."""

from enum import StrEnum


class Verdict(StrEnum):
    PRESENT = "PRESENT"
    PROTOCOL_SKIPPED = "PROTOCOL_SKIPPED"
    PROVIDER_HOLE = "PROVIDER_HOLE"
    BEFORE_RETENTION = "BEFORE_RETENTION"
    INDETERMINATE = "INDETERMINATE"
    #: The provider served a block at a position the anchor calls skipped.
    #: Never a hole and never a skip: something is wrong with one of the two,
    #: and the audit must say so rather than pick a winner.
    GROUND_TRUTH_CONFLICT = "GROUND_TRUTH_CONFLICT"


class GroundTruthState(StrEnum):
    PRODUCED = "PRODUCED"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"


class ProviderSlotState(StrEnum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    UNCOVERED = "UNCOVERED"


class ExistenceInference(StrEnum):
    """What the two providers, taken together, imply about a slot."""

    EXISTS = "EXISTS"
    ABSENT = "ABSENT"
    INDETERMINATE = "INDETERMINATE"


__all__ = [
    "ExistenceInference",
    "GroundTruthState",
    "ProviderSlotState",
    "Verdict",
]
