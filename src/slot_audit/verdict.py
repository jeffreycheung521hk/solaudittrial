"""The closed verdict taxonomy.

Every member is anchored: a slot is only PRESENT, PROTOCOL_SKIPPED or
PROVIDER_HOLE relative to ground truth, and INDETERMINATE otherwise. The
taxonomy previously also served a reconnaissance pass that had no anchor, which
is how a cross-provider discrepancy came to be labelled PROVIDER_HOLE. Keeping
one vocabulary for two evidence standards is what let the weaker one borrow the
stronger one's authority, so there is now only one standard here.
"""

from enum import StrEnum


class Verdict(StrEnum):
    PRESENT = "PRESENT"
    PROTOCOL_SKIPPED = "PROTOCOL_SKIPPED"
    PROVIDER_HOLE = "PROVIDER_HOLE"
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
