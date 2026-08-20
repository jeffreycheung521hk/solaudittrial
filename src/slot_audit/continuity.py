"""Decode block headers and validate the previous-blockhash chain.

:func:`decode_block_header` is the single boundary at which raw provider or
archive bytes become a typed header.  Everything downstream -- classification,
findings, continuity -- consumes the result of this function, so a corruption
injected into a raw response is a corruption the production audit must see.

The chain check is deliberately literal: for a produced slot ``S`` whose parent
is ``P``, ``header(S).previousBlockhash`` must equal ``header(P).blockhash``.  A
missing parent is indeterminate, never "fine".
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .car import is_base58_hash
from .evidence import EvidenceRef


class HeaderDecodeError(ValueError):
    """A ``getBlock`` payload is not a usable block header."""


class LinkOutcome(StrEnum):
    OK = "OK"
    PREVIOUS_BLOCKHASH_MISMATCH = "PREVIOUS_BLOCKHASH_MISMATCH"
    PARENT_SLOT_MISMATCH = "PARENT_SLOT_MISMATCH"
    MISSING_PARENT_HEADER = "MISSING_PARENT_HEADER"


@dataclass(frozen=True, slots=True)
class BlockHeader:
    """A decoded block header plus the evidence it was decoded from."""

    slot: int
    blockhash: str
    previous_blockhash: str
    parent_slot: int
    source: str
    evidence: tuple[EvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        if self.slot < 0 or self.parent_slot < 0:
            raise HeaderDecodeError("slots must be non-negative")
        if not self.source:
            raise HeaderDecodeError("a header must record where it came from")

    @property
    def is_complete(self) -> bool:
        """True only when every field a conclusive finding needs is populated."""

        return bool(
            is_base58_hash(self.blockhash)
            and is_base58_hash(self.previous_blockhash)
            and self.parent_slot < self.slot
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "blockhash": self.blockhash,
            "previousBlockhash": self.previous_blockhash,
            "parentSlot": self.parent_slot,
            "source": self.source,
            "evidence": [ref.to_payload() for ref in self.evidence],
        }


def decode_block_header(
    payload: Any,
    *,
    slot: int,
    source: str,
    evidence: Sequence[EvidenceRef] = (),
) -> BlockHeader:
    """Decode a ``getBlock`` result into a header without repairing it.

    Missing or malformed fields raise.  The audit must record an indeterminate
    matter rather than emit a finding with null hashes, and it can only do that
    if this function refuses to invent values.
    """

    if payload is None:
        raise HeaderDecodeError(f"getBlock returned null for slot {slot}")
    if not isinstance(payload, Mapping):
        raise HeaderDecodeError(f"getBlock result for slot {slot} is not an object")
    missing = [
        key for key in ("blockhash", "previousBlockhash", "parentSlot") if key not in payload
    ]
    if missing:
        raise HeaderDecodeError(
            f"getBlock result for slot {slot} is missing {', '.join(missing)}"
        )
    blockhash = payload["blockhash"]
    previous = payload["previousBlockhash"]
    parent_slot = payload["parentSlot"]
    if not isinstance(blockhash, str) or not isinstance(previous, str):
        raise HeaderDecodeError(f"getBlock result for slot {slot} has non-string hashes")
    if isinstance(parent_slot, bool) or not isinstance(parent_slot, int):
        raise HeaderDecodeError(f"getBlock result for slot {slot} has a non-integer parentSlot")
    return BlockHeader(
        slot=slot,
        blockhash=blockhash,
        previous_blockhash=previous,
        parent_slot=parent_slot,
        source=source,
        evidence=tuple(evidence),
    )


@dataclass(frozen=True, slots=True)
class HashLink:
    """One validated parent/child relationship."""

    slot: int
    parent_slot: int
    previous_blockhash: str | None
    parent_blockhash: str | None
    outcome: LinkOutcome
    detail: str
    evidence: tuple[EvidenceRef, ...] = ()

    @property
    def ok(self) -> bool:
        return self.outcome is LinkOutcome.OK

    def to_payload(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "parentSlot": self.parent_slot,
            "previousBlockhash": self.previous_blockhash,
            "parentBlockhash": self.parent_blockhash,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "evidence": [ref.to_payload() for ref in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class ContinuityResult:
    """The outcome of validating a declared hash-link population."""

    population: str
    population_size: int
    links: tuple[HashLink, ...]

    @property
    def checked(self) -> int:
        return len(self.links)

    @property
    def mismatches(self) -> tuple[HashLink, ...]:
        return tuple(
            link for link in self.links if link.outcome is LinkOutcome.PREVIOUS_BLOCKHASH_MISMATCH
        )

    @property
    def parent_slot_mismatches(self) -> tuple[HashLink, ...]:
        return tuple(
            link for link in self.links if link.outcome is LinkOutcome.PARENT_SLOT_MISMATCH
        )

    @property
    def indeterminate(self) -> tuple[HashLink, ...]:
        return tuple(
            link for link in self.links if link.outcome is LinkOutcome.MISSING_PARENT_HEADER
        )

    @property
    def outcomes(self) -> tuple[str, ...]:
        return tuple(sorted({link.outcome.value for link in self.links}))

    @property
    def clean(self) -> bool:
        return all(link.ok for link in self.links)

    def to_payload(self) -> dict[str, object]:
        return {
            "population": self.population,
            "population_size": self.population_size,
            "links_checked": self.checked,
            "mismatches": len(self.mismatches),
            "parent_slot_mismatches": len(self.parent_slot_mismatches),
            "indeterminate": len(self.indeterminate),
            "outcomes": list(self.outcomes),
            "failed_links": [
                link.to_payload() for link in self.links if not link.ok
            ],
        }


def validate_hash_links(
    headers: Mapping[int, BlockHeader],
    *,
    population: Iterable[int],
    population_name: str,
    expected_parents: Mapping[int, int] | None = None,
) -> ContinuityResult:
    """Validate ``previousBlockhash`` for every slot in the population.

    ``expected_parents`` lets the caller assert the parent relationship the
    ground truth implies, so a header that points at the wrong ancestor is
    reported instead of silently validating against itself.
    """

    slots = sorted(set(population))
    links: list[HashLink] = []
    for slot in slots:
        header = headers.get(slot)
        if header is None:
            continue
        expected_parent = None if expected_parents is None else expected_parents.get(slot)
        if expected_parent is not None and header.parent_slot != expected_parent:
            links.append(
                HashLink(
                    slot=slot,
                    parent_slot=header.parent_slot,
                    previous_blockhash=header.previous_blockhash,
                    parent_blockhash=None,
                    outcome=LinkOutcome.PARENT_SLOT_MISMATCH,
                    detail=(
                        f"slot {slot} declares parentSlot {header.parent_slot} but ground "
                        f"truth says the parent is {expected_parent}"
                    ),
                    evidence=header.evidence,
                )
            )
            continue
        parent = headers.get(header.parent_slot)
        if parent is None:
            links.append(
                HashLink(
                    slot=slot,
                    parent_slot=header.parent_slot,
                    previous_blockhash=header.previous_blockhash,
                    parent_blockhash=None,
                    outcome=LinkOutcome.MISSING_PARENT_HEADER,
                    detail=(
                        f"no header is available for parent slot {header.parent_slot}; "
                        f"the link from slot {slot} is indeterminate"
                    ),
                    evidence=header.evidence,
                )
            )
            continue
        if header.previous_blockhash != parent.blockhash:
            links.append(
                HashLink(
                    slot=slot,
                    parent_slot=parent.slot,
                    previous_blockhash=header.previous_blockhash,
                    parent_blockhash=parent.blockhash,
                    outcome=LinkOutcome.PREVIOUS_BLOCKHASH_MISMATCH,
                    detail=(
                        f"slot {slot} previousBlockhash {header.previous_blockhash} does not "
                        f"equal slot {parent.slot} blockhash {parent.blockhash}"
                    ),
                    evidence=tuple(dict.fromkeys((*header.evidence, *parent.evidence))),
                )
            )
            continue
        links.append(
            HashLink(
                slot=slot,
                parent_slot=parent.slot,
                previous_blockhash=header.previous_blockhash,
                parent_blockhash=parent.blockhash,
                outcome=LinkOutcome.OK,
                detail=f"slot {slot} links to slot {parent.slot}",
                evidence=tuple(dict.fromkeys((*header.evidence, *parent.evidence))),
            )
        )
    return ContinuityResult(
        population=population_name,
        population_size=len(slots),
        links=tuple(links),
    )


__all__ = [
    "BlockHeader",
    "ContinuityResult",
    "HashLink",
    "HeaderDecodeError",
    "LinkOutcome",
    "decode_block_header",
    "validate_hash_links",
]
