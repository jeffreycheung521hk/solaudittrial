"""Pass A: cheaply enumerate block-bearing slots and compare providers.

The RPC ``getBlocks`` response is already sorted.  This module deliberately keeps
that representation in a packed unsigned-64-bit array instead of expanding a
multi-million-slot audit into Python ``int`` objects or a ``set``.

Enumeration is not classification of protocol skips.  A slot omitted by one
successful ``getBlocks`` call is only a *candidate* until pointer resolution, or
until another provider returns that same slot.  Failed calls are retained as
explicit indeterminate ranges and never participate in the latter inference.
"""

from __future__ import annotations

import heapq
import inspect
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Awaitable, Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeAlias, overload

from .rpc import RequestBudgetExceeded
from .verdict import Verdict

MAX_GET_BLOCKS_SLOTS = 500_000


class EnumerationClient(Protocol):
    """The small part of :class:`RpcClient` needed by Pass A."""

    request_count: int

    async def get_first_available_block(self) -> int: ...

    async def get_blocks(self, start_slot: int, end_slot: int) -> Sequence[int]: ...


@dataclass(frozen=True, order=True, slots=True)
class SlotRange:
    """An inclusive range of Solana slots."""

    start: int
    end: int

    def __post_init__(self) -> None:
        _validate_slot(self.start, "start")
        _validate_slot(self.end, "end")
        if self.end < self.start:
            raise ValueError("slot range end must be greater than or equal to start")

    def __contains__(self, slot: object) -> bool:
        return (
            isinstance(slot, int)
            and not isinstance(slot, bool)
            and self.start <= slot <= self.end
        )

    @property
    def count(self) -> int:
        return self.end - self.start + 1


class SortedSlots(Sequence[int]):
    """Immutable, packed storage for strictly increasing non-negative slots.

    An ``array('Q')`` generally uses eight bytes per slot.  In contrast, a set of
    Python integers can require several dozen bytes per slot before allocator
    overhead, which matters for a 30-day Solana range.
    """

    __slots__ = ("_values",)

    def __init__(self, slots: Iterable[int] = ()) -> None:
        values = array("Q")
        previous: int | None = None
        for raw_slot in slots:
            slot = _validated_slot(raw_slot, "slot")
            if previous is not None:
                if slot < previous:
                    raise ValueError("slots must be sorted in ascending order")
                if slot == previous:
                    # Defensive de-duplication costs no auxiliary set and keeps
                    # RPC oddities from distorting presence counts.
                    continue
            values.append(slot)
            previous = slot
        self._values = values

    @classmethod
    def _take_array(cls, values: array[int]) -> SortedSlots:
        result = cls()
        result._values = values
        return result

    @overload
    def __getitem__(self, index: int) -> int: ...

    @overload
    def __getitem__(self, index: slice) -> SortedSlots: ...

    def __getitem__(self, index: int | slice) -> int | SortedSlots:
        if isinstance(index, slice):
            return type(self)._take_array(self._values[index])
        return int(self._values[index])

    def __iter__(self) -> Iterator[int]:
        return (int(value) for value in self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __contains__(self, slot: object) -> bool:
        if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0:
            return False
        index = bisect_left(self._values, slot)
        return index < len(self._values) and self._values[index] == slot

    def __repr__(self) -> str:
        preview = list(self._values[:8])
        suffix = ", ..." if len(self) > len(preview) else ""
        return f"SortedSlots([{', '.join(map(str, preview))}{suffix}])"

    @property
    def nbytes(self) -> int:
        """Bytes occupied by the packed values (excluding tiny object overhead)."""

        return self._values.buffer_info()[1] * self._values.itemsize

    def bisect_left(self, slot: int) -> int:
        return bisect_left(self._values, slot)

    def bisect_right(self, slot: int) -> int:
        return bisect_right(self._values, slot)


@dataclass(frozen=True, slots=True)
class ChunkEnumeration:
    """The checkpointable outcome of one inclusive ``getBlocks`` chunk."""

    provider: str
    slot_range: SlotRange
    present_slots: SortedSlots = field(default_factory=SortedSlots)
    error_type: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not self.provider:
            raise ValueError("provider name must not be empty")
        if (self.error_type is None) != (self.error_message is None):
            raise ValueError(
                "error_type and error_message must either both be set or both be absent"
            )
        if self.failed and self.present_slots:
            raise ValueError("a failed chunk cannot contain present slots")
        if not self.failed:
            for slot in self.present_slots:
                if slot not in self.slot_range:
                    raise ValueError(f"slot {slot} lies outside chunk {self.slot_range}")

    @property
    def succeeded(self) -> bool:
        return self.error_type is None

    @property
    def failed(self) -> bool:
        return not self.succeeded

    @classmethod
    def success(
        cls, provider: str, start_slot: int, end_slot: int, slots: Iterable[int]
    ) -> ChunkEnumeration:
        return cls(provider, SlotRange(start_slot, end_slot), SortedSlots(slots))

    @classmethod
    def failure(
        cls, provider: str, start_slot: int, end_slot: int, error: BaseException
    ) -> ChunkEnumeration:
        message = str(error).strip() or repr(error)
        return cls(
            provider,
            SlotRange(start_slot, end_slot),
            error_type=type(error).__name__,
            error_message=message,
        )


@dataclass(frozen=True, slots=True)
class ProviderEnumeration:
    """Compact Pass-A result for one provider."""

    provider: str
    requested_range: SlotRange
    first_available_block: int
    present_slots: SortedSlots
    successful_ranges: tuple[SlotRange, ...]
    failed_chunks: tuple[ChunkEnumeration, ...]
    request_count: int

    def __post_init__(self) -> None:
        if not self.provider:
            raise ValueError("provider name must not be empty")
        _validate_slot(self.first_available_block, "first_available_block")
        if self.request_count < 0:
            raise ValueError("request_count cannot be negative")

        successful = _coalesce_ranges(self.successful_ranges)
        object.__setattr__(self, "successful_ranges", successful)

        failed_ranges: list[SlotRange] = []
        for chunk in self.failed_chunks:
            if chunk.provider != self.provider:
                raise ValueError("failed chunk belongs to another provider")
            if not chunk.failed:
                raise ValueError("failed_chunks may only contain failed chunk outcomes")
            failed_ranges.append(chunk.slot_range)

        _validate_coverage_ranges(
            self.requested_range,
            self.first_available_block,
            successful,
            tuple(sorted(failed_ranges)),
        )
        _validate_present_coverage(self.present_slots, successful)

    @property
    def requested_start(self) -> int:
        return self.requested_range.start

    @property
    def requested_end(self) -> int:
        return self.requested_range.end

    @property
    def before_retention_range(self) -> SlotRange | None:
        end = min(self.requested_end, self.first_available_block - 1)
        if end < self.requested_start:
            return None
        return SlotRange(self.requested_start, end)

    @property
    def audited_slot_count(self) -> int:
        """Slots covered by successful calls; failures and retention are excluded."""

        return sum(slot_range.count for slot_range in self.successful_ranges)

    @property
    def failed_slot_count(self) -> int:
        return sum(chunk.slot_range.count for chunk in self.failed_chunks)

    @property
    def before_retention_slot_count(self) -> int:
        slot_range = self.before_retention_range
        return 0 if slot_range is None else slot_range.count

    @property
    def candidate_gap_count(self) -> int:
        return self.audited_slot_count - len(self.present_slots)

    def covers_successfully(self, slot: int) -> bool:
        return _ranges_contain(self.successful_ranges, slot)

    def verdict_at(self, slot: int) -> Verdict | None:
        """Return an enumeration-level verdict, or ``None`` for a candidate gap.

        ``None`` is intentional: Pass A alone cannot distinguish a protocol skip
        from a provider hole unless a corroborating provider has the block.
        """

        _validate_slot(slot, "slot")
        if slot not in self.requested_range:
            raise ValueError(f"slot {slot} is outside requested range {self.requested_range}")
        if slot < self.first_available_block:
            return Verdict.BEFORE_RETENTION
        if any(slot in chunk.slot_range for chunk in self.failed_chunks):
            return Verdict.INDETERMINATE
        if not self.covers_successfully(slot):
            # This can happen with deliberately partial/resumed input.  It is
            # never safe to treat an uncovered slot as an absent block.
            return Verdict.INDETERMINATE
        if slot in self.present_slots:
            return Verdict.PRESENT
        return None

    def iter_candidate_gap_ranges(self) -> Iterator[SlotRange]:
        """Yield missing runs only inside successful, in-retention coverage."""

        for covered in self.successful_ranges:
            cursor = covered.start
            start_index = self.present_slots.bisect_left(covered.start)
            end_index = self.present_slots.bisect_right(covered.end)
            for index in range(start_index, end_index):
                present = self.present_slots[index]
                if cursor < present:
                    yield SlotRange(cursor, present - 1)
                cursor = present + 1
            if cursor <= covered.end:
                yield SlotRange(cursor, covered.end)

    def candidate_gap_ranges(self) -> tuple[SlotRange, ...]:
        return tuple(self.iter_candidate_gap_ranges())


#: Explanations that cross-provider presence alone cannot rule out. They are
#: carried on every Pass-A row so a reader cannot mistake the row for a finding.
UNEXCLUDED_EXPLANATIONS: tuple[str, ...] = (
    "the provider silently truncated an otherwise successful getBlocks response "
    "(HTTP 200, well-formed JSON, incomplete list) -- a documented behaviour of "
    "commercial RPC gateways under internal response limits",
    "a transient backend inconsistency that a direct getBlock would not reproduce",
    "a genuine provider data hole",
)


@dataclass(frozen=True, slots=True)
class CrossProviderOmission:
    """A Pass-A *discrepancy*: one provider omitted a slot another returned.

    This is deliberately not a finding. Pass A never issues a direct ``getBlock``
    and therefore never obtains a semantically explicit denial from the provider,
    so it cannot separate a data hole from a silently truncated response. The
    single-epoch audit exists precisely to make that separation, against a
    ground-truth anchor; this class must not borrow its authority.
    """

    provider: str
    slot: int
    corroborating_providers: tuple[str, ...]
    reasoning: str
    verdict: Verdict = field(default=Verdict.UNCONFIRMED_OMISSION, init=False)

    def __post_init__(self) -> None:
        _validate_slot(self.slot, "slot")
        if not self.provider:
            raise ValueError("provider name must not be empty")
        if not self.corroborating_providers:
            raise ValueError(
                "a cross-provider omission needs at least one corroborating provider"
            )
        if self.provider in self.corroborating_providers:
            raise ValueError("a provider cannot corroborate itself")
        if not self.reasoning:
            raise ValueError("reasoning must be human-readable and non-empty")

    @property
    def confirmed(self) -> bool:
        """Always false. Pass A has no confirmation mechanism at all."""

        return False

    @property
    def evidence(self) -> dict[str, object]:
        return {
            "corroborating_providers": list(self.corroborating_providers),
            "reasoning": self.reasoning,
            "confirmed": False,
            "confirmation_method": None,
            "unexcluded_explanations": list(UNEXCLUDED_EXPLANATIONS),
        }


#: Retained so existing callers keep importing successfully. The old name made a
#: claim the class never supported.
CrossProviderHole = CrossProviderOmission


CheckpointCallback: TypeAlias = Callable[[ChunkEnumeration], Awaitable[None] | None]


def iter_inclusive_chunks(
    start_slot: int,
    end_slot: int,
    chunk_size: int = MAX_GET_BLOCKS_SLOTS,
) -> Iterator[SlotRange]:
    """Split an inclusive range without ever exceeding Solana's 500k limit."""

    _validate_slot(start_slot, "start_slot")
    _validate_slot(end_slot, "end_slot")
    if end_slot < start_slot:
        raise ValueError("end_slot must be greater than or equal to start_slot")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an integer")
    if not 1 <= chunk_size <= MAX_GET_BLOCKS_SLOTS:
        raise ValueError(f"chunk_size must be between 1 and {MAX_GET_BLOCKS_SLOTS}")

    cursor = start_slot
    while cursor <= end_slot:
        chunk_end = min(end_slot, cursor + chunk_size - 1)
        yield SlotRange(cursor, chunk_end)
        cursor = chunk_end + 1


async def enumerate_provider(
    client: EnumerationClient,
    provider: str,
    start_slot: int,
    end_slot: int,
    *,
    chunk_size: int = MAX_GET_BLOCKS_SLOTS,
    on_chunk: CheckpointCallback | None = None,
    resume_chunks: Iterable[ChunkEnumeration] = (),
    first_available_block: int | None = None,
) -> ProviderEnumeration:
    """Enumerate one provider's block-bearing slots over an inclusive range.

    The RPC client owns retry and rate-limit policy.  Any exception left after
    those retries marks precisely that chunk indeterminate.  The callback is
    invoked after every newly attempted chunk, successful or failed, and may be
    synchronous or asynchronous.
    """

    requested = SlotRange(start_slot, end_slot)
    if not provider:
        raise ValueError("provider name must not be empty")
    # Validate before making a network request.
    tuple(iter_inclusive_chunks(start_slot, end_slot, chunk_size))

    request_count_before = _client_request_count(client)
    if first_available_block is None:
        first_available = await client.get_first_available_block()
        first_available = _validated_slot(first_available, "getFirstAvailableBlock result")
    else:
        first_available = _validated_slot(first_available_block, "first_available_block")

    effective_start = max(start_slot, first_available)
    resumed = _normalize_resume_chunks(
        provider,
        requested,
        first_available,
        resume_chunks,
    )

    packed_present = array("Q")
    successful: list[SlotRange] = []
    failed: list[ChunkEnumeration] = []
    budget_error: RequestBudgetExceeded | None = None
    resume_index = 0
    cursor = effective_start

    while cursor <= end_slot:
        cached = resumed[resume_index] if resume_index < len(resumed) else None
        if cached is not None and cached.slot_range.start == cursor:
            successful.append(cached.slot_range)
            packed_present.extend(cached.present_slots._values)
            cursor = cached.slot_range.end + 1
            resume_index += 1
            continue

        uncovered_end = end_slot if cached is None else cached.slot_range.start - 1
        # Splitting each uncovered interval independently ensures every network
        # call remains <= 500k, while accepting old checkpoints whose first
        # chunk was clipped at an earlier retention boundary.
        for slot_range in iter_inclusive_chunks(cursor, uncovered_end, chunk_size):
            if budget_error is not None:
                outcome = ChunkEnumeration.failure(
                    provider, slot_range.start, slot_range.end, budget_error
                )
            else:
                try:
                    slots = await client.get_blocks(slot_range.start, slot_range.end)
                    outcome = ChunkEnumeration.success(
                        provider, slot_range.start, slot_range.end, slots
                    )
                except Exception as error:  # retry/error taxonomy belongs to RpcClient
                    outcome = ChunkEnumeration.failure(
                        provider, slot_range.start, slot_range.end, error
                    )
                    if isinstance(error, RequestBudgetExceeded):
                        # The limiter is a hard stop.  Preserve an honest partial
                        # result without pointlessly invoking it for every tail chunk.
                        budget_error = error
            if on_chunk is not None:
                callback_result = on_chunk(outcome)
                if inspect.isawaitable(callback_result):
                    await callback_result

            if outcome.succeeded:
                successful.append(slot_range)
                packed_present.extend(outcome.present_slots._values)
            else:
                failed.append(outcome)
        cursor = uncovered_end + 1

    request_count_after = _client_request_count(client)
    requests_made = max(0, request_count_after - request_count_before)
    return ProviderEnumeration(
        provider=provider,
        requested_range=requested,
        first_available_block=first_available,
        present_slots=SortedSlots._take_array(packed_present),
        successful_ranges=tuple(successful),
        failed_chunks=tuple(failed),
        request_count=requests_made,
    )


def iter_cross_provider_holes(
    enumerations: Iterable[ProviderEnumeration],
) -> Iterator[CrossProviderOmission]:
    """Merge sorted provider results and yield *unconfirmed* omissions.

    A row is emitted only when the target successfully audited that exact slot
    and omitted it, while at least one other successfully audited provider
    returned it. That excludes retention boundaries and failed chunks as causes,
    but it does not exclude silent truncation, and Pass A has no mechanism that
    could. Every row is therefore UNCONFIRMED_OMISSION, never PROVIDER_HOLE.

    Memory use is O(number of providers), apart from yielded rows.
    """

    results = tuple(enumerations)
    if len(results) < 2:
        return
    names = [result.provider for result in results]
    if len(set(names)) != len(names):
        raise ValueError("provider names must be unique for cross-provider comparison")

    # Entries are (slot, provider index, position within provider's packed array).
    heap: list[tuple[int, int, int]] = []
    for provider_index, result in enumerate(results):
        if result.present_slots:
            heapq.heappush(heap, (result.present_slots[0], provider_index, 0))

    while heap:
        slot = heap[0][0]
        present_provider_indexes: list[int] = []
        while heap and heap[0][0] == slot:
            _, provider_index, position = heapq.heappop(heap)
            source = results[provider_index]
            # ProviderEnumeration validates this invariant, but retaining the
            # guard makes the inference locally obvious and robust to subclasses.
            if source.covers_successfully(slot):
                present_provider_indexes.append(provider_index)
            next_position = position + 1
            if next_position < len(source.present_slots):
                heapq.heappush(
                    heap,
                    (source.present_slots[next_position], provider_index, next_position),
                )

        if not present_provider_indexes:
            continue
        present_indexes = set(present_provider_indexes)  # bounded by provider count
        corroborator_names = tuple(
            sorted(results[index].provider for index in present_provider_indexes)
        )
        for target_index, target in enumerate(results):
            if target_index in present_indexes or not target.covers_successfully(slot):
                continue
            corroborators = tuple(
                name for name in corroborator_names if name != target.provider
            )
            if not corroborators:
                continue
            joined = ", ".join(corroborators)
            reasoning = (
                f"{target.provider} successfully enumerated the range containing slot "
                f"{slot} but omitted it, while {joined} returned slot {slot}. That is "
                "the whole of the observation. Pass A issued no direct getBlock and "
                f"obtained no explicit denial from {target.provider}, so it has NOT "
                "established that this is a provider data hole; silent response "
                "truncation produces an identical signature. Treat this as a "
                "candidate for confirmation, never as a finding"
            )
            yield CrossProviderOmission(
                provider=target.provider,
                slot=slot,
                corroborating_providers=corroborators,
                reasoning=reasoning,
            )


def cross_provider_diff(
    enumerations: Iterable[ProviderEnumeration],
) -> tuple[CrossProviderHole, ...]:
    """Materialize :func:`iter_cross_provider_holes` for small/reporting use."""

    return tuple(iter_cross_provider_holes(enumerations))


def apply_retention_boundary(
    enumeration: ProviderEnumeration,
    first_available_block: int,
) -> ProviderEnumeration:
    """Clip an enumeration to a later retention boundary.

    Providers can advance their cleanup boundary while a long audit is in
    progress. A post-enumeration ``getFirstAvailableBlock`` check uses this
    helper before cross-provider comparison so a silently truncated prefix can
    never become a false hole.
    """

    boundary = _validated_slot(first_available_block, "first_available_block")
    boundary = max(boundary, enumeration.first_available_block)
    if boundary == enumeration.first_available_block:
        return enumeration

    successful_ranges = tuple(
        SlotRange(max(slot_range.start, boundary), slot_range.end)
        for slot_range in enumeration.successful_ranges
        if slot_range.end >= boundary
    )
    present_start = enumeration.present_slots.bisect_left(boundary)
    present_slots = enumeration.present_slots[present_start:]

    failed_chunks: list[ChunkEnumeration] = []
    for chunk in enumeration.failed_chunks:
        if chunk.slot_range.end < boundary:
            continue
        failed_chunks.append(
            ChunkEnumeration(
                provider=chunk.provider,
                slot_range=SlotRange(max(chunk.slot_range.start, boundary), chunk.slot_range.end),
                error_type=chunk.error_type,
                error_message=chunk.error_message,
            )
        )

    return ProviderEnumeration(
        provider=enumeration.provider,
        requested_range=enumeration.requested_range,
        first_available_block=boundary,
        present_slots=present_slots,
        successful_ranges=successful_ranges,
        failed_chunks=tuple(failed_chunks),
        request_count=enumeration.request_count,
    )


def _validated_slot(value: Any, label: str) -> int:
    _validate_slot(value, label)
    return value


def _validate_slot(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} cannot be negative")


def _client_request_count(client: EnumerationClient) -> int:
    value = getattr(client, "request_count", 0)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _coalesce_ranges(ranges: Iterable[SlotRange]) -> tuple[SlotRange, ...]:
    merged: list[SlotRange] = []
    for slot_range in sorted(ranges):
        if not merged or slot_range.start > merged[-1].end + 1:
            merged.append(slot_range)
        else:
            previous = merged[-1]
            merged[-1] = SlotRange(previous.start, max(previous.end, slot_range.end))
    return tuple(merged)


def _ranges_contain(ranges: tuple[SlotRange, ...], slot: int) -> bool:
    # Allocation-free binary search: this is called for every provider at every
    # slot in the multi-way merge, i.e. tens of millions of times in a 30-day run.
    low = 0
    high = len(ranges)
    while low < high:
        middle = (low + high) // 2
        if ranges[middle].start <= slot:
            low = middle + 1
        else:
            high = middle
    index = low - 1
    return index >= 0 and slot <= ranges[index].end


def _validate_coverage_ranges(
    requested: SlotRange,
    first_available: int,
    successful: tuple[SlotRange, ...],
    failed: tuple[SlotRange, ...],
) -> None:
    all_ranges = sorted((*successful, *failed))
    previous: SlotRange | None = None
    for slot_range in all_ranges:
        outside = (
            slot_range.start < max(requested.start, first_available)
            or slot_range.end > requested.end
        )
        if outside:
            raise ValueError(
                f"coverage range {slot_range} is outside the auditable requested range"
            )
        if previous is not None and slot_range.start <= previous.end:
            raise ValueError(f"coverage ranges overlap: {previous} and {slot_range}")
        previous = slot_range


def _validate_present_coverage(
    present_slots: SortedSlots, successful_ranges: tuple[SlotRange, ...]
) -> None:
    range_index = 0
    for slot in present_slots:
        while (
            range_index < len(successful_ranges)
            and successful_ranges[range_index].end < slot
        ):
            range_index += 1
        if (
            range_index >= len(successful_ranges)
            or slot < successful_ranges[range_index].start
        ):
            raise ValueError(f"present slot {slot} is outside successful coverage")


def _normalize_resume_chunks(
    provider: str,
    requested: SlotRange,
    first_available: int,
    resume_chunks: Iterable[ChunkEnumeration],
) -> tuple[ChunkEnumeration, ...]:
    """Clip reusable successes to current retention and reject overlap.

    Retention monotonically moves forward for a normal RPC node.  A checkpoint's
    old first chunk can therefore start below today's boundary and need not align
    with today's chunk grid.  Reusing its still-retained suffix is both safe and
    avoids repeating a potentially large ``getBlocks`` call.
    """

    clipped: list[ChunkEnumeration] = []
    auditable_start = max(requested.start, first_available)
    for chunk in resume_chunks:
        if chunk.provider != provider:
            raise ValueError(f"resume chunk belongs to {chunk.provider}, expected {provider}")
        # A successful completed call is immutable evidence and can be reused.
        # Failed calls remain indeterminate and should receive a fresh chance on
        # resume (the RpcClient will again apply its bounded retry policy).
        if chunk.failed:
            continue
        clipped_start = max(chunk.slot_range.start, auditable_start)
        clipped_end = min(chunk.slot_range.end, requested.end)
        if clipped_start > clipped_end:
            continue
        start_index = chunk.present_slots.bisect_left(clipped_start)
        end_index = chunk.present_slots.bisect_right(clipped_end)
        clipped.append(
            ChunkEnumeration(
                provider=provider,
                slot_range=SlotRange(clipped_start, clipped_end),
                present_slots=chunk.present_slots[start_index:end_index],
            )
        )

    clipped.sort(key=lambda chunk: chunk.slot_range)
    previous: ChunkEnumeration | None = None
    for chunk in clipped:
        if previous is not None and chunk.slot_range.start <= previous.slot_range.end:
            raise ValueError(
                f"successful resume chunks overlap: {previous.slot_range} and "
                f"{chunk.slot_range}"
            )
        previous = chunk
    return tuple(clipped)


__all__ = [
    "MAX_GET_BLOCKS_SLOTS",
    "UNEXCLUDED_EXPLANATIONS",
    "CheckpointCallback",
    "ChunkEnumeration",
    "CrossProviderHole",
    "CrossProviderOmission",
    "EnumerationClient",
    "ProviderEnumeration",
    "SlotRange",
    "SortedSlots",
    "cross_provider_diff",
    "apply_retention_boundary",
    "enumerate_provider",
    "iter_cross_provider_holes",
    "iter_inclusive_chunks",
]
