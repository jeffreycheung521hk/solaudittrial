from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from slot_audit.enumerate import (
    MAX_GET_BLOCKS_SLOTS,
    ChunkEnumeration,
    ProviderEnumeration,
    SlotRange,
    SortedSlots,
    apply_retention_boundary,
    cross_provider_diff,
    enumerate_provider,
    iter_inclusive_chunks,
)
from slot_audit.rpc import RequestBudgetExceeded
from slot_audit.verdict import Verdict

FIXTURES = Path(__file__).parent / "fixtures" / "enumerate"


class RecordedFailure(RuntimeError):
    pass


class RecordedEnumerationClient:
    def __init__(self, fixture: dict[str, Any]) -> None:
        self.fixture = fixture
        self.request_count = 0
        self.get_blocks_calls: list[tuple[int, int]] = []

    async def get_first_available_block(self) -> int:
        self.request_count += 1
        return int(self.fixture["first_available_block"])

    async def get_blocks(self, start_slot: int, end_slot: int) -> list[int]:
        self.request_count += 1
        self.get_blocks_calls.append((start_slot, end_slot))
        response = self.fixture["responses"][f"{start_slot}-{end_slot}"]
        if "error" in response:
            raise RecordedFailure(response["error"])
        return list(response["result"])


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


class ChunkingTests(unittest.TestCase):
    def test_inclusive_chunks_are_contiguous_and_never_exceed_rpc_limit(self) -> None:
        chunks = tuple(iter_inclusive_chunks(7, 1_000_012))

        self.assertEqual(
            chunks,
            (
                SlotRange(7, 500_006),
                SlotRange(500_007, 1_000_006),
                SlotRange(1_000_007, 1_000_012),
            ),
        )
        self.assertTrue(all(chunk.count <= MAX_GET_BLOCKS_SLOTS for chunk in chunks))
        self.assertEqual(sum(chunk.count for chunk in chunks), 1_000_006)

    def test_chunk_size_above_rpc_limit_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "500000"):
            tuple(iter_inclusive_chunks(0, 1, MAX_GET_BLOCKS_SLOTS + 1))

    def test_sorted_slots_are_packed_sorted_unique_storage(self) -> None:
        slots = SortedSlots([1, 2, 2, 5, 8])

        self.assertEqual(list(slots), [1, 2, 5, 8])
        self.assertEqual(slots.nbytes, 4 * 8)
        self.assertIn(5, slots)
        self.assertNotIn(4, slots)
        with self.assertRaisesRegex(ValueError, "sorted"):
            SortedSlots([2, 1])


class EnumerationTests(unittest.IsolatedAsyncioTestCase):
    async def test_retention_and_failed_chunks_are_not_candidate_gaps(self) -> None:
        fixture = load_fixture("retention_and_failure.json")
        client = RecordedEnumerationClient(fixture)
        checkpoints: list[ChunkEnumeration] = []

        result = await enumerate_provider(
            client,
            fixture["provider"],
            100,
            110,
            chunk_size=4,
            on_chunk=checkpoints.append,
        )

        self.assertEqual(result.before_retention_range, SlotRange(100, 102))
        self.assertEqual(result.successful_ranges, (SlotRange(103, 106),))
        self.assertEqual(
            tuple(chunk.slot_range for chunk in result.failed_chunks),
            (SlotRange(107, 110),),
        )
        self.assertEqual(list(result.present_slots), [103, 105])
        self.assertEqual(
            result.candidate_gap_ranges(), (SlotRange(104, 104), SlotRange(106, 106))
        )
        self.assertEqual(result.candidate_gap_count, 2)
        self.assertIs(result.verdict_at(101), Verdict.BEFORE_RETENTION)
        self.assertIs(result.verdict_at(103), Verdict.PRESENT)
        self.assertIsNone(result.verdict_at(104))
        self.assertIs(result.verdict_at(109), Verdict.INDETERMINATE)
        self.assertEqual(len(checkpoints), 2)
        self.assertEqual(result.request_count, 3)

    async def test_cross_provider_diff_uses_only_successful_shared_coverage(self) -> None:
        fixture = load_fixture("cross_provider.json")
        enumerations = []
        for provider_fixture in fixture["providers"]:
            enumerations.append(
                await enumerate_provider(
                    RecordedEnumerationClient(provider_fixture),
                    provider_fixture["provider"],
                    fixture["range"]["start"],
                    fixture["range"]["end"],
                    chunk_size=4,
                )
            )

        findings = cross_provider_diff(enumerations)

        self.assertEqual(
            [(finding.provider, finding.slot) for finding in findings],
            [("alpha", 102), ("alpha", 110)],
        )
        self.assertEqual(findings[0].corroborating_providers, ("bravo", "charlie"))
        self.assertIs(findings[0].verdict, Verdict.PROVIDER_HOLE)
        self.assertEqual(
            findings[0].evidence["corroborating_providers"], ["bravo", "charlie"]
        )
        self.assertIn("successfully enumerated", findings[0].reasoning)
        self.assertIn("proving that the block existed", findings[0].reasoning)

        # Alpha's failed 104-107 call cannot produce four false findings, despite
        # both peers returning those blocks. Charlie's 100-101 retention region is
        # likewise excluded.
        self.assertTrue(all(finding.slot not in range(104, 108) for finding in findings))
        self.assertTrue(
            all(
                not (finding.provider == "charlie" and finding.slot < 102)
                for finding in findings
            )
        )

    async def test_empty_success_chunk_is_coverage_not_failure(self) -> None:
        fixture = {
            "first_available_block": 20,
            "responses": {"20-22": {"result": []}},
        }
        result = await enumerate_provider(
            RecordedEnumerationClient(fixture), "empty", 20, 22, chunk_size=3
        )

        self.assertEqual(result.audited_slot_count, 3)
        self.assertEqual(result.failed_slot_count, 0)
        self.assertEqual(result.candidate_gap_ranges(), (SlotRange(20, 22),))
        self.assertIsNone(result.verdict_at(21))

    async def test_resume_reuses_success_but_retries_failure(self) -> None:
        fixture = {
            "first_available_block": 10,
            "responses": {
                "10-11": {"result": [10]},
                "12-13": {"result": [12, 13]},
            },
        }
        client = RecordedEnumerationClient(fixture)
        resumed_success = ChunkEnumeration.success("resume", 10, 11, [10])
        resumed_failure = ChunkEnumeration.failure(
            "resume", 12, 13, RecordedFailure("old transient failure")
        )

        result = await enumerate_provider(
            client,
            "resume",
            10,
            13,
            chunk_size=2,
            resume_chunks=(resumed_success, resumed_failure),
        )

        self.assertEqual(client.get_blocks_calls, [(12, 13)])
        self.assertEqual(list(result.present_slots), [10, 12, 13])
        self.assertEqual(result.failed_chunks, ())

    async def test_resume_clips_cached_chunk_when_retention_advances(self) -> None:
        fixture = {
            "first_available_block": 105,
            "responses": {"107-110": {"result": [107, 109, 110]}},
        }
        client = RecordedEnumerationClient(fixture)
        old_cached_chunk = ChunkEnumeration.success(
            "moving-retention", 103, 106, [103, 105]
        )

        result = await enumerate_provider(
            client,
            "moving-retention",
            100,
            110,
            chunk_size=4,
            resume_chunks=(old_cached_chunk,),
        )

        self.assertEqual(client.get_blocks_calls, [(107, 110)])
        self.assertEqual(result.before_retention_range, SlotRange(100, 104))
        self.assertEqual(result.successful_ranges, (SlotRange(105, 110),))
        self.assertEqual(list(result.present_slots), [105, 107, 109, 110])
        self.assertEqual(
            result.candidate_gap_ranges(), (SlotRange(106, 106), SlotRange(108, 108))
        )
        self.assertNotIn(103, result.present_slots)

    async def test_saved_retention_boundary_can_avoid_a_resume_request(self) -> None:
        fixture = {
            "first_available_block": 999,  # must not be read
            "responses": {},
        }
        client = RecordedEnumerationClient(fixture)
        cached = ChunkEnumeration.success("complete", 20, 22, [20, 21, 22])

        result = await enumerate_provider(
            client,
            "complete",
            20,
            22,
            resume_chunks=(cached,),
            first_available_block=20,
        )

        self.assertEqual(client.request_count, 0)
        self.assertEqual(result.request_count, 0)
        self.assertEqual(list(result.present_slots), [20, 21, 22])


class BudgetClient:
    def __init__(self) -> None:
        self.request_count = 0
        self.calls = 0

    async def get_first_available_block(self) -> int:
        self.request_count += 1
        return 0

    async def get_blocks(self, start_slot: int, end_slot: int) -> list[int]:
        self.calls += 1
        raise RequestBudgetExceeded("budgeted", 1, 1)


class BudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_budget_exhaustion_does_not_repeatedly_call_client(self) -> None:
        client = BudgetClient()
        checkpoints: list[ChunkEnumeration] = []

        result = await enumerate_provider(
            client,
            "budgeted",
            0,
            8,
            chunk_size=3,
            on_chunk=checkpoints.append,
        )

        self.assertEqual(client.calls, 1)
        self.assertEqual(
            tuple(chunk.slot_range for chunk in result.failed_chunks),
            (SlotRange(0, 2), SlotRange(3, 5), SlotRange(6, 8)),
        )
        self.assertTrue(
            all(
                chunk.error_type == "RequestBudgetExceeded"
                for chunk in result.failed_chunks
            )
        )
        self.assertEqual(len(checkpoints), 3)
        self.assertEqual(result.candidate_gap_count, 0)


class RetentionBoundaryTests(unittest.TestCase):
    def test_postflight_retention_clips_silent_prefix_omissions(self) -> None:
        result = ProviderEnumeration(
            provider="moving",
            requested_range=SlotRange(100, 110),
            first_available_block=100,
            present_slots=SortedSlots([105, 107]),
            successful_ranges=(SlotRange(100, 107),),
            failed_chunks=(
                ChunkEnumeration.failure("moving", 108, 110, RecordedFailure("transient")),
            ),
            request_count=2,
        )

        clipped = apply_retention_boundary(result, 104)

        self.assertEqual(clipped.first_available_block, 104)
        self.assertEqual(clipped.before_retention_range, SlotRange(100, 103))
        self.assertEqual(clipped.successful_ranges, (SlotRange(104, 107),))
        self.assertEqual(list(clipped.present_slots), [105, 107])
        self.assertEqual(clipped.failed_chunks[0].slot_range, SlotRange(108, 110))
        self.assertEqual(
            clipped.candidate_gap_ranges(),
            (SlotRange(104, 104), SlotRange(106, 106)),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
