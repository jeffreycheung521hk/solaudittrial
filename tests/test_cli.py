from __future__ import annotations

import json
import unittest
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from slot_audit.checkpoint import CheckpointStore
from slot_audit.cli import EXIT_COMPLETE, EXIT_FAILED, EXIT_PARTIAL, run_enumeration
from slot_audit.config import AuditConfig, ProviderConfig

EPOCH_SCHEDULE = {
    "slotsPerEpoch": 432_000,
    "leaderScheduleSlotOffset": 432_000,
    "warmup": False,
    "firstNormalEpoch": 0,
    "firstNormalSlot": 0,
}


def _read_output_tree(path: Path) -> str:
    return "".join(
        child.read_text(encoding="utf-8", errors="replace")
        for child in path.rglob("*")
        if child.is_file()
    )


def _config(*, max_requests: int = 100) -> AuditConfig:
    return AuditConfig.model_validate(
        {
            "providers": [
                {
                    "name": "provider-a",
                    "url": "https://a.invalid/?api-key=secret-a",
                    "rps": 100,
                    "archive": True,
                },
                {
                    "name": "provider-b",
                    "url": "https://b.invalid/?api-key=secret-b",
                    "rps": 100,
                    "archive": True,
                },
            ],
            "range": {"mode": "explicit", "start_slot": 100, "end_slot": 102},
            "limits": {
                "max_requests_per_provider": max_requests,
                "tip_safety_margin_slots": 150,
            },
        }
    )


class _Scenario:
    def __init__(self) -> None:
        self.blocks = {
            "provider-a": [100, 102],
            "provider-b": [100, 101, 102],
        }
        self.calls: list[tuple[str, str]] = []
        self.fail_blocks_once: set[str] = set()
        self.fail_tips: set[str] = set()
        self._already_failed: set[str] = set()
        self.retention_boundaries: dict[str, list[int]] = {
            "provider-a": [0],
            "provider-b": [0],
        }
        self.retention_calls: defaultdict[str, int] = defaultdict(int)

    def factory(self, provider: ProviderConfig, **kwargs: Any) -> _FakeClient:
        return _FakeClient(
            self,
            provider,
            max_requests=kwargs["max_requests"],
        )


class _FakeClient:
    def __init__(
        self, scenario: _Scenario, provider: ProviderConfig, *, max_requests: int
    ) -> None:
        self.scenario = scenario
        self.provider = provider
        self.name = provider.name
        self.max_requests = max_requests
        self.request_count = 0

    def _request(self, method: str) -> None:
        if self.request_count >= self.max_requests:
            raise RuntimeError(f"budget exhausted for {self.name}")
        self.request_count += 1
        self.scenario.calls.append((self.name, method))

    async def get_slot(self) -> int:
        self._request("getSlot")
        if self.name in self.scenario.fail_tips:
            raise RuntimeError(f"tip failed at {self.provider.rpc_url}")
        return 1_000

    async def get_first_available_block(self) -> int:
        self._request("getFirstAvailableBlock")
        boundaries = self.scenario.retention_boundaries[self.name]
        call_index = self.scenario.retention_calls[self.name]
        self.scenario.retention_calls[self.name] += 1
        return boundaries[min(call_index, len(boundaries) - 1)]

    async def get_epoch_schedule(self) -> dict[str, Any]:
        self._request("getEpochSchedule")
        return dict(EPOCH_SCHEDULE)

    async def get_blocks(self, start_slot: int, end_slot: int) -> list[int]:
        self._request("getBlocks")
        if (
            self.name in self.scenario.fail_blocks_once
            and self.name not in self.scenario._already_failed
        ):
            self.scenario._already_failed.add(self.name)
            raise RuntimeError(f"invalid API key secret-{self.name[-1]}")
        return [
            slot
            for slot in self.scenario.blocks[self.name]
            if start_slot <= slot <= end_slot
        ]

    async def aclose(self) -> None:
        return None


class EnumerationCliTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)

    async def test_enumerate_cli_writes_epoch_aware_sanitized_diff_and_summary(self) -> None:
        config = _config()
        scenario = _Scenario()

        status = await run_enumeration(
            config,
            self.tmp_path,
            chunk_size=500_000,
            client_factory=scenario.factory,
        )

        self.assertEqual(status, EXIT_COMPLETE)
        raw_text = (self.tmp_path / "raw-cross-provider-diff.jsonl").read_text(encoding="utf-8")
        self.assertEqual(raw_text, (self.tmp_path / "raw.jsonl").read_text(encoding="utf-8"))
        row = json.loads(raw_text)
        self.assertEqual(row["provider"], "provider-a")
        self.assertEqual(row["slot"], 101)
        self.assertEqual(row["epoch"], 0)
        self.assertEqual(row["verdict"], "PROVIDER_HOLE")
        self.assertTrue(row["error_code"] is None)
        self.assertEqual(row["evidence"]["evidence_method"], "cross_provider_presence")
        self.assertTrue(row["evidence"]["hash_verified"] is False)
        self.assertEqual(row["evidence"]["corroborating_providers"], ["provider-b"])

        summary = json.loads((self.tmp_path / "enumeration-summary.json").read_text())
        self.assertEqual(summary["pass"], "A")
        self.assertEqual(summary["status"], "complete")
        self.assertTrue(summary["trustworthy"] is True)
        self.assertEqual(summary["range"]["start_slot"], 100)
        self.assertEqual(summary["range"]["end_slot"], 102)
        self.assertEqual(summary["cross_provider_holes"], 1)
        by_provider = {item["provider"]: item for item in summary["providers"]}
        self.assertEqual(by_provider["provider-a"]["cross_provider_holes"], 1)
        self.assertEqual(by_provider["provider-b"]["cross_provider_holes"], 0)

        all_output = _read_output_tree(self.tmp_path)
        self.assertNotIn("secret-a", all_output)
        self.assertNotIn("secret-b", all_output)
        for line in (self.tmp_path / "run.log").read_text().splitlines():
            self.assertIsInstance(json.loads(line), dict)


    async def test_resume_reuses_range_and_chunks_but_refreshes_retention(self) -> None:
        config = _config()
        first_scenario = _Scenario()
        self.assertEqual(
            await run_enumeration(
                config, self.tmp_path, client_factory=first_scenario.factory
            ),
            EXIT_COMPLETE,
        )

        second_scenario = _Scenario()
        status = await run_enumeration(
            config,
            self.tmp_path,
            resume=True,
            client_factory=second_scenario.factory,
        )

        self.assertEqual(status, EXIT_COMPLETE)
        self.assertIn(("provider-a", "getSlot"), second_scenario.calls)
        self.assertIn(("provider-b", "getSlot"), second_scenario.calls)
        self.assertNotIn(("provider-a", "getEpochSchedule"), second_scenario.calls)
        self.assertNotIn(("provider-b", "getEpochSchedule"), second_scenario.calls)
        self.assertIn(("provider-a", "getFirstAvailableBlock"), second_scenario.calls)
        self.assertIn(("provider-b", "getFirstAvailableBlock"), second_scenario.calls)
        self.assertFalse(
            any(method == "getBlocks" for _, method in second_scenario.calls)
        )

        summary = json.loads((self.tmp_path / "enumeration-summary.json").read_text())
        self.assertTrue(summary["resumed"] is True)
        self.assertEqual(summary["range"]["start_slot"], 100)
        self.assertEqual(summary["range"]["end_slot"], 102)
        self.assertEqual(summary["requests_this_invocation"], 6)
        totals = {item["provider"]: item["total_requests"] for item in summary["providers"]}
        self.assertEqual(totals, {"provider-a": 8, "provider-b": 7})


    async def test_failed_chunk_is_partial_then_retried_on_resume(self) -> None:
        config = _config()
        scenario = _Scenario()
        scenario.blocks["provider-a"] = [100, 101, 102]
        scenario.fail_blocks_once.add("provider-b")

        first_status = await run_enumeration(
            config,
            self.tmp_path,
            client_factory=scenario.factory,
        )
        self.assertEqual(first_status, EXIT_PARTIAL)
        first_summary = json.loads((self.tmp_path / "enumeration-summary.json").read_text())
        self.assertEqual(first_summary["status"], "partial")
        self.assertTrue(first_summary["trustworthy"] is False)
        self.assertEqual(first_summary["providers"][1]["indeterminate"], 3)
        self.assertEqual(first_summary["providers"][1]["indeterminate_rate"], 1.0)
        self.assertTrue(first_summary["providers"][1]["indeterminate_exceeds_threshold"] is True)
        self.assertTrue(any("not trustworthy" in item for item in first_summary["limitations"]))
        self.assertNotIn("secret-b", json.dumps(first_summary))

        scenario.calls.clear()
        second_status = await run_enumeration(
            config,
            self.tmp_path,
            resume=True,
            client_factory=scenario.factory,
        )

        self.assertEqual(second_status, EXIT_COMPLETE)
        self.assertIn(("provider-b", "getBlocks"), scenario.calls)
        self.assertNotIn(("provider-a", "getBlocks"), scenario.calls)
        self.assertTrue(
            CheckpointStore(
                self.tmp_path, config.public_fingerprint()
            ).chunks_for_provider("provider-b", successful_only=True)
        )


    async def test_no_usable_tip_still_writes_honest_failed_summary(self) -> None:
        config = _config()
        scenario = _Scenario()
        scenario.fail_tips = {"provider-a", "provider-b"}

        status = await run_enumeration(
            config,
            self.tmp_path,
            client_factory=scenario.factory,
        )

        self.assertEqual(status, EXIT_FAILED)
        summary = json.loads((self.tmp_path / "enumeration-summary.json").read_text())
        self.assertEqual(summary["status"], "failed")
        self.assertTrue(summary["range"] is None)
        self.assertTrue(summary["partial_errors"])
        self.assertEqual((self.tmp_path / "raw-cross-provider-diff.jsonl").read_text(), "")
        self.assertNotIn("secret-a", json.dumps(summary))
        self.assertNotIn("secret-b", json.dumps(summary))


    async def test_provider_without_safe_tip_is_excluded_from_cross_diff(self) -> None:
        config = _config()
        scenario = _Scenario()
        scenario.fail_tips = {"provider-b"}
        # If incorrectly enumerated, this truncated response would make the healthy
        # provider's slots look like holes in provider-b.
        scenario.blocks["provider-b"] = [100]

        status = await run_enumeration(
            config,
            self.tmp_path,
            client_factory=scenario.factory,
        )

        self.assertEqual(status, EXIT_PARTIAL)
        self.assertNotIn(("provider-b", "getBlocks"), scenario.calls)
        self.assertEqual((self.tmp_path / "raw-cross-provider-diff.jsonl").read_text(), "")
        summary = json.loads((self.tmp_path / "enumeration-summary.json").read_text())
        self.assertEqual(summary["providers"][1]["status"], "unavailable")
        self.assertTrue(
            any(
                issue["error_type"] == "InsufficientComparableProviders"
                for issue in summary["partial_errors"]
            )
        )


    async def test_advancing_retention_boundary_is_clipped_before_cross_diff(self) -> None:
        config = _config()
        scenario = _Scenario()
        scenario.blocks["provider-a"] = [102]
        scenario.retention_boundaries["provider-a"] = [0, 102]

        status = await run_enumeration(
            config,
            self.tmp_path,
            client_factory=scenario.factory,
        )

        self.assertEqual(status, EXIT_COMPLETE)
        self.assertEqual((self.tmp_path / "raw-cross-provider-diff.jsonl").read_text(), "")
        summary = json.loads((self.tmp_path / "enumeration-summary.json").read_text())
        provider_a = summary["providers"][0]
        self.assertEqual(provider_a["first_available_block"], 102)
        self.assertEqual(provider_a["before_retention"], 2)
        self.assertEqual(provider_a["slots_audited"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
