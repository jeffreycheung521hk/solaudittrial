"""The three negative controls, asserted on the production run's final output.

These are not helper tests. Each control drives
:func:`slot_audit.audit.run_epoch_audit` end to end and the assertions below are
made against the finished :class:`~slot_audit.audit.AuditRun`, the rendered
``summary.md`` and the machine-readable ``result.json``.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.assessment import GateStatus
from slot_audit.continuity import LinkOutcome
from slot_audit.evidence import verify_manifest
from slot_audit.negative_controls import (
    LedgerDefects,
    build_simulated_epoch,
    control_corrupted_previous_blockhash,
    control_removed_known_block,
    control_truncated_token_enumeration,
    run_all_negative_controls,
)
from slot_audit.report import render_summary, write_reports
from slot_audit.verdict import Verdict
from tests.epoch_support import run_audit


class ControlTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)


class RemovedKnownBlockControlTests(ControlTestCase):
    async def test_removing_a_block_known_to_exist_yields_a_provider_hole(self) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[len(epoch.produced_slots) // 2]

        run = await run_audit(
            directory=self.tmp_path / "run",
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        )

        self.assertEqual(len(run.findings), 1)
        finding = run.findings[0]
        self.assertEqual(finding.slot, target)
        self.assertEqual(finding.provider, "control-a")
        self.assertIs(finding.verdict, Verdict.PROVIDER_HOLE)

    async def test_the_removed_block_is_never_reclassified_as_a_protocol_skip(self) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[3]

        run = await run_audit(
            directory=self.tmp_path / "run",
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        )

        outcome = next(item for item in run.tally.candidate_holes if item.slot == target)
        self.assertIs(outcome.verdicts["control-a"], Verdict.PROVIDER_HOLE)
        self.assertIsNot(outcome.verdicts["control-a"], Verdict.PROTOCOL_SKIPPED)
        # The count of genuine protocol skips is unchanged by the injected defect.
        self.assertEqual(
            run.tally.verdict_counts["control-a"][Verdict.PROTOCOL_SKIPPED.value],
            epoch.spec.skipped_slots,
        )
        self.assertEqual(
            run.tally.verdict_counts["control-a"][Verdict.PROVIDER_HOLE.value], 1
        )

    async def test_the_finding_cites_range_direct_and_ground_truth_evidence(self) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[5]
        directory = self.tmp_path / "run"

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        )
        finding = run.findings[0]

        self.assertIn("range_response", finding.evidence)
        self.assertIn("direct_response", finding.evidence)
        self.assertIn("ground_truth_header", finding.evidence)
        self.assertIn("peer_response", finding.evidence)
        self.assertTrue(finding.complete)

        # The cited range response really is the getBlocks batch that omitted it.
        raw = json.loads(
            (run.evidence_root / finding.evidence["range_response"].relative_path)
            .read_text(encoding="utf-8")
        )
        self.assertIn(target, epoch.produced_slots)
        self.assertNotIn(target, raw["result"])

        # The cited direct response is the provider's own refusal of that slot.
        direct = json.loads(
            (run.evidence_root / finding.evidence["direct_response"].relative_path)
            .read_text(encoding="utf-8")
        )
        self.assertIn("error", direct)

        # The cited ground-truth header proves the block existed.
        header = json.loads(
            (run.evidence_root / finding.evidence["ground_truth_header"].relative_path)
            .read_text(encoding="utf-8")
        )
        self.assertEqual(header["slot"], target)
        self.assertEqual(header["blockhash"], epoch.headers[target].blockhash)

    async def test_the_report_shows_every_cited_reference_with_digest_and_length(
        self,
    ) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[7]
        directory = self.tmp_path / "run"

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        )
        summary_path, result_path = write_reports(run, results_dir=directory)
        summary = summary_path.read_text(encoding="utf-8")
        result = json.loads(result_path.read_text(encoding="utf-8"))

        finding = run.findings[0]
        for name, ref in finding.evidence.items():
            with self.subTest(evidence=name):
                self.assertIn(ref.relative_path, summary)
                self.assertIn(ref.sha256, summary)
                self.assertIn(f"{ref.byte_length} bytes", summary)
        self.assertEqual(result["findings"][0]["slot"], target)
        self.assertEqual(result["findings"][0]["verdict"], "PROVIDER_HOLE")
        self.assertTrue(result["findings"][0]["evidence_complete"])


class TruncatedTokenEnumerationControlTests(ControlTestCase):
    async def test_a_dropped_account_under_reports_by_exactly_its_balance(self) -> None:
        epoch = build_simulated_epoch()
        pubkey, amount, _state = epoch.token_accounts[2]
        defects = LedgerDefects(dropped_token_accounts=frozenset({pubkey}))

        run = await run_audit(
            directory=self.tmp_path / "run",
            epoch=epoch,
            defects={"control-a": defects, "control-b": defects},
        )

        self.assertGreater(amount, 0)
        for name, result in run.token_results.items():
            with self.subTest(provider=name):
                self.assertEqual(result.signed_difference, -amount)
                self.assertEqual(result.mint_supply, epoch.mint_supply)
                self.assertEqual(result.enumerated_total, epoch.mint_supply - amount)
                self.assertFalse(result.reconciled)

    async def test_the_exact_signed_difference_reaches_the_report(self) -> None:
        epoch = build_simulated_epoch()
        pubkey, amount, _state = epoch.token_accounts[4]
        defects = LedgerDefects(dropped_token_accounts=frozenset({pubkey}))
        directory = self.tmp_path / "run"

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={"control-a": defects, "control-b": defects},
        )
        summary_path, result_path = write_reports(run, results_dir=directory)
        summary = summary_path.read_text(encoding="utf-8")
        result = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertIn(str(-amount), summary)
        for name in run.token_results:
            self.assertEqual(
                result["token"][name]["signed_difference_base_units"], -amount
            )
        gate = run.assessment.gate("token_supply_reconciliation")
        self.assertIs(gate.status, GateStatus.FAIL)

    async def test_an_untruncated_enumeration_reconciles_to_zero(self) -> None:
        run = await run_audit(directory=self.tmp_path / "run")

        for result in run.token_results.values():
            self.assertEqual(result.signed_difference, 0)
            self.assertTrue(result.reconciled)


class CorruptedPreviousBlockhashControlTests(ControlTestCase):
    async def test_a_corrupted_previous_blockhash_is_reported_not_passed(self) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[2]
        corrupted = "So11111111111111111111111111111111111111112"

        run = await run_audit(
            directory=self.tmp_path / "run",
            epoch=epoch,
            defects={
                "control-a": LedgerDefects(
                    corrupted_previous_blockhash={target: corrupted}
                )
            },
        )

        mismatches = [
            link
            for result in run.continuity
            for link in result.links
            if link.outcome is LinkOutcome.PREVIOUS_BLOCKHASH_MISMATCH
        ]
        self.assertEqual([link.slot for link in mismatches], [target])
        self.assertEqual(mismatches[0].previous_blockhash, corrupted)
        self.assertEqual(
            mismatches[0].parent_blockhash,
            epoch.headers[epoch.headers[target].parent_slot].blockhash,
        )
        self.assertIs(
            run.assessment.gate("hash_link_continuity").status, GateStatus.FAIL
        )

    async def test_the_corruption_travels_from_raw_bytes_through_the_decoder(self) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[4]
        corrupted = "So11111111111111111111111111111111111111112"
        directory = self.tmp_path / "run"

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={
                "control-a": LedgerDefects(
                    corrupted_previous_blockhash={target: corrupted}
                )
            },
        )

        # The corruption is present in the retained raw bytes, which is what
        # makes the detection re-performable rather than merely asserted.
        raw_files = sorted((run.evidence_root / "raw").glob("*getBlock.json"))
        bodies = [path.read_text(encoding="utf-8") for path in raw_files]
        self.assertTrue(any(corrupted in body for body in bodies))

        summary = render_summary(run, results_dir=directory)
        self.assertIn("PREVIOUS_BLOCKHASH_MISMATCH", summary)

    async def test_an_uncorrupted_chain_reports_no_mismatch(self) -> None:
        run = await run_audit(directory=self.tmp_path / "run")

        for result in run.continuity:
            with self.subTest(population=result.population):
                self.assertTrue(result.clean)
                self.assertEqual(result.outcomes, ("OK",))
        self.assertIs(
            run.assessment.gate("hash_link_continuity").status, GateStatus.PASS
        )


class ShippedControlSuiteTests(ControlTestCase):
    async def test_every_shipped_control_detects_its_defect(self) -> None:
        results = await run_all_negative_controls(results_dir=self.tmp_path / "controls")

        self.assertEqual(
            [item.control_id for item in results],
            [
                "removed_known_block",
                "truncated_token_enumeration",
                "corrupted_previous_blockhash",
            ],
        )
        for item in results:
            with self.subTest(control=item.control_id):
                self.assertTrue(item.detected, item.detail)
                self.assertTrue(item.observed)

    async def test_each_control_run_retains_its_own_verifiable_evidence(self) -> None:
        await run_all_negative_controls(results_dir=self.tmp_path / "controls")

        for name in (
            "removed_known_block",
            "truncated_token_enumeration",
            "corrupted_previous_blockhash",
        ):
            with self.subTest(control=name):
                evidence_root = self.tmp_path / "controls" / name / "evidence"
                self.assertTrue(evidence_root.is_dir())
                self.assertTrue(verify_manifest(evidence_root).ok)

    async def test_the_controls_record_what_they_observed_not_just_a_boolean(
        self,
    ) -> None:
        hole = await control_removed_known_block(directory=self.tmp_path / "hole")
        token = await control_truncated_token_enumeration(
            directory=self.tmp_path / "token"
        )
        chain = await control_corrupted_previous_blockhash(
            directory=self.tmp_path / "chain"
        )

        self.assertEqual(hole.observed["verdict"], "PROVIDER_HOLE")
        self.assertFalse(hole.observed["became_protocol_skipped"])
        self.assertIn("range_response", hole.observed["evidence_keys"])
        self.assertEqual(
            token.observed["expected_signed_difference"],
            -token.observed["removed_amount_base_units"],
        )
        self.assertEqual(
            set(token.observed["observed_signed_differences"].values()),
            {token.observed["expected_signed_difference"]},
        )
        self.assertEqual(chain.observed["outcome"], "PREVIOUS_BLOCKHASH_MISMATCH")
        self.assertFalse(chain.observed["silently_passed"])

    async def test_a_full_run_gates_on_its_own_controls(self) -> None:
        run = await run_audit(
            directory=self.tmp_path / "full", run_negative_controls=True
        )

        for gate_id in (
            "negative_control_provider_hole",
            "negative_control_token_truncation",
            "negative_control_previous_blockhash",
        ):
            with self.subTest(gate=gate_id):
                gate = run.assessment.gate(gate_id)
                self.assertIs(gate.status, GateStatus.PASS)
                self.assertTrue(gate.mandatory)
                self.assertTrue(gate.evidence)
                # The cited artifact lives in this run's own evidence store.
                for ref in gate.evidence:
                    self.assertTrue((run.evidence_root / ref.relative_path).is_file())

    async def test_a_run_without_controls_cannot_conclude(self) -> None:
        run = await run_audit(
            directory=self.tmp_path / "uncontrolled", run_negative_controls=False
        )

        self.assertEqual(run.findings, ())
        self.assertEqual(run.conclusion.result.value, "NO_CONCLUSION")
        self.assertIn("negative_control_provider_hole", run.conclusion.blocked_by)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
