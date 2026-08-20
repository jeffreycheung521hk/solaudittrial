"""Regressions for the orchestration, the assessment and the report.

Each test below fails against an implementation that classifies without an
anchor, discards the batch response it reasoned from, recomputes a threshold in
two places, or lets a null hash reach a conclusive finding.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit import report as report_module
from slot_audit.assessment import (
    MANDATORY_GATES,
    GateStatus,
    RunResult,
    within_threshold,
)
from slot_audit.audit import (
    REQUIRED_FINDING_EVIDENCE,
    AuditError,
    BlockFinding,
    ProviderCollection,
    RangeResponse,
    SlotOutcome,
    build_findings,
)
from slot_audit.evidence import EvidenceError, EvidenceStore, verify_manifest
from slot_audit.groundtruth import GroundTruth
from slot_audit.negative_controls import (
    LedgerDefects,
    build_control_config,
    build_simulated_epoch,
    control_token_scope,
    resolve_control_config,
)
from slot_audit.report import render_summary, write_reports
from slot_audit.transport import AuditRpcClient, ScriptedTransport
from slot_audit.verdict import (
    ExistenceInference,
    GroundTruthState,
    ProviderSlotState,
    Verdict,
)
from tests.epoch_support import (
    failing_get_blocks,
    inexact_context,
    run_audit,
    with_thresholds,
)


class EpochAuditTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)


class UnverifiableAnchorTests(EpochAuditTestCase):
    async def test_an_absent_archive_cannot_produce_a_conclusive_provider_hole(
        self,
    ) -> None:
        """Without ground truth, a provider omission is not a hole -- it is unknown."""

        epoch = build_simulated_epoch()
        target = epoch.produced_slots[6]

        run = await run_audit(
            directory=self.tmp_path / "run",
            epoch=epoch,
            write_car=False,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        )

        self.assertFalse(run.ground_truth.verified)
        self.assertEqual(run.findings, ())
        self.assertEqual(run.tally.candidate_holes, ())
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)
        self.assertIn("ground_truth_provenance_binding", run.conclusion.blocked_by)
        self.assertIn("ground_truth_full_epoch_coverage", run.conclusion.blocked_by)

    async def test_an_unverifiable_anchor_is_recorded_as_an_indeterminate_matter(
        self,
    ) -> None:
        run = await run_audit(directory=self.tmp_path / "run", write_car=False)

        subjects = {matter.subject for matter in run.indeterminate}
        self.assertIn("ground_truth", subjects)
        self.assertEqual(
            run.tally.ground_truth_unknown, run.spec.scheduled_slot_positions
        )
        self.assertEqual(
            run.tally.verdict_counts["control-a"][Verdict.INDETERMINATE.value],
            run.spec.scheduled_slot_positions,
        )

    async def test_the_summary_says_what_it_could_not_determine(self) -> None:
        directory = self.tmp_path / "run"

        run = await run_audit(directory=directory, write_car=False)
        summary = render_summary(run, results_dir=directory)

        self.assertIn("## What this run could not determine", summary)
        self.assertIn("`NO_CONCLUSION`", summary)
        self.assertIn("car_present", summary)


class ConstantProvenanceGateTests(EpochAuditTestCase):
    """The FAIL path of the gate that currently blocks every epoch-100 run.

    Without these, a typo in the gate's ``passed=`` expression or a flipped
    default on :class:`ConstantProvenance` would silently unblock a run whose
    anchor traces to nothing, and the suite would stay green.
    """

    def _unverified(self, epoch):
        from slot_audit.groundtruth import UNVERIFIED_PROVENANCE

        return dataclasses.replace(
            epoch, spec=dataclasses.replace(epoch.spec, provenance=UNVERIFIED_PROVENANCE)
        )

    async def test_unverified_constants_fail_the_gate(self) -> None:
        epoch = self._unverified(build_simulated_epoch())

        run = await run_audit(directory=self.tmp_path / "unverified", epoch=epoch)

        gate = run.assessment.gate("ground_truth_constants_provenance")
        self.assertIs(gate.status, GateStatus.FAIL)
        self.assertTrue(gate.mandatory)
        self.assertEqual(gate.metrics["verified_against_archive"], "False")
        self.assertIn("no provenance was recorded", gate.detail)

    async def test_unverified_constants_force_no_conclusion(self) -> None:
        """Even with a clean archive, a clean chain and zero findings."""

        epoch = self._unverified(build_simulated_epoch())

        run = await run_audit(
            directory=self.tmp_path / "unverified",
            epoch=epoch,
            run_negative_controls=True,
        )

        # Everything the archive itself can prove still passes ...
        self.assertTrue(run.ground_truth.verified)
        self.assertIs(
            run.assessment.gate("ground_truth_provenance_binding").status,
            GateStatus.PASS,
        )
        self.assertEqual(run.findings, ())
        # ... and the run still refuses, because the pinned values it verified
        # against trace to nothing.
        self.assertIs(run.assessment.status, GateStatus.FAIL)
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)
        self.assertIn("ground_truth_constants_provenance", run.conclusion.blocked_by)

    async def test_unverified_constants_block_an_otherwise_conclusive_finding(
        self,
    ) -> None:
        """The strongest form: a defensible finding that still cannot be reported."""

        from slot_audit.config import ContinuityConfig
        from slot_audit.negative_controls import run_all_negative_controls

        controls = await run_all_negative_controls(
            results_dir=self.tmp_path / "controls"
        )
        epoch = self._unverified(
            build_simulated_epoch(
                epoch=900_500, first_slot=420_000_000, positions=512, produced=384
            )
        )
        target = epoch.produced_slots[100]
        config = build_control_config(epoch).model_copy(
            update={
                "continuity": ContinuityConfig(
                    hash_link_validation_population="findings_and_adjacent"
                )
            }
        )

        run = await run_audit(
            directory=self.tmp_path / "blocked",
            epoch=epoch,
            config=config,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
            negative_controls=controls,
        )

        self.assertEqual(len(run.findings), 1)
        self.assertTrue(run.findings[0].complete)
        self.assertEqual(run.conclusion.blocked_by, ("ground_truth_constants_provenance",))
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)

    async def test_the_summary_names_the_unverified_constants(self) -> None:
        epoch = self._unverified(build_simulated_epoch())
        directory = self.tmp_path / "unverified"

        run = await run_audit(directory=directory, epoch=epoch)
        summary = render_summary(run, results_dir=directory)

        self.assertIn("**Result:** `NO_CONCLUSION`", summary)
        self.assertIn("ground_truth_constants_provenance", summary)
        self.assertIn("The pinned constants below are unverified", summary)

    def test_the_shipped_epoch_100_constants_are_unverified_today(self) -> None:
        """Pins the repository's actual state: epoch 100 cannot conclude."""

        from slot_audit.groundtruth import EPOCH_100_GROUND_TRUTH

        self.assertFalse(
            EPOCH_100_GROUND_TRUTH.provenance.verified_against_archive,
            "if this ever passes, the constants were verified -- update the README "
            "status block and this test together",
        )

    def test_a_verified_provenance_passes_the_same_gate(self) -> None:
        """The gate must be capable of passing, or it proves nothing."""

        epoch = build_simulated_epoch()

        self.assertTrue(epoch.spec.provenance.verified_against_archive)
        self.assertIn("computed from the archive bytes", epoch.spec.provenance.note)


class MissingGroundTruthHeaderTests(EpochAuditTestCase):
    """Directly exercise the guard that refuses a hole without a header."""

    class _HeaderlessGroundTruth(GroundTruth):
        def header_for(self, slot: int):  # type: ignore[override]
            return None

    async def test_a_hole_without_a_ground_truth_header_becomes_indeterminate(
        self,
    ) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[3]
        directory = self.tmp_path / "guard"
        directory.mkdir(parents=True)
        evidence = EvidenceStore(directory / "evidence")
        resolved = resolve_control_config(
            build_control_config(epoch), car_path=directory / "epoch.car"
        )
        provider = resolved.providers[0]
        from slot_audit.negative_controls import SimulatedProviderLedger

        ledger = SimulatedProviderLedger(
            epoch,
            scope=control_token_scope(),
            defects=LedgerDefects(dropped_slots=frozenset({target})),
        )
        client = AuditRpcClient(
            provider=provider.name,
            url=provider.rpc_url,
            endpoint_fingerprint=provider.endpoint_fingerprint,
            transport=ScriptedTransport(ledger.handle),
            evidence=evidence,
        )
        range_call = await client.get_blocks(epoch.spec.first_slot, epoch.spec.last_slot)
        collection = ProviderCollection(
            provider=provider.name,
            endpoint_fingerprint=provider.endpoint_fingerprint,
            ranges=(
                RangeResponse(
                    provider=provider.name,
                    start_slot=epoch.spec.first_slot,
                    end_slot=epoch.spec.last_slot,
                    succeeded=True,
                    present_count=len(ledger.visible_slots()),
                    raw=range_call.raw_ref,
                    request=range_call.request_ref,
                ),
            ),
            present_slots=frozenset(ledger.visible_slots()),
            version_evidence=None,
            version_text=None,
        )
        outcome = SlotOutcome(
            slot=target,
            ground_truth=GroundTruthState.PRODUCED,
            provider_states={provider.name: ProviderSlotState.ABSENT},
            combined_inference=ExistenceInference.EXISTS,
            verdicts={provider.name: Verdict.PROVIDER_HOLE},
        )
        tally = dataclasses.replace(
            _empty_tally(epoch.spec.scheduled_slot_positions),
            candidate_holes=(outcome,),
        )
        headerless = self._HeaderlessGroundTruth(
            spec=epoch.spec,
            extractor=_dummy_extractor(),
            headers={},
            predecessor_header=None,
            filtered_predecessor_rows=0,
            trust_chain=(),
        )

        findings, indeterminate = await build_findings(
            tally=tally,
            ground_truth=headerless,
            collections=[collection],
            clients={provider.name: client},
            evidence=evidence,
        )

        self.assertEqual(findings, ())
        self.assertEqual(len(indeterminate), 1)
        matter = indeterminate[0]
        self.assertEqual(matter.slot, target)
        self.assertIn("could not be retrieved or derived", matter.reason)
        self.assertTrue(matter.evidence)


class NullFieldTests(unittest.TestCase):
    def _finding(self, **overrides: object) -> BlockFinding:
        base: dict[str, object] = {
            "slot": 43_200_010,
            "provider": "provider-a",
            "verdict": Verdict.PROVIDER_HOLE,
            "blockhash": "So11111111111111111111111111111111111111112",
            "previous_blockhash": "So11111111111111111111111111111111111111112",
            "parent_slot": 43_200_009,
            "source": "old_faithful_car_derived_ground_truth",
            "inference": "the anchor shows a produced block",
            "evidence": {},
        }
        base.update(overrides)
        return BlockFinding(**base)  # type: ignore[arg-type]

    def test_a_conclusive_finding_cannot_have_a_null_blockhash(self) -> None:
        for field in ("blockhash", "previous_blockhash", "source", "inference"):
            for empty in ("", None):
                with self.subTest(field=field, value=empty), self.assertRaisesRegex(
                    AuditError, "null"
                ):
                    self._finding(**{field: empty})

    def test_a_conclusive_finding_needs_a_real_parent_slot(self) -> None:
        with self.assertRaisesRegex(AuditError, "parentSlot"):
            self._finding(parent_slot=-1)

    def test_required_evidence_is_declared_and_enforced(self) -> None:
        self.assertEqual(
            REQUIRED_FINDING_EVIDENCE,
            ("range_response", "direct_response", "ground_truth_header"),
        )
        incomplete = self._finding()
        self.assertFalse(incomplete.complete)
        self.assertEqual(incomplete.missing_evidence, REQUIRED_FINDING_EVIDENCE)


class FindingEvidenceTests(EpochAuditTestCase):
    async def test_every_conclusive_finding_is_fully_populated_and_manifested(
        self,
    ) -> None:
        epoch = build_simulated_epoch()
        targets = {epoch.produced_slots[2], epoch.produced_slots[9]}
        directory = self.tmp_path / "run"

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset(targets))},
        )

        self.assertEqual({finding.slot for finding in run.findings}, targets)
        for finding in run.findings:
            with self.subTest(slot=finding.slot):
                self.assertTrue(finding.blockhash)
                self.assertTrue(finding.previous_blockhash)
                self.assertIsNotNone(finding.parent_slot)
                self.assertTrue(finding.source)
                self.assertTrue(finding.inference)
                self.assertTrue(finding.complete)
                for ref in finding.evidence.values():
                    path = run.evidence_root / ref.relative_path
                    self.assertTrue(path.is_file())
                    self.assertEqual(path.stat().st_size, ref.byte_length)
        self.assertIs(
            run.assessment.gate("finding_evidence_completeness").status, GateStatus.PASS
        )
        self.assertTrue(verify_manifest(run.evidence_root).ok)

    async def test_each_hole_cites_the_batch_response_that_demonstrated_it(self) -> None:
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[11]
        directory = self.tmp_path / "run"

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
            chunk_size=8,
        )

        finding = run.findings[0]
        ref = finding.evidence["range_response"]
        body = json.loads((run.evidence_root / ref.relative_path).read_text())
        request = json.loads(
            (run.evidence_root / finding.evidence["range_request"].relative_path)
            .read_text()
        )
        start, end = request["params"][0], request["params"][1]

        self.assertEqual(request["method"], "getBlocks")
        self.assertLessEqual(start, target)
        self.assertLessEqual(target, end)
        self.assertNotIn(target, body["result"])
        # Neighbouring produced slots inside the same batch are present, so the
        # omission is attributable to the batch rather than to the range.
        neighbours = [
            slot for slot in epoch.produced_slots if start <= slot <= end and slot != target
        ]
        self.assertTrue(neighbours)
        for slot in neighbours:
            self.assertIn(slot, body["result"])


class DecimalThresholdBoundaryTests(EpochAuditTestCase):
    async def _run_at(self, threshold: str, name: str):
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[4]
        config = with_thresholds(
            build_control_config(epoch), indeterminate_threshold=threshold
        )
        directory = self.tmp_path / name
        run = await run_audit(
            directory=directory,
            epoch=epoch,
            config=config,
            chunk_size=1,
            handler_wrappers={"control-a": failing_get_blocks(target)},
            negative_controls=self._controls,
        )
        return run, directory

    async def asyncSetUp(self) -> None:
        from slot_audit.negative_controls import run_all_negative_controls

        self._controls = await run_all_negative_controls(
            results_dir=self.tmp_path / "controls"
        )

    async def test_exactly_one_indeterminate_position_of_thirty_two(self) -> None:
        run, _ = await self._run_at("0.03125", "boundary")

        self.assertEqual(run.tally.indeterminate_positions, 1)
        self.assertEqual(run.spec.scheduled_slot_positions, 32)

    async def test_the_exact_boundary_passes_and_one_ulp_below_it_fails(self) -> None:
        on_boundary, on_dir = await self._run_at("0.03125", "on-boundary")
        below, below_dir = await self._run_at("0.031249999999999999", "below-boundary")

        self.assertIs(
            on_boundary.assessment.gate("indeterminate_threshold").status,
            GateStatus.PASS,
        )
        self.assertIs(
            below.assessment.gate("indeterminate_threshold").status, GateStatus.FAIL
        )
        self.assertIs(on_boundary.conclusion.result, RunResult.NO_FINDINGS)
        self.assertIs(below.conclusion.result, RunResult.NO_CONCLUSION)

    async def test_the_summary_reports_the_same_status_as_the_audit(self) -> None:
        for threshold, name in (
            ("0.03125", "summary-on"),
            ("0.031249999999999999", "summary-below"),
        ):
            with self.subTest(threshold=threshold):
                run, directory = await self._run_at(threshold, name)
                summary = render_summary(run, results_dir=directory)

                self.assertIn(
                    f"**Instrument validation status:** `{run.assessment.status.value}`",
                    summary,
                )
                self.assertIn(f"**Result:** `{run.conclusion.result.value}`", summary)

    def test_the_comparison_itself_is_exact(self) -> None:
        rate = Fraction(1, 32)

        self.assertTrue(within_threshold(rate, Decimal("0.03125")))
        self.assertFalse(within_threshold(rate, Decimal("0.031249999999999999")))
        # A float round-trip loses the distinction the Decimal comparison keeps.
        self.assertEqual(
            float(Decimal("0.03125")), float(Decimal("0.031249999999999999"))
        )


class SingleAssessmentTests(EpochAuditTestCase):
    async def test_the_summary_renders_the_assessment_it_is_given(self) -> None:
        directory = self.tmp_path / "run"
        run = await run_audit(directory=directory, run_negative_controls=True)
        self.assertIs(run.assessment.status, GateStatus.PASS)
        self.assertIs(run.conclusion.result, RunResult.NO_FINDINGS)

        # Fail one mandatory gate in the authoritative object only. A renderer
        # that recomputed anything from findings would still say PASS here.
        gates = tuple(
            dataclasses.replace(gate, status=GateStatus.FAIL)
            if gate.gate_id == "distinct_endpoints"
            else gate
            for gate in run.assessment.gates
        )
        assessment = dataclasses.replace(run.assessment, gates=gates)
        conclusion = dataclasses.replace(run.conclusion, assessment=assessment)
        forced = dataclasses.replace(run, assessment=assessment, conclusion=conclusion)

        summary = render_summary(forced, results_dir=directory)

        self.assertEqual(forced.conclusion.finding_count, 0)
        self.assertIn("**Instrument validation status:** `FAIL`", summary)
        self.assertIn("**Result:** `NO_CONCLUSION`", summary)
        self.assertIn("distinct_endpoints", summary)

    def test_the_report_module_evaluates_no_thresholds(self) -> None:
        source = Path(report_module.__file__).read_text(encoding="utf-8")

        for forbidden in ("Decimal", "Fraction", "within_threshold", "at_least", "exact_rate"):
            with self.subTest(symbol=forbidden):
                self.assertNotIn(forbidden, source)

    def test_a_mandatory_gate_cannot_be_relabelled_advisory(self) -> None:
        """Demoting a gate would let a failing check stop forcing NO_CONCLUSION."""

        from slot_audit.assessment import Gate, InstrumentAssessment

        gates = tuple(
            Gate(
                gate_id=name,
                title=name,
                status=GateStatus.PASS,
                detail="",
                mandatory=(name != "per_provider_agreement"),
            )
            for name in MANDATORY_GATES
        )

        with self.assertRaisesRegex(ValueError, "may not be marked advisory"):
            InstrumentAssessment(gates=gates)

    def test_the_mandatory_gate_list_is_the_declared_one(self) -> None:
        self.assertEqual(
            MANDATORY_GATES,
            (
                "negative_control_provider_hole",
                "negative_control_token_truncation",
                "negative_control_previous_blockhash",
                "ground_truth_constants_provenance",
                "ground_truth_provenance_binding",
                "ground_truth_full_epoch_coverage",
                "per_provider_agreement",
                "indeterminate_threshold",
                "exact_pinned_slot_support",
                "distinct_endpoints",
                "finding_evidence_completeness",
                "manifest_provenance_completeness",
            ),
        )

    async def test_zero_findings_with_a_failed_gate_is_still_no_conclusion(self) -> None:
        run = await run_audit(directory=self.tmp_path / "run", run_negative_controls=False)

        self.assertEqual(run.findings, ())
        self.assertIs(run.assessment.status, GateStatus.FAIL)
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)
        self.assertTrue(run.conclusion.blocked_by)


class AbsenceConfirmationTests(EpochAuditTestCase):
    """A conclusive hole needs the provider to *say* it has no block."""

    async def _run_with_direct_answer(self, answer, name: str):
        from tests.epoch_support import get_block_answers

        epoch = build_simulated_epoch()
        target = epoch.produced_slots[5]
        run = await run_audit(
            directory=self.tmp_path / name,
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
            handler_wrappers={"control-a": get_block_answers(target, answer)},
        )
        return run, target

    async def test_a_skipped_slot_answer_confirms_absence(self) -> None:
        from slot_audit.transport import ScriptedRpcError

        run, target = await self._run_with_direct_answer(
            ScriptedRpcError(-32007, "Slot was skipped or missing"), "confirmed-32007"
        )

        self.assertEqual([finding.slot for finding in run.findings], [target])
        self.assertIn("-32007", run.findings[0].inference)

    async def test_a_null_block_answer_confirms_absence_only_after_a_second_read(
        self,
    ) -> None:
        run, target = await self._run_with_direct_answer(None, "confirmed-null")

        self.assertEqual([finding.slot for finding in run.findings], [target])
        finding = run.findings[0]
        self.assertIn("null block", finding.inference)
        self.assertIn("confirming re-read against the same endpoint agreed", finding.inference)
        # The residual limit of an in-band check is stated, not implied.
        self.assertIn("not an endpoint that consistently returns null", finding.inference)
        self.assertIn("direct_response_confirmation", finding.evidence)
        self.assertTrue(
            (run.evidence_root / finding.evidence["direct_response_confirmation"]
             .relative_path).is_file()
        )

    async def test_a_single_unreplicated_null_is_not_enough(self) -> None:
        """An edge-cache miss returns null once; it must not become a finding."""

        from tests.epoch_support import Handler

        epoch = build_simulated_epoch()
        target = epoch.produced_slots[5]
        header = epoch.headers[target]
        seen = {"n": 0}

        def flaky(handler: Handler) -> Handler:
            def wrapped(url: str, method: str, params: list) -> object:
                if method == "getBlock" and int(params[0]) == target:
                    seen["n"] += 1
                    # Null for the hash-link read and the first direct read; the
                    # confirming re-read finds the block the provider had all along.
                    if seen["n"] < 3:
                        return None
                    return {
                        "blockhash": header.blockhash,
                        "previousBlockhash": header.previous_blockhash,
                        "parentSlot": header.parent_slot,
                    }
                return handler(url, method, params)

            return wrapped

        run = await run_audit(
            directory=self.tmp_path / "flaky-null",
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
            handler_wrappers={"control-a": flaky},
            chunk_size=epoch.spec.scheduled_slot_positions,
        )

        self.assertEqual(run.findings, ())
        matter = next(
            item
            for item in run.indeterminate
            if item.slot == target and item.subject.startswith("provider_hole:")
        )
        self.assertIn("did not agree", matter.reason)
        self.assertIn("unreplicated null", matter.reason)

    async def test_an_unhealthy_node_never_becomes_a_hole(self) -> None:
        from slot_audit.transport import ScriptedRpcError

        run, target = await self._run_with_direct_answer(
            ScriptedRpcError(-32005, "Node is unhealthy"), "unhealthy"
        )

        self.assertEqual(run.findings, ())
        matter = next(
            item
            for item in run.indeterminate
            if item.slot == target and item.subject.startswith("provider_hole:")
        )
        self.assertIn("could not establish", matter.reason)
        self.assertTrue(matter.evidence)
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)

    async def test_a_transport_failure_never_becomes_a_hole(self) -> None:
        from slot_audit.transport import TransportError

        def wrapper(handler):  # type: ignore[no-untyped-def]
            def wrapped(url: str, method: str, params: list) -> object:
                if method == "getBlock":
                    raise TransportError("connection reset")
                return handler(url, method, params)

            return wrapped

        epoch = build_simulated_epoch()
        target = epoch.produced_slots[5]

        run = await run_audit(
            directory=self.tmp_path / "transport",
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
            handler_wrappers={"control-a": wrapper},
        )

        self.assertEqual(run.findings, ())
        self.assertTrue(
            any(item.subject.startswith("provider_hole:") for item in run.indeterminate)
        )

    async def test_a_pruned_block_is_a_retention_limit_not_a_hole(self) -> None:
        from slot_audit.transport import ScriptedRpcError

        run, target = await self._run_with_direct_answer(
            ScriptedRpcError(-32001, "Block cleaned up. First available block: 500"),
            "retention",
        )

        self.assertEqual(run.findings, ())
        matter = next(
            item
            for item in run.indeterminate
            if item.slot == target and item.subject.startswith("provider_hole:")
        )
        self.assertIn("BLOCK_CLEANED_UP", matter.reason)
        self.assertIn("storage-window limitation", matter.reason)
        self.assertIn("not a demonstrated data hole", matter.reason)

    async def test_a_contradicting_direct_answer_is_not_a_hole(self) -> None:
        """The batch omitted it but the direct call served it: unresolved."""

        from slot_audit.transport import ScriptedRpcError  # noqa: F401

        epoch = build_simulated_epoch()
        target = epoch.produced_slots[5]
        header = epoch.headers[target]
        from tests.epoch_support import get_block_answers

        run = await run_audit(
            directory=self.tmp_path / "contradiction",
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
            handler_wrappers={
                "control-a": get_block_answers(
                    target,
                    {
                        "blockhash": header.blockhash,
                        "previousBlockhash": header.previous_blockhash,
                        "parentSlot": header.parent_slot,
                    },
                )
            },
        )

        self.assertEqual(run.findings, ())
        matter = next(
            item
            for item in run.indeterminate
            if item.slot == target and item.subject.startswith("provider_hole:")
        )
        self.assertIn("contradicting the batch omission", matter.reason)


class ConclusiveFindingRunTests(EpochAuditTestCase):
    """The one path the whole instrument exists for, end to end.

    Every other test either produces no findings, or produces findings on a run
    that is blocked from concluding. Until this test existed, the case the tool
    is actually built to handle -- every mandatory gate passes *and* a defensible
    PROVIDER_HOLE is reported -- had never been exercised.

    A 512-position fixture is used so that one lost block leaves agreement at
    511/512, above the configured 0.99 minimum. On the 32-slot fixture a single
    finding drags agreement to 96.875% and the run is correctly refused, which is
    why the case was previously unreachable.
    """

    async def asyncSetUp(self) -> None:
        from slot_audit.config import ContinuityConfig
        from slot_audit.negative_controls import run_all_negative_controls

        self.controls = await run_all_negative_controls(
            results_dir=self.tmp_path / "controls"
        )
        self.epoch = build_simulated_epoch(
            epoch=900_400, first_slot=410_000_000, positions=512, produced=384
        )
        self.target = self.epoch.produced_slots[100]
        config = build_control_config(self.epoch)
        self.config = config.model_copy(
            update={
                "continuity": ContinuityConfig(
                    hash_link_validation_population="findings_and_adjacent"
                )
            }
        )
        self.directory = self.tmp_path / "conclusive"
        self.run = await run_audit(
            directory=self.directory,
            epoch=self.epoch,
            config=self.config,
            defects={
                "control-a": LedgerDefects(dropped_slots=frozenset({self.target}))
            },
            negative_controls=self.controls,
        )

    async def test_the_run_concludes_with_a_finding(self) -> None:
        self.assertIs(self.run.assessment.status, GateStatus.PASS)
        self.assertIs(self.run.conclusion.result, RunResult.FINDINGS)
        self.assertEqual(self.run.conclusion.blocked_by, ())
        self.assertEqual(len(self.run.findings), 1)

    async def test_every_mandatory_gate_passed(self) -> None:
        for gate_id in MANDATORY_GATES:
            with self.subTest(gate=gate_id):
                gate = self.run.assessment.gate(gate_id)
                self.assertTrue(gate.mandatory)
                self.assertIs(gate.status, GateStatus.PASS, gate.detail)

    async def test_the_finding_is_fully_defensible(self) -> None:
        finding = self.run.findings[0]
        header = self.epoch.headers[self.target]

        self.assertEqual(finding.slot, self.target)
        self.assertEqual(finding.provider, "control-a")
        self.assertIs(finding.verdict, Verdict.PROVIDER_HOLE)
        self.assertEqual(finding.blockhash, header.blockhash)
        self.assertEqual(finding.previous_blockhash, header.previous_blockhash)
        self.assertEqual(finding.parent_slot, header.parent_slot)
        self.assertEqual(finding.corroborating_providers, ("control-b",))
        self.assertTrue(finding.complete)

    async def test_agreement_survives_a_single_lost_block(self) -> None:
        agreement = next(
            item for item in self.run.provider_agreements if item.provider == "control-a"
        )

        self.assertEqual(
            agreement.classification_rate, Fraction(511, 512)
        )
        self.assertGreater(agreement.classification_rate, Fraction(99, 100))

    async def test_summary_result_and_sealed_evidence_all_agree(self) -> None:
        from slot_audit.report import verify_reports

        summary_path, result_path = write_reports(
            self.run, results_dir=self.directory
        )
        summary = summary_path.read_text(encoding="utf-8")
        result = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertIn("**Result:** `FINDINGS`", summary)
        self.assertIn("**Instrument validation status:** `PASS`", summary)
        self.assertIn(str(self.target), summary)
        self.assertEqual(result["conclusion"]["result"], "FINDINGS")
        self.assertEqual(result["findings"][0]["slot"], self.target)
        self.assertEqual(result["assessment"]["status"], "PASS")

        # The readable copies are the sealed bytes, and the store is intact.
        self.assertTrue(verify_manifest(self.run.evidence_root).ok)
        self.assertTrue(verify_reports(self.directory, self.run.evidence_root).ok)
        self.assertIsNotNone(self.run.summary_evidence)
        self.assertIsNotNone(self.run.result_evidence)

    async def test_the_conclusion_is_reachable_only_because_the_gates_passed(
        self,
    ) -> None:
        """The same run without its controls must refuse to conclude."""

        rerun = await run_audit(
            directory=self.tmp_path / "uncontrolled",
            epoch=self.epoch,
            config=self.config,
            defects={
                "control-a": LedgerDefects(dropped_slots=frozenset({self.target}))
            },
            run_negative_controls=False,
        )

        self.assertEqual(len(rerun.findings), 1)
        self.assertIs(rerun.conclusion.result, RunResult.NO_CONCLUSION)


class VacuousChainTests(EpochAuditTestCase):
    async def test_a_chain_with_nothing_to_check_does_not_claim_success(self) -> None:
        from slot_audit.continuity import ContinuityResult

        empty = ContinuityResult(population="nothing", population_size=0, links=())

        self.assertTrue(empty.vacuous)
        self.assertFalse(empty.clean)
        self.assertIn("vacuous", empty.to_payload())
        self.assertTrue(empty.to_payload()["vacuous"])


class RequestCostTests(EpochAuditTestCase):
    async def test_request_cost_is_recorded_per_provider_and_reported(self) -> None:
        directory = self.tmp_path / "run"

        run = await run_audit(directory=directory)
        summary = render_summary(run, results_dir=directory)
        payload = run.to_payload()["request_stats"]

        self.assertEqual({item.provider for item in run.request_stats},
                         {"control-a", "control-b"})
        for stats in run.request_stats:
            with self.subTest(provider=stats.provider):
                self.assertGreater(stats.logical_calls, 0)
                self.assertGreaterEqual(stats.attempts, stats.logical_calls)
                self.assertEqual(stats.retries, 0)
                self.assertFalse(stats.budget_exhausted)
                self.assertEqual(stats.budget_limit, 5_000)
        self.assertIn("## Request cost and limits", summary)
        self.assertEqual(len(payload), 2)

    async def test_an_exhausted_budget_is_declared_not_silently_absorbed(self) -> None:
        epoch = build_simulated_epoch()
        config = build_control_config(epoch)
        starved = config.model_copy(
            update={"limits": config.limits.model_copy(update={"max_requests_per_provider": 3})}
        )
        directory = self.tmp_path / "starved"

        run = await run_audit(directory=directory, epoch=epoch, config=starved)

        self.assertTrue(any(item.budget_exhausted for item in run.request_stats))
        subjects = {matter.subject for matter in run.indeterminate}
        self.assertTrue(
            any(subject.startswith("request_budget:") for subject in subjects), subjects
        )
        # A run that stopped asking must not be able to conclude anything.
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)
        self.assertEqual(run.findings, ())
        summary = render_summary(run, results_dir=directory)
        self.assertIn("YES", summary)

    async def test_a_starved_run_never_reports_a_provider_hole(self) -> None:
        """Not asking is not evidence of absence."""

        epoch = build_simulated_epoch()
        config = build_control_config(epoch)
        starved = config.model_copy(
            update={"limits": config.limits.model_copy(update={"max_requests_per_provider": 4})}
        )

        run = await run_audit(
            directory=self.tmp_path / "starved",
            epoch=epoch,
            config=starved,
            defects={
                "control-a": LedgerDefects(
                    dropped_slots=frozenset({epoch.produced_slots[5]})
                )
            },
        )

        self.assertEqual(run.findings, ())
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)


class AgreementReportingTests(EpochAuditTestCase):
    async def test_agreement_is_reported_once_not_as_two_lookalike_metrics(self) -> None:
        """Two figures that are always equal are one measurement, not two."""

        run = await run_audit(directory=self.tmp_path / "run")
        payload = run.to_payload()["agreement"]["per_provider"][0]

        self.assertNotIn("availability_agreement", payload)
        self.assertIn("classification_agreement", payload)
        self.assertIn("coverage_completeness", payload)
        self.assertIn("counted twice", payload["note"])
        # Coverage is scored over every scheduled position and never over the
        # agreement denominator, so the two cannot collapse into each other.
        self.assertEqual(
            payload["coverage_completeness"]["denominator"],
            run.spec.scheduled_slot_positions,
        )

    async def test_coverage_and_agreement_diverge_when_a_provider_cannot_answer(
        self,
    ) -> None:
        from tests.epoch_support import failing_get_blocks

        epoch = build_simulated_epoch()
        run = await run_audit(
            directory=self.tmp_path / "partial",
            epoch=epoch,
            chunk_size=1,
            handler_wrappers={"control-a": failing_get_blocks(epoch.produced_slots[4])},
        )
        agreement = next(
            item for item in run.provider_agreements if item.provider == "control-a"
        )

        # Perfect agreement over what it answered for, but incomplete coverage.
        # A single number could not express both.
        self.assertEqual(agreement.classification_rate, Fraction(1, 1))
        self.assertEqual(
            agreement.coverage_rate,
            Fraction(
                epoch.spec.scheduled_slot_positions - 1,
                epoch.spec.scheduled_slot_positions,
            ),
        )
        self.assertNotEqual(agreement.classification_rate, agreement.coverage_rate)

    async def test_per_provider_and_combined_agreement_are_reported_separately(
        self,
    ) -> None:
        directory = self.tmp_path / "run"
        epoch = build_simulated_epoch()
        target = epoch.produced_slots[8]

        run = await run_audit(
            directory=directory,
            epoch=epoch,
            defects={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        )
        summary_path, result_path = write_reports(run, results_dir=directory)
        summary = summary_path.read_text(encoding="utf-8")
        result = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertIn("### Per-provider agreement", summary)
        self.assertIn("### Combined two-provider existence inference agreement", summary)
        self.assertIn("not a per-provider number", summary)

        per_provider = {item["provider"]: item for item in result["agreement"]["per_provider"]}
        self.assertEqual(set(per_provider), {"control-a", "control-b"})
        combined = result["agreement"]["combined_two_provider_existence_inference"]
        self.assertEqual(combined["scope"], "combined_two_provider_existence_inference")

        # The provider that lost a block disagrees with the anchor; the pair,
        # taken together, still infers existence correctly. Distinct numbers.
        self.assertLess(
            Fraction(
                per_provider["control-a"]["classification_agreement"]["numerator"],
                per_provider["control-a"]["classification_agreement"]["denominator"],
            ),
            Fraction(combined["numerator"], combined["denominator"]),
        )

    async def test_each_agreement_reports_numerator_denominator_and_policy(self) -> None:
        run = await run_audit(directory=self.tmp_path / "run")
        payload = run.to_payload()["agreement"]

        for item in payload["per_provider"]:
            with self.subTest(provider=item["provider"]):
                for section in ("classification_agreement", "coverage_completeness"):
                    block = item[section]
                    self.assertIn("numerator", block)
                    self.assertIn("denominator", block)
                    self.assertIn("rate", block)
                    self.assertIn("percent", block)
                self.assertIn("indeterminate_count", item)
                self.assertEqual(
                    item["denominator_policy"], "determinate_positions_only"
                )
        combined = payload["combined_two_provider_existence_inference"]
        for key in (
            "numerator",
            "denominator",
            "rate",
            "indeterminate_count",
            "denominator_policy",
        ):
            self.assertIn(key, combined)


class ScopeAndOrderingTests(EpochAuditTestCase):
    async def test_provider_inference_is_frozen_before_the_anchor_is_read(self) -> None:
        run = await run_audit(directory=self.tmp_path / "run")
        order = _write_order(run)

        frozen_index = order.index("artifacts/provider-only-inference.json")
        anchor_index = next(
            index
            for index, path in enumerate(order)
            if path.startswith("artifacts/ground-truth-epoch-")
        )

        self.assertLess(frozen_index, anchor_index)
        # Every provider batch response is older still: the freeze covers a
        # complete collection, not a partial one.
        last_range = max(
            index for index, path in enumerate(order) if "getBlocks" in path
        )
        self.assertLess(last_range, frozen_index)

    async def test_a_run_refuses_to_overwrite_a_previous_evidence_run(self) -> None:
        directory = self.tmp_path / "run"
        await run_audit(directory=directory)

        with self.assertRaisesRegex(EvidenceError, "never be overwritten"):
            EvidenceStore(directory / "evidence")

    async def test_config_disagreeing_with_the_pinned_specification_is_fatal(
        self,
    ) -> None:
        epoch = build_simulated_epoch()
        config = build_control_config(epoch)
        tampered = config.model_copy(
            update={
                "ground_truth": config.ground_truth.model_copy(
                    update={"produced_blocks": config.ground_truth.produced_blocks + 1}
                )
            }
        )

        with self.assertRaisesRegex(AuditError, "pinned"):
            await run_audit(
                directory=self.tmp_path / "run", epoch=epoch, config=tampered
            )

    async def test_an_inexact_context_slot_blocks_the_conclusion(self) -> None:
        epoch = build_simulated_epoch()

        run = await run_audit(
            directory=self.tmp_path / "run",
            epoch=epoch,
            handler_wrappers={"control-a": inexact_context(epoch.pinned_slot - 1)},
            run_negative_controls=True,
        )

        self.assertIs(
            run.assessment.gate("exact_pinned_slot_support").status, GateStatus.FAIL
        )
        self.assertIs(run.conclusion.result, RunResult.NO_CONCLUSION)
        self.assertIn("exact_pinned_slot_support", run.conclusion.blocked_by)

    async def test_the_scope_echo_reaches_both_evidence_and_summary(self) -> None:
        directory = self.tmp_path / "run"
        run = await run_audit(directory=directory)
        summary = render_summary(run, results_dir=directory)
        stored = json.loads(
            (run.evidence_root / "artifacts" / "scope.json").read_text(encoding="utf-8")
        )

        self.assertEqual(stored["scope"]["epoch"], run.spec.epoch)
        self.assertEqual(stored["thresholds"]["indeterminate_threshold"], "0.01")
        self.assertIn("Exact-context policy: `require_exact_pinned_slot`", summary)
        self.assertIn("Denominator policy: `determinate_positions_only`", summary)
        self.assertIn("Materiality threshold: `0.0001`", summary)
        self.assertIn("Duplicate-pubkey policy: `reject`", summary)
        self.assertIn("Zero-balance inclusion policy: `include`", summary)
        self.assertIn(
            "Hash-link validation population: `all_produced_blocks`", summary
        )

    async def test_the_summary_gives_verification_and_re_performance_commands(
        self,
    ) -> None:
        directory = self.tmp_path / "run"
        run = await run_audit(directory=directory)
        summary = render_summary(run, results_dir=directory)

        self.assertIn("python3 -m slot_audit verify-evidence --evidence-dir", summary)
        self.assertIn("shasum -a 256", summary)
        self.assertIn("python3 -m unittest discover -s tests -v", summary)


def _write_order(run) -> list[str]:
    """The order in which the store actually recorded evidence."""

    manifest = json.loads(
        (run.evidence_root / "manifest.json").read_text(encoding="utf-8")
    )
    return list(manifest["write_order"])


def _empty_tally(positions: int):
    from slot_audit.audit import ClassificationTally

    return ClassificationTally(
        scheduled_positions=positions,
        ground_truth_produced=0,
        ground_truth_skipped=0,
        ground_truth_unknown=0,
        verdict_counts={},
        inference_counts={},
        indeterminate_positions=0,
        candidate_holes=(),
        conflicts=(),
        indeterminate_outcomes=(),
        provider_coverage={},
        provider_classification={},
        combined_agreement=(0, 0),
    )


def _dummy_extractor():
    from slot_audit.groundtruth import ExtractorIdentity

    return ExtractorIdentity(
        name="test",
        version="0",
        source_commit="0" * 40,
        command="test",
        node_schema="test",
    )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
