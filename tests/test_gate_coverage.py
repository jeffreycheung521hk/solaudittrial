"""Every mandatory gate must have a test that watches it fail.

The most consequential gate in this tool once shipped without a FAIL-path test,
and an external reviewer had to find that. It was not an oversight so much as a
structural certainty: gates had no addressable identity, so nobody could ask
"which gates lack a failure test?" and get an answer.

This module makes that question mechanical. Each mandatory gate needs a scenario
here that *executes* and produces a FAIL for it. Adding a gate to
``GATE_REGISTRY`` without adding a scenario breaks the build.

Each scenario declares its level honestly:

``orchestration``
    the gate is driven to FAIL through a full :func:`run_epoch_audit`.
``assessment``
    the FAIL condition cannot be reached through the orchestration -- usually
    because an earlier layer already refuses it -- so the assessment is
    re-evaluated over a crafted input. Named as such rather than dressed up.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
from collections.abc import Awaitable, Callable
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.assessment import (
    GATE_REGISTRY,
    MANDATORY_GATES,
    GateStatus,
    InstrumentAssessment,
    build_gate,
)
from slot_audit.audit import BlockFinding, build_assessment
from slot_audit.evidence import MANIFEST_NAME, EvidenceRef
from slot_audit.groundtruth import UNVERIFIED_PROVENANCE
from slot_audit.negative_controls import (
    PROVIDER_A_URL,
    LedgerDefects,
    build_simulated_epoch,
)
from tests.epoch_support import failing_get_blocks, inexact_context, run_audit

LEVELS = {"orchestration", "assessment"}


@dataclasses.dataclass(frozen=True, slots=True)
class GateFailScenario:
    """A way to make one gate fail, and an honest label for how it does it."""

    gate_id: str
    level: str
    why: str
    produce: Callable[[Path], Awaitable[InstrumentAssessment]]

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            raise ValueError(f"unknown scenario level {self.level!r}")


class _StoreView:
    """A read-only stand-in for a sealed store, rebuilt from its manifest."""

    def __init__(self, root: Path) -> None:
        self.root = root
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
        self.entries = {
            entry["relative_path"]: EvidenceRef.from_payload(entry)
            for entry in manifest["entries"]
        }


async def _reassess(directory: Path, **overrides) -> InstrumentAssessment:
    """Re-evaluate a completed run's assessment with something changed."""

    sink: list = []
    run = await run_audit(
        directory=directory, run_negative_controls=True, resolved_sink=sink
    )
    arguments = {
        "resolved": sink[0],
        "spec": run.spec,
        "ground_truth": run.ground_truth,
        "tally": run.tally,
        "findings": run.findings,
        "continuity": run.continuity,
        "token_results": run.token_results,
        "collections": run.collections,
        "controls": run.negative_controls,
        "provider_agreements": run.provider_agreements,
        "combined_agreement": run.combined_agreement,
        "evidence": _StoreView(run.evidence_root),
        "provenance": run.provenance,
        "frozen_inference": run.frozen_inference,
    }
    arguments.update(overrides)
    return build_assessment(**arguments)


async def _no_controls(directory: Path) -> InstrumentAssessment:
    run = await run_audit(directory=directory, run_negative_controls=False)
    return run.assessment


async def _no_archive(directory: Path) -> InstrumentAssessment:
    run = await run_audit(directory=directory, write_car=False)
    return run.assessment


async def _unverified_constants(directory: Path) -> InstrumentAssessment:
    epoch = build_simulated_epoch()
    unverified = dataclasses.replace(
        epoch, spec=dataclasses.replace(epoch.spec, provenance=UNVERIFIED_PROVENANCE)
    )
    run = await run_audit(directory=directory, epoch=unverified)
    return run.assessment


async def _wholesale_disagreement(directory: Path) -> InstrumentAssessment:
    epoch = build_simulated_epoch()
    lost = frozenset(epoch.produced_slots[:12])
    run = await run_audit(
        directory=directory,
        epoch=epoch,
        defects={"control-a": LedgerDefects(dropped_slots=lost)},
    )
    return run.assessment



async def _uncovered_epoch(directory: Path) -> InstrumentAssessment:
    epoch = build_simulated_epoch()
    # The whole batch fails, so control-a covers nothing and every scheduled
    # position becomes indeterminate.
    run = await run_audit(
        directory=directory,
        epoch=epoch,
        handler_wrappers={"control-a": failing_get_blocks(epoch.produced_slots[0])},
    )
    return run.assessment


async def _inexact_context(directory: Path) -> InstrumentAssessment:
    epoch = build_simulated_epoch()
    run = await run_audit(
        directory=directory,
        epoch=epoch,
        handler_wrappers={"control-a": inexact_context(epoch.pinned_slot - 1)},
    )
    return run.assessment


async def _one_endpoint_twice(directory: Path) -> InstrumentAssessment:
    run = await run_audit(
        directory=directory, provider_urls=(PROVIDER_A_URL, PROVIDER_A_URL)
    )
    return run.assessment


async def _incomplete_finding(directory: Path) -> InstrumentAssessment:
    incomplete = BlockFinding(
        slot=388_843_210,
        provider="control-a",
        verdict=__import__(
            "slot_audit.verdict", fromlist=["Verdict"]
        ).Verdict.PROVIDER_HOLE,
        blockhash="So11111111111111111111111111111111111111112",
        previous_blockhash="So11111111111111111111111111111111111111112",
        parent_slot=388_843_209,
        source="old_faithful_car_derived_ground_truth",
        inference="crafted for the coverage scenario",
        evidence={},
    )
    return await _reassess(directory, findings=(incomplete,))


async def _damaged_evidence(directory: Path) -> InstrumentAssessment:
    sink: list = []
    run = await run_audit(
        directory=directory, run_negative_controls=True, resolved_sink=sink
    )
    view = _StoreView(run.evidence_root)
    # Delete a manifested artifact after the fact: the store's own integrity
    # check must notice it is gone.
    victim = next(iter(sorted(view.entries)))
    (run.evidence_root / victim).unlink()
    return build_assessment(
        resolved=sink[0],
        spec=run.spec,
        ground_truth=run.ground_truth,
        tally=run.tally,
        findings=run.findings,
        continuity=run.continuity,
        token_results=run.token_results,
        collections=run.collections,
        controls=run.negative_controls,
        provider_agreements=run.provider_agreements,
        combined_agreement=run.combined_agreement,
        evidence=view,
        provenance=run.provenance,
        frozen_inference=run.frozen_inference,
    )


SCENARIOS: tuple[GateFailScenario, ...] = (
    GateFailScenario(
        "negative_control_provider_hole",
        "orchestration",
        "a run that never executed its controls has not validated itself",
        _no_controls,
    ),
    GateFailScenario(
        "negative_control_token_truncation",
        "orchestration",
        "same run, same omission",
        _no_controls,
    ),
    GateFailScenario(
        "negative_control_previous_blockhash",
        "orchestration",
        "same run, same omission",
        _no_controls,
    ),
    GateFailScenario(
        "ground_truth_constants_provenance",
        "orchestration",
        "constants with no stated provenance, which is epoch 100's real state",
        _unverified_constants,
    ),
    GateFailScenario(
        "ground_truth_provenance_binding",
        "orchestration",
        "the archive is absent, so nothing binds the classification",
        _no_archive,
    ),
    GateFailScenario(
        "ground_truth_full_epoch_coverage",
        "orchestration",
        "no archive means no coverage of any position",
        _no_archive,
    ),
    GateFailScenario(
        "per_provider_agreement",
        "orchestration",
        "twelve lost blocks drag agreement below the configured minimum",
        _wholesale_disagreement,
    ),
    GateFailScenario(
        "indeterminate_threshold",
        "orchestration",
        "a failed batch leaves the whole epoch indeterminate for one provider",
        _uncovered_epoch,
    ),
    GateFailScenario(
        "exact_pinned_slot_support",
        "orchestration",
        "a provider answering at a different context slot",
        _inexact_context,
    ),
    GateFailScenario(
        "distinct_endpoints",
        "orchestration",
        "two providers resolving to one endpoint; resolve_epoch_config refuses to "
        "build this, so the gate is defence in depth behind it",
        _one_endpoint_twice,
    ),
    GateFailScenario(
        "finding_evidence_completeness",
        "assessment",
        "the orchestration cannot emit an evidence-less finding -- build_findings "
        "attaches the references or records an indeterminate matter -- so the "
        "guard is exercised by re-assessing a crafted finding",
        _incomplete_finding,
    ),
    GateFailScenario(
        "manifest_provenance_completeness",
        "assessment",
        "evidence is damaged after the run completes, then re-assessed",
        _damaged_evidence,
    ),
)

SCENARIOS_BY_GATE = {scenario.gate_id: scenario for scenario in SCENARIOS}


class GateCoverageMetaTests(unittest.TestCase):
    """Assertions about the test suite itself."""

    def test_every_mandatory_gate_has_a_failure_scenario(self) -> None:
        missing = [gate for gate in MANDATORY_GATES if gate not in SCENARIOS_BY_GATE]

        self.assertEqual(
            missing,
            [],
            "these mandatory gates have no test that watches them fail; add a "
            "GateFailScenario for each",
        )

    def test_no_scenario_names_an_unregistered_gate(self) -> None:
        registered = {spec.gate_id for spec in GATE_REGISTRY}

        for scenario in SCENARIOS:
            with self.subTest(gate=scenario.gate_id):
                self.assertIn(scenario.gate_id, registered)

    def test_mandatory_gates_are_derived_from_the_registry(self) -> None:
        self.assertEqual(
            MANDATORY_GATES,
            tuple(spec.gate_id for spec in GATE_REGISTRY if spec.mandatory),
        )
        self.assertEqual(len(MANDATORY_GATES), 12)

    def test_every_registered_gate_states_why_it_exists(self) -> None:
        for spec in GATE_REGISTRY:
            with self.subTest(gate=spec.gate_id):
                self.assertTrue(spec.rationale)
                self.assertTrue(spec.title)

    def test_a_gate_cannot_be_built_outside_the_registry(self) -> None:
        with self.assertRaisesRegex(ValueError, "not in GATE_REGISTRY"):
            build_gate("invented_gate", "t", passed=True, detail="")

    def test_a_gate_cannot_be_built_against_its_registered_status(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be constructed as the opposite"):
            build_gate(
                "per_provider_agreement", "t", passed=True, detail="", mandatory=False
            )
        with self.assertRaisesRegex(ValueError, "cannot be constructed as the opposite"):
            build_gate(
                "hash_link_continuity", "t", passed=True, detail="", mandatory=True
            )

    def test_scenario_levels_are_declared_and_mostly_orchestration(self) -> None:
        levels = [scenario.level for scenario in SCENARIOS]

        self.assertTrue(all(level in LEVELS for level in levels))
        # If this ratio slips, gates are drifting out of reach of the real path.
        self.assertGreaterEqual(levels.count("orchestration"), 10)


class GateFailureExecutionTests(unittest.IsolatedAsyncioTestCase):
    """Not a declaration: each scenario is run and its gate observed failing."""

    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)

    async def test_each_mandatory_gate_actually_fails_in_its_scenario(self) -> None:
        for gate_id in MANDATORY_GATES:
            scenario = SCENARIOS_BY_GATE[gate_id]
            with self.subTest(gate=gate_id, level=scenario.level):
                assessment = await scenario.produce(self.tmp_path / gate_id)
                gate = assessment.gate(gate_id)

                self.assertIs(
                    gate.status,
                    GateStatus.FAIL,
                    f"{gate_id} did not fail in its declared scenario "
                    f"({scenario.why}); detail was {gate.detail!r}",
                )
                self.assertTrue(gate.mandatory)
                self.assertFalse(assessment.passed)
                self.assertIn(
                    gate_id, [item.gate_id for item in assessment.failed_mandatory_gates]
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
