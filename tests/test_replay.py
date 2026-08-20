"""Replay: the conclusion must be reproducible from the retained bytes alone.

These tests are the reason the raw-byte retention is worth its disk space. They
also close, in practice, the gap an unsigned manifest leaves open: a forger who
edits a response and recomputes the manifest passes ``verify-evidence`` but
cannot make the forged bytes reproduce the sealed conclusion.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.config import ContinuityConfig
from slot_audit.evidence import MANIFEST_NAME, verify_manifest
from slot_audit.negative_controls import (
    LedgerDefects,
    build_control_config,
    build_simulated_epoch,
    run_all_negative_controls,
)
from slot_audit.replay import (
    ReplayError,
    ReplayTransport,
    load_exchanges,
    reconstruct_ground_truth,
    reconstruct_spec,
    replay_audit,
)
from slot_audit.report import write_reports
from tests.epoch_support import run_audit


def _set_manifest_entry(root: Path, relative: str, data: bytes) -> None:
    manifest_path = root / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["entries"]:
        if entry["relative_path"] == relative:
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["byte_length"] = len(data)
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def forge_response(root: Path, sequence: int, body: bytes) -> None:
    """Rewrite a recorded response the way a determined forger would have to.

    Three places have to agree: the raw bytes, the independent digest the meta
    record keeps, and the manifest entry. Doing only one or two is caught before
    replay even starts, which is itself worth knowing.
    """

    stem = f"{sequence:06d}-"
    raw_relative = next(
        path.relative_to(root).as_posix()
        for path in sorted((root / "raw").glob("*.json"))
        if path.name.startswith(stem)
    )
    meta_path = next(
        path for path in sorted((root / "meta").glob("*.json"))
        if path.name.startswith(stem)
    )
    (root / raw_relative).write_bytes(body)
    _set_manifest_entry(root, raw_relative, body)

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["response"]["sha256"] = hashlib.sha256(body).hexdigest()
    meta["response"]["byte_length"] = len(body)
    meta_bytes = (
        json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
    meta_path.write_bytes(meta_bytes)
    _set_manifest_entry(root, meta_path.relative_to(root).as_posix(), meta_bytes)


class ReplayTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)

    async def _sealed_run(self, *, with_finding: bool = True):
        controls = await run_all_negative_controls(
            results_dir=self.tmp_path / "controls"
        )
        epoch = build_simulated_epoch(
            epoch=900_400, first_slot=410_000_000, positions=512, produced=384
        )
        config = build_control_config(epoch).model_copy(
            update={
                "continuity": ContinuityConfig(
                    hash_link_validation_population="findings_and_adjacent"
                )
            }
        )
        target = epoch.produced_slots[100]
        defects = (
            {"control-a": LedgerDefects(dropped_slots=frozenset({target}))}
            if with_finding
            else {}
        )
        directory = self.tmp_path / "original"
        run = await run_audit(
            directory=directory,
            epoch=epoch,
            config=config,
            defects=defects,
            negative_controls=controls,
        )
        write_reports(run, results_dir=directory)
        return run, epoch, target


class ReproductionTests(ReplayTestCase):
    async def test_a_conclusive_run_reproduces_from_its_own_evidence(self) -> None:
        run, _epoch, target = await self._sealed_run()
        self.assertEqual(run.conclusion.result.value, "FINDINGS")

        result, replayed = await replay_audit(
            run.evidence_root, output_dir=self.tmp_path / "replay"
        )

        self.assertTrue(result.reproduced, result.describe())
        self.assertEqual(result.original_result, "FINDINGS")
        self.assertEqual(result.replayed_result, "FINDINGS")
        self.assertEqual(result.gate_differences, ())
        self.assertEqual(result.finding_differences, ())
        self.assertEqual([item.slot for item in replayed.findings], [target])

    async def test_a_clean_run_reproduces_too(self) -> None:
        run, _epoch, _target = await self._sealed_run(with_finding=False)

        result, _ = await replay_audit(
            run.evidence_root, output_dir=self.tmp_path / "replay"
        )

        self.assertTrue(result.reproduced, result.describe())
        self.assertEqual(result.replayed_result, run.conclusion.result.value)

    async def test_every_recorded_call_is_consumed(self) -> None:
        """A replay that skipped work would not be re-performing the run."""

        run, _epoch, _target = await self._sealed_run()

        result, _ = await replay_audit(
            run.evidence_root, output_dir=self.tmp_path / "replay"
        )

        self.assertTrue(result.unconsumed_calls)
        for provider, unconsumed in result.unconsumed_calls.items():
            with self.subTest(provider=provider):
                self.assertEqual(unconsumed, ())

    async def test_replay_reaches_no_network(self) -> None:
        """Structural: the only transport in play serves recorded bytes."""

        run, _epoch, _target = await self._sealed_run()
        exchanges = load_exchanges(run.evidence_root)
        transport = ReplayTransport("control-a", exchanges)

        self.assertTrue(exchanges)
        self.assertFalse(hasattr(transport, "_client"))
        with self.assertRaisesRegex(ReplayError, "never made"):
            await transport.post(
                "https://replay.invalid/x",
                {"method": "getBlock", "params": [999_999_999], "id": 1},
            )

    async def test_the_replay_records_what_it_could_not_re_establish(self) -> None:
        run, _epoch, _target = await self._sealed_run()

        result, _ = await replay_audit(
            run.evidence_root, output_dir=self.tmp_path / "replay"
        )
        notes = " ".join(result.notes)

        self.assertIn("archive was not re-read", notes)
        self.assertIn("URLs were never retained", notes)
        self.assertIn("Epoch specification", notes)


class ForgeryTests(ReplayTestCase):
    async def test_forging_a_finding_in_demands_evidence_that_does_not_exist(
        self,
    ) -> None:
        """The unsigned manifest passes; replay refuses anyway.

        To manufacture a hole, a forger must remove a slot from a batch. Replay
        then needs the direct getBlock that would confirm the new candidate --
        and the original never made that call, because it had no such candidate.
        Forging a finding therefore requires forging its confirmation too.
        """

        run, epoch, _target = await self._sealed_run()
        neighbour = epoch.produced_slots[101]

        # Edit control-a's getBlocks batch to also omit a slot it really served,
        # rewriting the raw bytes, the meta digest and the manifest so that every
        # integrity check the store can perform on itself still passes.
        batch = next(
            item
            for item in load_exchanges(run.evidence_root)
            if item.provider == "control-a" and item.method == "getBlocks"
        )
        envelope = json.loads(batch.body.decode("utf-8"))
        envelope["result"] = [slot for slot in envelope["result"] if slot != neighbour]
        forge_response(
            run.evidence_root,
            batch.sequence,
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        # Invisible to closed-world manifest verification ...
        self.assertTrue(verify_manifest(run.evidence_root).ok)

        # ... and refused by replay, which will not invent the confirming call.
        with self.assertRaises(ReplayError) as raised:
            await replay_audit(run.evidence_root, output_dir=self.tmp_path / "replay")

        message = str(raised.exception)
        self.assertIn("never made", message)
        self.assertIn("not reproducible from its own evidence", message)
        # The call replay could not get served is a block-level confirmation --
        # exactly the evidence the forged batch would need and does not have.
        self.assertIn("getBlock", message)
        self.assertIn("control-a", message)

    async def test_forging_a_finding_out_fails_to_reproduce_the_conclusion(
        self,
    ) -> None:
        """The other direction: suppressing a real finding.

        Removing the omission needs no new calls, so replay runs to completion --
        and reports a conclusion that no longer contains the sealed finding, plus
        the confirming calls the forged run no longer had any reason to make.
        """

        run, _epoch, target = await self._sealed_run()
        batch = next(
            item
            for item in load_exchanges(run.evidence_root)
            if item.provider == "control-a" and item.method == "getBlocks"
        )
        envelope = json.loads(batch.body.decode("utf-8"))
        envelope["result"] = sorted({*envelope["result"], target})
        forge_response(
            run.evidence_root,
            batch.sequence,
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        self.assertTrue(verify_manifest(run.evidence_root).ok)

        result, replayed = await replay_audit(
            run.evidence_root, output_dir=self.tmp_path / "replay"
        )

        self.assertFalse(result.reproduced, result.describe())
        self.assertEqual(replayed.findings, ())
        self.assertTrue(
            any(str(target) in item for item in result.finding_differences),
            result.describe(),
        )
        self.assertTrue(
            any(result.unconsumed_calls.values()),
            "the confirming calls the sealed run made are now unexplained",
        )

    async def test_a_deleted_response_stops_the_replay(self) -> None:
        run, _epoch, _target = await self._sealed_run()
        victim = sorted((run.evidence_root / "raw").glob("*getBlock.json"))[-1]
        victim.unlink()

        with self.assertRaises(ReplayError):
            await replay_audit(run.evidence_root, output_dir=self.tmp_path / "replay")

    async def test_a_partial_forgery_is_caught_before_replay_begins(self) -> None:
        """Editing the bytes and the manifest, but not the meta digest, fails."""

        run, _epoch, _target = await self._sealed_run()
        victim = sorted((run.evidence_root / "raw").glob("*getBlocks.json"))[0]
        forged = b'{"jsonrpc":"2.0","id":1,"result":[]}'
        victim.write_bytes(forged)
        _set_manifest_entry(
            run.evidence_root, victim.relative_to(run.evidence_root).as_posix(), forged
        )

        self.assertTrue(verify_manifest(run.evidence_root).ok)
        with self.assertRaisesRegex(ReplayError, "does not match its recorded digest"):
            load_exchanges(run.evidence_root)

    async def test_a_body_that_does_not_match_its_digest_is_refused(self) -> None:
        run, _epoch, _target = await self._sealed_run()
        victim = sorted((run.evidence_root / "raw").glob("*getBlocks.json"))[0]
        victim.write_bytes(b'{"jsonrpc":"2.0","id":1,"result":[]}')

        with self.assertRaisesRegex(ReplayError, "does not match its recorded digest"):
            load_exchanges(run.evidence_root)


class AnchorReconstructionTests(ReplayTestCase):
    async def test_the_anchor_is_rebuilt_from_retained_records(self) -> None:
        run, epoch, _target = await self._sealed_run()

        truth = reconstruct_ground_truth(run.evidence_root)

        self.assertEqual(truth.produced_count, epoch.spec.produced_blocks)
        self.assertEqual(truth.filtered_predecessor_rows, 1)
        self.assertIsNotNone(truth.predecessor_header)
        self.assertTrue(truth.verified)
        steps = {step.step for step in truth.trust_chain}
        self.assertIn("replayed_from_retained_records", steps)
        # Replay must not pretend it re-established the CAR-level links.
        detail = next(
            step.detail
            for step in truth.trust_chain
            if step.step == "replayed_from_retained_records"
        )
        self.assertIn("archive itself was not re-read", " ".join(detail.split()))

    async def test_tampering_with_the_derived_records_is_caught(self) -> None:
        run, _epoch, _target = await self._sealed_run()
        derived = next((run.evidence_root / "artifacts").glob("ground-truth-*.jsonl"))
        rows = derived.read_bytes().splitlines()
        derived.write_bytes(b"\n".join(rows[:-1]) + b"\n")

        with self.assertRaisesRegex(ReplayError, "does not hash|hash to"):
            reconstruct_ground_truth(run.evidence_root)

    async def test_an_unpinned_epoch_uses_the_retained_specification(self) -> None:
        run, epoch, _target = await self._sealed_run()

        spec, origin = reconstruct_spec(run.evidence_root)

        self.assertEqual(spec.epoch, epoch.spec.epoch)
        self.assertIn("not pinned", origin)

    async def test_a_pinned_epoch_refuses_a_disagreeing_record(self) -> None:
        """An edited derivation record cannot relax a pinned specification."""

        run, _epoch, _target = await self._sealed_run()
        record_path = next(
            (run.evidence_root / "artifacts").glob("ground-truth-epoch-*-derivation.json")
        )
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["spec"]["epoch"] = 100  # claim to be the pinned epoch
        record_path.write_text(json.dumps(record), encoding="utf-8")

        with self.assertRaisesRegex(ReplayError, "disagrees"):
            reconstruct_spec(run.evidence_root)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
