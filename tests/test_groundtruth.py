"""The ground-truth anchor: what may and may not be called verified."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.car import CarBlock, Cid, cbor_encode, encode_car
from slot_audit.evidence import EvidenceStore, sha256_hex
from slot_audit.groundtruth import (
    BLOCK_NODE_KIND,
    EPOCH_100_GROUND_TRUTH,
    PINNED_EPOCH_GROUND_TRUTH,
    CarBlockHeaderExtractor,
    EpochGroundTruthSpec,
    GroundTruthError,
    GroundTruthHeader,
    derive_ground_truth,
    pinned_spec,
)
from slot_audit.negative_controls import build_simulated_epoch
from slot_audit.token import base58_encode


def _hash(label: str) -> str:
    return base58_encode(hashlib.sha256(label.encode()).digest())


def build_archive(headers: list[GroundTruthHeader], *, epoch: int) -> tuple[bytes, Cid]:
    """Build a deterministic CAR carrying exactly the supplied headers."""

    blocks: list[CarBlock] = []
    child_cids: list[Cid] = []
    for header in headers:
        data = cbor_encode(
            {
                "kind": BLOCK_NODE_KIND,
                "slot": header.slot,
                "blockhash": header.blockhash,
                "previousBlockhash": header.previous_blockhash,
                "parentSlot": header.parent_slot,
            }
        )
        cid = Cid.for_data(data)
        blocks.append(CarBlock(cid=cid, data=data))
        child_cids.append(cid)
    root_data = cbor_encode({"kind": 4, "epoch": epoch, "subsets": child_cids})
    root_cid = Cid.for_data(root_data)
    blocks.insert(0, CarBlock(cid=root_cid, data=root_data))
    return encode_car([root_cid], blocks), root_cid


class PublishedEpoch100Tests(unittest.TestCase):
    def test_pinned_constants_are_unchanged(self) -> None:
        """A change detector, NOT external verification.

        Restating the same literals in a test file proves only that nobody
        edited them by accident. It cannot establish that they are correct,
        because there is no authority in this repository to check them against.
        That gap is what :meth:`test_the_constants_declare_that_nobody_verified_them`
        asserts is disclosed, and what the mandatory
        ``ground_truth_constants_provenance`` gate blocks on.
        """

        spec = EPOCH_100_GROUND_TRUTH

        self.assertEqual(spec.epoch, 100)
        self.assertEqual(spec.first_slot, 43_200_000)
        self.assertEqual(spec.last_slot, 43_631_999)
        self.assertEqual(spec.scheduled_slot_positions, 432_000)
        self.assertEqual(spec.produced_blocks, 402_076)
        self.assertEqual(spec.skipped_slots, 29_924)
        self.assertEqual(spec.predecessor_boundary_slot, 43_199_999)
        self.assertEqual(spec.slots_file_name, "100.slots.txt")
        self.assertEqual(
            spec.car_root_cid,
            "bafyreibqt2nvroysxlxctgb52xxn27ectsllv2xyka4qar7ga6vupmbs3i",
        )
        self.assertEqual(
            spec.car_sha256,
            "9f6d631833a8dfe0a4253ceede8e4af18a63603f0131a71ca5e947ba77eaec5a",
        )
        self.assertEqual(spec.source_commit, "a69a0d2e189006608e3b73b7659a957b00b3567e")

    def test_the_constants_declare_that_nobody_verified_them(self) -> None:
        """The repository must not present unsourced numbers as established."""

        provenance = EPOCH_100_GROUND_TRUTH.provenance

        self.assertFalse(provenance.verified_against_archive)
        self.assertIn("commissioned this tool", provenance.source)
        self.assertIn("NOT INDEPENDENTLY VERIFIED", provenance.note)
        self.assertIn("inverts the check", provenance.note)

    def test_a_specification_without_stated_provenance_is_unverified(self) -> None:
        from slot_audit.groundtruth import UNVERIFIED_PROVENANCE

        spec = EpochGroundTruthSpec(
            epoch=7,
            first_slot=100,
            last_slot=131,
            scheduled_slot_positions=32,
            produced_blocks=30,
            skipped_slots=2,
            predecessor_boundary_slot=99,
            slots_file_name="7.slots.txt",
            car_root_cid=EPOCH_100_GROUND_TRUTH.car_root_cid,
            car_sha256=EPOCH_100_GROUND_TRUTH.car_sha256,
            source_commit=EPOCH_100_GROUND_TRUTH.source_commit,
        )

        self.assertIs(spec.provenance, UNVERIFIED_PROVENANCE)
        self.assertFalse(spec.provenance.verified_against_archive)

    def test_the_declared_figures_are_internally_consistent(self) -> None:
        spec = EPOCH_100_GROUND_TRUTH

        self.assertEqual(spec.produced_blocks + spec.skipped_slots, 432_000)
        self.assertEqual(spec.last_slot - spec.first_slot + 1, 432_000)
        self.assertEqual(spec.predecessor_boundary_slot + 1, spec.first_slot)

    def test_an_inconsistent_specification_cannot_be_constructed(self) -> None:
        with self.assertRaises(GroundTruthError):
            EpochGroundTruthSpec(
                epoch=100,
                first_slot=43_200_000,
                last_slot=43_631_999,
                scheduled_slot_positions=432_000,
                produced_blocks=402_077,  # one too many
                skipped_slots=29_924,
                predecessor_boundary_slot=43_199_999,
                slots_file_name="100.slots.txt",
                car_root_cid=EPOCH_100_GROUND_TRUTH.car_root_cid,
                car_sha256=EPOCH_100_GROUND_TRUTH.car_sha256,
                source_commit=EPOCH_100_GROUND_TRUTH.source_commit,
            )

    def test_only_pinned_epochs_can_be_anchored(self) -> None:
        self.assertIs(pinned_spec(100), EPOCH_100_GROUND_TRUTH)
        self.assertEqual(set(PINNED_EPOCH_GROUND_TRUTH), {100})
        with self.assertRaises(GroundTruthError):
            pinned_spec(101)


class DerivationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)
        self.epoch = build_simulated_epoch()
        self.car_path = self.tmp_path / "epoch.car"
        self.car_path.write_bytes(self.epoch.car_bytes)
        self._store_index = 0

    def store(self) -> EvidenceStore:
        self._store_index += 1
        return EvidenceStore(self.tmp_path / f"evidence-{self._store_index}")

    def extractor(self, commit: str | None = None) -> CarBlockHeaderExtractor:
        return CarBlockHeaderExtractor(
            source_commit=commit or self.epoch.spec.source_commit
        )

    def derive(self, *, spec=None, path=None, extractor=None):
        return derive_ground_truth(
            path or self.car_path,
            spec=spec or self.epoch.spec,
            extractor=extractor or self.extractor(),
            evidence=self.store(),
        )


class SuccessfulDerivationTests(DerivationTestCase):
    def test_a_matching_archive_verifies_with_exact_coverage(self) -> None:
        truth = self.derive()

        self.assertTrue(truth.verified, truth.failures)
        self.assertEqual(truth.produced_count, self.epoch.spec.produced_blocks)
        self.assertEqual(truth.skipped_count, self.epoch.spec.skipped_slots)
        self.assertEqual(
            truth.produced_count + truth.skipped_count,
            self.epoch.spec.scheduled_slot_positions,
        )

    def test_the_predecessor_boundary_row_is_filtered_explicitly_and_counted(self) -> None:
        truth = self.derive()

        self.assertEqual(truth.filtered_predecessor_rows, 1)
        self.assertNotIn(self.epoch.spec.predecessor_boundary_slot, truth.headers)
        self.assertIsNotNone(truth.predecessor_header)
        assert truth.predecessor_header is not None
        self.assertEqual(
            truth.predecessor_header.slot, self.epoch.spec.predecessor_boundary_slot
        )
        # It is still reachable as a parent, which is why it is kept at all.
        self.assertIsNotNone(
            truth.header_for(self.epoch.spec.predecessor_boundary_slot)
        )
        step = next(
            item for item in truth.trust_chain if item.step == "predecessor_boundary_row"
        )
        self.assertTrue(step.passed)
        self.assertIn("filtered 1 row", step.detail)

    def test_the_derived_records_are_retained_with_digest_and_length(self) -> None:
        truth = self.derive()

        self.assertTrue(truth.evidence_refs)
        for ref in truth.evidence_refs:
            self.assertEqual(len(ref.sha256), 64)
            self.assertGreater(ref.byte_length, 0)
        derived = next(
            ref for ref in truth.evidence_refs if ref.relative_path.endswith(".jsonl")
        )
        self.assertIn("ground-truth", derived.relative_path)

    def test_the_trust_chain_is_bound_to_the_archive_and_nothing_else(self) -> None:
        truth = self.derive()

        steps = {item.step for item in truth.trust_chain}
        self.assertEqual(
            steps,
            {
                "extractor_pinned",
                "car_present",
                "car_sha256",
                "car_structure",
                "car_root_cid",
                "car_block_integrity",
                "car_root_block_present",
                "in_range_only",
                "unique_slots",
                "predecessor_boundary_row",
                "produced_block_count",
                "skipped_slot_count",
                "predecessor_header_available",
                "derived_artifact_retained",
            },
        )
        # No step can be satisfied by an RPC endpoint answering anything at all:
        # derivation never contacts one.
        self.assertNotIn("rpc", " ".join(steps))
        self.assertNotIn("version", " ".join(steps))


class StreamingDerivationTests(DerivationTestCase):
    """The published archive is 62.9 GB; nothing may load it whole."""

    def test_the_archive_is_never_read_into_memory(self) -> None:
        import pathlib as _pathlib

        original = _pathlib.Path.read_bytes
        calls: list[str] = []

        def refuse(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            if self.suffix == ".car":
                calls.append(str(self))
                raise AssertionError(
                    f"{self.name} was read into memory; derivation must stream"
                )
            return original(self, *args, **kwargs)

        _pathlib.Path.read_bytes = refuse  # type: ignore[method-assign]
        try:
            truth = self.derive()
        finally:
            _pathlib.Path.read_bytes = original  # type: ignore[method-assign]

        self.assertTrue(truth.verified, truth.failures)
        self.assertEqual(calls, [])
        self.assertEqual(truth.produced_count, self.epoch.spec.produced_blocks)

    def test_the_streaming_digest_agrees_with_the_in_memory_one(self) -> None:
        from slot_audit.evidence import sha256_file

        self.assertEqual(
            sha256_file(self.car_path), sha256_hex(self.car_path.read_bytes())
        )
        # A chunk size below the file length exercises the incremental path.
        self.assertEqual(
            sha256_file(self.car_path, chunk_bytes=7),
            sha256_hex(self.car_path.read_bytes()),
        )

    def test_the_derivation_record_reports_the_archive_size_and_block_count(self) -> None:
        truth = self.derive()

        derivation = next(
            ref for ref in truth.evidence_refs if ref.relative_path.endswith(".json")
        )
        payload = json.loads(
            (self.tmp_path / "evidence-1" / derivation.relative_path).read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(payload["car_byte_length"], len(self.epoch.car_bytes))
        self.assertEqual(
            payload["derived_row_count"], self.epoch.spec.produced_blocks + 1
        )
        self.assertEqual(payload["filtered_predecessor_rows"], 1)
        self.assertGreater(payload["car_block_count"], self.epoch.spec.produced_blocks)


class RejectedAnchorTests(DerivationTestCase):
    def test_an_arbitrary_file_whose_digest_a_user_supplied_cannot_verify(self) -> None:
        """A digest a user typed is not authority; the pinned digest is."""

        arbitrary = self.tmp_path / "arbitrary.bin"
        arbitrary.write_bytes(b"this is not an Old Faithful CAR file")
        user_supplied_digest = sha256_hex(arbitrary.read_bytes())
        # The operator has faithfully copied the file's own digest into config.
        self.assertNotEqual(user_supplied_digest, self.epoch.spec.car_sha256)

        truth = self.derive(path=arbitrary)

        self.assertFalse(truth.verified)
        failed = {step.step for step in truth.failures}
        self.assertEqual(failed, {"car_sha256"})
        self.assertEqual(truth.car_sha256, user_supplied_digest)
        self.assertEqual(truth.produced_count, 0)

    def test_matching_the_digest_is_not_enough_the_root_cid_must_match_too(self) -> None:
        """Pin the arbitrary file's digest; structure still rejects it."""

        arbitrary = self.tmp_path / "arbitrary.car"
        arbitrary.write_bytes(b"still not a CAR file, but now the digest agrees")
        forged = EpochGroundTruthSpec(
            epoch=self.epoch.spec.epoch,
            first_slot=self.epoch.spec.first_slot,
            last_slot=self.epoch.spec.last_slot,
            scheduled_slot_positions=self.epoch.spec.scheduled_slot_positions,
            produced_blocks=self.epoch.spec.produced_blocks,
            skipped_slots=self.epoch.spec.skipped_slots,
            predecessor_boundary_slot=self.epoch.spec.predecessor_boundary_slot,
            slots_file_name=self.epoch.spec.slots_file_name,
            car_root_cid=self.epoch.spec.car_root_cid,
            car_sha256=sha256_hex(arbitrary.read_bytes()),
            source_commit=self.epoch.spec.source_commit,
        )

        truth = self.derive(spec=forged, path=arbitrary)

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"car_structure"})

    def test_a_yaml_like_file_containing_the_expected_substrings_cannot_verify(self) -> None:
        text = (
            f"car_root_cid: {self.epoch.spec.car_root_cid}\n"
            f"car_sha256: {self.epoch.spec.car_sha256}\n"
            f"source_commit: {self.epoch.spec.source_commit}\n"
            f"produced_blocks: {self.epoch.spec.produced_blocks}\n"
        )
        decoy = self.tmp_path / "ground-truth.yaml"
        decoy.write_text(text, encoding="utf-8")

        truth = self.derive(path=decoy)

        self.assertFalse(truth.verified)
        self.assertIn("car_sha256", {step.step for step in truth.failures})

    def test_a_wrong_root_cid_is_rejected_even_with_a_valid_archive(self) -> None:
        other_epoch = build_simulated_epoch(
            epoch=self.epoch.spec.epoch,
            first_slot=self.epoch.spec.first_slot,
            positions=self.epoch.spec.scheduled_slot_positions,
            produced=self.epoch.spec.produced_blocks,
        )
        mismatched = EpochGroundTruthSpec(
            **{
                **other_epoch.spec.to_payload(),
                "car_root_cid": (
                    "bafyreibqt2nvroysxlxctgb52xxn27ectsllv2xyka4qar7ga6vupmbs3i"
                ),
            }
        )

        truth = self.derive(spec=mismatched)

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"car_root_cid"})

    def test_a_missing_archive_is_unverified_rather_than_assumed(self) -> None:
        truth = self.derive(path=self.tmp_path / "absent.car")

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"car_present"})

    def test_an_unpinned_extractor_is_refused_before_the_archive_is_read(self) -> None:
        truth = self.derive(extractor=self.extractor("d" * 40))

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"extractor_pinned"})
        self.assertEqual(len(truth.trust_chain), 1)

    def test_a_short_produced_count_fails_full_epoch_coverage(self) -> None:
        headers = [self.epoch.predecessor, *self.epoch.headers.values()][:-1]
        archive, root = build_archive(headers, epoch=self.epoch.spec.epoch)
        path = self.tmp_path / "short.car"
        path.write_bytes(archive)
        spec = EpochGroundTruthSpec(
            **{
                **self.epoch.spec.to_payload(),
                "car_root_cid": root.encode(),
                "car_sha256": sha256_hex(archive),
            }
        )

        truth = self.derive(spec=spec, path=path)

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"produced_block_count"})
        self.assertIn("expected exactly", truth.failures[0].detail)

    def test_a_slot_outside_the_epoch_is_refused(self) -> None:
        stray = GroundTruthHeader(
            slot=self.epoch.spec.last_slot + 5,
            blockhash=_hash("stray"),
            previous_blockhash=_hash("stray-parent"),
            parent_slot=self.epoch.spec.last_slot,
        )
        headers = [self.epoch.predecessor, *self.epoch.headers.values(), stray]
        archive, root = build_archive(headers, epoch=self.epoch.spec.epoch)
        path = self.tmp_path / "stray.car"
        path.write_bytes(archive)
        spec = EpochGroundTruthSpec(
            **{
                **self.epoch.spec.to_payload(),
                "car_root_cid": root.encode(),
                "car_sha256": sha256_hex(archive),
            }
        )

        truth = self.derive(spec=spec, path=path)

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"in_range_only"})

    def test_an_archive_without_the_predecessor_row_is_unverified(self) -> None:
        headers = list(self.epoch.headers.values())
        archive, root = build_archive(headers, epoch=self.epoch.spec.epoch)
        path = self.tmp_path / "no-predecessor.car"
        path.write_bytes(archive)
        spec = EpochGroundTruthSpec(
            **{
                **self.epoch.spec.to_payload(),
                "car_root_cid": root.encode(),
                "car_sha256": sha256_hex(archive),
            }
        )

        truth = self.derive(spec=spec, path=path)

        self.assertFalse(truth.verified)
        self.assertEqual(
            {step.step for step in truth.failures}, {"predecessor_header_available"}
        )

    def test_a_corrupted_archive_byte_fails_block_integrity(self) -> None:
        corrupted = bytearray(self.epoch.car_bytes)
        corrupted[-1] ^= 0xFF
        path = self.tmp_path / "corrupt.car"
        path.write_bytes(bytes(corrupted))
        spec = EpochGroundTruthSpec(
            **{
                **self.epoch.spec.to_payload(),
                "car_sha256": sha256_hex(bytes(corrupted)),
            }
        )

        truth = self.derive(spec=spec, path=path)

        self.assertFalse(truth.verified)
        self.assertEqual({step.step for step in truth.failures}, {"car_block_integrity"})


class SchemaProbeTests(DerivationTestCase):
    """The probe answers a question about the file; it asserts nothing."""

    def test_the_probe_finds_the_shape_this_build_derives_from(self) -> None:
        from slot_audit.groundtruth import BLOCK_NODE_SCHEMA, probe_car

        census = probe_car(self.car_path)

        self.assertTrue(census.schema_present)
        self.assertEqual(census.expected_schema, BLOCK_NODE_SCHEMA)
        self.assertEqual(
            census.recognized_block_nodes, self.epoch.spec.produced_blocks + 1
        )
        self.assertEqual(census.declared_roots, (self.epoch.spec.car_root_cid,))
        self.assertTrue(census.root_seen)
        self.assertIn(
            "blockhash,kind,parentSlot,previousBlockhash,slot",
            census.key_signature_counts,
        )
        self.assertIn("the shape this build derives from is present", census.describe())

    def test_an_archive_without_the_shape_is_reported_as_such(self) -> None:
        from slot_audit.car import CarBlock, Cid, cbor_encode, encode_car
        from slot_audit.groundtruth import probe_car

        # A structurally valid CAR whose nodes are a different shape entirely.
        blocks = []
        for index in range(4):
            data = cbor_encode({"kind": 9, "index": index, "payload": b"\x00"})
            blocks.append(CarBlock(cid=Cid.for_data(data), data=data))
        path = self.tmp_path / "other-shape.car"
        path.write_bytes(encode_car([blocks[0].cid], blocks))

        census = probe_car(path)

        self.assertFalse(census.schema_present)
        self.assertEqual(census.recognized_block_nodes, 0)
        self.assertEqual(census.node_kind_counts, {"9": 4})
        self.assertIn("NOT seen", census.describe())
        self.assertIn("conclude nothing", census.describe())

    def test_a_prefix_scan_stops_where_asked(self) -> None:
        from slot_audit.groundtruth import probe_car

        census = probe_car(self.car_path, max_blocks=5)

        self.assertEqual(census.blocks_scanned, 5)
        self.assertTrue(census.stopped_early)
        self.assertIn("limit of 5 blocks", str(census.stop_reason))
        self.assertLess(census.bytes_scanned, len(self.epoch.car_bytes))

    def test_the_probe_never_loads_the_archive(self) -> None:
        import pathlib as _pathlib

        from slot_audit.groundtruth import probe_car

        original = _pathlib.Path.read_bytes

        def refuse(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            if self.suffix == ".car":
                raise AssertionError("the probe must stream, not load")
            return original(self, *args, **kwargs)

        _pathlib.Path.read_bytes = refuse  # type: ignore[method-assign]
        try:
            census = probe_car(self.car_path)
        finally:
            _pathlib.Path.read_bytes = original  # type: ignore[method-assign]

        self.assertTrue(census.schema_present)

    def test_a_truncated_archive_is_reported_not_raised(self) -> None:
        from slot_audit.groundtruth import probe_car

        path = self.tmp_path / "truncated.car"
        path.write_bytes(self.epoch.car_bytes[: len(self.epoch.car_bytes) // 2])

        census = probe_car(path)

        self.assertTrue(census.stopped_early)
        self.assertIsNotNone(census.stop_reason)
        self.assertGreater(census.blocks_scanned, 0)

    def test_a_non_car_file_is_a_clear_error(self) -> None:
        from slot_audit.groundtruth import GroundTruthError, probe_car

        path = self.tmp_path / "notes.txt"
        path.write_text("this is not a CAR file", encoding="utf-8")

        with self.assertRaisesRegex(GroundTruthError, "not a readable CAR"):
            probe_car(path)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
