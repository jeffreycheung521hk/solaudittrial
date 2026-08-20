from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.checkpoint import (
    CheckpointError,
    CheckpointMismatch,
    CheckpointStore,
)
from slot_audit.config import redact_text


class CheckpointTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)


class CheckpointStoreTests(CheckpointTestCase):
    def test_successful_empty_chunk_is_checkpointed_and_resumed(self) -> None:
        store = CheckpointStore(self.tmp_path, "public-fingerprint")
        store.initialize(100, 199, ["provider-a"])

        saved = store.record_chunk("provider-a", 100, 199, [])

        self.assertTrue(saved.successful)
        resumed = CheckpointStore(self.tmp_path, "public-fingerprint")
        resumed.initialize(100, 199, ["provider-a"])
        self.assertEqual(resumed.chunks_for_provider("provider-a"), (saved,))
        self.assertEqual(list(self.tmp_path.glob(".*.tmp")), [])

    def test_checkpoint_records_failed_chunk_honestly_and_redacts_urls(self) -> None:
        secret_url = "https://rpc.invalid/?api-key=do-not-write-this"
        store = CheckpointStore(
            self.tmp_path,
            "public-fingerprint",
            redact=lambda value: redact_text(value, secrets=(secret_url,)),
        )
        store.initialize(1, 2, ["provider"])

        saved = store.record_chunk(
            "provider", 1, 2, [], error=f"transport failed for {secret_url}"
        )

        self.assertEqual(saved.error, "transport failed for <redacted>")
        all_checkpoint_text = "".join(
            path.read_text(encoding="utf-8")
            for path in self.tmp_path.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("do-not-write-this", all_checkpoint_text)
        self.assertEqual(store.chunks_for_provider("provider", successful_only=True), ())

    def test_checkpoint_manifest_contains_only_public_identity(self) -> None:
        store = CheckpointStore(self.tmp_path, "not-secret-derived")
        store.initialize(10, 20, ["provider"])
        payload = json.loads(
            (self.tmp_path / ".checkpoint.json").read_text(encoding="utf-8")
        )

        self.assertEqual(payload["providers"], ["provider"])
        self.assertNotIn("url", json.dumps(payload).lower())
        self.assertEqual(payload["range"], {"start_slot": 10, "end_slot": 20})

    def test_mismatched_checkpoint_requires_an_explicit_fresh_run(self) -> None:
        CheckpointStore(self.tmp_path, "first").initialize(10, 20, ["provider"])

        with self.assertRaisesRegex(CheckpointMismatch, "--no-resume"):
            CheckpointStore(self.tmp_path, "second").initialize(10, 20, ["provider"])

    def test_no_resume_resets_index_without_reusing_orphans(self) -> None:
        store = CheckpointStore(self.tmp_path, "same")
        store.initialize(10, 20, ["provider"])
        store.record_chunk("provider", 10, 20, [10])

        fresh = CheckpointStore(self.tmp_path, "same")
        fresh.initialize(10, 20, ["provider"], resume=False)

        self.assertEqual(fresh.chunks_for_provider("provider"), ())

    def test_chunk_outside_manifest_range_is_rejected(self) -> None:
        for start, end in ((9, 15), (15, 21)):
            with self.subTest(start=start, end=end):
                directory = self.tmp_path / f"case-{start}-{end}"
                store = CheckpointStore(directory, "fingerprint")
                store.initialize(10, 20, ["provider"])

                with self.assertRaisesRegex(CheckpointError, "outside"):
                    store.record_chunk("provider", start, end, [])

    def test_corrupt_chunk_is_not_silently_treated_as_complete(self) -> None:
        store = CheckpointStore(self.tmp_path, "fingerprint")
        store.initialize(10, 20, ["provider"])
        store.record_chunk("provider", 10, 20, [10, 12])
        chunk_path = next((self.tmp_path / ".checkpoint-chunks").iterdir())
        chunk_path.write_text("not json", encoding="utf-8")

        with self.assertRaisesRegex(CheckpointError, "Could not read checkpoint chunk"):
            store.chunks_for_provider("provider")

    def test_record_chunk_does_not_coerce_invalid_slots(self) -> None:
        for invalid_slot in (True, 10.5, "10"):
            with self.subTest(invalid_slot=invalid_slot):
                directory = self.tmp_path / f"invalid-{type(invalid_slot).__name__}"
                store = CheckpointStore(directory, "fingerprint")
                store.initialize(10, 20, ["provider"])

                with self.assertRaisesRegex(CheckpointError, "present_slots"):
                    store.record_chunk("provider", 10, 20, [invalid_slot])  # type: ignore[list-item]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
