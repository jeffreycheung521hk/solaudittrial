"""Evidence retention, closed-world manifest verification and provenance."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.evidence import (
    MANIFEST_NAME,
    PROVENANCE_NAME,
    EvidenceError,
    EvidenceRef,
    EvidenceStore,
    build_provenance,
    endpoint_fingerprint,
    endpoint_host_fingerprint,
    sha256_hex,
    utc_now,
    verify_manifest,
)


class EvidenceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)

    def _store(self, name: str = "evidence") -> EvidenceStore:
        return EvidenceStore(self.tmp_path / name)

    def _finalized_store(self) -> EvidenceStore:
        store = self._store()
        store.record_call(
            provider="provider-a",
            method="getBlocks",
            params=[1, 2, {"commitment": "finalized"}],
            endpoint_fingerprint="f" * 64,
            raw_response=b'{"jsonrpc":"2.0","id":1,"result":[1,2]}',
            http_status=200,
            started_at=utc_now(),
            completed_at=utc_now(),
        )
        store.record_json_artifact("scope.json", {"epoch": 100})
        store.finalize(
            provenance=build_provenance(
                resolved_config_sha256="a" * 64, started_at=utc_now()
            ).completed(utc_now())
        )
        return store


class RawByteRetentionTests(EvidenceTestCase):
    def test_response_bytes_are_retained_verbatim(self) -> None:
        store = self._store()
        # Deliberately ugly spacing and key order: a re-encoded copy would not
        # hash to the same value as what the provider actually sent.
        body = b'{ "jsonrpc":"2.0",   "result": [1,\n 2], "id":1 }'

        call = store.record_call(
            provider="provider-a",
            method="getBlocks",
            params=[1, 2],
            endpoint_fingerprint="f" * 64,
            raw_response=body,
            http_status=200,
            started_at=utc_now(),
            completed_at=utc_now(),
        )

        stored = (store.root / call.raw.relative_path).read_bytes()
        self.assertEqual(stored, body)
        self.assertEqual(call.raw.sha256, sha256_hex(body))
        self.assertEqual(call.raw.byte_length, len(body))

    def test_request_metadata_records_a_fingerprint_and_never_a_url(self) -> None:
        store = self._store()
        secret_url = "https://provider.invalid/?api-key=super-secret"

        call = store.record_call(
            provider="provider-a",
            method="getVersion",
            params=[],
            endpoint_fingerprint=endpoint_fingerprint(secret_url),
            raw_response=b"{}",
            http_status=200,
            started_at=utc_now(),
            completed_at=utc_now(),
        )

        payload = json.loads((store.root / call.request.relative_path).read_text())
        self.assertEqual(payload["endpoint_fingerprint"], endpoint_fingerprint(secret_url))
        self.assertNotIn("super-secret", json.dumps(payload))
        self.assertNotIn("https://", json.dumps(payload))

    def test_evidence_reference_exposes_path_digest_and_length(self) -> None:
        ref = EvidenceRef("raw/000001-a-getBlocks.json", "a" * 64, 42)

        described = ref.describe()

        self.assertIn("raw/000001-a-getBlocks.json", described)
        self.assertIn("a" * 64, described)
        self.assertIn("42 bytes", described)


class NoOverwriteTests(EvidenceTestCase):
    def test_a_previous_evidence_run_is_never_overwritten(self) -> None:
        first = self._finalized_store()
        self.assertTrue((first.root / MANIFEST_NAME).is_file())

        with self.assertRaisesRegex(EvidenceError, "never be overwritten"):
            EvidenceStore(first.root)

    def test_a_finalized_store_refuses_further_writes(self) -> None:
        store = self._finalized_store()

        with self.assertRaisesRegex(EvidenceError, "finalized"):
            store.record_json_artifact("late.json", {"too": "late"})

    def test_recording_the_same_path_twice_is_refused(self) -> None:
        store = self._store()
        store.record_json_artifact("scope.json", {"a": 1})

        with self.assertRaisesRegex(EvidenceError, "already recorded"):
            store.record_json_artifact("scope.json", {"a": 2})


class ClosedWorldManifestTests(EvidenceTestCase):
    def test_an_untouched_run_verifies(self) -> None:
        store = self._finalized_store()

        verification = verify_manifest(store.root)

        self.assertTrue(verification.ok)
        self.assertEqual(verification.missing, ())
        self.assertEqual(verification.modified, ())
        self.assertEqual(verification.unexpected, ())
        self.assertIn("no missing, modified or unexpected", verification.describe())

    def test_tampering_with_a_retained_response_is_detected(self) -> None:
        store = self._finalized_store()
        target = next(iter(sorted(store.root.glob("raw/*.json"))))
        target.write_bytes(b'{"jsonrpc":"2.0","id":1,"result":[1,2,3]}')

        verification = verify_manifest(store.root)

        self.assertFalse(verification.ok)
        self.assertEqual(
            verification.modified, (target.relative_to(store.root).as_posix(),)
        )
        self.assertIn("modified", verification.describe())

    def test_a_length_preserving_edit_is_still_detected(self) -> None:
        store = self._finalized_store()
        target = next(iter(sorted(store.root.glob("raw/*.json"))))
        original = target.read_bytes()
        edited = original.replace(b"[1,2]", b"[1,3]")
        self.assertEqual(len(edited), len(original))
        target.write_bytes(edited)

        self.assertEqual(
            verify_manifest(store.root).modified,
            (target.relative_to(store.root).as_posix(),),
        )

    def test_deleting_a_manifested_artifact_is_detected(self) -> None:
        store = self._finalized_store()
        target = store.root / "artifacts" / "scope.json"
        target.unlink()

        verification = verify_manifest(store.root)

        self.assertFalse(verification.ok)
        self.assertEqual(verification.missing, ("artifacts/scope.json",))

    def test_an_unexpected_unmanifested_file_is_detected(self) -> None:
        store = self._finalized_store()
        (store.root / "artifacts" / "smuggled.json").write_text("{}", encoding="utf-8")

        verification = verify_manifest(store.root)

        self.assertFalse(verification.ok)
        self.assertEqual(verification.unexpected, ("artifacts/smuggled.json",))
        self.assertIn("unexpected", verification.describe())

    def test_all_three_tampering_modes_are_reported_together(self) -> None:
        store = self._finalized_store()
        (store.root / "artifacts" / "scope.json").unlink()
        raw = next(iter(sorted(store.root.glob("raw/*.json"))))
        raw.write_bytes(b"tampered")
        (store.root / "extra.json").write_text("{}", encoding="utf-8")

        verification = verify_manifest(store.root)

        self.assertEqual(verification.missing, ("artifacts/scope.json",))
        self.assertEqual(verification.modified, (raw.relative_to(store.root).as_posix(),))
        self.assertEqual(verification.unexpected, ("extra.json",))

    def test_a_missing_manifest_is_an_error_not_a_pass(self) -> None:
        store = self._finalized_store()
        (store.root / MANIFEST_NAME).unlink()

        with self.assertRaises(EvidenceError):
            verify_manifest(store.root)


class ProvenanceTests(EvidenceTestCase):
    def test_provenance_records_every_required_field(self) -> None:
        store = self._finalized_store()

        payload = json.loads((store.root / PROVENANCE_NAME).read_text(encoding="utf-8"))

        self.assertTrue(payload["package_version"])
        self.assertEqual(len(payload["source_tree_sha256"]), 64)
        self.assertIn("Python", payload["python_version"])
        self.assertEqual(len(payload["resolved_config_sha256"]), 64)
        self.assertTrue(payload["run_started_at"].endswith("Z"))
        self.assertTrue(payload["run_completed_at"].endswith("Z"))

    def test_incomplete_provenance_is_visible(self) -> None:
        provenance = build_provenance(
            resolved_config_sha256="b" * 64, started_at=utc_now()
        )

        self.assertFalse(provenance.is_complete)
        self.assertTrue(provenance.completed(utc_now()).is_complete)

    def test_finalizing_without_provenance_is_refused(self) -> None:
        store = self._store("no-provenance")

        with self.assertRaisesRegex(EvidenceError, "provenance"):
            store.finalize()


class FingerprintTests(unittest.TestCase):
    def test_differing_only_by_credential_shares_a_host_fingerprint(self) -> None:
        first = "https://rpc.example.invalid/?api-key=one"
        second = "https://rpc.example.invalid/?api-key=two"

        self.assertNotEqual(endpoint_fingerprint(first), endpoint_fingerprint(second))
        self.assertEqual(
            endpoint_host_fingerprint(first), endpoint_host_fingerprint(second)
        )

    def test_different_hosts_have_different_host_fingerprints(self) -> None:
        self.assertNotEqual(
            endpoint_host_fingerprint("https://a.invalid/"),
            endpoint_host_fingerprint("https://b.invalid/"),
        )

    def test_a_fingerprint_never_contains_the_url(self) -> None:
        url = "https://rpc.example.invalid/secret-path?api-key=leak"

        self.assertNotIn("leak", endpoint_fingerprint(url))
        self.assertNotIn("secret-path", endpoint_fingerprint(url))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
