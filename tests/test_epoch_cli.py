"""The command-line surface of the single-epoch audit."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.cli import EXIT_COMPLETE, EXIT_FAILED, build_parser, main
from slot_audit.evidence import EvidenceStore, build_provenance, utc_now

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = str(REPO_ROOT / "config.epoch-100.yaml")


def _run(argv: list[str], environment: dict[str, str] | None = None) -> tuple[int, str]:
    import os

    previous = dict(os.environ)
    try:
        if environment is not None:
            os.environ.update(environment)
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = main(argv)
        return code, stream.getvalue()
    finally:
        os.environ.clear()
        os.environ.update(previous)


class ParserTests(unittest.TestCase):
    def test_the_audit_and_verification_commands_are_exposed(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["audit", "--config", "c.yaml", "--results-dir", "r"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.config, "c.yaml")
        self.assertEqual(args.results_dir, "r")

        verify = parser.parse_args(["verify-evidence", "--evidence-dir", "e"])
        self.assertEqual(verify.command, "verify-evidence")
        self.assertEqual(verify.evidence_dir, "e")


class VerifyEvidenceCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)
        self.store = EvidenceStore(self.tmp_path / "evidence")
        self.store.record_json_artifact("scope.json", {"epoch": 100})
        self.store.record_call(
            provider="provider-a",
            method="getBlocks",
            params=[1, 2],
            endpoint_fingerprint="f" * 64,
            raw_response=b'{"jsonrpc":"2.0","id":1,"result":[1,2]}',
            http_status=200,
            started_at=utc_now(),
            completed_at=utc_now(),
        )
        self.store.finalize(
            provenance=build_provenance(
                resolved_config_sha256="a" * 64, started_at=utc_now()
            ).completed(utc_now())
        )

    def test_a_clean_store_verifies_and_exits_zero(self) -> None:
        code, output = _run(["verify-evidence", "--evidence-dir", str(self.store.root)])

        self.assertEqual(code, EXIT_COMPLETE)
        self.assertIn("manifest verified", output)

    def test_tampering_deletion_and_smuggling_all_exit_non_zero(self) -> None:
        (self.store.root / "artifacts" / "scope.json").write_text("{}", encoding="utf-8")
        (self.store.root / "artifacts" / "smuggled.json").write_text("{}", encoding="utf-8")
        raw = next(iter(sorted((self.store.root / "raw").glob("*.json"))))
        raw.unlink()

        code, output = _run(["verify-evidence", "--evidence-dir", str(self.store.root)])

        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("modified", output)
        self.assertIn("unexpected", output)
        self.assertIn("missing", output)

    def test_a_directory_without_a_manifest_is_an_error(self) -> None:
        code, output = _run(["verify-evidence", "--evidence-dir", str(self.tmp_path)])

        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("manifest.json", output)


class ProbeCarCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)
        from slot_audit.negative_controls import build_simulated_epoch

        self.epoch = build_simulated_epoch()
        self.car_path = self.tmp_path / "epoch.car"
        self.car_path.write_bytes(self.epoch.car_bytes)

    def test_a_matching_archive_reports_the_schema_and_exits_zero(self) -> None:
        code, output = _run(["probe-car", "--car", str(self.car_path)])

        self.assertEqual(code, EXIT_COMPLETE)
        self.assertIn("slot-audit/oldfaithful-block-header-v1", output)
        self.assertIn("is present in the scanned prefix", output)

    def test_a_non_matching_archive_exits_non_zero_and_says_why(self) -> None:
        from slot_audit.car import CarBlock, Cid, cbor_encode, encode_car

        data = cbor_encode({"kind": 9, "unrelated": 1})
        block = CarBlock(cid=Cid.for_data(data), data=data)
        other = self.tmp_path / "other.car"
        other.write_bytes(encode_car([block.cid], [block]))

        code, output = _run(["probe-car", "--car", str(other)])

        self.assertEqual(code, 1)
        self.assertIn("NOT seen", output)
        self.assertIn("conclude nothing", output)

    def test_the_json_form_is_machine_readable(self) -> None:
        import json as _json

        code, output = _run(
            ["probe-car", "--car", str(self.car_path), "--max-blocks", "3", "--json"]
        )

        payload = _json.loads(output)
        self.assertEqual(code, EXIT_COMPLETE)
        self.assertEqual(payload["blocks_scanned"], 3)
        self.assertTrue(payload["stopped_early"])
        self.assertIn("schema_present", payload)

    def test_a_missing_archive_is_a_clean_error(self) -> None:
        code, output = _run(["probe-car", "--car", str(self.tmp_path / "absent.car")])

        self.assertEqual(EXIT_FAILED, code)
        self.assertIn("was not found", output)


class ReportSealingTests(unittest.IsolatedAsyncioTestCase):
    """A deleted readable copy and an edited one must read differently."""

    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)

    async def _run(self):
        from slot_audit.negative_controls import build_simulated_epoch, run_control_audit
        from slot_audit.report import write_reports

        directory = self.tmp_path / "run"
        run = await run_control_audit(
            directory=directory,
            epoch=build_simulated_epoch(),
            defects_by_provider={},
        )
        write_reports(run, results_dir=directory)
        return run, directory

    async def test_faithful_copies_verify(self) -> None:
        run, directory = await self._run()

        code, output = _run(
            ["verify-evidence", "--evidence-dir", str(run.evidence_root)]
        )

        self.assertEqual(code, EXIT_COMPLETE)
        self.assertIn("summary.md: matches its sealed copy", output)
        self.assertIn("result.json: matches its sealed copy", output)

    async def test_an_edited_copy_is_reported_as_modified_and_fails(self) -> None:
        run, directory = await self._run()
        (directory / "summary.md").write_text("provider-x lost blocks", encoding="utf-8")

        code, output = _run(
            ["verify-evidence", "--evidence-dir", str(run.evidence_root)]
        )

        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("summary.md: DIFFERS", output)
        self.assertNotIn("summary.md: NOT PRESENT", output)

    async def test_a_deleted_copy_is_reported_distinctly_and_does_not_fail(
        self,
    ) -> None:
        """The sealed original is intact, so this is recoverable -- but visible."""

        run, directory = await self._run()
        (directory / "summary.md").unlink()

        code, output = _run(
            ["verify-evidence", "--evidence-dir", str(run.evidence_root)]
        )

        self.assertEqual(code, EXIT_COMPLETE)
        self.assertIn("summary.md: NOT PRESENT", output)
        self.assertIn("can be restored from it", output)
        self.assertNotIn("summary.md: DIFFERS", output)

    async def test_the_sealed_result_explains_its_own_null_provenance(self) -> None:
        import json as _json

        run, directory = await self._run()
        payload = _json.loads(
            (directory / "result.json").read_text(encoding="utf-8")
        )

        # These are null by construction, and the document says so rather than
        # leaving a downstream parser to infer an incomplete run.
        self.assertIsNone(payload["manifest"])
        self.assertIsNone(payload["provenance"]["run_completed_at"])
        self.assertIn("by construction, not by omission", payload["sealing_note"])
        self.assertIn("provenance.json", payload["sealing_note"])
        self.assertTrue((run.evidence_root / "provenance.json").is_file())


class AuditCommandRefusalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)

    def test_two_credentials_on_one_host_are_refused_before_any_request(self) -> None:
        code, output = _run(
            ["audit", "--config", CONFIG, "--results-dir", str(self.tmp_path / "out")],
            {
                "PROVIDER_A_URL": "https://rpc.example.invalid/?api-key=alpha-secret",
                "PROVIDER_B_URL": "https://rpc.example.invalid/?api-key=bravo-secret",
                "OLD_FAITHFUL_EPOCH_100_CAR": str(self.tmp_path / "absent.car"),
            },
        )

        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("same host", output)
        self.assertFalse((self.tmp_path / "out").exists())

    def test_a_refusal_never_echoes_the_credential(self) -> None:
        code, output = _run(
            ["audit", "--config", CONFIG, "--results-dir", str(self.tmp_path / "out")],
            {
                "PROVIDER_A_URL": "https://rpc.example.invalid/?api-key=alpha-secret",
                "PROVIDER_B_URL": "https://rpc.example.invalid/?api-key=bravo-secret",
                "OLD_FAITHFUL_EPOCH_100_CAR": str(self.tmp_path / "absent.car"),
            },
        )

        self.assertEqual(code, EXIT_FAILED)
        self.assertNotIn("alpha-secret", output)
        self.assertNotIn("bravo-secret", output)
        self.assertNotIn("https://", output)

    def test_a_missing_environment_variable_names_it_without_values(self) -> None:
        import os

        previous = os.environ.pop("PROVIDER_B_URL", None)
        try:
            code, output = _run(
                [
                    "audit",
                    "--config",
                    CONFIG,
                    "--results-dir",
                    str(self.tmp_path / "out"),
                ],
                {
                    "PROVIDER_A_URL": "https://alpha.invalid/rpc",
                    "OLD_FAITHFUL_EPOCH_100_CAR": str(self.tmp_path / "absent.car"),
                },
            )
        finally:
            if previous is not None:
                os.environ["PROVIDER_B_URL"] = previous

        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("PROVIDER_B_URL", output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
