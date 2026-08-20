"""Command-line entry point for the single-epoch audit."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from functools import partial
from pathlib import Path

import anyio

from .config import ConfigError

EXIT_COMPLETE = 0
EXIT_PARTIAL = 1
EXIT_FAILED = 2

#: Solana's inclusive ``getBlocks`` range ceiling, and therefore the default
#: batch size for collecting an epoch.
MAX_GET_BLOCKS_SLOTS = 500_000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solana-slot-audit",
        description="Evidence-focused Solana RPC slot auditing",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit_parser = subparsers.add_parser(
        "audit",
        help=(
            "run the fail-closed single-epoch audit: two distinct providers, one "
            "Old Faithful ground-truth anchor, one legacy SPL Token mint"
        ),
    )
    audit_parser.add_argument(
        "--config",
        "-c",
        default="config.epoch-100.yaml",
        help="epoch-audit YAML configuration path",
    )
    audit_parser.add_argument(
        "--results-dir",
        "--results",
        "-o",
        default="results/epoch-audit",
        help="output directory; an existing evidence run is never overwritten",
    )
    audit_parser.add_argument(
        "--chunk-size",
        type=int,
        default=MAX_GET_BLOCKS_SLOTS,
        help=f"inclusive getBlocks chunk size (1-{MAX_GET_BLOCKS_SLOTS})",
    )

    probe_parser = subparsers.add_parser(
        "probe-car",
        help=(
            "stream a prefix of an Old Faithful CAR and report the node shapes it "
            "actually contains"
        ),
    )
    probe_parser.add_argument("--car", required=True, help="path to the CAR file")
    probe_parser.add_argument(
        "--max-blocks",
        type=int,
        default=None,
        help="stop after this many blocks (omit to scan the whole archive)",
    )
    probe_parser.add_argument(
        "--json", action="store_true", help="emit the census as JSON"
    )

    replay_parser = subparsers.add_parser(
        "replay",
        help=(
            "re-perform a sealed run from its own evidence, without touching the "
            "network, and check that the conclusion reproduces"
        ),
    )
    replay_parser.add_argument(
        "--evidence-dir", required=True, help="the evidence directory to replay"
    )
    replay_parser.add_argument(
        "--output-dir",
        required=True,
        help="where to write the replay's own evidence and reports",
    )
    replay_parser.add_argument(
        "--json", action="store_true", help="emit the comparison as JSON"
    )

    verify_parser = subparsers.add_parser(
        "verify-evidence",
        help="closed-world verification of an evidence manifest",
    )
    verify_parser.add_argument(
        "--evidence-dir",
        required=True,
        help="the evidence directory containing manifest.json",
    )
    verify_parser.add_argument(
        "--results-dir",
        default=None,
        help=(
            "also compare summary.md and result.json in this directory against the "
            "sealed copies inside the evidence store (defaults to the evidence "
            "directory's parent)"
        ),
    )
    return parser


async def run_epoch_audit_command(
    config_path: str,
    results_dir: str,
    *,
    chunk_size: int,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Load, resolve and run one single-epoch audit, then write the reports."""

    from .audit import run_epoch_audit
    from .config import load_epoch_config, read_environment, resolve_epoch_config
    from .evidence import EvidenceStore
    from .report import write_reports
    from .transport import AuditRpcClient, HttpxTransport

    model = load_epoch_config(config_path)
    merged = read_environment(config_path, environment=environment)
    resolved = resolve_epoch_config(model, environment=merged)
    output_dir = Path(results_dir)
    evidence = EvidenceStore(output_dir / "evidence")

    def client_factory(provider):  # type: ignore[no-untyped-def]
        return AuditRpcClient(
            provider=provider.name,
            url=provider.rpc_url,
            endpoint_fingerprint=provider.endpoint_fingerprint,
            transport=HttpxTransport(),
            evidence=evidence,
            commitment=model.scope.commitment,
            rps=provider.rps,
            max_requests=model.limits.max_requests_per_provider,
            max_retries=model.limits.max_retries,
        )

    run = await run_epoch_audit(
        resolved,
        evidence=evidence,
        client_factory=client_factory,
        results_dir=output_dir,
        chunk_size=chunk_size,
    )
    summary_path, result_path = write_reports(run, results_dir=output_dir)
    print(f"instrument validation: {run.assessment.status.value}")
    print(f"result: {run.conclusion.result.value}")
    print(f"summary: {summary_path}")
    print(f"machine-readable result: {result_path}")
    return EXIT_COMPLETE if run.conclusion.result.value != "NO_CONCLUSION" else EXIT_PARTIAL


async def replay_command(
    evidence_dir: str, output_dir: str, *, as_json: bool
) -> int:
    """Re-perform a run from its evidence and report whether it reproduced."""

    from .replay import replay_audit
    from .report import write_reports

    result, run = await replay_audit(evidence_dir, output_dir=output_dir)
    write_reports(run, results_dir=output_dir)
    if as_json:
        print(json.dumps(result.to_payload(), indent=2, sort_keys=True))
    else:
        print(result.describe())
    return EXIT_COMPLETE if result.reproduced else EXIT_FAILED


def probe_car_command(car: str, *, max_blocks: int | None, as_json: bool) -> int:
    """Report what an archive contains, so a schema assumption can be checked."""

    from .groundtruth import probe_car

    census = probe_car(car, max_blocks=max_blocks)
    if as_json:
        print(json.dumps(census.to_payload(), indent=2, sort_keys=True))
    else:
        print(census.describe())
    return EXIT_COMPLETE if census.schema_present else EXIT_PARTIAL


def verify_evidence_command(evidence_dir: str, results_dir: str | None = None) -> int:
    from .evidence import verify_manifest
    from .report import verify_reports

    verification = verify_manifest(evidence_dir)
    print(verification.describe())

    reports_dir = Path(results_dir) if results_dir else Path(evidence_dir).parent
    reports = verify_reports(reports_dir, evidence_dir)
    lines = reports.describe()
    for line in lines:
        print(line)
    if not lines:
        print("no readable report copies were found or sealed")
    return EXIT_COMPLETE if verification.ok and reports.ok else EXIT_FAILED


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify-evidence":
        from .evidence import EvidenceError

        try:
            return verify_evidence_command(args.evidence_dir, args.results_dir)
        except EvidenceError as exc:
            print(f"error: {exc}")
            return EXIT_FAILED
    if args.command == "replay":
        from .evidence import EvidenceError
        from .replay import ReplayError

        try:
            operation = partial(
                replay_command,
                args.evidence_dir,
                args.output_dir,
                as_json=args.json,
            )
            return anyio.run(operation, backend="asyncio")
        except (ReplayError, EvidenceError, ConfigError, ValueError) as exc:
            print(f"error: {exc}")
            return EXIT_FAILED
    if args.command == "probe-car":
        from .groundtruth import GroundTruthError

        try:
            return probe_car_command(
                args.car, max_blocks=args.max_blocks, as_json=args.json
            )
        except GroundTruthError as exc:
            print(f"error: {exc}")
            return EXIT_FAILED

    from .audit import AuditError
    from .evidence import EvidenceError

    try:
        operation = partial(
            run_epoch_audit_command,
            args.config,
            args.results_dir,
            chunk_size=args.chunk_size,
        )
        return anyio.run(operation, backend="asyncio")
    except (ConfigError, AuditError, EvidenceError, ValueError) as exc:
        print(f"error: {exc}")
        return EXIT_FAILED


__all__ = [
    "EXIT_COMPLETE",
    "EXIT_FAILED",
    "EXIT_PARTIAL",
    "MAX_GET_BLOCKS_SLOTS",
    "build_parser",
    "main",
    "probe_car_command",
    "replay_command",
    "run_epoch_audit_command",
    "verify_evidence_command",
]
