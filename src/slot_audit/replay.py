"""Re-perform a run from its own evidence, without touching the network.

The tool's most valuable asset is that it keeps the exact bytes of every call.
Until this module existed, nothing consumed that asset: a reviewer who wanted to
check a conclusion had to spend 400,000 fresh RPC calls, and "re-performable"
was an adjective in the README rather than a command anyone could run.

The design follows the seam the audit already had. Replay does **not**
reimplement collection, classification, finding construction or assessment --
reimplementing them would only prove that the copy agrees with itself. It runs
:func:`slot_audit.audit.run_epoch_audit` unchanged, with a transport that serves
recorded responses instead of a socket and an anchor rebuilt from the retained
derived records. Every judgment is therefore made by the same code, from the
same bytes, and the recomputed conclusion is compared against the sealed one.

Three properties follow, and all three are checks rather than promises:

* **A call the original never made is a failure.** :class:`ReplayTransport`
  raises when asked for a request that is not in the log, so a replay cannot
  quietly wander off the recorded path.
* **A call the original made and replay skipped is a failure.** Unconsumed
  entries are reported.
* **The conclusion must match.** Result, gate statuses and every finding are
  compared field by field against the sealed ``conclusion.json``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from .audit import AuditRun, run_epoch_audit
from .config import (
    EpochAuditConfig,
    ResolvedEpochAuditConfig,
    ResolvedProvider,
)
from .evidence import EvidenceStore, sha256_hex, verify_manifest
from .groundtruth import (
    PINNED_EPOCH_GROUND_TRUTH,
    ConstantProvenance,
    EpochGroundTruthSpec,
    ExtractorIdentity,
    GroundTruth,
    GroundTruthHeader,
    TrustStep,
)
from .transport import TransportError, TransportResponse
from .verdict import Verdict


class ReplayError(RuntimeError):
    """The evidence cannot be replayed as recorded."""


async def _no_delay(_seconds: float) -> None:
    """Replay re-walks recorded retries; it must not re-wait them."""

    return None


def _canonical(params: Sequence[object]) -> str:
    return json.dumps(list(params), sort_keys=True, separators=(",", ":"), default=str)


#: Not every retained record is a response. When a request could not be sent --
#: the socket failed, or the budget was already spent -- the store keeps a
#: synthetic entry so the gap is explicable rather than invisible. Replay has to
#: recognise those: replaying a synthetic transport failure *as a response* would
#: hand the client an HTTP 0 it treats as a hard error, and an honest run
#: containing one transient blip would then fail to reproduce itself. Over
#: 400,000 calls a real run will contain several, so this is the difference
#: between replay being usable and replay accusing every honest operator.
SYNTHETIC_STATUS = 0


@dataclass(frozen=True, slots=True)
class RecordedExchange:
    """One call as the original run made it -- or the reason it was not made."""

    sequence: int
    provider: str
    method: str
    params: list[Any]
    http_status: int
    body: bytes

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.provider, self.method, _canonical(self.params))

    @property
    def synthetic_kind(self) -> str | None:
        """``transport_error``, ``budget_exhausted``, or ``None`` for a response."""

        if self.http_status != SYNTHETIC_STATUS:
            return None
        try:
            payload = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "unknown"
        if not isinstance(payload, dict):
            return "unknown"
        if "transport_error" in payload:
            return "transport_error"
        if payload.get("budget_exhausted"):
            return "budget_exhausted"
        return "unknown"

    @property
    def transport_error_message(self) -> str:
        try:
            payload = json.loads(self.body.decode("utf-8"))
            return str(payload.get("transport_error", "transport failure"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "transport failure"


def load_exchanges(evidence_dir: str | Path) -> tuple[RecordedExchange, ...]:
    """Read every recorded call back out of an evidence store, in order."""

    root = Path(evidence_dir)
    meta_dir = root / "meta"
    if not meta_dir.is_dir():
        raise ReplayError(f"{root} has no meta/ directory; it is not an evidence store")
    exchanges: list[RecordedExchange] = []
    for path in sorted(meta_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        response = payload.get("response") or {}
        relative = response.get("relative_path")
        if not relative:
            raise ReplayError(f"{path.name} does not reference a response body")
        body_path = root / relative
        if not body_path.is_file():
            raise ReplayError(f"{path.name} references missing body {relative}")
        body = body_path.read_bytes()
        digest = response.get("sha256")
        if digest and sha256_hex(body) != digest:
            raise ReplayError(f"{relative} does not match its recorded digest")
        exchanges.append(
            RecordedExchange(
                sequence=int(payload["sequence"]),
                provider=str(payload["provider"]),
                method=str(payload["method"]),
                params=list(payload.get("params") or []),
                http_status=int(payload.get("http_status", 200)),
                body=body,
            )
        )
    exchanges.sort(key=lambda item: item.sequence)
    return tuple(exchanges)


class ReplayTransport:
    """Serve recorded responses; refuse anything the original never asked."""

    def __init__(self, provider: str, exchanges: Sequence[RecordedExchange]) -> None:
        self.provider = provider
        self._queues: dict[tuple[str, str, str], list[RecordedExchange]] = {}
        self.skipped_budget_entries: list[int] = []
        for exchange in exchanges:
            if exchange.provider != provider:
                continue
            if exchange.synthetic_kind == "budget_exhausted":
                # No request was sent, so nothing will ask for it. The replaying
                # client hits the same budget at the same point and writes its
                # own record; queueing this one would leave it permanently
                # unconsumed and read as a gap in the replay.
                self.skipped_budget_entries.append(exchange.sequence)
                continue
            self._queues.setdefault(exchange.key, []).append(exchange)
        self.served: list[int] = []
        self.replayed_failures: list[int] = []
        self.closed = False

    @property
    def unconsumed(self) -> tuple[int, ...]:
        return tuple(
            sorted(
                exchange.sequence
                for queue in self._queues.values()
                for exchange in queue
            )
        )

    async def post(self, url: str, payload: Mapping[str, object]) -> TransportResponse:
        method = str(payload.get("method", ""))
        params = list(payload.get("params", []) or [])
        key = (self.provider, method, _canonical(params))
        queue = self._queues.get(key)
        if not queue:
            raise ReplayError(
                f"replay asked {self.provider} for {method}{params!r}, which the "
                "recorded run never made; the run is not reproducible from its "
                "own evidence"
            )
        exchange = queue.pop(0)
        self.served.append(exchange.sequence)
        if exchange.synthetic_kind == "transport_error":
            # Re-raise rather than serve. The client then follows exactly the
            # retry path it followed originally, instead of being handed a
            # status it would treat as a hard, non-retryable failure.
            self.replayed_failures.append(exchange.sequence)
            raise TransportError(exchange.transport_error_message)
        return TransportResponse(status_code=exchange.http_status, body=exchange.body)

    async def aclose(self) -> None:
        self.closed = True


def _derivation_record(evidence_dir: str | Path) -> dict[str, Any]:
    artifacts = Path(evidence_dir) / "artifacts"
    derivations = sorted(artifacts.glob("ground-truth-epoch-*-derivation.json"))
    if not derivations:
        raise ReplayError("no ground-truth derivation record was retained")
    return json.loads(derivations[0].read_text(encoding="utf-8"))


def reconstruct_spec(evidence_dir: str | Path) -> tuple[EpochGroundTruthSpec, str]:
    """Recover the epoch specification, preferring the pinned one.

    For an epoch this build pins, the in-source constants are authoritative even
    during replay: otherwise an edited derivation record could relax the very
    values the anchor is checked against, and replay would faithfully reproduce a
    weakened run. The recorded spec is used only for epochs with no pinned entry,
    and the choice is reported.
    """

    record = _derivation_record(evidence_dir)
    spec_payload = dict(record["spec"])
    provenance_payload = spec_payload.pop("provenance", None) or {}
    recorded = EpochGroundTruthSpec(
        **spec_payload,
        provenance=ConstantProvenance(
            source=str(provenance_payload.get("source", "unstated")),
            verified_against_archive=bool(
                provenance_payload.get("verified_against_archive", False)
            ),
            note=str(provenance_payload.get("note", "")),
        ),
    )
    if recorded.epoch in PINNED_EPOCH_GROUND_TRUTH:
        pinned = PINNED_EPOCH_GROUND_TRUTH[recorded.epoch]
        if pinned != recorded:
            raise ReplayError(
                f"the retained specification for epoch {recorded.epoch} disagrees "
                "with the constants pinned in this build; replay will not proceed "
                "against a specification it cannot vouch for"
            )
        return pinned, "pinned in this build"
    return recorded, "recovered from the retained derivation record (epoch not pinned)"


def reconstruct_ground_truth(evidence_dir: str | Path) -> GroundTruth:
    """Rebuild the anchor from the retained derived records.

    The archive is not re-read -- replay is meant to work without 62.9 GB on
    hand. What *is* re-verified is that the derived record file still hashes to
    the digest the original derivation recorded, and the original trust chain is
    carried forward with an explicit step saying which link replay could and
    could not re-establish. Nothing here silently upgrades a recorded claim.
    """

    root = Path(evidence_dir)
    artifacts = root / "artifacts"
    record = _derivation_record(root)
    spec, _origin = reconstruct_spec(root)
    extractor_payload = dict(record["extractor"])
    extractor = ExtractorIdentity(**extractor_payload)

    derived_path = artifacts / str(record["derived_file"])
    if not derived_path.is_file():
        raise ReplayError(f"derived record file {record['derived_file']} is missing")
    derived_bytes = derived_path.read_bytes()
    observed = sha256_hex(derived_bytes)
    if observed != record["derived_sha256"]:
        raise ReplayError(
            f"derived records hash to {observed}, not the recorded "
            f"{record['derived_sha256']}"
        )

    headers: dict[int, GroundTruthHeader] = {}
    predecessor: GroundTruthHeader | None = None
    filtered = 0
    for line in derived_bytes.decode("utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        header = GroundTruthHeader(
            slot=int(row["slot"]),
            blockhash=str(row["blockhash"]),
            previous_blockhash=str(row["previousBlockhash"]),
            parent_slot=int(row["parentSlot"]),
        )
        if header.slot == spec.predecessor_boundary_slot:
            predecessor = header
            filtered += 1
            continue
        headers[header.slot] = header

    steps = [
        TrustStep(
            "replayed_from_retained_records",
            True,
            "the anchor was rebuilt from the retained derived records, whose "
            f"sha256 {observed} matches the derivation record; the archive itself "
            "was not re-read, so the CAR digest and per-block CID checks are "
            "carried over from the original run rather than re-established here",
        ),
        TrustStep(
            "derived_records_intact",
            True,
            f"{len(headers)} produced headers and {filtered} predecessor row(s) "
            f"recovered from {record['derived_file']}",
        ),
        TrustStep(
            "produced_block_count",
            len(headers) == spec.produced_blocks,
            f"recovered {len(headers)} produced blocks against a declared "
            f"{spec.produced_blocks}",
        ),
        TrustStep(
            "predecessor_header_available",
            predecessor is not None,
            "the predecessor boundary header was recovered"
            if predecessor is not None
            else "the predecessor boundary header is missing from the records",
        ),
    ]
    return GroundTruth(
        spec=spec,
        extractor=extractor,
        headers=headers,
        predecessor_header=predecessor,
        filtered_predecessor_rows=filtered,
        trust_chain=tuple(steps),
        evidence_refs=(),
        car_sha256=str(record.get("car_sha256") or "") or None,
    )


def _resolved_from_scope(
    scope: Mapping[str, Any], *, car_path: str
) -> ResolvedEpochAuditConfig:
    """Rebuild the resolved configuration from the retained scope echo.

    URLs were deliberately never retained, so replay reconstructs providers from
    their recorded fingerprints. That is the honest reconstruction: it verifies
    what the run committed to, and cannot resurrect what the run refused to keep.
    """

    model_payload = {
        key: scope[key]
        for key in (
            "schema_version",
            "population",
            "scope",
            "thresholds",
            "token",
            "continuity",
            "limits",
            "ground_truth",
        )
    }
    scope_block = dict(model_payload["scope"])
    scope_block.pop("inclusive_slot_bounds", None)
    model_payload["scope"] = scope_block
    model_payload["providers"] = [
        {"name": item["name"], "url_env": item["url_env"], "rps": item["rps"]}
        for item in scope["providers"]
    ]
    model = EpochAuditConfig.model_validate(model_payload)
    providers = tuple(
        ResolvedProvider(
            name=item["name"],
            url_env=item["url_env"],
            url=SecretStr(f"https://replay.invalid/{item['endpoint_fingerprint']}"),
            rps=float(item["rps"]),
            endpoint_fingerprint=item["endpoint_fingerprint"],
            host_fingerprint=item["host_fingerprint"],
        )
        for item in scope["providers"]
    )
    anchor = scope.get("anchor") or {}
    return ResolvedEpochAuditConfig(
        config=model,
        providers=providers,
        car_path=car_path,
        anchor_endpoint=None,
        anchor_endpoint_fingerprint=anchor.get("endpoint_fingerprint"),
        anchor_host_fingerprint=anchor.get("host_fingerprint"),
    )


#: Gate metrics that legitimately differ between a run and its replay, with the
#: reason. Everything not listed here must match: comparing only gate *status*
#: would let a forged agreement figure through so long as it stayed on the
#: passing side of the threshold. The list is deliberately tiny and was derived
#: by diffing an honest replay, not by guessing.
_CONTROL_EVIDENCE_REASON = (
    "the controls are re-run, and their request records carry fresh timestamps, "
    "so the meta digests differ; the raw response digests do not, and the "
    "detected verdicts are compared separately"
)

VOLATILE_GATE_METRICS: Mapping[str, Mapping[str, str]] = {
    "manifest_provenance_completeness": {
        "run_started_at": "the replay is a different run and starts at a different time",
        "manifested_entries": (
            "the replay does not re-derive the anchor from the archive, so its "
            "store holds fewer artifacts than the original's"
        ),
    },
    "negative_control_provider_hole": {"evidence_refs": _CONTROL_EVIDENCE_REASON},
    "negative_control_token_truncation": {"evidence_refs": _CONTROL_EVIDENCE_REASON},
    "negative_control_previous_blockhash": {"evidence_refs": _CONTROL_EVIDENCE_REASON},
}


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Whether the sealed conclusion could be reproduced from the sealed bytes."""

    original_result: str
    replayed_result: str
    original_status: str
    replayed_status: str
    gate_differences: tuple[str, ...] = ()
    metric_differences: tuple[str, ...] = ()
    finding_differences: tuple[str, ...] = ()
    control_differences: tuple[str, ...] = ()
    unconsumed_calls: Mapping[str, tuple[int, ...]] = field(default_factory=dict)
    replayed_transport_failures: Mapping[str, tuple[int, ...]] = field(
        default_factory=dict
    )
    manifest_ok: bool = True
    notes: tuple[str, ...] = ()

    @property
    def reproduced(self) -> bool:
        return (
            self.manifest_ok
            and self.original_result == self.replayed_result
            and self.original_status == self.replayed_status
            and not self.gate_differences
            and not self.metric_differences
            and not self.finding_differences
            and not self.control_differences
            and not any(self.unconsumed_calls.values())
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "reproduced": self.reproduced,
            "manifest_ok": self.manifest_ok,
            "original": {"result": self.original_result, "status": self.original_status},
            "replayed": {"result": self.replayed_result, "status": self.replayed_status},
            "gate_differences": list(self.gate_differences),
            "metric_differences": list(self.metric_differences),
            "finding_differences": list(self.finding_differences),
            "control_differences": list(self.control_differences),
            "unconsumed_calls": {
                name: list(values) for name, values in self.unconsumed_calls.items()
            },
            "replayed_transport_failures": {
                name: list(values)
                for name, values in self.replayed_transport_failures.items()
            },
            "notes": list(self.notes),
        }

    def describe(self) -> str:
        lines = [
            f"manifest: {'verified' if self.manifest_ok else 'FAILED'}",
            f"original : result={self.original_result} status={self.original_status}",
            f"replayed : result={self.replayed_result} status={self.replayed_status}",
        ]
        for name, values in sorted(self.unconsumed_calls.items()):
            if values:
                lines.append(
                    f"{name}: {len(values)} recorded call(s) were never replayed: "
                    f"{list(values)[:10]}"
                )
        for name, values in sorted(self.replayed_transport_failures.items()):
            if values:
                lines.append(
                    f"{name}: {len(values)} recorded transport failure(s) were "
                    "re-walked through the same retry path"
                )
        lines.extend(f"gate differs: {item}" for item in self.gate_differences)
        lines.extend(f"metric differs: {item}" for item in self.metric_differences)
        lines.extend(f"finding differs: {item}" for item in self.finding_differences)
        lines.extend(f"control differs: {item}" for item in self.control_differences)
        lines.extend(f"note: {item}" for item in self.notes)
        lines.append(
            "RESULT: the sealed conclusion was reproduced from the sealed bytes"
            if self.reproduced
            else "RESULT: the sealed conclusion was NOT reproduced"
        )
        return "\n".join(lines)


async def replay_audit(
    evidence_dir: str | Path,
    *,
    output_dir: str | Path,
) -> tuple[ReplayResult, AuditRun]:
    """Re-run the audit from an evidence store and compare the conclusions."""

    root = Path(evidence_dir)
    manifest = verify_manifest(root)
    exchanges = load_exchanges(root)
    scope = json.loads((root / "artifacts" / "scope.json").read_text(encoding="utf-8"))
    sealed = json.loads(
        (root / "artifacts" / "conclusion.json").read_text(encoding="utf-8")
    )
    sealed_assessment = json.loads(
        (root / "artifacts" / "assessment.json").read_text(encoding="utf-8")
    )
    sealed_result = json.loads(
        (root / "artifacts" / "result.json").read_text(encoding="utf-8")
    )

    sealed_controls = {
        json.loads(path.read_text(encoding="utf-8"))["control_id"]: json.loads(
            path.read_text(encoding="utf-8")
        )
        for path in sorted((root / "artifacts").glob("negative-control-*.json"))
    }
    # The controls are offline and deterministic, so re-running them costs
    # nothing and buys a second question. The sealed verdicts say what the code
    # did on the day; a fresh run says what today's code does. Comparing the two
    # gets both answers instead of choosing between them.
    from .negative_controls import run_all_negative_controls

    controls = list(
        await run_all_negative_controls(results_dir=Path(output_dir) / "controls")
    )
    control_differences: list[str] = []
    for control in controls:
        sealed_control = sealed_controls.get(control.control_id)
        if sealed_control is None:
            control_differences.append(
                f"{control.control_id}: run now but absent from the sealed evidence"
            )
        elif bool(sealed_control["detected"]) != control.detected:
            control_differences.append(
                f"{control.control_id}: sealed detected="
                f"{sealed_control['detected']}, re-run detected={control.detected}"
            )
    for control_id in sealed_controls:
        if all(control.control_id != control_id for control in controls):
            control_differences.append(
                f"{control_id}: in the sealed evidence but no longer run"
            )

    spec, spec_origin = reconstruct_spec(root)
    resolved = _resolved_from_scope(scope, car_path=str(root / "artifacts"))
    output = Path(output_dir)
    evidence = EvidenceStore(output / "evidence")
    transports: dict[str, ReplayTransport] = {}

    def client_factory(provider: ResolvedProvider):  # type: ignore[no-untyped-def]
        from .transport import AuditRpcClient

        transport = ReplayTransport(provider.name, exchanges)
        transports[provider.name] = transport
        return AuditRpcClient(
            provider=provider.name,
            url=provider.rpc_url,
            endpoint_fingerprint=provider.endpoint_fingerprint,
            transport=transport,
            evidence=evidence,
            commitment=resolved.config.scope.commitment,
            max_requests=resolved.config.limits.max_requests_per_provider,
            max_retries=resolved.config.limits.max_retries,
            # A replay re-walks every retry the original made. Sleeping through
            # the original's exponential backoff again would make replaying a
            # long, flaky run take longer than the run did.
            backoff_base=0.0,
            sleep=_no_delay,
        )

    run = await run_epoch_audit(
        resolved,
        evidence=evidence,
        client_factory=client_factory,
        results_dir=output,
        spec=spec,
        ground_truth_loader=lambda _store: reconstruct_ground_truth(root),
        negative_controls=controls,
        chunk_size=int(scope["collection"]["getblocks_chunk_size"]),
    )

    gate_differences: list[str] = []
    original_gates = {
        item["gate_id"]: item["status"] for item in sealed_assessment["gates"]
    }
    for gate in run.assessment.gates:
        expected = original_gates.get(gate.gate_id)
        if expected is None:
            gate_differences.append(f"{gate.gate_id}: absent from the sealed assessment")
        elif expected != gate.status.value:
            gate_differences.append(
                f"{gate.gate_id}: sealed {expected}, replayed {gate.status.value}"
            )
    for gate_id in original_gates:
        if all(gate.gate_id != gate_id for gate in run.assessment.gates):
            gate_differences.append(f"{gate_id}: missing from the replayed assessment")

    original_metrics = {
        item["gate_id"]: item.get("metrics") or {} for item in sealed_assessment["gates"]
    }
    metric_differences: list[str] = []
    for gate in run.assessment.gates:
        volatile = VOLATILE_GATE_METRICS.get(gate.gate_id, {})
        sealed_metrics = original_metrics.get(gate.gate_id, {})
        for key in sorted(set(gate.metrics) | set(sealed_metrics)):
            if key in volatile:
                continue
            left = sealed_metrics.get(key)
            right = gate.metrics.get(key)
            if left != right:
                metric_differences.append(
                    f"{gate.gate_id}.{key}: sealed {left!r}, replayed {right!r}"
                )

    finding_differences: list[str] = []
    sealed_findings = {
        (item["slot"], item["provider"]): item for item in sealed_result["findings"]
    }
    replayed_findings = {
        (item.slot, item.provider): item.to_payload() for item in run.findings
    }
    for key in sorted(set(sealed_findings) | set(replayed_findings), key=str):
        left = sealed_findings.get(key)
        right = replayed_findings.get(key)
        if left is None:
            finding_differences.append(f"{key}: present only in the replay")
        elif right is None:
            finding_differences.append(f"{key}: present only in the sealed run")
        else:
            for column in (
                "verdict",
                "blockhash",
                "previousBlockhash",
                "parentSlot",
                "source",
            ):
                if left.get(column) != right.get(column):
                    finding_differences.append(
                        f"{key}.{column}: sealed {left.get(column)!r}, "
                        f"replayed {right.get(column)!r}"
                    )

    notes = [
        "The archive was not re-read; the anchor was rebuilt from the retained "
        "derived records and its CAR-level trust steps are carried over.",
        "Provider URLs were never retained, so endpoints are reconstructed from "
        "their recorded fingerprints.",
        f"Epoch specification: {spec_origin}.",
        "The negative controls were re-run against today's code and compared "
        "with the sealed verdicts, rather than being taken on trust.",
    ]
    result = ReplayResult(
        original_result=sealed["result"],
        replayed_result=run.conclusion.result.value,
        original_status=sealed["instrument_validation_status"],
        replayed_status=run.assessment.status.value,
        gate_differences=tuple(gate_differences),
        metric_differences=tuple(metric_differences),
        finding_differences=tuple(finding_differences),
        control_differences=tuple(control_differences),
        unconsumed_calls={
            name: transport.unconsumed for name, transport in transports.items()
        },
        replayed_transport_failures={
            name: tuple(transport.replayed_failures)
            for name, transport in transports.items()
        },
        manifest_ok=manifest.ok,
        notes=tuple(notes),
    )
    return result, run


__all__ = [
    "SYNTHETIC_STATUS",
    "VOLATILE_GATE_METRICS",
    "RecordedExchange",
    "ReplayError",
    "ReplayResult",
    "ReplayTransport",
    "Verdict",
    "load_exchanges",
    "reconstruct_ground_truth",
    "reconstruct_spec",
    "replay_audit",
]
