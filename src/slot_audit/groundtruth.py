"""Ground truth for one complete epoch, bound to a verified Old Faithful CAR.

The anchor exists to answer one question that two RPC providers cannot answer
between them: when both omit a slot, was the slot *skipped by the protocol* or
*lost by both providers*?  An anchor that can be satisfied by an arbitrary file
answers nothing, so the binding here is deliberately narrow.

Trust chain
-----------
1. The expected CAR digest, root CID and extractor commit are pinned **in this
   source tree** (:data:`PINNED_EPOCH_GROUND_TRUTH`).  Configuration must repeat
   them -- an unstated scoping value is a defect -- but configuration is never
   the authority.  Re-stating a wrong value fails the run; it cannot bless a file.
2. The archive must hash to the pinned digest, parse as CAR v1, and declare
   exactly the pinned root CID.  Every block is content-addressed on read, so a
   single flipped byte anywhere in the archive is fatal.
3. Records are produced by a pinned extractor whose identity is retained.  The
   derived record file is written into evidence with its own SHA-256 and byte
   length, so the derivation is re-performable without the archive.
4. Coverage is asserted against the published epoch constants: the predecessor
   boundary row is filtered *explicitly* and counted, and the number of in-range
   produced blocks must equal the published figure exactly.

Any failed step leaves the anchor unverified, and an unverified anchor is not
allowed to produce a conclusive classification.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .car import (
    DAG_CBOR_CODEC,
    CarBlock,
    CarError,
    Cid,
    is_base58_hash,
    iter_car_blocks,
    read_car_header,
)
from .evidence import EvidenceRef, EvidenceStore, sha256_file

#: Old Faithful node kind for a confirmed block.
BLOCK_NODE_KIND = 2

#: Schema identifier for the node shape :class:`CarBlockHeaderExtractor` reads.
BLOCK_NODE_SCHEMA = "slot-audit/oldfaithful-block-header-v1"


class GroundTruthError(ValueError):
    """Ground truth could not be derived in a way that can be defended."""


@dataclass(frozen=True, slots=True)
class EpochGroundTruthSpec:
    """Published, in-source constants for one complete epoch."""

    epoch: int
    first_slot: int
    last_slot: int
    scheduled_slot_positions: int
    produced_blocks: int
    skipped_slots: int
    predecessor_boundary_slot: int
    slots_file_name: str
    car_root_cid: str
    car_sha256: str
    source_commit: str

    def __post_init__(self) -> None:
        if self.last_slot < self.first_slot:
            raise GroundTruthError("last_slot must not precede first_slot")
        span = self.last_slot - self.first_slot + 1
        if span != self.scheduled_slot_positions:
            raise GroundTruthError(
                f"epoch {self.epoch} spans {span} slots but declares "
                f"{self.scheduled_slot_positions} scheduled positions"
            )
        if self.produced_blocks + self.skipped_slots != self.scheduled_slot_positions:
            raise GroundTruthError(
                "produced_blocks + skipped_slots must equal scheduled_slot_positions"
            )
        if self.predecessor_boundary_slot != self.first_slot - 1:
            raise GroundTruthError(
                "predecessor_boundary_slot must be the slot immediately before the epoch"
            )
        if len(self.car_sha256) != 64:
            raise GroundTruthError("car_sha256 must be 64 hex characters")
        Cid.decode(self.car_root_cid)

    def contains(self, slot: int) -> bool:
        return self.first_slot <= slot <= self.last_slot

    def to_payload(self) -> dict[str, object]:
        return {
            "epoch": self.epoch,
            "first_slot": self.first_slot,
            "last_slot": self.last_slot,
            "scheduled_slot_positions": self.scheduled_slot_positions,
            "produced_blocks": self.produced_blocks,
            "skipped_slots": self.skipped_slots,
            "predecessor_boundary_slot": self.predecessor_boundary_slot,
            "slots_file_name": self.slots_file_name,
            "car_root_cid": self.car_root_cid,
            "car_sha256": self.car_sha256,
            "source_commit": self.source_commit,
        }


EPOCH_100_GROUND_TRUTH = EpochGroundTruthSpec(
    epoch=100,
    first_slot=43_200_000,
    last_slot=43_631_999,
    scheduled_slot_positions=432_000,
    produced_blocks=402_076,
    skipped_slots=29_924,
    predecessor_boundary_slot=43_199_999,
    slots_file_name="100.slots.txt",
    car_root_cid="bafyreibqt2nvroysxlxctgb52xxn27ectsllv2xyka4qar7ga6vupmbs3i",
    car_sha256="9f6d631833a8dfe0a4253ceede8e4af18a63603f0131a71ca5e947ba77eaec5a",
    source_commit="a69a0d2e189006608e3b73b7659a957b00b3567e",
)

#: Epochs this build is allowed to anchor against, keyed by epoch number.
PINNED_EPOCH_GROUND_TRUTH: Mapping[int, EpochGroundTruthSpec] = {
    EPOCH_100_GROUND_TRUTH.epoch: EPOCH_100_GROUND_TRUTH,
}


def pinned_spec(epoch: int) -> EpochGroundTruthSpec:
    try:
        return PINNED_EPOCH_GROUND_TRUTH[epoch]
    except KeyError:
        raise GroundTruthError(
            f"epoch {epoch} has no pinned ground-truth specification in this build"
        ) from None


@dataclass(frozen=True, slots=True)
class GroundTruthHeader:
    """One produced block's identity, as derived from the archive."""

    slot: int
    blockhash: str
    previous_blockhash: str
    parent_slot: int

    def __post_init__(self) -> None:
        if self.slot < 0 or self.parent_slot < 0:
            raise GroundTruthError("slots must be non-negative")
        if self.parent_slot >= self.slot:
            raise GroundTruthError("parent_slot must precede slot")
        if not is_base58_hash(self.blockhash):
            raise GroundTruthError(f"blockhash for slot {self.slot} is not a 32-byte base58 value")
        if not is_base58_hash(self.previous_blockhash):
            raise GroundTruthError(
                f"previousBlockhash for slot {self.slot} is not a 32-byte base58 value"
            )

    def to_payload(self) -> dict[str, object]:
        return {
            "slot": self.slot,
            "blockhash": self.blockhash,
            "previousBlockhash": self.previous_blockhash,
            "parentSlot": self.parent_slot,
        }


@dataclass(frozen=True, slots=True)
class ExtractorIdentity:
    """Identity of the pinned tool that turned archive bytes into records."""

    name: str
    version: str
    source_commit: str
    command: str
    node_schema: str
    binary_sha256: str | None = None
    validated_against_published_car: bool = False

    def to_payload(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "source_commit": self.source_commit,
            "command": self.command,
            "node_schema": self.node_schema,
            "binary_sha256": self.binary_sha256,
            "validated_against_published_car": self.validated_against_published_car,
        }


class GroundTruthExtractor(Protocol):
    """Turns verified CAR blocks into block-header records."""

    @property
    def identity(self) -> ExtractorIdentity: ...

    def extract(self, blocks: Iterable[CarBlock]) -> Iterator[GroundTruthHeader]: ...


class CarBlockHeaderExtractor:
    """Read block headers directly from DAG-CBOR nodes in a verified CAR.

    The node shape is declared, not guessed: a map carrying ``kind`` equal to
    :data:`BLOCK_NODE_KIND` together with ``slot``, ``blockhash``,
    ``previousBlockhash`` and ``parentSlot``.  Nodes of any other kind are
    skipped; a node that claims to be a block but cannot supply a complete,
    well-formed header is an error rather than a silent omission, because a
    silently dropped block would masquerade as a protocol skip.
    """

    def __init__(self, *, source_commit: str, version: str = "car-block-header/1") -> None:
        if not source_commit:
            raise GroundTruthError("extractor source_commit must be pinned")
        self._identity = ExtractorIdentity(
            name="slot-audit.CarBlockHeaderExtractor",
            version=version,
            source_commit=source_commit,
            command="slot_audit.groundtruth.CarBlockHeaderExtractor.extract(car)",
            node_schema=BLOCK_NODE_SCHEMA,
            binary_sha256=None,
            validated_against_published_car=False,
        )

    @property
    def identity(self) -> ExtractorIdentity:
        return self._identity

    def extract(self, blocks: Iterable[CarBlock]) -> Iterator[GroundTruthHeader]:
        for block in blocks:
            if block.cid.codec != 0x71:
                continue
            try:
                node = block.decode()
            except CarError as exc:
                raise GroundTruthError(
                    f"CAR block {block.cid.encode()} is not decodable DAG-CBOR: {exc}"
                ) from None
            if not isinstance(node, dict) or node.get("kind") != BLOCK_NODE_KIND:
                continue
            missing = [
                key
                for key in ("slot", "blockhash", "previousBlockhash", "parentSlot")
                if key not in node
            ]
            if missing:
                raise GroundTruthError(
                    f"block node {block.cid.encode()} is missing {', '.join(missing)}"
                )
            slot = node["slot"]
            parent_slot = node["parentSlot"]
            if not isinstance(slot, int) or not isinstance(parent_slot, int):
                raise GroundTruthError(f"block node {block.cid.encode()} has non-integer slots")
            yield GroundTruthHeader(
                slot=slot,
                blockhash=node["blockhash"],
                previous_blockhash=node["previousBlockhash"],
                parent_slot=parent_slot,
            )


@dataclass(slots=True)
class _StreamCensus:
    """What a single streaming pass observed, without retaining the blocks."""

    blocks: int = 0
    root_seen: bool = False


def _census_blocks(
    blocks: Iterable[CarBlock], expected_root: Cid, census: _StreamCensus
) -> Iterator[CarBlock]:
    """Count blocks and spot the root while they flow past to the extractor."""

    for block in blocks:
        census.blocks += 1
        if block.cid == expected_root:
            census.root_seen = True
        yield block


@dataclass(frozen=True, slots=True)
class TrustStep:
    """One named, individually reportable link of the ground-truth chain."""

    step: str
    passed: bool
    detail: str

    def to_payload(self) -> dict[str, object]:
        return {"step": self.step, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """A derived, coverage-checked epoch ground truth (verified or not)."""

    spec: EpochGroundTruthSpec
    extractor: ExtractorIdentity
    headers: Mapping[int, GroundTruthHeader]
    predecessor_header: GroundTruthHeader | None
    filtered_predecessor_rows: int
    trust_chain: tuple[TrustStep, ...]
    evidence_refs: tuple[EvidenceRef, ...] = ()
    car_sha256: str | None = None

    @property
    def verified(self) -> bool:
        return all(step.passed for step in self.trust_chain) and bool(self.trust_chain)

    @property
    def failures(self) -> tuple[TrustStep, ...]:
        return tuple(step for step in self.trust_chain if not step.passed)

    @property
    def produced_count(self) -> int:
        return len(self.headers)

    @property
    def skipped_count(self) -> int:
        return self.spec.scheduled_slot_positions - self.produced_count

    def is_produced(self, slot: int) -> bool:
        return slot in self.headers

    def header_for(self, slot: int) -> GroundTruthHeader | None:
        if slot == self.spec.predecessor_boundary_slot:
            return self.predecessor_header
        return self.headers.get(slot)

    def to_payload(self) -> dict[str, object]:
        return {
            "spec": self.spec.to_payload(),
            "extractor": self.extractor.to_payload(),
            "car_sha256": self.car_sha256,
            "verified": self.verified,
            "produced_blocks_derived": self.produced_count,
            "skipped_slots_derived": self.skipped_count,
            "filtered_predecessor_rows": self.filtered_predecessor_rows,
            "predecessor_header": (
                None if self.predecessor_header is None else self.predecessor_header.to_payload()
            ),
            "trust_chain": [step.to_payload() for step in self.trust_chain],
            "evidence": [ref.to_payload() for ref in self.evidence_refs],
        }


def _unverified(
    spec: EpochGroundTruthSpec,
    extractor: ExtractorIdentity,
    steps: Sequence[TrustStep],
    *,
    refs: Sequence[EvidenceRef] = (),
    car_sha256: str | None = None,
) -> GroundTruth:
    return GroundTruth(
        spec=spec,
        extractor=extractor,
        headers={},
        predecessor_header=None,
        filtered_predecessor_rows=0,
        trust_chain=tuple(steps),
        evidence_refs=tuple(refs),
        car_sha256=car_sha256,
    )


def derive_ground_truth(
    car_path: str | Path,
    *,
    spec: EpochGroundTruthSpec,
    extractor: GroundTruthExtractor,
    evidence: EvidenceStore | None = None,
    artifact_name: str | None = None,
) -> GroundTruth:
    """Verify the archive, then derive and coverage-check epoch ground truth.

    The function never raises for an unverifiable archive: an unverified
    :class:`GroundTruth` carrying the failed step is the audit-relevant answer,
    and callers must refuse to draw conclusions from it.
    """

    identity = extractor.identity
    steps: list[TrustStep] = []
    refs: list[EvidenceRef] = []
    path = Path(car_path)
    name = artifact_name or f"ground-truth-epoch-{spec.epoch}.jsonl"

    if identity.source_commit != spec.source_commit:
        steps.append(
            TrustStep(
                "extractor_pinned",
                False,
                f"extractor commit {identity.source_commit} != pinned {spec.source_commit}",
            )
        )
        return _unverified(spec, identity, steps)
    steps.append(
        TrustStep("extractor_pinned", True, f"extractor pinned at commit {spec.source_commit}")
    )

    if not path.is_file():
        steps.append(TrustStep("car_present", False, f"archive {path.name} was not found"))
        return _unverified(spec, identity, steps)
    steps.append(TrustStep("car_present", True, f"archive {path.name} is present"))

    # Pass one: digest the archive without loading it. Nothing below is allowed
    # to look at the contents until the file has proved it is the pinned one.
    digest = sha256_file(path)
    if digest != spec.car_sha256:
        steps.append(
            TrustStep(
                "car_sha256",
                False,
                f"archive sha256 {digest} != pinned {spec.car_sha256}",
            )
        )
        return _unverified(spec, identity, steps, car_sha256=digest)
    steps.append(TrustStep("car_sha256", True, f"archive sha256 matches pinned {digest}"))

    expected_root = Cid.decode(spec.car_root_cid)
    headers: dict[int, GroundTruthHeader] = {}
    predecessor: GroundTruthHeader | None = None
    filtered = 0
    census = _StreamCensus()

    # Pass two: stream the blocks. Each block is content-addressed as it is read
    # and discarded immediately, so peak memory is one block plus the derived
    # header table -- not the archive.
    with path.open("rb") as stream:
        try:
            header = read_car_header(stream)
        except CarError as exc:
            steps.append(TrustStep("car_structure", False, f"not a CAR v1 archive: {exc}"))
            return _unverified(spec, identity, steps, car_sha256=digest)
        steps.append(TrustStep("car_structure", True, "archive parses as CAR v1"))

        if len(header.roots) != 1 or header.roots[0] != expected_root:
            found = ", ".join(root.encode() for root in header.roots)
            steps.append(
                TrustStep(
                    "car_root_cid",
                    False,
                    f"archive roots [{found}] != pinned {spec.car_root_cid}",
                )
            )
            return _unverified(spec, identity, steps, car_sha256=digest)
        steps.append(TrustStep("car_root_cid", True, f"archive root is {spec.car_root_cid}"))

        blocks = _census_blocks(
            iter_car_blocks(stream, verify=True), expected_root, census
        )
        try:
            for record in extractor.extract(blocks):
                if record.slot == spec.predecessor_boundary_slot:
                    # Explicitly filtered: the boundary row belongs to the previous
                    # epoch and must never inflate the in-range produced count. It
                    # is retained separately so the epoch's first block can still be
                    # hash-link validated against its real parent.
                    filtered += 1
                    if predecessor is not None and predecessor != record:
                        steps.append(
                            TrustStep(
                                "predecessor_boundary_row",
                                False,
                                "conflicting predecessor boundary rows were derived",
                            )
                        )
                        return _unverified(spec, identity, steps, car_sha256=digest)
                    predecessor = record
                    continue
                if not spec.contains(record.slot):
                    steps.append(
                        TrustStep(
                            "in_range_only",
                            False,
                            f"derived slot {record.slot} lies outside epoch {spec.epoch}",
                        )
                    )
                    return _unverified(spec, identity, steps, car_sha256=digest)
                if record.slot in headers:
                    steps.append(
                        TrustStep(
                            "unique_slots",
                            False,
                            f"slot {record.slot} was derived more than once",
                        )
                    )
                    return _unverified(spec, identity, steps, car_sha256=digest)
                headers[record.slot] = record
        except CarError as exc:
            steps.append(TrustStep("car_block_integrity", False, str(exc)))
            return _unverified(spec, identity, steps, car_sha256=digest)
        except GroundTruthError as exc:
            steps.append(TrustStep("extraction", False, str(exc)))
            return _unverified(spec, identity, steps, car_sha256=digest)

    steps.append(
        TrustStep(
            "car_block_integrity",
            True,
            f"all {census.blocks} blocks are content-addressed by their own CID",
        )
    )
    if not census.root_seen:
        steps.append(
            TrustStep(
                "car_root_block_present",
                False,
                "the declared root block is not in the archive",
            )
        )
        return _unverified(spec, identity, steps, car_sha256=digest)
    steps.append(TrustStep("car_root_block_present", True, "the declared root block is present"))
    steps.append(
        TrustStep("in_range_only", True, f"all derived slots lie inside epoch {spec.epoch}")
    )
    steps.append(TrustStep("unique_slots", True, "no slot was derived twice"))
    steps.append(
        TrustStep(
            "predecessor_boundary_row",
            True,
            f"filtered {filtered} row(s) for predecessor slot {spec.predecessor_boundary_slot}",
        )
    )

    produced = len(headers)
    if produced != spec.produced_blocks:
        steps.append(
            TrustStep(
                "produced_block_count",
                False,
                f"derived {produced} in-range produced blocks, expected exactly "
                f"{spec.produced_blocks}",
            )
        )
        return _unverified(spec, identity, steps, car_sha256=digest)
    steps.append(
        TrustStep(
            "produced_block_count",
            True,
            f"derived exactly {spec.produced_blocks} in-range produced blocks",
        )
    )

    skipped = spec.scheduled_slot_positions - produced
    if skipped != spec.skipped_slots:
        steps.append(
            TrustStep(
                "skipped_slot_count",
                False,
                f"derived {skipped} skipped slots, expected {spec.skipped_slots}",
            )
        )
        return _unverified(spec, identity, steps, car_sha256=digest)
    steps.append(
        TrustStep("skipped_slot_count", True, f"derived exactly {spec.skipped_slots} skipped slots")
    )

    if predecessor is None:
        steps.append(
            TrustStep(
                "predecessor_header_available",
                False,
                f"no header was derived for predecessor slot {spec.predecessor_boundary_slot}",
            )
        )
        return _unverified(spec, identity, steps, car_sha256=digest)
    steps.append(
        TrustStep(
            "predecessor_header_available",
            True,
            f"predecessor slot {spec.predecessor_boundary_slot} header is available",
        )
    )

    if evidence is not None:
        def _rows() -> Iterator[bytes]:
            yield _jsonl(predecessor.to_payload())
            for slot in sorted(headers):
                yield _jsonl(headers[slot].to_payload())

        derived_ref = evidence.record_artifact_stream(name, _rows())
        refs.append(derived_ref)
        refs.append(
            evidence.record_json_artifact(
                f"ground-truth-epoch-{spec.epoch}-derivation.json",
                {
                    "spec": spec.to_payload(),
                    "extractor": identity.to_payload(),
                    "car_sha256": digest,
                    "car_byte_length": path.stat().st_size,
                    "car_block_count": census.blocks,
                    "derived_file": name,
                    "derived_sha256": derived_ref.sha256,
                    "derived_byte_length": derived_ref.byte_length,
                    "derived_row_count": len(headers) + 1,
                    "filtered_predecessor_rows": filtered,
                },
            )
        )
        steps.append(
            TrustStep(
                "derived_artifact_retained",
                True,
                f"derived records retained as {name} "
                f"(sha256={derived_ref.sha256}, {derived_ref.byte_length} bytes)",
            )
        )
    else:
        steps.append(
            TrustStep(
                "derived_artifact_retained",
                False,
                "no evidence store was supplied, so the derivation was not retained",
            )
        )

    return GroundTruth(
        spec=spec,
        extractor=identity,
        headers=headers,
        predecessor_header=predecessor,
        filtered_predecessor_rows=filtered,
        trust_chain=tuple(steps),
        evidence_refs=tuple(refs),
        car_sha256=digest,
    )


# ---------------------------------------------------------------------------
# Schema probe
#
# This build derives ground truth from a declared node shape. Whether the
# published archive actually uses that shape is a question about a 62.9 GB file
# nobody wants to read twice, so the probe answers it factually and cheaply:
# stream a prefix, report what is genuinely there, and let the operator compare.
# It asserts nothing about what *should* be present.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CarCensus:
    """What a streaming prefix scan actually observed in an archive."""

    path_name: str
    blocks_scanned: int
    bytes_scanned: int
    stopped_early: bool
    stop_reason: str | None
    declared_roots: tuple[str, ...]
    root_seen: bool
    codec_counts: Mapping[str, int]
    node_kind_counts: Mapping[str, int]
    key_signature_counts: Mapping[str, int]
    expected_schema: str
    recognized_block_nodes: int

    @property
    def schema_present(self) -> bool:
        """True only if the shape this build derives from was actually seen."""

        return self.recognized_block_nodes > 0

    def to_payload(self) -> dict[str, object]:
        return {
            "archive": self.path_name,
            "blocks_scanned": self.blocks_scanned,
            "bytes_scanned": self.bytes_scanned,
            "stopped_early": self.stopped_early,
            "stop_reason": self.stop_reason,
            "declared_roots": list(self.declared_roots),
            "root_block_seen": self.root_seen,
            "codec_counts": dict(self.codec_counts),
            "node_kind_counts": dict(self.node_kind_counts),
            "key_signature_counts": dict(self.key_signature_counts),
            "expected_schema": self.expected_schema,
            "recognized_block_nodes": self.recognized_block_nodes,
            "schema_present": self.schema_present,
        }

    def describe(self) -> str:
        lines = [
            f"archive: {self.path_name}",
            f"blocks scanned: {self.blocks_scanned} ({self.bytes_scanned} bytes)",
            f"declared roots: {', '.join(self.declared_roots) or 'none'}",
            f"root block seen in scanned prefix: {self.root_seen}",
        ]
        if self.stopped_early:
            lines.append(f"scan stopped early: {self.stop_reason}")
        lines.append("codecs:")
        for codec, count in sorted(self.codec_counts.items()):
            lines.append(f"  {codec}: {count}")
        if self.node_kind_counts:
            lines.append("dag-cbor node 'kind' values:")
            for kind, count in sorted(self.node_kind_counts.items()):
                lines.append(f"  {kind}: {count}")
        if self.key_signature_counts:
            lines.append("dag-cbor map key signatures:")
            for signature, count in sorted(
                self.key_signature_counts.items(), key=lambda item: (-item[1], item[0])
            )[:20]:
                lines.append(f"  [{signature}]: {count}")
        lines.append("")
        lines.append(f"expected block-header schema: {self.expected_schema}")
        lines.append(f"nodes matching it: {self.recognized_block_nodes}")
        if self.schema_present:
            lines.append(
                "RESULT: the shape this build derives from is present in the scanned "
                "prefix."
            )
        else:
            lines.append(
                "RESULT: the shape this build derives from was NOT seen. Ground-truth "
                "derivation would fail the produced-block count gate and the run would "
                "conclude nothing. Do not treat this archive as anchored."
            )
        return "\n".join(lines)


def _matches_block_header_schema(node: object) -> bool:
    if not isinstance(node, dict) or node.get("kind") != BLOCK_NODE_KIND:
        return False
    required = ("slot", "blockhash", "previousBlockhash", "parentSlot")
    if any(key not in node for key in required):
        return False
    return (
        isinstance(node["slot"], int)
        and not isinstance(node["slot"], bool)
        and isinstance(node["parentSlot"], int)
        and not isinstance(node["parentSlot"], bool)
        and is_base58_hash(node["blockhash"])
        and is_base58_hash(node["previousBlockhash"])
    )


def probe_car(
    car_path: str | Path,
    *,
    max_blocks: int | None = None,
    expected_schema: str = BLOCK_NODE_SCHEMA,
) -> CarCensus:
    """Stream a prefix of an archive and report what is in it.

    The archive is neither trusted nor verified here -- that is what
    :func:`derive_ground_truth` is for. The probe exists so an operator holding
    the real file can confirm the extractor's assumption in one command, against
    a prefix, before committing to a full run.
    """

    path = Path(car_path)
    if not path.is_file():
        raise GroundTruthError(f"archive {path} was not found")

    codec_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    signature_counts: dict[str, int] = {}
    blocks = 0
    scanned = 0
    recognized = 0
    root_seen = False
    stopped_early = False
    stop_reason: str | None = None
    roots: tuple[str, ...] = ()

    with path.open("rb") as stream:
        try:
            header = read_car_header(stream)
        except CarError as exc:
            raise GroundTruthError(f"{path.name} is not a readable CAR v1 file: {exc}") from None
        roots = tuple(root.encode() for root in header.roots)
        root_cids = set(header.roots)
        try:
            for block in iter_car_blocks(stream, verify=True):
                blocks += 1
                scanned += len(block.data)
                if block.cid in root_cids:
                    root_seen = True
                codec = f"0x{block.cid.codec:02x}"
                codec_counts[codec] = codec_counts.get(codec, 0) + 1
                if block.cid.codec == DAG_CBOR_CODEC:
                    try:
                        node = block.decode()
                    except CarError:
                        signature_counts["<undecodable>"] = (
                            signature_counts.get("<undecodable>", 0) + 1
                        )
                        node = None
                    if isinstance(node, dict):
                        signature = ",".join(sorted(node))
                        signature_counts[signature] = signature_counts.get(signature, 0) + 1
                        kind = node.get("kind")
                        label = str(kind) if isinstance(kind, int) else "<none>"
                        kind_counts[label] = kind_counts.get(label, 0) + 1
                        if _matches_block_header_schema(node):
                            recognized += 1
                    elif node is not None:
                        name = f"<{type(node).__name__}>"
                        signature_counts[name] = signature_counts.get(name, 0) + 1
                if max_blocks is not None and blocks >= max_blocks:
                    stopped_early = True
                    stop_reason = f"reached the requested limit of {max_blocks} blocks"
                    break
        except CarError as exc:
            stopped_early = True
            stop_reason = str(exc)

    return CarCensus(
        path_name=path.name,
        blocks_scanned=blocks,
        bytes_scanned=scanned,
        stopped_early=stopped_early,
        stop_reason=stop_reason,
        declared_roots=roots,
        root_seen=root_seen,
        codec_counts=codec_counts,
        node_kind_counts=kind_counts,
        key_signature_counts=signature_counts,
        expected_schema=expected_schema,
        recognized_block_nodes=recognized,
    )


def _jsonl(payload: Mapping[str, object]) -> bytes:
    from .evidence import canonical_json

    return canonical_json(payload) + b"\n"


__all__ = [
    "BLOCK_NODE_KIND",
    "BLOCK_NODE_SCHEMA",
    "EPOCH_100_GROUND_TRUTH",
    "PINNED_EPOCH_GROUND_TRUTH",
    "CarBlockHeaderExtractor",
    "CarCensus",
    "EpochGroundTruthSpec",
    "ExtractorIdentity",
    "GroundTruth",
    "GroundTruthError",
    "GroundTruthExtractor",
    "GroundTruthHeader",
    "TrustStep",
    "derive_ground_truth",
    "pinned_spec",
    "probe_car",
]
