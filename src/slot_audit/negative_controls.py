"""End-to-end negative controls that run the production audit.

A control that calls a helper proves the helper works.  These controls build a
deterministic offline epoch, hand it to an injectable transport, and then call
:func:`slot_audit.audit.run_epoch_audit` -- the same function a live run calls.
Collection, freezing, anchoring, classification, finding construction, evidence
retention and assessment all execute unmodified.  The only substitution is the
socket.

Each control injects one specific defect and asserts that the *final* output
names it:

``removed_known_block``
    A block that demonstrably exists is removed from one provider.  The run must
    emit ``PROVIDER_HOLE`` -- never ``PROTOCOL_SKIPPED`` -- and the finding must
    cite the range response, the direct response and the ground-truth header.

``truncated_token_enumeration``
    One account holding ``N`` base units disappears from the enumeration.  The
    reconciliation must under-report by exactly ``-N``.

``corrupted_previous_blockhash``
    A ``previousBlockhash`` is corrupted in the raw response.  The run must
    report ``PREVIOUS_BLOCKHASH_MISMATCH`` rather than pass quietly.

The fixtures are generated from fixed seeds, so the archive bytes, its digest
and its root CID are identical on every machine and every run.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from .assessment import GateStatus
from .audit import AuditRun, NegativeControlResult, run_epoch_audit
from .car import CarBlock, Cid, cbor_encode, encode_car
from .config import (
    ContinuityConfig,
    EpochAuditConfig,
    EpochLimitsConfig,
    EpochProviderConfig,
    GroundTruthConfig,
    PopulationConfig,
    ResolvedEpochAuditConfig,
    ResolvedProvider,
    ScopeConfig,
    ThresholdConfig,
    TokenConfig,
)
from .continuity import LinkOutcome
from .evidence import EvidenceStore, endpoint_fingerprint, endpoint_host_fingerprint, utc_now
from .groundtruth import (
    BLOCK_NODE_KIND,
    CarBlockHeaderExtractor,
    ConstantProvenance,
    EpochGroundTruthSpec,
    GroundTruthHeader,
)
from .token import (
    LEGACY_TOKEN_PROGRAM_ID,
    AccountState,
    DuplicatePubkeyPolicy,
    TokenScope,
    ZeroBalancePolicy,
    base58_encode,
    encode_account_payload,
    encode_mint_account,
    encode_token_account,
)
from .transport import AuditRpcClient, ScriptedRpcError, ScriptedTransport
from .verdict import Verdict

CONTROL_SOURCE_COMMIT = "c0000000000000000000000000000000000000c1"
CONTROL_EPOCH = 900_100
CONTROL_FIRST_SLOT = 388_843_200
CONTROL_POSITIONS = 32
CONTROL_PRODUCED = 24
CONTROL_MINT = base58_encode(hashlib.sha256(b"slot-audit/control-mint").digest())
CONTROL_TOKEN_ACCOUNTS = 6
PROVIDER_A_URL = "https://control-a.invalid/rpc?api-key=control-a"
PROVIDER_B_URL = "https://control-b.invalid/rpc?api-key=control-b"

_SKIPPED_SLOT_ERROR = (
    -32009,
    "Slot {slot} was skipped, or missing due to ledger jump to recent snapshot",
)


def _deterministic_hash(label: str) -> str:
    return base58_encode(hashlib.sha256(label.encode("utf-8")).digest())


@dataclass(frozen=True, slots=True)
class SimulatedEpoch:
    """A complete, tiny, deterministic epoch with its own verifiable archive."""

    spec: EpochGroundTruthSpec
    headers: Mapping[int, GroundTruthHeader]
    predecessor: GroundTruthHeader
    car_bytes: bytes
    token_accounts: tuple[tuple[str, int, AccountState], ...]
    mint_supply: int
    pinned_slot: int

    @property
    def produced_slots(self) -> tuple[int, ...]:
        return tuple(sorted(self.headers))


def build_simulated_epoch(
    *,
    epoch: int = CONTROL_EPOCH,
    first_slot: int = CONTROL_FIRST_SLOT,
    positions: int = CONTROL_POSITIONS,
    produced: int = CONTROL_PRODUCED,
) -> SimulatedEpoch:
    """Build the fixture epoch and the CAR that is its ground truth.

    The archive's digest and root CID are computed from the bytes just built, so
    the pinned specification below describes this archive and no other.
    """

    if not 0 < produced <= positions:
        raise ValueError("produced must be within the scheduled positions")
    last_slot = first_slot + positions - 1
    # A fixed, spread-out skip pattern: every fourth position after the first.
    all_positions = list(range(first_slot, last_slot + 1))
    skipped = {
        slot for index, slot in enumerate(all_positions) if index % 4 == 3
    }
    produced_slots = [slot for slot in all_positions if slot not in skipped]
    while len(produced_slots) > produced:
        skipped.add(produced_slots.pop())
    if len(produced_slots) != produced:
        raise ValueError("could not build the requested produced-block count")

    predecessor_slot = first_slot - 1
    predecessor = GroundTruthHeader(
        slot=predecessor_slot,
        blockhash=_deterministic_hash(f"block/{predecessor_slot}"),
        previous_blockhash=_deterministic_hash(f"block/{predecessor_slot - 1}"),
        parent_slot=predecessor_slot - 1,
    )
    headers: dict[int, GroundTruthHeader] = {}
    parent = predecessor
    for slot in produced_slots:
        header = GroundTruthHeader(
            slot=slot,
            blockhash=_deterministic_hash(f"block/{slot}"),
            previous_blockhash=parent.blockhash,
            parent_slot=parent.slot,
        )
        headers[slot] = header
        parent = header

    blocks: list[CarBlock] = []
    child_cids: list[Cid] = []
    for header in (predecessor, *(headers[slot] for slot in produced_slots)):
        node = {
            "kind": BLOCK_NODE_KIND,
            "slot": header.slot,
            "blockhash": header.blockhash,
            "previousBlockhash": header.previous_blockhash,
            "parentSlot": header.parent_slot,
        }
        data = cbor_encode(node)
        cid = Cid.for_data(data)
        blocks.append(CarBlock(cid=cid, data=data))
        child_cids.append(cid)
    root_node = {"kind": 4, "epoch": epoch, "subsets": child_cids}
    root_data = cbor_encode(root_node)
    root_cid = Cid.for_data(root_data)
    blocks.insert(0, CarBlock(cid=root_cid, data=root_data))
    car_bytes = encode_car([root_cid], blocks)

    spec = EpochGroundTruthSpec(
        epoch=epoch,
        first_slot=first_slot,
        last_slot=last_slot,
        scheduled_slot_positions=positions,
        produced_blocks=len(headers),
        skipped_slots=positions - len(headers),
        predecessor_boundary_slot=predecessor_slot,
        slots_file_name=f"{epoch}.slots.txt",
        car_root_cid=root_cid.encode(),
        car_sha256=hashlib.sha256(car_bytes).hexdigest(),
        source_commit=CONTROL_SOURCE_COMMIT,
        provenance=ConstantProvenance(
            source=(
                "generated deterministically by build_simulated_epoch in this "
                "repository"
            ),
            verified_against_archive=True,
            note=(
                "The digest and root CID are computed from the archive bytes that "
                "were just built, so they describe this archive by construction."
            ),
        ),
    )

    accounts = tuple(
        (
            base58_encode(hashlib.sha256(f"control/token/{index}".encode()).digest()),
            (index + 1) * 1_000,
            AccountState.INITIALIZED,
        )
        for index in range(CONTROL_TOKEN_ACCOUNTS)
    )
    supply = sum(amount for _, amount, _ in accounts)
    return SimulatedEpoch(
        spec=spec,
        headers=headers,
        predecessor=predecessor,
        car_bytes=car_bytes,
        token_accounts=accounts,
        mint_supply=supply,
        pinned_slot=produced_slots[-1],
    )


@dataclass(slots=True)
class LedgerDefects:
    """The defects a control injects into one provider's answers."""

    dropped_slots: frozenset[int] = frozenset()
    dropped_token_accounts: frozenset[str] = frozenset()
    corrupted_previous_blockhash: Mapping[int, str] = field(default_factory=dict)


class SimulatedProviderLedger:
    """A provider's whole view of the fixture epoch, defects included."""

    def __init__(
        self,
        epoch: SimulatedEpoch,
        *,
        scope: TokenScope,
        defects: LedgerDefects | None = None,
        version: str = "1.18.26",
    ) -> None:
        self.epoch = epoch
        self.scope = scope
        self.defects = defects or LedgerDefects()
        self.version = version

    def visible_slots(self) -> list[int]:
        return [
            slot for slot in self.epoch.produced_slots if slot not in self.defects.dropped_slots
        ]

    def handle(self, url: str, method: str, params: list[Any]) -> Any:
        if method == "getVersion":
            return {"solana-core": self.version, "feature-set": 3_241_752_244}
        if method == "getBlocks":
            start, end = int(params[0]), int(params[1])
            return [slot for slot in self.visible_slots() if start <= slot <= end]
        if method == "getBlock":
            return self._get_block(int(params[0]))
        if method == "getProgramAccounts":
            return self._get_program_accounts()
        if method == "getAccountInfo":
            return self._get_account_info(str(params[0]))
        raise ScriptedRpcError(-32601, f"Method not found: {method}")

    def _get_block(self, slot: int) -> Any:
        header = self.epoch.headers.get(slot)
        if header is None or slot in self.defects.dropped_slots:
            code, template = _SKIPPED_SLOT_ERROR
            raise ScriptedRpcError(code, template.format(slot=slot))
        previous = self.defects.corrupted_previous_blockhash.get(
            slot, header.previous_blockhash
        )
        return {
            "blockhash": header.blockhash,
            "previousBlockhash": previous,
            "parentSlot": header.parent_slot,
            "blockHeight": slot - self.epoch.spec.first_slot,
            "blockTime": 1_600_000_000 + slot,
        }

    def _get_program_accounts(self) -> Any:
        value = []
        for pubkey, amount, state in self.epoch.token_accounts:
            if pubkey in self.defects.dropped_token_accounts:
                continue
            data = encode_token_account(
                mint=self.epoch_mint,
                owner=pubkey,
                amount=amount,
                state=state,
                scope=self.scope,
            )
            value.append(
                {
                    "pubkey": pubkey,
                    "account": encode_account_payload(data, owner=self.scope.program_id),
                }
            )
        return {
            "context": {"slot": self.epoch.pinned_slot, "apiVersion": self.version},
            "value": value,
        }

    def _get_account_info(self, pubkey: str) -> Any:
        if pubkey != self.epoch_mint:
            return {"context": {"slot": self.epoch.pinned_slot}, "value": None}
        data = encode_mint_account(supply=self.epoch.mint_supply, scope=self.scope)
        return {
            "context": {"slot": self.epoch.pinned_slot, "apiVersion": self.version},
            "value": encode_account_payload(data, owner=self.scope.program_id),
        }

    @property
    def epoch_mint(self) -> str:
        return CONTROL_MINT


def control_token_scope() -> TokenScope:
    return TokenScope(
        program_id=LEGACY_TOKEN_PROGRAM_ID,
        account_size=165,
        mint_offset=0,
        amount_offset=64,
        state_offset=108,
        supply_offset=36,
        included_account_states=(AccountState.INITIALIZED, AccountState.FROZEN),
        zero_balance_policy=ZeroBalancePolicy.INCLUDE,
        duplicate_pubkey_policy=DuplicatePubkeyPolicy.REJECT,
    )


def build_control_config(epoch: SimulatedEpoch) -> EpochAuditConfig:
    """Restate the fixture spec as a complete, defaults-free configuration."""

    spec = epoch.spec
    return EpochAuditConfig(
        schema_version=1,
        population=PopulationConfig(
            definition=(
                f"every scheduled slot position of epoch {spec.epoch} "
                f"({spec.first_slot}-{spec.last_slot}) plus every token account of one "
                "legacy SPL Token mint at the pinned slot"
            ),
            unit="scheduled slot position",
            description="deterministic offline fixture epoch used by the negative controls",
        ),
        scope=ScopeConfig(
            epoch=spec.epoch,
            first_slot=spec.first_slot,
            last_slot=spec.last_slot,
            scheduled_slot_positions=spec.scheduled_slot_positions,
            commitment="finalized",
            pinned_slot=epoch.pinned_slot,
            exact_context_policy="require_exact_pinned_slot",
        ),
        thresholds=ThresholdConfig(
            indeterminate_threshold="0.01",
            denominator_policy="determinate_positions_only",
            materiality_threshold="0.0001",
            minimum_provider_agreement="0.99",
        ),
        token=TokenConfig(
            mint=CONTROL_MINT,
            program_id=LEGACY_TOKEN_PROGRAM_ID,
            account_size=165,
            mint_offset=0,
            amount_offset=64,
            state_offset=108,
            supply_offset=36,
            included_account_states=["initialized", "frozen"],
            zero_balance_policy="include",
            duplicate_pubkey_policy="reject",
        ),
        continuity=ContinuityConfig(hash_link_validation_population="all_produced_blocks"),
        limits=EpochLimitsConfig(max_requests_per_provider=5_000, max_retries=3),
        ground_truth=GroundTruthConfig(
            source="old_faithful_car",
            car_path_env="CONTROL_CAR_PATH",
            car_sha256=spec.car_sha256,
            car_root_cid=spec.car_root_cid,
            source_commit=spec.source_commit,
            slots_file_name=spec.slots_file_name,
            predecessor_boundary_slot=spec.predecessor_boundary_slot,
            produced_blocks=spec.produced_blocks,
            skipped_slots=spec.skipped_slots,
            extractor="car_block_header",
            endpoint_env=None,
        ),
        providers=[
            EpochProviderConfig(name="control-a", url_env="CONTROL_PROVIDER_A_URL", rps=50.0),
            EpochProviderConfig(name="control-b", url_env="CONTROL_PROVIDER_B_URL", rps=50.0),
        ],
    )


def resolve_control_config(
    config: EpochAuditConfig,
    *,
    car_path: Path,
    urls: tuple[str, str] = (PROVIDER_A_URL, PROVIDER_B_URL),
) -> ResolvedEpochAuditConfig:
    """Resolve a fixture configuration without consulting the environment.

    ``urls`` is a parameter so a fixture can construct the degenerate case of two
    providers resolving to one endpoint. :func:`resolve_epoch_config` refuses to
    build that from real configuration, which is why the ``distinct_endpoints``
    gate needs another route to be exercised at all.
    """

    providers = tuple(
        ResolvedProvider(
            name=model.name,
            url_env=model.url_env,
            url=SecretStr(url),
            rps=model.rps,
            endpoint_fingerprint=endpoint_fingerprint(url),
            host_fingerprint=endpoint_host_fingerprint(url),
        )
        for model, url in zip(config.providers, urls, strict=True)
    )
    return ResolvedEpochAuditConfig(
        config=config,
        providers=providers,
        car_path=str(car_path),
        anchor_endpoint=None,
        anchor_endpoint_fingerprint=None,
        anchor_host_fingerprint=None,
    )


def _materialize_fixture(directory: Path, epoch: SimulatedEpoch) -> Path:
    """Write the fixture archive to disk (synchronously, before the run)."""

    directory.mkdir(parents=True, exist_ok=True)
    car_path = directory / f"epoch-{epoch.spec.epoch}.car"
    car_path.write_bytes(epoch.car_bytes)
    return car_path


async def run_control_audit(
    *,
    directory: Path,
    epoch: SimulatedEpoch,
    defects_by_provider: Mapping[str, LedgerDefects],
    now: Callable[[], str] = utc_now,
    run_negative_controls: bool = False,
) -> AuditRun:
    """Run the real audit against the fixture epoch through a scripted transport."""

    car_path = _materialize_fixture(directory, epoch)
    config = build_control_config(epoch)
    resolved = resolve_control_config(config, car_path=car_path)
    scope = control_token_scope()
    ledgers = {
        provider.name: SimulatedProviderLedger(
            epoch,
            scope=scope,
            defects=defects_by_provider.get(provider.name, LedgerDefects()),
        )
        for provider in resolved.providers
    }
    evidence = EvidenceStore(directory / "evidence")

    def client_factory(provider: ResolvedProvider) -> AuditRpcClient:
        ledger = ledgers[provider.name]
        return AuditRpcClient(
            provider=provider.name,
            url=provider.rpc_url,
            endpoint_fingerprint=provider.endpoint_fingerprint,
            transport=ScriptedTransport(ledger.handle),
            evidence=evidence,
            clock=now,
            max_requests=config.limits.max_requests_per_provider,
            max_retries=config.limits.max_retries,
        )

    return await run_epoch_audit(
        resolved,
        evidence=evidence,
        client_factory=client_factory,
        results_dir=directory,
        spec=epoch.spec,
        extractor=CarBlockHeaderExtractor(source_commit=epoch.spec.source_commit),
        run_negative_controls=run_negative_controls,
        chunk_size=epoch.spec.scheduled_slot_positions,
        now=now,
    )


async def control_removed_known_block(
    *, directory: Path, now: Callable[[], str] = utc_now
) -> NegativeControlResult:
    """Remove a block that provably exists and require a PROVIDER_HOLE."""

    epoch = build_simulated_epoch()
    produced = epoch.produced_slots
    target = produced[len(produced) // 2]
    run = await run_control_audit(
        directory=directory,
        epoch=epoch,
        defects_by_provider={"control-a": LedgerDefects(dropped_slots=frozenset({target}))},
        now=now,
    )
    matching = [
        finding
        for finding in run.findings
        if finding.slot == target and finding.provider == "control-a"
    ]
    finding = matching[0] if matching else None
    verdicts = {
        outcome.slot: dict(outcome.verdicts)
        for outcome in run.tally.candidate_holes
    }
    observed_verdict = verdicts.get(target, {}).get("control-a")
    skipped_count = run.tally.verdict_counts["control-a"][Verdict.PROTOCOL_SKIPPED.value]
    expected_skips = epoch.spec.skipped_slots
    detected = (
        finding is not None
        and finding.verdict is Verdict.PROVIDER_HOLE
        and observed_verdict is Verdict.PROVIDER_HOLE
        and finding.complete
        and bool(finding.blockhash and finding.previous_blockhash)
        and finding.parent_slot >= 0
        and skipped_count == expected_skips
        and "range_response" in finding.evidence
        and "direct_response" in finding.evidence
        and "ground_truth_header" in finding.evidence
    )
    detail = (
        f"removed produced slot {target} from control-a; "
        + (
            f"classified {observed_verdict} with evidence "
            f"{sorted(finding.evidence)}"
            if finding is not None
            else "no finding was produced"
        )
    )
    return NegativeControlResult(
        control_id="removed_known_block",
        title="Removing a block known to exist yields PROVIDER_HOLE",
        detected=detected,
        detail=detail,
        observed={
            "removed_slot": target,
            "finding_count": len(run.findings),
            "verdict": None if observed_verdict is None else observed_verdict.value,
            "became_protocol_skipped": observed_verdict is Verdict.PROTOCOL_SKIPPED,
            "protocol_skipped_count": skipped_count,
            "expected_protocol_skipped_count": expected_skips,
            "finding_blockhash": None if finding is None else finding.blockhash,
            "finding_previous_blockhash": (
                None if finding is None else finding.previous_blockhash
            ),
            "finding_parent_slot": None if finding is None else finding.parent_slot,
            "finding_source": None if finding is None else finding.source,
            "evidence_keys": sorted(finding.evidence) if finding else [],
            "evidence_refs": (
                {
                    name: ref.describe()
                    for name, ref in sorted(finding.evidence.items())
                }
                if finding
                else {}
            ),
            "control_manifest_ok": run.evidence_root.exists(),
        },
    )


async def control_truncated_token_enumeration(
    *, directory: Path, now: Callable[[], str] = utc_now
) -> NegativeControlResult:
    """Drop one funded token account and require an exact signed shortfall."""

    epoch = build_simulated_epoch()
    pubkey, amount, _state = epoch.token_accounts[2]
    defects = LedgerDefects(dropped_token_accounts=frozenset({pubkey}))
    run = await run_control_audit(
        directory=directory,
        epoch=epoch,
        defects_by_provider={"control-a": defects, "control-b": defects},
        now=now,
    )
    differences = {
        name: result.signed_difference for name, result in run.token_results.items()
    }
    detected = bool(differences) and all(
        value == -amount for value in differences.values()
    )
    return NegativeControlResult(
        control_id="truncated_token_enumeration",
        title="A truncated enumeration under-reports supply by exactly the dropped balance",
        detected=detected,
        detail=(
            f"removed token account holding {amount} base units; observed signed "
            f"differences {differences} against an expected {-amount}"
        ),
        observed={
            "removed_account": pubkey,
            "removed_amount_base_units": amount,
            "expected_signed_difference": -amount,
            "observed_signed_differences": differences,
            "mint_supply": epoch.mint_supply,
            "enumerated_totals": {
                name: result.enumerated_total for name, result in run.token_results.items()
            },
        },
    )


async def control_corrupted_previous_blockhash(
    *, directory: Path, now: Callable[[], str] = utc_now
) -> NegativeControlResult:
    """Corrupt a previousBlockhash in the raw response and require detection."""

    epoch = build_simulated_epoch()
    produced = epoch.produced_slots
    target = produced[2]
    corrupted = _deterministic_hash(f"corrupt/{target}")
    run = await run_control_audit(
        directory=directory,
        epoch=epoch,
        defects_by_provider={
            "control-a": LedgerDefects(
                corrupted_previous_blockhash={target: corrupted}
            )
        },
        now=now,
    )
    mismatched = [
        link
        for result in run.continuity
        for link in result.links
        if link.outcome is LinkOutcome.PREVIOUS_BLOCKHASH_MISMATCH
    ]
    gate = run.assessment.gate("hash_link_continuity")
    detected = (
        any(link.slot == target for link in mismatched)
        and gate.status is GateStatus.FAIL
    )
    return NegativeControlResult(
        control_id="corrupted_previous_blockhash",
        title="A corrupted previousBlockhash surfaces as PREVIOUS_BLOCKHASH_MISMATCH",
        detected=detected,
        detail=(
            f"corrupted previousBlockhash of slot {target} in control-a's raw getBlock "
            f"response; {len(mismatched)} mismatch(es) reported, continuity gate "
            f"{gate.status.value}"
        ),
        observed={
            "corrupted_slot": target,
            "injected_previous_blockhash": corrupted,
            "expected_previous_blockhash": epoch.headers[target].previous_blockhash,
            "mismatch_count": len(mismatched),
            "mismatched_slots": sorted({link.slot for link in mismatched}),
            "outcome": LinkOutcome.PREVIOUS_BLOCKHASH_MISMATCH.value,
            "continuity_gate_status": gate.status.value,
            "silently_passed": not mismatched,
        },
    )


CONTROLS: tuple[tuple[str, Callable[..., Any]], ...] = (
    ("removed_known_block", control_removed_known_block),
    ("truncated_token_enumeration", control_truncated_token_enumeration),
    ("corrupted_previous_blockhash", control_corrupted_previous_blockhash),
)


async def run_all_negative_controls(
    *, results_dir: str | Path, now: Callable[[], str] = utc_now
) -> tuple[NegativeControlResult, ...]:
    """Run every shipped control through the production audit path."""

    root = Path(results_dir)
    results: list[NegativeControlResult] = []
    for name, control in CONTROLS:
        results.append(await control(directory=root / name, now=now))
    return tuple(results)


__all__ = [
    "CONTROLS",
    "CONTROL_EPOCH",
    "CONTROL_MINT",
    "LedgerDefects",
    "SimulatedEpoch",
    "SimulatedProviderLedger",
    "build_control_config",
    "build_simulated_epoch",
    "control_corrupted_previous_blockhash",
    "control_removed_known_block",
    "control_token_scope",
    "control_truncated_token_enumeration",
    "resolve_control_config",
    "run_all_negative_controls",
    "run_control_audit",
]
