"""Command-line entry point for the staged Solana slot audit."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from fractions import Fraction
from functools import partial
from pathlib import Path
from typing import Any, Protocol

import anyio

from .checkpoint import CheckpointError, CheckpointMismatch, CheckpointState, CheckpointStore
from .config import (
    AuditConfig,
    ConfigError,
    ProviderConfig,
    load_config,
    redact_text,
    url_redaction_values,
)
from .enumerate import (
    MAX_GET_BLOCKS_SLOTS,
    ChunkEnumeration,
    CrossProviderOmission,
    ProviderEnumeration,
    apply_retention_boundary,
    enumerate_provider,
    iter_cross_provider_holes,
)
from .epochs import EpochSchedule
from .rpc import RetryEvent, RpcClient

EXIT_COMPLETE = 0
EXIT_PARTIAL = 1
EXIT_FAILED = 2
# Exact, like every other judgment threshold in this tool. A float literal here
# would mean the shipped package decides "trustworthy" by binary comparison in
# one code path while insisting on Decimal in the other.
INDETERMINATE_TRUST_THRESHOLD = Decimal("0.01")


class _EnumerationRpcClient(Protocol):
    request_count: int

    async def get_slot(self) -> int: ...

    async def get_first_available_block(self) -> int: ...

    async def get_epoch_schedule(self) -> dict[str, Any]: ...

    async def get_blocks(self, start_slot: int, end_slot: int) -> Sequence[int]: ...

    async def aclose(self) -> None: ...


ClientFactory = Callable[..., _EnumerationRpcClient]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class _JsonlRunLog:
    """A private structured logger that never attaches HTTP client loggers."""

    def __init__(
        self,
        path: Path,
        *,
        run_id: str,
        secrets: tuple[str, ...],
        append: bool,
    ) -> None:
        self.path = path
        self.run_id = run_id
        self.secrets = secrets
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not append:
            path.write_text("", encoding="utf-8")

    def emit(self, event: str, **fields: object) -> None:
        record = {
            "timestamp": _utc_now(),
            "run_id": self.run_id,
            "event": event,
            **fields,
        }
        safe_record = _sanitize_for_output(record, secrets=self.secrets)
        encoded = json.dumps(
            safe_record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
            stream.flush()


@dataclass(frozen=True, slots=True)
class _RunIssue:
    stage: str
    error_type: str
    message: str
    provider: str | None = None
    start_slot: int | None = None
    end_slot: int | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            key: value
            for key, value in asdict(self).items()
            if value is not None
        }


def _sanitize_for_output(value: object, *, secrets: tuple[str, ...]) -> object:
    if isinstance(value, str):
        return redact_text(value, secrets=secrets)
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_for_output(item, secrets=secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_output(item, secrets=secrets) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value, secrets=secrets)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_write_json(path: Path, value: object) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_text(path, encoded)


def _stream_cross_provider_rows(
    output_dir: Path,
    findings: Iterable[CrossProviderOmission],
    *,
    epoch_schedule: EpochSchedule | None,
    checked_at: str,
    secrets: tuple[str, ...],
    run_log: _JsonlRunLog,
    provider_names: Sequence[str],
) -> tuple[int, dict[str, int]]:
    """Write both Pass-A raw files without materializing findings or rows."""

    targets = (
        output_dir / "raw-cross-provider-diff.jsonl",
        output_dir / "raw.jsonl",
    )
    temporary_pairs: list[tuple[Path, Path]] = []
    descriptors: list[int] = []
    count = 0
    by_provider = {provider: 0 for provider in provider_names}
    try:
        for target in targets:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                text=True,
            )
            descriptors.append(descriptor)
            temporary_pairs.append((Path(temporary_name), target))

        with ExitStack() as stack:
            streams = [
                stack.enter_context(os.fdopen(descriptor, "w", encoding="utf-8"))
                for descriptor in descriptors
            ]
            descriptors.clear()
            for finding in findings:
                epoch = (
                    None
                    if epoch_schedule is None
                    else epoch_schedule.epoch_for_slot(finding.slot)
                )
                row: dict[str, object] = {
                    "provider": finding.provider,
                    "slot": finding.slot,
                    "epoch": epoch,
                    "verdict": finding.verdict.value,
                    # Top level, not buried in evidence: a reader scanning rows
                    # must not be able to miss that nothing was confirmed.
                    "confirmed": False,
                    "conclusive": False,
                    "error_code": None,
                    "error_message": None,
                    "evidence": {
                        "evidence_method": "cross_provider_presence",
                        "hash_verified": False,
                        "direct_getblock_issued": False,
                        **finding.evidence,
                    },
                    "checked_at": checked_at,
                }
                safe_row = _sanitize_for_output(row, secrets=secrets)
                encoded = json.dumps(
                    safe_row,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ) + "\n"
                for stream in streams:
                    stream.write(encoded)
                count += 1
                by_provider[finding.provider] += 1
                # The raw row above is the per-decision trace. Keep run.log
                # operational rather than opening it once for every finding.
                if count % 10_000 == 0:
                    run_log.emit(
                        "cross_provider_holes_streamed",
                        count=count,
                        latest_slot=finding.slot,
                    )
            for stream in streams:
                stream.flush()
                os.fsync(stream.fileno())

        for temporary, target in temporary_pairs:
            os.replace(temporary, target)
        return count, by_provider
    except BaseException:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for temporary, _ in temporary_pairs:
            temporary.unlink(missing_ok=True)
        raise


def _validate_existing_checkpoint(
    state: CheckpointState,
    *,
    fingerprint: str,
    provider_names: tuple[str, ...],
) -> None:
    if state.config_fingerprint != fingerprint or state.providers != provider_names:
        raise CheckpointMismatch(
            "Existing checkpoint does not match this configuration; use --no-resume "
            "or a different results directory"
        )


async def run_enumeration(
    config: AuditConfig,
    results_dir: str | Path = "results",
    *,
    resume: bool = True,
    chunk_size: int = MAX_GET_BLOCKS_SLOTS,
    client_factory: ClientFactory | None = None,
) -> int:
    """Run Pass A and return a process-style status code.

    Providers enumerate concurrently, but each owns an independent RPC client,
    rate limiter, concurrency semaphore, and remaining request budget.
    """

    if not 1 <= chunk_size <= MAX_GET_BLOCKS_SLOTS:
        raise ValueError(f"chunk_size must be between 1 and {MAX_GET_BLOCKS_SLOTS}")
    output_dir = Path(results_dir)
    await anyio.Path(output_dir).mkdir(parents=True, exist_ok=True)
    provider_names = tuple(provider.name for provider in config.providers)
    secrets = url_redaction_values(provider.rpc_url for provider in config.providers)
    fingerprint = config.public_fingerprint()

    def redactor(value: object) -> str:
        return redact_text(value, secrets=secrets)

    checkpoint = CheckpointStore(output_dir, fingerprint, redact=redactor)

    existing = checkpoint.load() if resume else None
    if existing is not None:
        _validate_existing_checkpoint(
            existing,
            fingerprint=fingerprint,
            provider_names=provider_names,
        )
    resumed = existing is not None
    run_id = uuid.uuid4().hex
    run_log = _JsonlRunLog(
        output_dir / "run.log",
        run_id=run_id,
        secrets=secrets,
        append=resumed,
    )
    run_started_at = _utc_now()
    run_started_clock = time.monotonic()
    run_log.emit(
        "enumeration_started",
        pass_name="A",
        resumed=resumed,
        providers=list(provider_names),
        chunk_size=chunk_size,
    )

    base_request_counts = (
        dict(existing.request_counts)
        if existing is not None
        else {provider: 0 for provider in provider_names}
    )
    max_requests = config.limits.max_requests_per_provider
    factory = RpcClient if client_factory is None else client_factory
    clients: dict[str, _EnumerationRpcClient] = {}
    issues: list[_RunIssue] = []
    warnings: list[_RunIssue] = []
    tips: dict[str, int] = {}
    observed_tips: dict[str, int] = {}
    eligible_provider_names: set[str] = set()
    enumerations: dict[str, ProviderEnumeration] = {}
    safe_tip: int | None = None
    epoch_schedule: EpochSchedule | None = None

    async def retry_hook(event: RetryEvent) -> None:
        run_log.emit("rpc_retry", **event.as_dict())

    for provider in config.providers:
        remaining = max_requests - base_request_counts[provider.name]
        if remaining < 0:
            raise CheckpointError(
                f"Checkpoint request count exceeds the configured budget for {provider.name}"
            )
        clients[provider.name] = factory(
            provider,
            max_requests=remaining,
            retry_hook=retry_hook,
        )

    state: CheckpointState | None = existing
    start_slot: int | None = existing.start_slot if existing is not None else None
    end_slot: int | None = existing.end_slot if existing is not None else None

    def cumulative_requests(provider: str) -> int:
        return base_request_counts[provider] + clients[provider].request_count

    try:
        if existing is None:

            async def fetch_tip(provider: ProviderConfig) -> None:
                try:
                    tip = await clients[provider.name].get_slot()
                except Exception as exc:
                    issue = _issue_from_exception("get_slot", exc, redactor, provider.name)
                    issues.append(issue)
                    run_log.emit("provider_tip_failed", **issue.to_payload())
                else:
                    tips[provider.name] = tip
                    observed_tips[provider.name] = tip
                    run_log.emit("provider_tip_observed", provider=provider.name, slot=tip)

            async with anyio.create_task_group() as task_group:
                for provider in config.providers:
                    task_group.start_soon(fetch_tip, provider)

            if tips:
                safe_tip = min(tips.values()) - config.limits.tip_safety_margin_slots
                try:
                    start_slot, end_slot = config.range.resolve(safe_tip)
                except ConfigError as exc:
                    issues.append(_issue_from_exception("resolve_range", exc, redactor))
                else:
                    state = checkpoint.initialize(
                        start_slot,
                        end_slot,
                        provider_names,
                        resume=False,
                        initial_request_counts={
                            provider: cumulative_requests(provider)
                            for provider in provider_names
                        },
                        finalized_tips=tips,
                    )
                    eligible_provider_names = set(tips)
                    run_log.emit(
                        "range_resolved",
                        common_safe_tip=safe_tip,
                        start_slot=start_slot,
                        end_slot=end_slot,
                    )
            else:
                issues.append(
                    _RunIssue(
                        stage="get_slot",
                        error_type="NoUsableProvider",
                        message="No provider returned a finalized slot",
                    )
                )
        else:
            assert start_slot is not None and end_slot is not None
            state = checkpoint.initialize(
                start_slot,
                end_slot,
                provider_names,
                resume=True,
            )
            run_log.emit(
                "range_resumed",
                start_slot=start_slot,
                end_slot=end_slot,
            )
            # Refresh every provider: a backend can regress or lag between
            # processes, and a truncated successful getBlocks response must not
            # be interpreted as a provider hole.
            async def refresh_tip(provider: ProviderConfig) -> None:
                try:
                    tip = await clients[provider.name].get_slot()
                except Exception as exc:
                    issue = _issue_from_exception("get_slot", exc, redactor, provider.name)
                    issues.append(issue)
                    run_log.emit("provider_tip_failed", **issue.to_payload())
                else:
                    required_tip = end_slot + config.limits.tip_safety_margin_slots
                    observed_tips[provider.name] = tip
                    if tip < required_tip:
                        issue = _RunIssue(
                            stage="get_slot",
                            provider=provider.name,
                            error_type="ProviderBehindAuditRange",
                            message=(
                                f"Finalized tip {tip} is below required safe tip "
                                f"{required_tip}"
                            ),
                        )
                        issues.append(issue)
                        run_log.emit("provider_tip_behind", **issue.to_payload())
                    else:
                        tips[provider.name] = tip
                        eligible_provider_names.add(provider.name)
                        run_log.emit(
                            "provider_tip_observed", provider=provider.name, slot=tip
                        )
                checkpoint.update_provider_progress(
                    provider.name,
                    request_count=cumulative_requests(provider.name),
                    finalized_tip=observed_tips.get(provider.name),
                )

            async with anyio.create_task_group() as task_group:
                for provider in config.providers:
                    task_group.start_soon(refresh_tip, provider)

            if tips:
                safe_tip = min(tips.values()) - config.limits.tip_safety_margin_slots

        if state is not None:
            if state.epoch_schedule is not None:
                try:
                    epoch_schedule = EpochSchedule.from_rpc(state.epoch_schedule)
                except ValueError as exc:
                    raise CheckpointError("Checkpoint epoch schedule is invalid") from exc
            else:
                # The epoch schedule is a network-wide constant. Try providers in
                # config order until one returns a valid value, persisting it so a
                # resumed run does not spend another request.
                schedule_failures: list[_RunIssue] = []
                for provider in config.providers:
                    if provider.name not in eligible_provider_names:
                        continue
                    try:
                        raw_schedule = await clients[provider.name].get_epoch_schedule()
                        candidate = EpochSchedule.from_rpc(raw_schedule)
                    except Exception as exc:
                        issue = _issue_from_exception(
                            "get_epoch_schedule", exc, redactor, provider.name
                        )
                        schedule_failures.append(issue)
                        run_log.emit("epoch_schedule_failed", **issue.to_payload())
                        checkpoint.update_provider_progress(
                            provider.name,
                            request_count=cumulative_requests(provider.name),
                        )
                        continue
                    epoch_schedule = candidate
                    normalized_schedule: dict[str, int | bool] = {
                        "slotsPerEpoch": candidate.slots_per_epoch,
                        "leaderScheduleSlotOffset": candidate.leader_schedule_slot_offset,
                        "warmup": candidate.warmup,
                        "firstNormalEpoch": candidate.first_normal_epoch,
                        "firstNormalSlot": candidate.first_normal_slot,
                    }
                    checkpoint.update_provider_progress(
                        provider.name,
                        request_count=cumulative_requests(provider.name),
                    )
                    checkpoint.set_epoch_schedule(normalized_schedule)
                    run_log.emit("epoch_schedule_loaded", provider=provider.name)
                    break
                if epoch_schedule is None:
                    issues.extend(schedule_failures)
                    issues.append(
                        _RunIssue(
                            stage="get_epoch_schedule",
                            error_type="NoEpochSchedule",
                            message="No provider returned a valid epoch schedule",
                        )
                    )
                else:
                    # Earlier providers failing this global lookup is observable,
                    # but does not make their independent enumeration partial.
                    warnings.extend(schedule_failures)

        if state is not None and start_slot is not None and end_slot is not None:

            async def enumerate_one(provider: ProviderConfig) -> None:
                client = clients[provider.name]
                # Retention can advance between processes. Refresh it on every
                # run before trusting cached absence; stale retention is a common
                # source of false provider-hole findings.
                try:
                    observed_first_available = await client.get_first_available_block()
                except Exception as exc:
                    issue = _issue_from_exception(
                        "get_first_available_block", exc, redactor, provider.name
                    )
                    issues.append(issue)
                    run_log.emit("provider_enumeration_failed", **issue.to_payload())
                    checkpoint.update_provider_progress(
                        provider.name,
                        request_count=cumulative_requests(provider.name),
                    )
                    return
                # A retention boundary should only advance. Preserve the larger
                # checkpointed value if a replacement backend reports a stale
                # or inconsistent lower boundary.
                first_available = max(
                    observed_first_available,
                    state.first_available_blocks.get(provider.name, 0),
                )
                checkpoint.update_provider_progress(
                    provider.name,
                    request_count=cumulative_requests(provider.name),
                    first_available_block=first_available,
                )

                def resumed_chunks() -> Iterator[ChunkEnumeration]:
                    for saved in checkpoint.iter_chunks_for_provider(
                        provider.name, successful_only=True
                    ):
                        # Conversion immediately packs Python JSON ints into an
                        # array('Q'); the SavedChunk can then be released.
                        yield ChunkEnumeration.success(
                            saved.provider,
                            saved.start_slot,
                            saved.end_slot,
                            saved.present_slots,
                        )

                def on_chunk(chunk: ChunkEnumeration) -> None:
                    error = None
                    if chunk.failed:
                        error = f"{chunk.error_type}: {redactor(chunk.error_message)}"
                    checkpoint.record_chunk(
                        provider.name,
                        chunk.slot_range.start,
                        chunk.slot_range.end,
                        chunk.present_slots,
                        error=error,
                        request_count=cumulative_requests(provider.name),
                    )
                    run_log.emit(
                        "enumeration_chunk_completed",
                        provider=provider.name,
                        start_slot=chunk.slot_range.start,
                        end_slot=chunk.slot_range.end,
                        status="succeeded" if chunk.succeeded else "failed",
                        present_slots=len(chunk.present_slots),
                        error_type=chunk.error_type,
                        error_message=(
                            None if chunk.error_message is None else redactor(chunk.error_message)
                        ),
                        cumulative_requests=cumulative_requests(provider.name),
                    )

                try:
                    result = await enumerate_provider(
                        client,
                        provider.name,
                        start_slot,
                        end_slot,
                        chunk_size=chunk_size,
                        on_chunk=on_chunk,
                        resume_chunks=resumed_chunks(),
                        first_available_block=first_available,
                    )
                except Exception as exc:
                    issue = _issue_from_exception("enumerate", exc, redactor, provider.name)
                    issues.append(issue)
                    run_log.emit("provider_enumeration_failed", **issue.to_payload())
                else:
                    # Retention may advance while a long enumeration is running.
                    # A second probe prevents a silently truncated final chunk
                    # from becoming false cross-provider holes.
                    try:
                        postflight_first_available = (
                            await client.get_first_available_block()
                        )
                    except Exception as exc:
                        issue = _issue_from_exception(
                            "get_first_available_block_postflight",
                            exc,
                            redactor,
                            provider.name,
                        )
                        issues.append(issue)
                        run_log.emit(
                            "provider_postflight_retention_failed",
                            **issue.to_payload(),
                        )
                        return
                    effective_first_available = max(
                        first_available, postflight_first_available
                    )
                    result = apply_retention_boundary(
                        result, effective_first_available
                    )
                    checkpoint.update_provider_progress(
                        provider.name,
                        request_count=cumulative_requests(provider.name),
                        first_available_block=effective_first_available,
                    )
                    enumerations[provider.name] = result
                    for chunk in result.failed_chunks:
                        issue = _RunIssue(
                            stage="get_blocks",
                            provider=provider.name,
                            start_slot=chunk.slot_range.start,
                            end_slot=chunk.slot_range.end,
                            error_type=chunk.error_type or "UnknownError",
                            message=redactor(chunk.error_message or "Chunk failed"),
                        )
                        issues.append(issue)
                    run_log.emit(
                        "provider_enumeration_completed",
                        provider=provider.name,
                        present_slots=len(result.present_slots),
                        candidate_gaps=result.candidate_gap_count,
                        failed_chunks=len(result.failed_chunks),
                    )
                finally:
                    checkpoint.update_provider_progress(
                        provider.name,
                        request_count=cumulative_requests(provider.name),
                    )

            async with anyio.create_task_group() as task_group:
                for provider in config.providers:
                    if provider.name in eligible_provider_names:
                        task_group.start_soon(enumerate_one, provider)
    finally:

        async def close_client(provider: str, client: _EnumerationRpcClient) -> None:
            try:
                await client.aclose()
            except Exception as exc:
                issue = _issue_from_exception("close", exc, redactor, provider)
                warnings.append(issue)
                run_log.emit("provider_close_failed", **issue.to_payload())

        async with anyio.create_task_group() as task_group:
            for name, client in clients.items():
                task_group.start_soon(close_client, name, client)

    ordered_enumerations = [
        enumerations[name] for name in provider_names if name in enumerations
    ]
    checked_at = _utc_now()
    hole_count, holes_by_provider = _stream_cross_provider_rows(
        output_dir,
        iter_cross_provider_holes(ordered_enumerations),
        epoch_schedule=epoch_schedule,
        checked_at=checked_at,
        secrets=secrets,
        run_log=run_log,
        provider_names=provider_names,
    )

    usable = any(result.audited_slot_count > 0 for result in ordered_enumerations)
    limitations: list[str] = []
    tip_excluded = len(provider_names) - len(eligible_provider_names)
    if tip_excluded:
        limitations.append(
            f"{tip_excluded} provider(s) were excluded because no sufficiently safe "
            "finalized tip was available."
        )
    incomplete_eligible = len(eligible_provider_names) - len(ordered_enumerations)
    if incomplete_eligible:
        limitations.append(
            f"{incomplete_eligible} tip-safe provider(s) did not complete trustworthy "
            "enumeration."
        )
    if hole_count:
        limitations.append(
            f"{hole_count} cross-provider omission(s) were observed. Pass A issues no "
            "direct getBlock and obtains no explicit denial, so none of them is a "
            "confirmed provider data hole; silent response truncation by a gateway "
            "produces an identical signature. Confirm with the single-epoch audit "
            "before attributing data loss to any provider."
        )
    if epoch_schedule is None and hole_count:
        limitations.append(
            "Epoch attribution is unavailable because no valid epoch schedule was returned; "
            "hole evidence is retained with epoch set to null."
        )
    indeterminate_rates: dict[str, Fraction] = {}
    for result in ordered_enumerations:
        in_retention_scope = result.audited_slot_count + result.failed_slot_count
        rate = (
            Fraction(result.failed_slot_count, in_retention_scope)
            if in_retention_scope
            else Fraction(0)
        )
        indeterminate_rates[result.provider] = rate
        if rate > Fraction(INDETERMINATE_TRUST_THRESHOLD):
            limitations.append(
                f"{result.provider} has {result.failed_slot_count} INDETERMINATE slots "
                f"({rate.numerator}/{rate.denominator} of its in-retention range), "
                f"exceeding the {INDETERMINATE_TRUST_THRESHOLD} threshold; "
                "this run is not trustworthy."
            )
    if usable and not _has_overlapping_successful_coverage(ordered_enumerations):
        limitation = (
            "Fewer than two providers have overlapping successful coverage; "
            "Pass A cannot establish cross-provider holes for this run."
        )
        limitations.append(limitation)
        issues.append(
            _RunIssue(
                stage="cross_provider_diff",
                error_type="InsufficientComparableProviders",
                message=limitation,
            )
        )
    if not usable:
        status = "failed"
        exit_code = EXIT_FAILED
    elif issues:
        status = "partial"
        exit_code = EXIT_PARTIAL
    else:
        status = "complete"
        exit_code = EXIT_COMPLETE
    trustworthy = status == "complete" and all(
        rate <= Fraction(INDETERMINATE_TRUST_THRESHOLD)
        for rate in indeterminate_rates.values()
    )

    provider_summaries: list[dict[str, object]] = []
    for provider in config.providers:
        result = enumerations.get(provider.name)
        total_requests = cumulative_requests(provider.name)
        summary: dict[str, object] = {
            "provider": provider.name,
            "archive": provider.archive,
            "status": "unavailable" if result is None else "complete",
            "total_requests": total_requests,
            "requests_this_invocation": clients[provider.name].request_count,
            "remaining_request_budget": max(0, max_requests - total_requests),
            "unconfirmed_omissions": holes_by_provider[provider.name],
            "observed_finalized_tip": observed_tips.get(provider.name),
            "tip_safe_for_range": provider.name in eligible_provider_names,
        }
        if result is not None:
            summary.update(
                {
                    "status": "partial" if result.failed_chunks else "complete",
                    "first_available_block": result.first_available_block,
                    "slots_requested": result.requested_range.count,
                    "slots_audited": result.audited_slot_count,
                    "present": len(result.present_slots),
                    "candidate_gaps": result.candidate_gap_count,
                    "before_retention": result.before_retention_slot_count,
                    "indeterminate": result.failed_slot_count,
                    "indeterminate_rate": float(indeterminate_rates[result.provider]),
                    "indeterminate_rate_exact": (
                        f"{indeterminate_rates[result.provider].numerator}/"
                        f"{indeterminate_rates[result.provider].denominator}"
                    ),
                    "indeterminate_exceeds_threshold": (
                        indeterminate_rates[result.provider]
                        > Fraction(INDETERMINATE_TRUST_THRESHOLD)
                    ),
                    "failed_chunks": [
                        {
                            "start_slot": chunk.slot_range.start,
                            "end_slot": chunk.slot_range.end,
                            "error_type": chunk.error_type,
                            "error_message": redactor(chunk.error_message),
                        }
                        for chunk in result.failed_chunks
                    ],
                }
            )
        provider_summaries.append(summary)

    summary_payload: dict[str, object] = {
        "schema_version": 1,
        "pass": "A",
        "status": status,
        "trustworthy": trustworthy,
        "indeterminate_trust_threshold": str(INDETERMINATE_TRUST_THRESHOLD),
        "run_id": run_id,
        "started_at": run_started_at,
        "completed_at": checked_at,
        "wall_clock_seconds": round(time.monotonic() - run_started_clock, 6),
        "resumed": resumed,
        "range": (
            None
            if start_slot is None or end_slot is None
            else {
                "mode": config.range.mode,
                "start_slot": start_slot,
                "end_slot": end_slot,
                "slot_count": end_slot - start_slot + 1,
                "common_safe_tip": safe_tip,
                "tip_safety_margin_slots": config.limits.tip_safety_margin_slots,
            }
        ),
        "observed_finalized_tips": dict(sorted(observed_tips.items())),
        "chunk_size": chunk_size,
        "providers": provider_summaries,
        "total_requests": sum(cumulative_requests(name) for name in provider_names),
        "requests_this_invocation": sum(
            client.request_count for client in clients.values()
        ),
        "unconfirmed_omissions": hole_count,
        "partial_errors": [
            issue.to_payload()
            for issue in sorted(issues, key=_issue_sort_key)
        ],
        "warnings": [
            warning.to_payload()
            for warning in sorted(warnings, key=_issue_sort_key)
        ],
        "limitations": limitations,
        "outputs": {
            "raw": "raw.jsonl",
            "cross_provider_diff": "raw-cross-provider-diff.jsonl",
            "checkpoint": ".checkpoint.json",
            "log": "run.log",
        },
    }
    sanitized_summary = _sanitize_for_output(summary_payload, secrets=secrets)
    _atomic_write_json(output_dir / "enumeration-summary.json", sanitized_summary)
    run_log.emit(
        "enumeration_completed",
        status=status,
        exit_code=exit_code,
        unconfirmed_omissions=hole_count,
        total_requests=summary_payload["total_requests"],
    )
    return exit_code


def _issue_from_exception(
    stage: str,
    error: Exception,
    redact: Callable[[object], str],
    provider: str | None = None,
) -> _RunIssue:
    return _RunIssue(
        stage=stage,
        provider=provider,
        error_type=type(error).__name__,
        message=redact(error),
    )


def _issue_sort_key(issue: _RunIssue) -> tuple[object, ...]:
    return (
        issue.provider or "",
        issue.stage,
        -1 if issue.start_slot is None else issue.start_slot,
        -1 if issue.end_slot is None else issue.end_slot,
        issue.error_type,
        issue.message,
    )


def _has_overlapping_successful_coverage(
    enumerations: Sequence[ProviderEnumeration],
) -> bool:
    for left_index, left in enumerate(enumerations):
        for right in enumerations[left_index + 1 :]:
            left_range_index = 0
            right_range_index = 0
            while (
                left_range_index < len(left.successful_ranges)
                and right_range_index < len(right.successful_ranges)
            ):
                left_range = left.successful_ranges[left_range_index]
                right_range = right.successful_ranges[right_range_index]
                if max(left_range.start, right_range.start) <= min(
                    left_range.end, right_range.end
                ):
                    return True
                if left_range.end < right_range.end:
                    left_range_index += 1
                else:
                    right_range_index += 1
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solana-slot-audit",
        description="Evidence-focused Solana RPC slot auditing",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    enumerate_parser = subparsers.add_parser(
        "enumerate",
        help="run Pass A getBlocks enumeration and cross-provider comparison",
    )
    enumerate_parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="YAML configuration path (default: config.yaml)",
    )
    enumerate_parser.add_argument(
        "--results-dir",
        "--results",
        "-o",
        default="results",
        help="output directory (default: results)",
    )
    enumerate_parser.add_argument(
        "--chunk-size",
        type=int,
        default=MAX_GET_BLOCKS_SLOTS,
        help=f"inclusive getBlocks chunk size (1-{MAX_GET_BLOCKS_SLOTS})",
    )
    enumerate_parser.add_argument(
        "--no-resume",
        action="store_true",
        help="start a fresh checkpoint in the selected results directory",
    )

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
    if args.command == "audit":
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
    try:
        config = load_config(args.config)
        operation = partial(
            run_enumeration,
            config,
            args.results_dir,
            resume=not args.no_resume,
            chunk_size=args.chunk_size,
        )
        exit_code = anyio.run(operation, backend="asyncio")
    except (ConfigError, CheckpointError, ValueError) as exc:
        # ConfigError is already guaranteed not to include expanded values. Other
        # expected errors contain only paths, provider names, and numeric state.
        print(f"error: {exc}")
        return EXIT_FAILED
    print(f"Pass A finished with status code {exit_code}; see {args.results_dir}")
    return exit_code


__all__ = [
    "EXIT_COMPLETE",
    "EXIT_FAILED",
    "EXIT_PARTIAL",
    "build_parser",
    "main",
    "run_enumeration",
    "probe_car_command",
    "replay_command",
    "run_epoch_audit_command",
    "verify_evidence_command",
]
