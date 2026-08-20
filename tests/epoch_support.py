"""Shared deterministic-offline scaffolding for the epoch-audit tests.

Everything here composes the *production* entry points. The only thing the tests
substitute is the transport, which is exactly the seam the instrument declares.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from slot_audit.audit import AuditRun, run_epoch_audit
from slot_audit.config import EpochAuditConfig, ResolvedProvider, ThresholdConfig
from slot_audit.evidence import EvidenceStore
from slot_audit.groundtruth import CarBlockHeaderExtractor
from slot_audit.negative_controls import (
    LedgerDefects,
    SimulatedEpoch,
    SimulatedProviderLedger,
    build_control_config,
    build_simulated_epoch,
    control_token_scope,
    resolve_control_config,
)
from slot_audit.transport import AuditRpcClient, ScriptedTransport

Handler = Callable[[str, str, list[Any]], Any]
HandlerWrapper = Callable[[Handler], Handler]


def with_thresholds(config: EpochAuditConfig, **overrides: str) -> EpochAuditConfig:
    """Return the same configuration with different exact-decimal thresholds."""

    current = config.thresholds.model_dump()
    current.update(
        {key: value for key, value in overrides.items() if value is not None}
    )
    return config.model_copy(update={"thresholds": ThresholdConfig(**current)})


def _materialize(
    directory: Path,
    epoch: SimulatedEpoch,
    *,
    car_bytes: bytes | None,
    write_car: bool,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    car_path = directory / f"epoch-{epoch.spec.epoch}.car"
    if write_car:
        car_path.write_bytes(epoch.car_bytes if car_bytes is None else car_bytes)
    return car_path


async def run_audit(
    *,
    directory: Path,
    epoch: SimulatedEpoch | None = None,
    defects: Mapping[str, LedgerDefects] | None = None,
    handler_wrappers: Mapping[str, HandlerWrapper] | None = None,
    config: EpochAuditConfig | None = None,
    chunk_size: int | None = None,
    car_bytes: bytes | None = None,
    write_car: bool = True,
    run_negative_controls: bool = False,
    negative_controls: object = None,
    provider_urls: tuple[str, str] | None = None,
    resolved_sink: list | None = None,
) -> AuditRun:
    """Run the production audit over a fixture epoch with injectable defects."""

    epoch = epoch or build_simulated_epoch()
    car_path = _materialize(
        directory, epoch, car_bytes=car_bytes, write_car=write_car
    )
    model = config or build_control_config(epoch)
    resolved = (
        resolve_control_config(model, car_path=car_path, urls=provider_urls)
        if provider_urls is not None
        else resolve_control_config(model, car_path=car_path)
    )
    if resolved_sink is not None:
        resolved_sink.append(resolved)
    scope = control_token_scope()
    wrappers = dict(handler_wrappers or {})
    ledgers = {
        provider.name: SimulatedProviderLedger(
            epoch, scope=scope, defects=(defects or {}).get(provider.name, LedgerDefects())
        )
        for provider in resolved.providers
    }
    evidence = EvidenceStore(directory / "evidence")

    def client_factory(provider: ResolvedProvider) -> AuditRpcClient:
        handler: Handler = ledgers[provider.name].handle
        wrapper = wrappers.get(provider.name)
        if wrapper is not None:
            handler = wrapper(handler)
        return AuditRpcClient(
            provider=provider.name,
            url=provider.rpc_url,
            endpoint_fingerprint=provider.endpoint_fingerprint,
            transport=ScriptedTransport(handler),
            evidence=evidence,
            max_requests=model.limits.max_requests_per_provider,
            max_retries=model.limits.max_retries,
            backoff_base=0.0,
        )

    return await run_epoch_audit(
        resolved,
        evidence=evidence,
        client_factory=client_factory,
        results_dir=directory,
        spec=epoch.spec,
        extractor=CarBlockHeaderExtractor(source_commit=epoch.spec.source_commit),
        negative_controls=negative_controls,
        run_negative_controls=run_negative_controls,
        chunk_size=chunk_size or epoch.spec.scheduled_slot_positions,
    )


def realistic_noise(
    *, seed: int, failure_rate: float = 0.08, unhealthy_rate: float = 0.05
) -> HandlerWrapper:
    """Inject retryable faults the way a real endpoint would, deterministically.

    Three defects in a row got through review because every fixture answered
    perfectly on the first attempt: the conclusive-FINDINGS path was untestable,
    the constants gate had no FAIL path, and replay could not survive a single
    transient blip. The fixtures were not wrong, they were *tidy*, and a tidy
    fixture only exercises the path its author already had in mind.

    This wrapper makes a share of calls fail in ways the transport is supposed to
    absorb -- a dropped connection, an unhealthy node -- so that an end-to-end
    test which passes has passed against a messy run rather than an ideal one.
    The seed is fixed, so failures land in the same places on every machine.
    """

    import random as _random

    from slot_audit.transport import ScriptedRpcError, TransportError

    if not 0.0 <= failure_rate + unhealthy_rate < 1.0:
        raise ValueError("combined failure rates must leave room for success")

    def wrapper(handler: Handler) -> Handler:
        rng = _random.Random(seed)

        def wrapped(url: str, method: str, params: list[Any]) -> Any:
            roll = rng.random()
            if roll < failure_rate:
                raise TransportError("simulated connection reset")
            if roll < failure_rate + unhealthy_rate:
                raise ScriptedRpcError(-32005, "Node is unhealthy")
            return handler(url, method, params)

        return wrapped

    return wrapper


def failing_get_blocks(slot: int) -> HandlerWrapper:
    """Make exactly the one-slot ``getBlocks`` chunk covering ``slot`` fail."""

    from slot_audit.transport import ScriptedRpcError

    def wrapper(handler: Handler) -> Handler:
        def wrapped(url: str, method: str, params: list[Any]) -> Any:
            if method == "getBlocks" and int(params[0]) <= slot <= int(params[1]):
                raise ScriptedRpcError(-32005, "Node is unhealthy")
            return handler(url, method, params)

        return wrapped

    return wrapper


def get_block_answers(slot: int, answer: Any) -> HandlerWrapper:
    """Replace one slot's ``getBlock`` answer.

    ``answer`` may be a value to return (including ``None``) or a
    :class:`ScriptedRpcError` to raise, so a test can distinguish "the provider
    said there is no block" from "we never got an answer".
    """

    from slot_audit.transport import ScriptedRpcError

    def wrapper(handler: Handler) -> Handler:
        def wrapped(url: str, method: str, params: list[Any]) -> Any:
            if method == "getBlock" and int(params[0]) == slot:
                if isinstance(answer, ScriptedRpcError):
                    raise answer
                return answer
            return handler(url, method, params)

        return wrapped

    return wrapper


def inexact_context(slot: int) -> HandlerWrapper:
    """Answer token queries at a different context slot than the pinned one."""

    def wrapper(handler: Handler) -> Handler:
        def wrapped(url: str, method: str, params: list[Any]) -> Any:
            result = handler(url, method, params)
            if method in {"getProgramAccounts", "getAccountInfo"} and isinstance(
                result, dict
            ):
                result = dict(result)
                result["context"] = {**result.get("context", {}), "slot": slot}
            return result

        return wrapped

    return wrapper


__all__ = [
    "Handler",
    "HandlerWrapper",
    "build_simulated_epoch",
    "failing_get_blocks",
    "get_block_answers",
    "inexact_context",
    "realistic_noise",
    "run_audit",
    "with_thresholds",
]
