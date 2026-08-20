"""An evidence-recording JSON-RPC client over an injectable transport.

Two things separate this from :mod:`slot_audit.rpc`.  First, the *bytes* of
every response are retained before anything is parsed, so a finding can point at
what the provider actually said rather than at a re-serialized summary of it.
Second, the transport is a parameter.  The shipped negative controls therefore
drive the same client, the same envelope parsing and the same collection code as
a live run -- only the socket is different.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .evidence import CallEvidence, EvidenceRef, EvidenceStore, utc_now
from .ratelimit import TokenBucket
from .solana_codes import is_retryable

FINALIZED = "finalized"
TOKEN_ACCOUNT_ENCODING = "base64"

#: The audit never retries more than this, whatever a caller asks for. An
#: unbounded retry turns a provider outage into an arbitrarily long run whose
#: coverage nobody can characterise.
MAX_RETRIES = 3


class TransportError(RuntimeError):
    """The request could not be completed at the transport level."""


class RequestBudgetExhausted(RuntimeError):
    """The per-provider hard request budget was spent; no request was sent."""

    def __init__(self, provider: str, limit: int) -> None:
        self.provider = provider
        self.limit = limit
        super().__init__(
            f"request budget of {limit} exhausted for provider {provider!r}"
        )


class RpcCallError(RuntimeError):
    """A JSON-RPC error, or a malformed envelope, from a recorded call."""

    def __init__(self, message: str, *, code: int | None = None) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status_code: int
    body: bytes


class RpcTransport(Protocol):
    """The single seam between the audit and the network."""

    async def post(self, url: str, payload: Mapping[str, object]) -> TransportResponse: ...

    async def aclose(self) -> None: ...


class HttpxTransport:
    """The live transport.  It performs no retries and no interpretation."""

    def __init__(self, *, timeout: float = 60.0, transport: object | None = None) -> None:
        import httpx

        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)  # type: ignore[arg-type]

    async def post(self, url: str, payload: Mapping[str, object]) -> TransportResponse:
        import httpx

        try:
            response = await self._client.post(url, json=dict(payload))
        except httpx.HTTPError as exc:
            raise TransportError(f"transport failure: {type(exc).__name__}") from None
        return TransportResponse(status_code=response.status_code, body=response.content)

    async def aclose(self) -> None:
        await self._client.aclose()


class ScriptedTransport:
    """A deterministic offline transport backed by a plain Python handler.

    The handler returns the ``result`` half of a JSON-RPC envelope, or raises
    :class:`ScriptedRpcError` to produce an ``error`` half.  Everything else --
    envelope construction, byte encoding, status codes -- happens exactly as it
    would on the wire, so parsing and evidence capture are genuinely exercised.
    """

    def __init__(
        self,
        handler: Callable[[str, str, list[Any]], Any],
        *,
        status_code: int = 200,
    ) -> None:
        self._handler = handler
        self._status_code = status_code
        self.requests: list[tuple[str, str, list[Any]]] = []
        self.closed = False

    async def post(self, url: str, payload: Mapping[str, object]) -> TransportResponse:
        method = str(payload.get("method", ""))
        params = list(payload.get("params", []) or [])
        self.requests.append((url, method, params))
        envelope: dict[str, Any] = {"jsonrpc": "2.0", "id": payload.get("id", 1)}
        try:
            envelope["result"] = self._handler(url, method, params)
        except ScriptedRpcError as error:
            envelope["error"] = {"code": error.code, "message": error.message}
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return TransportResponse(status_code=self._status_code, body=body)

    async def aclose(self) -> None:
        self.closed = True


class ScriptedRpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class RecordedCall:
    """A completed call together with the evidence that proves it happened.

    ``evidence`` is the attempt whose answer the audit used. ``attempt_evidence``
    holds every attempt including the retried ones: a run that retried four
    times before succeeding is a different observation from one that succeeded
    immediately, and the record has to be able to show which happened.
    """

    method: str
    provider: str
    result: Any
    evidence: CallEvidence
    error_code: int | None = None
    error_message: str | None = None
    attempt_evidence: tuple[CallEvidence, ...] = ()

    @property
    def raw_ref(self) -> EvidenceRef:
        return self.evidence.raw

    @property
    def request_ref(self) -> EvidenceRef:
        return self.evidence.request

    @property
    def attempts(self) -> int:
        return max(1, len(self.attempt_evidence))

    @property
    def retried(self) -> bool:
        return self.attempts > 1

    @property
    def failed(self) -> bool:
        return self.error_code is not None or self.error_message is not None

    def refs(self) -> tuple[EvidenceRef, ...]:
        return (self.evidence.raw, self.evidence.request)

    def all_refs(self) -> tuple[EvidenceRef, ...]:
        refs: list[EvidenceRef] = []
        for attempt in self.attempt_evidence or (self.evidence,):
            refs.extend((attempt.raw, attempt.request))
        return tuple(refs)


class AuditRpcClient:
    """Issue audit RPC calls, retaining raw bytes for every one of them.

    Policy lives here rather than in the orchestration because all three of its
    concerns change what a run may claim. A rate limiter keeps a 400,000-call
    epoch from being throttled into a wall of false indeterminates; a bounded
    retry keeps one transient ``-32005`` from being recorded as missing data; a
    hard budget keeps a runaway loop from quietly spending someone's quota.
    Every attempt is retained, so retries are visible rather than smoothed away.

    **Calls are issued one at a time, by design.** This tool is rate-limited, not
    latency-bound, so concurrency would buy little; and it would cost two things
    the instrument actually argues from. The evidence store's write order is what
    demonstrates that the provider-only inference was frozen before the anchor
    was read, and interleaved writes would blur it. Replay matches recorded
    responses to requests in order, so deterministic sequencing is what makes
    that matching sound rather than lucky. There is deliberately no semaphore.
    """

    def __init__(
        self,
        *,
        provider: str,
        url: str,
        endpoint_fingerprint: str,
        transport: RpcTransport,
        evidence: EvidenceStore,
        commitment: str = FINALIZED,
        clock: Callable[[], str] = utc_now,
        rps: float | None = None,
        max_requests: int | None = None,
        max_retries: int = MAX_RETRIES,
        backoff_base: float = 0.25,
        backoff_cap: float = 8.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        random_source: random.Random | None = None,
    ) -> None:
        if not provider:
            raise ValueError("provider name must not be empty")
        if not url:
            raise ValueError("provider URL must not be empty")
        if not 0 <= max_retries <= MAX_RETRIES:
            raise ValueError(f"max_retries must be between 0 and {MAX_RETRIES}")
        if max_requests is not None and max_requests < 1:
            raise ValueError("max_requests must be at least one when set")
        if rps is not None and rps <= 0:
            raise ValueError("rps must be greater than zero when set")
        self.provider = provider
        self.commitment = commitment
        self.max_requests = max_requests
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self._url = url
        self._fingerprint = endpoint_fingerprint
        self._transport = transport
        self._evidence = evidence
        self._clock = clock
        self._sleep = sleep
        self._random = random_source or random.Random(0)
        self._bucket = (
            None if rps is None else TokenBucket(rps, sleep=sleep, clock=monotonic)
        )
        self._next_id = 1
        self.call_count = 0
        self.attempt_count = 0
        self.retry_count = 0
        self.budget_exhausted = False

    @property
    def budget_remaining(self) -> int | None:
        if self.max_requests is None:
            return None
        return max(0, self.max_requests - self.attempt_count)

    async def aclose(self) -> None:
        await self._transport.aclose()

    def _retry_delay(self, retry_number: int) -> float:
        exponential = min(self.backoff_cap, self.backoff_base * 2 ** (retry_number - 1))
        # Equal jitter: an exponential floor without synchronized retry waves.
        return exponential * (0.5 + self._random.random() / 2.0)

    async def call(self, method: str, params: Sequence[object]) -> RecordedCall:
        """Send one logical call, retrying bounded and retaining every attempt."""

        self.call_count += 1
        attempts: list[CallEvidence] = []
        outcome: RecordedCall | None = None

        for attempt in range(1, self.max_retries + 2):
            if self.max_requests is not None and self.attempt_count >= self.max_requests:
                self.budget_exhausted = True
                evidence = self._record_synthetic(
                    method,
                    params,
                    payload={
                        "budget_exhausted": True,
                        "limit": self.max_requests,
                        "attempts_sent": self.attempt_count,
                    },
                    error=str(RequestBudgetExhausted(self.provider, self.max_requests)),
                )
                attempts.append(evidence)
                return RecordedCall(
                    method=method,
                    provider=self.provider,
                    result=None,
                    evidence=evidence,
                    error_message=str(
                        RequestBudgetExhausted(self.provider, self.max_requests)
                    ),
                    attempt_evidence=tuple(attempts),
                )

            outcome, retryable = await self._attempt(method, params)
            attempts.append(outcome.evidence)
            if not retryable or attempt > self.max_retries:
                break
            self.retry_count += 1
            await self._sleep(self._retry_delay(attempt))

        assert outcome is not None
        return RecordedCall(
            method=outcome.method,
            provider=outcome.provider,
            result=outcome.result,
            evidence=outcome.evidence,
            error_code=outcome.error_code,
            error_message=outcome.error_message,
            attempt_evidence=tuple(attempts),
        )

    def _record_synthetic(
        self,
        method: str,
        params: Sequence[object],
        *,
        payload: Mapping[str, object],
        error: str,
    ) -> CallEvidence:
        """Retain a decision that produced no request, so the gap is explicable."""

        moment = self._clock()
        body = json.dumps(
            {"method": method, **dict(payload)}, sort_keys=True
        ).encode("utf-8")
        return self._evidence.record_call(
            provider=self.provider,
            method=method,
            params=list(params),
            endpoint_fingerprint=self._fingerprint,
            raw_response=body,
            http_status=0,
            started_at=moment,
            completed_at=moment,
            error=error,
        )

    async def _attempt(
        self, method: str, params: Sequence[object]
    ) -> tuple[RecordedCall, bool]:
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": list(params),
        }
        if self._bucket is not None:
            await self._bucket.acquire()
        self.attempt_count += 1
        started_at = self._clock()
        try:
            response = await self._transport.post(self._url, payload)
        except TransportError as exc:
            evidence = self._record_synthetic(
                method,
                params,
                payload={"transport_error": str(exc)},
                error=str(exc),
            )
            return (
                RecordedCall(
                    method=method,
                    provider=self.provider,
                    result=None,
                    evidence=evidence,
                    error_message=str(exc),
                ),
                True,
            )
        completed_at = self._clock()

        result: Any = None
        error_code: int | None = None
        error_message: str | None = None
        retryable = False
        envelope: Any = None
        try:
            envelope = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            error_message = "response body is not valid JSON"
        if error_message is None:
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                error_message = f"HTTP {response.status_code}"
                retryable = True
            elif not 200 <= response.status_code <= 299:
                error_message = f"HTTP {response.status_code}"
            elif not isinstance(envelope, dict):
                error_message = "JSON-RPC response is not an object"
            elif envelope.get("error") is not None:
                raw_error = envelope["error"]
                if isinstance(raw_error, dict):
                    code = raw_error.get("code")
                    error_code = code if isinstance(code, int) else None
                    error_message = str(raw_error.get("message", "RPC error"))
                    retryable = is_retryable(error_code)
                else:
                    error_message = "JSON-RPC error object is malformed"
            elif "result" not in envelope:
                error_message = "JSON-RPC response has neither result nor error"
            else:
                result = envelope["result"]

        evidence = self._evidence.record_call(
            provider=self.provider,
            method=method,
            params=list(params),
            endpoint_fingerprint=self._fingerprint,
            raw_response=response.body,
            http_status=response.status_code,
            started_at=started_at,
            completed_at=completed_at,
            error=error_message,
        )
        return (
            RecordedCall(
                method=method,
                provider=self.provider,
                result=result,
                evidence=evidence,
                error_code=error_code,
                error_message=error_message,
            ),
            retryable,
        )

    # -- typed wrappers -----------------------------------------------------

    async def get_version(self) -> RecordedCall:
        return await self.call("getVersion", [])

    async def get_blocks(self, start_slot: int, end_slot: int) -> RecordedCall:
        if end_slot < start_slot:
            raise ValueError("end_slot must not precede start_slot")
        return await self.call(
            "getBlocks", [start_slot, end_slot, {"commitment": self.commitment}]
        )

    async def get_block(self, slot: int) -> RecordedCall:
        return await self.call(
            "getBlock",
            [
                slot,
                {
                    "commitment": self.commitment,
                    "transactionDetails": "none",
                    "rewards": False,
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )

    async def get_account_info(self, pubkey: str, *, min_context_slot: int) -> RecordedCall:
        return await self.call(
            "getAccountInfo",
            [
                pubkey,
                {
                    "commitment": self.commitment,
                    "encoding": TOKEN_ACCOUNT_ENCODING,
                    "minContextSlot": min_context_slot,
                },
            ],
        )

    async def get_program_accounts(
        self,
        program_id: str,
        *,
        mint: str,
        account_size: int,
        mint_offset: int,
        min_context_slot: int,
    ) -> RecordedCall:
        return await self.call(
            "getProgramAccounts",
            [
                program_id,
                {
                    "commitment": self.commitment,
                    "encoding": TOKEN_ACCOUNT_ENCODING,
                    "withContext": True,
                    "minContextSlot": min_context_slot,
                    "filters": [
                        {"dataSize": account_size},
                        {"memcmp": {"offset": mint_offset, "bytes": mint}},
                    ],
                },
            ],
        )


__all__ = [
    "FINALIZED",
    "MAX_RETRIES",
    "RequestBudgetExhausted",
    "AuditRpcClient",
    "HttpxTransport",
    "RecordedCall",
    "RpcCallError",
    "RpcTransport",
    "ScriptedRpcError",
    "ScriptedTransport",
    "TransportError",
    "TransportResponse",
]
