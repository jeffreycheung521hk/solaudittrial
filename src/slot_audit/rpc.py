"""Async, rate-limited Solana JSON-RPC client.

The audit deliberately keeps transport concerns in this module.  In particular,
an RPC answer from an unhealthy node is *never* converted into an audit verdict:
retryable failures leave this layer as typed exceptions after the retry budget is
exhausted.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import random
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Protocol, TypeAlias

import httpx

from .config import ProviderConfig
from .solana_codes import RETRYABLE_CODES

FINALIZED = "finalized"
MAX_GET_BLOCKS_RANGE = 500_000
MAX_RETRIES = 3
#: Single source of truth: see :mod:`slot_audit.solana_codes` for what each code
#: means and why it is or is not worth another attempt.
RETRYABLE_RPC_CODES = RETRYABLE_CODES

_FIRST_AVAILABLE_BLOCK_RE = re.compile(
    r"first\s+available\s+block\s*:\s*([0-9][0-9_,]*)", re.IGNORECASE
)


class _ProviderLike(Protocol):
    name: str
    rps: float

    @property
    def rpc_url(self) -> str: ...


@dataclass(frozen=True, slots=True)
class RetryEvent:
    """A secret-free, structured record emitted before each retry."""

    provider: str
    method: str
    attempt: int
    retry_number: int
    max_retries: int
    delay_seconds: float
    reason: str
    http_status: int | None = None
    rpc_code: int | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


RetryHook: TypeAlias = Callable[[RetryEvent], Awaitable[None] | None]
Sleep: TypeAlias = Callable[[float], Awaitable[None]]
Clock: TypeAlias = Callable[[], float]


class RpcError(RuntimeError):
    """Base class for errors produced by this RPC layer."""


class RpcProtocolError(RpcError):
    """The server returned an invalid JSON-RPC response."""


class RpcHttpError(RpcError):
    """A non-retryable HTTP response."""

    def __init__(self, provider: str, method: str, status_code: int) -> None:
        self.provider = provider
        self.method = method
        self.status_code = status_code
        super().__init__(f"provider {provider!r} returned HTTP {status_code} for {method}")


class RpcResponseError(RpcError):
    """A non-success ``error`` object from a JSON-RPC response."""

    def __init__(
        self,
        *,
        provider: str,
        method: str,
        code: int,
        message: str,
        data: object = None,
    ) -> None:
        self.provider = provider
        self.method = method
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"provider {provider!r} returned RPC error {code} for {method}: {message}")


class FirstAvailableBlockError(RpcResponseError):
    """RPC ``-32001``: the requested block is below retention."""

    def __init__(self, *, first_available_block: int | None, **kwargs: Any) -> None:
        self.first_available_block = first_available_block
        super().__init__(**kwargs)


class RequestBudgetExceeded(RpcError):
    """No request was sent because the per-provider hard budget was spent."""

    def __init__(self, provider: str, limit: int, request_count: int) -> None:
        self.provider = provider
        self.limit = limit
        self.request_count = request_count
        super().__init__(
            f"request budget exhausted for provider {provider!r}: "
            f"{request_count}/{limit} requests sent"
        )


class RpcRetryExhausted(RpcError):
    """A retryable failure remained after the initial call and three retries."""

    def __init__(
        self,
        *,
        provider: str,
        method: str,
        attempts: int,
        last_error: RpcError,
    ) -> None:
        self.provider = provider
        self.method = method
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            f"provider {provider!r} did not complete {method} after {attempts} attempts"
        )


class BlockUnavailableError(RpcRetryExhausted):
    """RPC ``-32004`` persisted after all retries.

    Callers may report this as ``INDETERMINATE``.  It is not evidence of a
    protocol skip or provider hole.
    """


class NodeUnhealthyError(RpcRetryExhausted):
    """RPC ``-32005`` persisted after all retries and cannot yield a verdict."""


class HttpRetryExhausted(RpcRetryExhausted):
    """HTTP 429/5xx persisted after all retries."""

    @property
    def status_code(self) -> int | None:
        error = self.last_error
        return error.status_code if isinstance(error, RpcHttpError) else None


class TransportRetryExhausted(RpcRetryExhausted):
    """A network transport failure persisted after all retries."""


def parse_first_available_block(message: str) -> int | None:
    """Extract ``N`` from a Solana ``First available block: N`` message."""

    match = _FIRST_AVAILABLE_BLOCK_RE.search(message)
    if match is None:
        return None
    return int(match.group(1).replace("_", "").replace(",", ""))


class TokenBucket:
    """An async token bucket with a bounded initial burst.

    A bucket belongs to one :class:`RpcClient`, and therefore to one provider.
    Providers cannot consume each other's capacity.
    """

    def __init__(
        self,
        rate: float,
        *,
        capacity: float | None = None,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
    ) -> None:
        if rate <= 0:
            raise ValueError("token rate must be greater than zero")
        chosen_capacity = max(1.0, rate) if capacity is None else capacity
        if chosen_capacity < 1:
            raise ValueError("token bucket capacity must be at least one")
        self.rate = float(rate)
        self.capacity = float(chosen_capacity)
        self._tokens = self.capacity
        self._updated_at = clock()
        self._sleep = sleep
        self._clock = clock
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until one request token is available, then consume it."""

        while True:
            async with self._lock:
                now = self._clock()
                elapsed = max(0.0, now - self._updated_at)
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                self._updated_at = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                delay = (1.0 - self._tokens) / self.rate
            await self._sleep(delay)


class RpcClient:
    """One async Solana JSON-RPC client, limiter, and budget per provider."""

    def __init__(
        self,
        provider: _ProviderLike,
        *,
        max_requests: int = 200_000,
        max_concurrency: int = 8,
        timeout: float | httpx.Timeout = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        retry_hook: RetryHook | None = None,
        logger: logging.Logger | None = None,
        max_retries: int = MAX_RETRIES,
        backoff_base: float = 0.25,
        backoff_cap: float = 8.0,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
        random_source: random.Random | None = None,
    ) -> None:
        if max_requests < 0:
            raise ValueError("max_requests must not be negative")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least one")
        if not 0 <= max_retries <= MAX_RETRIES:
            raise ValueError(f"max_retries must be between 0 and {MAX_RETRIES}")
        if backoff_base < 0 or backoff_cap < 0:
            raise ValueError("backoff values must not be negative")

        # Copy only known, non-secret values.  The URL is deliberately never
        # included in logs or exception text because it commonly contains a key.
        self.provider = provider
        self.name = str(provider.name)
        self.url = _provider_url(provider)
        self.rps = float(provider.rps)
        if not self.name:
            raise ValueError("provider name must not be empty")
        if not self.url:
            raise ValueError("provider URL must not be empty")
        if self.rps <= 0:
            raise ValueError("provider rps must be greater than zero")

        self.max_requests = max_requests
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self._retry_hook = retry_hook
        self._logger = logger or logging.getLogger(__name__)
        self._sleep = sleep
        self._random = random_source or random.Random()
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._token_bucket = TokenBucket(self.rps, sleep=sleep, clock=clock)
        self._counter_lock = asyncio.Lock()
        self._request_count = 0
        self._next_request_id = 1
        headers = getattr(provider, "headers", None)
        self._http = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            headers=dict(headers) if headers else None,
        )
        self._closed = False

    @property
    def request_count(self) -> int:
        """Number of actual HTTP attempts sent, including retries."""

        return self._request_count

    @property
    def total_requests(self) -> int:
        """Alias used by run summaries."""

        return self._request_count

    @property
    def budget_remaining(self) -> int:
        return self.max_requests - self._request_count

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def __aenter__(self) -> RpcClient:
        if self._closed:
            raise RuntimeError("RPC client is already closed")
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._http.aclose()

    async def close(self) -> None:
        """Compatibility spelling for :meth:`aclose`."""

        await self.aclose()

    async def get_slot(self) -> int:
        result = await self.call("getSlot", [{"commitment": FINALIZED}])
        if not isinstance(result, int) or isinstance(result, bool):
            raise RpcProtocolError(f"provider {self.name!r} returned a non-integer slot")
        return result

    async def get_first_available_block(self) -> int:
        # This RPC method has no commitment parameter in Solana's API.
        result = await self.call("getFirstAvailableBlock", [])
        if not isinstance(result, int) or isinstance(result, bool):
            raise RpcProtocolError(
                f"provider {self.name!r} returned a non-integer retention boundary"
            )
        return result

    async def get_epoch_info(self) -> dict[str, Any]:
        result = await self.call("getEpochInfo", [{"commitment": FINALIZED}])
        if not isinstance(result, dict):
            raise RpcProtocolError(
                f"provider {self.name!r} returned an invalid getEpochInfo result"
            )
        return result

    async def get_epoch_schedule(self) -> dict[str, Any]:
        # getEpochSchedule describes the static schedule and accepts no
        # commitment option in Solana's API.
        result = await self.call("getEpochSchedule", [])
        if not isinstance(result, dict):
            raise RpcProtocolError(
                f"provider {self.name!r} returned an invalid getEpochSchedule result"
            )
        return result

    async def get_blocks(self, start_slot: int, end_slot: int) -> list[int]:
        _validate_slot(start_slot, "start_slot")
        _validate_slot(end_slot, "end_slot")
        if end_slot < start_slot:
            raise ValueError("end_slot must be greater than or equal to start_slot")
        if end_slot - start_slot + 1 > MAX_GET_BLOCKS_RANGE:
            raise ValueError(f"getBlocks range cannot exceed {MAX_GET_BLOCKS_RANGE:,} slots")
        result = await self.call(
            "getBlocks",
            [start_slot, end_slot, {"commitment": FINALIZED}],
        )
        if not isinstance(result, list) or any(
            not isinstance(slot, int) or isinstance(slot, bool) for slot in result
        ):
            raise RpcProtocolError(f"provider {self.name!r} returned an invalid getBlocks result")
        return result

    async def get_block(
        self,
        slot: int,
        *,
        transaction_details: str = "none",
        rewards: bool = False,
    ) -> dict[str, Any] | None:
        _validate_slot(slot, "slot")
        if transaction_details not in {"none", "signatures", "full", "accounts"}:
            raise ValueError(f"unsupported transactionDetails value: {transaction_details!r}")
        result = await self.call(
            "getBlock",
            [
                slot,
                {
                    "commitment": FINALIZED,
                    "transactionDetails": transaction_details,
                    "rewards": rewards,
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
        if result is not None and not isinstance(result, dict):
            raise RpcProtocolError(f"provider {self.name!r} returned an invalid getBlock result")
        return result

    async def call(self, method: str, params: Sequence[object]) -> object:
        """Issue one logical RPC call, applying retry policy to each attempt."""

        if self._closed:
            raise RuntimeError("RPC client is closed")
        if not method:
            raise ValueError("RPC method must not be empty")

        for attempt in range(1, self.max_retries + 2):
            try:
                return await self._attempt(method, params)
            except _RetryableFailure as failure:
                if attempt > self.max_retries:
                    raise self._exhausted_error(
                        method=method,
                        attempts=attempt,
                        failure=failure,
                    ) from failure.error
                retry_number = attempt
                delay = self._retry_delay(retry_number)
                event = RetryEvent(
                    provider=self.name,
                    method=method,
                    attempt=attempt,
                    retry_number=retry_number,
                    max_retries=self.max_retries,
                    delay_seconds=delay,
                    reason=failure.reason,
                    http_status=failure.http_status,
                    rpc_code=failure.rpc_code,
                )
                await self._emit_retry(event)
                await self._sleep(delay)

        raise AssertionError("retry loop terminated unexpectedly")

    async def _attempt(self, method: str, params: Sequence[object]) -> object:
        try:
            async with self._semaphore:
                # Queue for provider-local concurrency before consuming a rate
                # token. Otherwise slow in-flight calls let queued tasks refill
                # and pre-consume the bucket, producing a burst when they drain.
                await self._token_bucket.acquire()
                request_id = await self._reserve_request()
                payload = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": list(params),
                }
                response = await self._http.post(self.url, json=payload)
        except httpx.TransportError as error:
            safe_error = RpcError(f"provider {self.name!r} had a transport failure for {method}")
            raise _RetryableFailure(
                error=safe_error,
                reason="transport_error",
            ) from error

        if response.status_code == 429 or 500 <= response.status_code <= 599:
            error = RpcHttpError(self.name, method, response.status_code)
            raise _RetryableFailure(
                error=error,
                reason="http_status",
                http_status=response.status_code,
            )
        if not 200 <= response.status_code <= 299:
            raise RpcHttpError(self.name, method, response.status_code)

        try:
            envelope = response.json()
        except ValueError as error:
            raise RpcProtocolError(
                f"provider {self.name!r} returned invalid JSON for {method}"
            ) from error
        if not isinstance(envelope, dict):
            raise RpcProtocolError(
                f"provider {self.name!r} returned a non-object JSON-RPC response"
            )
        if "error" in envelope and envelope["error"] is not None:
            rpc_error = self._response_error(method, envelope["error"])
            if rpc_error.code in RETRYABLE_RPC_CODES:
                raise _RetryableFailure(
                    error=rpc_error,
                    reason="rpc_error",
                    rpc_code=rpc_error.code,
                )
            raise rpc_error
        if "result" not in envelope:
            raise RpcProtocolError(
                f"provider {self.name!r} returned JSON-RPC without result or error"
            )
        return envelope["result"]

    async def _reserve_request(self) -> int:
        async with self._counter_lock:
            if self._request_count >= self.max_requests:
                raise RequestBudgetExceeded(
                    self.name,
                    self.max_requests,
                    self._request_count,
                )
            request_id = self._next_request_id
            self._next_request_id += 1
            self._request_count += 1
            return request_id

    def _response_error(self, method: str, raw_error: object) -> RpcResponseError:
        if not isinstance(raw_error, dict):
            raise RpcProtocolError(
                f"provider {self.name!r} returned an invalid JSON-RPC error object"
            )
        code = raw_error.get("code")
        message = raw_error.get("message")
        if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
            raise RpcProtocolError(
                f"provider {self.name!r} returned an invalid JSON-RPC error object"
            )
        kwargs: dict[str, Any] = {
            "provider": self.name,
            "method": method,
            "code": code,
            "message": message,
            "data": raw_error.get("data"),
        }
        if code == -32001:
            return FirstAvailableBlockError(
                first_available_block=parse_first_available_block(message),
                **kwargs,
            )
        return RpcResponseError(**kwargs)

    def _retry_delay(self, retry_number: int) -> float:
        exponential = min(
            self.backoff_cap,
            self.backoff_base * (2 ** (retry_number - 1)),
        )
        # Equal jitter avoids synchronized retry waves while retaining an
        # exponential lower bound.  With a zero base (useful in tests), it is 0.
        return exponential * (0.5 + self._random.random() / 2.0)

    async def _emit_retry(self, event: RetryEvent) -> None:
        self._logger.warning("rpc_retry", extra={"rpc_retry": event.as_dict()})
        if self._retry_hook is None:
            return
        hook_result = self._retry_hook(event)
        if inspect.isawaitable(hook_result):
            await hook_result

    def _exhausted_error(
        self,
        *,
        method: str,
        attempts: int,
        failure: _RetryableFailure,
    ) -> RpcRetryExhausted:
        kwargs = {
            "provider": self.name,
            "method": method,
            "attempts": attempts,
            "last_error": failure.error,
        }
        if failure.rpc_code == -32004:
            return BlockUnavailableError(**kwargs)
        if failure.rpc_code == -32005:
            return NodeUnhealthyError(**kwargs)
        if failure.http_status is not None:
            return HttpRetryExhausted(**kwargs)
        return TransportRetryExhausted(**kwargs)


class _RetryableFailure(Exception):
    def __init__(
        self,
        *,
        error: RpcError,
        reason: str,
        http_status: int | None = None,
        rpc_code: int | None = None,
    ) -> None:
        self.error = error
        self.reason = reason
        self.http_status = http_status
        self.rpc_code = rpc_code
        super().__init__(reason)


def _validate_slot(slot: int, name: str) -> None:
    if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _provider_url(provider: object) -> str:
    """Read a transport URL without ever relying on SecretStr.__str__."""

    rpc_url = getattr(provider, "rpc_url", None)
    if isinstance(rpc_url, str):
        return rpc_url
    value = getattr(provider, "url", None)
    get_secret_value = getattr(value, "get_secret_value", None)
    if callable(get_secret_value):
        secret = get_secret_value()
        if isinstance(secret, str):
            return secret
    if isinstance(value, str):
        return value
    raise ValueError("provider must expose rpc_url or a string URL")


# Friendly aliases for callers that use the fully-spelled class name.
SolanaRpcClient = RpcClient
SolanaRPCClient = RpcClient
RPCClient = RpcClient


__all__ = [
    "FINALIZED",
    "MAX_GET_BLOCKS_RANGE",
    "MAX_RETRIES",
    "BlockUnavailableError",
    "FirstAvailableBlockError",
    "HttpRetryExhausted",
    "NodeUnhealthyError",
    "ProviderConfig",
    "RPCClient",
    "RequestBudgetExceeded",
    "RetryEvent",
    "RpcClient",
    "RpcError",
    "RpcHttpError",
    "RpcProtocolError",
    "RpcResponseError",
    "RpcRetryExhausted",
    "SolanaRPCClient",
    "SolanaRpcClient",
    "TokenBucket",
    "TransportRetryExhausted",
    "parse_first_available_block",
]
