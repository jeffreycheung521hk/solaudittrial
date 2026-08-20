"""A provider-scoped async token bucket.

Kept in its own module because both RPC clients need it and neither owns it.
That also means the Pass A subsystem can be removed without stranding it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TypeAlias

Sleep: TypeAlias = Callable[[float], Awaitable[None]]
Clock: TypeAlias = Callable[[], float]


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


__all__ = ["Clock", "Sleep", "TokenBucket"]
