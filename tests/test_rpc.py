from __future__ import annotations

import asyncio
import json
import logging
import random
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from slot_audit.config import ProviderConfig
from slot_audit.rpc import (
    BlockUnavailableError,
    FirstAvailableBlockError,
    HttpRetryExhausted,
    NodeUnhealthyError,
    RequestBudgetExceeded,
    RetryEvent,
    RpcClient,
    RpcResponseError,
    TokenBucket,
    parse_first_available_block,
)

FIXTURES = Path(__file__).parent / "fixtures" / "rpc"


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def provider(name: str = "fixture", *, rps: float = 100.0) -> ProviderConfig:
    return ProviderConfig(
        name=name,
        url="https://rpc.invalid/?api-key=fixture-secret",
        rps=rps,
        archive=True,
    )


def json_transport(
    response: dict[str, Any] | Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    if callable(response):
        return httpx.MockTransport(response)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response, request=request)

    return httpx.MockTransport(handler)


async def no_sleep(_: float) -> None:
    return None


class RpcWrapperTests(unittest.IsolatedAsyncioTestCase):
    async def test_finalized_safe_wrappers_and_version_zero(self) -> None:
        requests: list[dict[str, Any]] = []
        responses = {
            "getSlot": {"jsonrpc": "2.0", "result": 340000000, "id": 1},
            "getFirstAvailableBlock": fixture("first_available_success.json"),
            "getBlocks": fixture("get_blocks_success.json"),
            "getBlock": fixture("get_block_success.json"),
            "getEpochInfo": fixture("get_epoch_info_success.json"),
            "getEpochSchedule": fixture("get_epoch_schedule_success.json"),
        }

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            requests.append(payload)
            return httpx.Response(200, json=responses[payload["method"]], request=request)

        async with RpcClient(provider(), transport=json_transport(handler)) as client:
            self.assertEqual(await client.get_slot(), 340000000)
            self.assertEqual(await client.get_first_available_block(), 88776655)
            self.assertEqual(await client.get_blocks(100, 104), [100, 102, 104])
            block = await client.get_block(104)
            self.assertIsNotNone(block)
            assert block is not None
            self.assertEqual(block["parentSlot"], 102)
            self.assertEqual((await client.get_epoch_info())["epoch"], 787)
            self.assertEqual(
                (await client.get_epoch_schedule())["slotsPerEpoch"], 432000
            )

            self.assertEqual(client.request_count, 6)
            self.assertEqual(client.total_requests, 6)
            self.assertEqual(client.budget_remaining, 200_000 - 6)

        by_method = {request["method"]: request for request in requests}
        self.assertEqual(by_method["getSlot"]["params"], [{"commitment": "finalized"}])
        self.assertEqual(by_method["getFirstAvailableBlock"]["params"], [])
        self.assertEqual(
            by_method["getBlocks"]["params"], [100, 104, {"commitment": "finalized"}]
        )
        self.assertEqual(
            by_method["getEpochInfo"]["params"], [{"commitment": "finalized"}]
        )
        self.assertEqual(by_method["getEpochSchedule"]["params"], [])
        block_config = by_method["getBlock"]["params"][1]
        self.assertEqual(
            block_config,
            {
                "commitment": "finalized",
                "transactionDetails": "none",
                "rewards": False,
                "maxSupportedTransactionVersion": 0,
            },
        )
        # SecretStr must be unwrapped for transport, never stringified as **********.
        self.assertTrue(requests)

    async def test_get_blocks_enforces_500000_inclusive_slot_limit(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "result": [], "id": calls},
                request=request,
            )

        async with RpcClient(provider(), transport=json_transport(handler)) as client:
            self.assertEqual(await client.get_blocks(0, 499_999), [])
            with self.assertRaisesRegex(ValueError, "500,000"):
                await client.get_blocks(0, 500_000)

        self.assertEqual(calls, 1)


class RpcErrorTaxonomyTests(unittest.IsolatedAsyncioTestCase):
    async def test_error_32001_parses_first_available_block_without_retry(self) -> None:
        async with RpcClient(
            provider(),
            transport=json_transport(fixture("block_cleaned_up_32001.json")),
        ) as client:
            with self.assertRaises(FirstAvailableBlockError) as caught:
                await client.get_block(123)

            self.assertEqual(caught.exception.code, -32001)
            self.assertEqual(caught.exception.first_available_block, 88776655)
            self.assertEqual(client.request_count, 1)

        self.assertEqual(parse_first_available_block("First available block: 12_345"), 12345)
        self.assertIsNone(parse_first_available_block("cleaned up"))

    async def test_node_unhealthy_retries_three_times_and_never_classifies(self) -> None:
        events: list[RetryEvent] = []
        delays: list[float] = []

        async def retry_hook(event: RetryEvent) -> None:
            events.append(event)

        async def record_sleep(delay: float) -> None:
            delays.append(delay)

        with self.assertLogs("slot_audit.rpc", level=logging.WARNING) as captured:
            async with RpcClient(
                provider(),
                transport=json_transport(fixture("node_unhealthy_32005.json")),
                retry_hook=retry_hook,
                sleep=record_sleep,
                random_source=random.Random(7),
            ) as client:
                with self.assertRaises(NodeUnhealthyError) as caught:
                    await client.get_block(123)

                self.assertEqual(caught.exception.attempts, 4)
                self.assertIsInstance(caught.exception.last_error, RpcResponseError)
                self.assertEqual(caught.exception.last_error.code, -32005)
                self.assertFalse(hasattr(caught.exception, "verdict"))
                self.assertEqual(client.request_count, 4)

        self.assertEqual([event.retry_number for event in events], [1, 2, 3])
        self.assertEqual([event.rpc_code for event in events], [-32005, -32005, -32005])
        self.assertEqual(len(delays), 3)
        self.assertLess(delays[0], delays[1])
        self.assertLess(delays[1], delays[2])
        records = [
            record for record in captured.records if record.getMessage() == "rpc_retry"
        ]
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].rpc_retry["provider"], "fixture")  # type: ignore[attr-defined]
        self.assertNotIn("fixture-secret", "\n".join(captured.output))

    async def test_block_unavailable_exhaustion_is_typed_indeterminate_failure(self) -> None:
        async with RpcClient(
            provider(),
            transport=json_transport(fixture("block_unavailable_32004.json")),
            backoff_base=0,
            sleep=no_sleep,
        ) as client:
            with self.assertRaises(BlockUnavailableError) as caught:
                await client.get_block(123)

            self.assertEqual(caught.exception.attempts, 4)
            self.assertEqual(caught.exception.last_error.code, -32004)  # type: ignore[attr-defined]
            self.assertEqual(client.total_requests, 4)

    async def test_retryable_rpc_error_can_recover_on_last_attempt(self) -> None:
        failure = fixture("block_unavailable_32004.json")
        success = fixture("get_block_success.json")
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            body = success if calls == 4 else failure
            return httpx.Response(200, json=body, request=request)

        async with RpcClient(
            provider(),
            transport=json_transport(handler),
            backoff_base=0,
            sleep=no_sleep,
        ) as client:
            result = await client.get_block(123)

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["blockhash"], "child-hash")
            self.assertEqual(client.request_count, 4)

    async def test_http_429_and_5xx_retry_then_succeed(self) -> None:
        statuses = iter([429, 500, 503, 200])
        events: list[RetryEvent] = []

        def handler(request: httpx.Request) -> httpx.Response:
            status = next(statuses)
            return httpx.Response(
                status,
                json={"jsonrpc": "2.0", "result": 44, "id": 1},
                request=request,
            )

        async with RpcClient(
            provider(),
            transport=json_transport(handler),
            backoff_base=0,
            sleep=no_sleep,
            retry_hook=events.append,
        ) as client:
            self.assertEqual(await client.get_slot(), 44)
            self.assertEqual(client.request_count, 4)

        self.assertEqual([event.http_status for event in events], [429, 500, 503])

    async def test_http_retry_exhaustion_is_typed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, request=request)

        async with RpcClient(
            provider(),
            transport=json_transport(handler),
            backoff_base=0,
            sleep=no_sleep,
        ) as client:
            with self.assertRaises(HttpRetryExhausted) as caught:
                await client.get_slot()

            self.assertEqual(caught.exception.status_code, 503)
            self.assertEqual(caught.exception.attempts, 4)

    async def test_request_budget_is_a_hard_stop_even_during_retries(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200,
                json=fixture("node_unhealthy_32005.json"),
                request=request,
            )

        async with RpcClient(
            provider(),
            max_requests=2,
            transport=json_transport(handler),
            backoff_base=0,
            sleep=no_sleep,
        ) as client:
            with self.assertRaises(RequestBudgetExceeded) as caught:
                await client.get_block(123)

            self.assertEqual(caught.exception.limit, 2)
            self.assertEqual(caught.exception.request_count, 2)
            self.assertEqual(client.request_count, 2)
            self.assertEqual(client.budget_remaining, 0)
            self.assertEqual(calls, 2)

    async def test_non_retryable_rpc_error_is_returned_immediately(self) -> None:
        skipped = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32007,
                "message": "Slot 123 was skipped, or missing due to ledger jump",
            },
            "id": 1,
        }
        async with RpcClient(provider(), transport=json_transport(skipped)) as client:
            with self.assertRaises(RpcResponseError) as caught:
                await client.get_block(123)

            self.assertEqual(caught.exception.code, -32007)
            self.assertEqual(client.request_count, 1)


class LimiterIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_semaphore_limits_only_its_own_concurrency(self) -> None:
        active = 0
        maximum_active = 0
        first_entered = asyncio.Event()
        release = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            first_entered.set()
            await release.wait()
            active -= 1
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "result": 1, "id": 1},
                request=request,
            )

        async with RpcClient(
            provider(),
            max_concurrency=1,
            transport=httpx.MockTransport(handler),
        ) as client:
            first = asyncio.create_task(client.get_slot())
            await first_entered.wait()
            second = asyncio.create_task(client.get_slot())
            await asyncio.sleep(0)
            self.assertEqual(maximum_active, 1)
            self.assertEqual(client.request_count, 1)
            release.set()
            self.assertEqual(await first, 1)
            self.assertEqual(await second, 1)

        self.assertEqual(maximum_active, 1)

    async def test_token_bucket_refills_at_configured_provider_rate(self) -> None:
        now = 100.0
        delays: list[float] = []

        async def advance(delay: float) -> None:
            nonlocal now
            delays.append(delay)
            now += delay

        bucket = TokenBucket(rate=2, capacity=1, sleep=advance, clock=lambda: now)
        await bucket.acquire()
        await bucket.acquire()

        self.assertEqual(len(delays), 1)
        self.assertAlmostEqual(delays[0], 0.5, places=9)

    async def test_clients_have_independent_provider_limiters_and_budgets(self) -> None:
        transport = json_transport({"jsonrpc": "2.0", "result": 1, "id": 1})
        first = RpcClient(provider("first"), max_requests=1, transport=transport)
        second = RpcClient(provider("second"), max_requests=1, transport=transport)
        try:
            self.assertIsNot(first._semaphore, second._semaphore)
            self.assertIsNot(first._token_bucket, second._token_bucket)
            self.assertEqual(await first.get_slot(), 1)
            with self.assertRaises(RequestBudgetExceeded):
                await first.get_slot()
            self.assertEqual(await second.get_slot(), 1)
            self.assertEqual(first.request_count, 1)
            self.assertEqual(second.request_count, 1)
        finally:
            await first.aclose()
            await second.aclose()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
