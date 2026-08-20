"""Retry, rate limiting and budget policy on the evidence-recording client.

All three change what a run may claim, so all three are asserted here rather
than assumed: a retry that is not retained looks like a clean first answer, and
a budget cut-off that is not recorded looks like missing data.
"""

from __future__ import annotations

import json
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from slot_audit.evidence import EvidenceStore
from slot_audit.transport import (
    MAX_RETRIES,
    AuditRpcClient,
    ScriptedRpcError,
    ScriptedTransport,
    TransportError,
    TransportResponse,
)


class ScriptedStatusTransport:
    """Replay a fixed script of (status, body) pairs, then repeat the last."""

    def __init__(self, script: list[tuple[int, object]]) -> None:
        self.script = script
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    async def post(self, url: str, payload) -> TransportResponse:  # type: ignore[no-untyped-def]
        self.sent.append(dict(payload))
        status, body = self.script[min(len(self.sent) - 1, len(self.script) - 1)]
        if body is TransportError:
            raise TransportError("simulated transport failure")
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        return TransportResponse(status_code=status, body=encoded)

    async def aclose(self) -> None:
        self.closed = True


def ok(result: object) -> tuple[int, object]:
    return 200, {"jsonrpc": "2.0", "id": 1, "result": result}


def rpc_error(code: int, message: str = "boom") -> tuple[int, object]:
    return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}}


class TransportTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)
        self.store = EvidenceStore(self.tmp_path / "evidence")
        self.delays: list[float] = []

    async def _sleep(self, delay: float) -> None:
        self.delays.append(delay)

    def client(self, transport, **kwargs: Any) -> AuditRpcClient:
        options: dict[str, Any] = {
            "backoff_base": 1.0,
            "sleep": self._sleep,
            "random_source": random.Random(1),
        }
        options.update(kwargs)
        return AuditRpcClient(
            provider="provider-a",
            url="https://provider.invalid/rpc?api-key=secret",
            endpoint_fingerprint="f" * 64,
            transport=transport,
            evidence=self.store,
            **options,
        )


class RetryPolicyTests(TransportTestCase):
    async def test_a_transient_node_error_is_retried_and_then_succeeds(self) -> None:
        transport = ScriptedStatusTransport(
            [rpc_error(-32005, "Node is unhealthy")] * 3 + [ok([1, 2, 3])]
        )
        client = self.client(transport)

        call = await client.call("getBlocks", [1, 3])

        self.assertEqual(call.result, [1, 2, 3])
        self.assertFalse(call.failed)
        self.assertEqual(call.attempts, 4)
        self.assertTrue(call.retried)
        self.assertEqual(len(transport.sent), 4)
        self.assertEqual(client.retry_count, 3)

    async def test_every_attempt_is_retained_as_its_own_evidence(self) -> None:
        transport = ScriptedStatusTransport(
            [rpc_error(-32004, "Block not available")] * 2 + [ok(7)]
        )
        client = self.client(transport)

        call = await client.call("getSlot", [])

        self.assertEqual(len(call.attempt_evidence), 3)
        paths = [item.raw.relative_path for item in call.attempt_evidence]
        self.assertEqual(len(set(paths)), 3, "attempts must not overwrite one another")
        bodies = [
            json.loads((self.store.root / path).read_text(encoding="utf-8"))
            for path in paths
        ]
        self.assertEqual(bodies[0]["error"]["code"], -32004)
        self.assertEqual(bodies[1]["error"]["code"], -32004)
        self.assertEqual(bodies[2]["result"], 7)
        # The retained record shows the retries; it does not present a clean
        # first answer.
        self.assertEqual(len(call.all_refs()), 6)

    async def test_retries_are_bounded_and_exhaustion_is_reported_honestly(self) -> None:
        transport = ScriptedStatusTransport([rpc_error(-32005, "Node is unhealthy")])
        client = self.client(transport)

        call = await client.call("getBlock", [10])

        self.assertTrue(call.failed)
        self.assertEqual(call.error_code, -32005)
        self.assertEqual(call.attempts, MAX_RETRIES + 1)
        self.assertEqual(len(transport.sent), MAX_RETRIES + 1)
        self.assertIsNone(call.result)

    async def test_a_skipped_slot_is_terminal_and_never_retried(self) -> None:
        transport = ScriptedStatusTransport(
            [rpc_error(-32009, "Slot 10 was skipped")]
        )
        client = self.client(transport)

        call = await client.call("getBlock", [10])

        self.assertTrue(call.failed)
        self.assertEqual(call.error_code, -32009)
        self.assertEqual(call.attempts, 1)
        self.assertEqual(len(transport.sent), 1)

    async def test_http_429_and_5xx_are_retried_but_4xx_is_not(self) -> None:
        throttled = ScriptedStatusTransport([(429, {}), (503, {}), ok(1)])
        client = self.client(throttled)
        call = await client.call("getSlot", [])
        self.assertEqual(call.result, 1)
        self.assertEqual(call.attempts, 3)

        forbidden = ScriptedStatusTransport([(403, {})])
        other = self.client(forbidden)
        refused = await other.call("getSlot", [])
        self.assertTrue(refused.failed)
        self.assertEqual(refused.attempts, 1)
        self.assertIn("403", str(refused.error_message))

    async def test_a_transport_failure_is_retried_and_recorded(self) -> None:
        transport = ScriptedStatusTransport([(0, TransportError), ok(5)])
        client = self.client(transport)

        call = await client.call("getSlot", [])

        self.assertEqual(call.result, 5)
        self.assertEqual(call.attempts, 2)
        first = json.loads(
            (self.store.root / call.attempt_evidence[0].raw.relative_path).read_text()
        )
        self.assertIn("transport_error", first)

    async def test_zero_retries_means_one_attempt(self) -> None:
        transport = ScriptedStatusTransport([rpc_error(-32005)])
        client = self.client(transport, max_retries=0)

        call = await client.call("getSlot", [])

        self.assertEqual(call.attempts, 1)
        self.assertEqual(self.delays, [])

    async def test_backoff_grows_and_stays_under_the_cap(self) -> None:
        transport = ScriptedStatusTransport([rpc_error(-32005)])
        client = self.client(transport, backoff_base=1.0, backoff_cap=4.0)

        await client.call("getSlot", [])

        self.assertEqual(len(self.delays), MAX_RETRIES)
        for delay in self.delays:
            self.assertGreater(delay, 0.0)
            self.assertLessEqual(delay, 4.0)
        # Equal jitter keeps an exponential floor.
        self.assertGreaterEqual(self.delays[1], self.delays[0] / 2)

    async def test_an_out_of_range_retry_ceiling_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.client(ScriptedStatusTransport([ok(1)]), max_retries=MAX_RETRIES + 1)


class BudgetTests(TransportTestCase):
    async def test_the_budget_is_a_hard_stop_that_explains_itself(self) -> None:
        transport = ScriptedStatusTransport([ok(1)])
        client = self.client(transport, max_requests=2)

        first = await client.call("getSlot", [])
        second = await client.call("getSlot", [])
        third = await client.call("getSlot", [])

        self.assertFalse(first.failed)
        self.assertFalse(second.failed)
        self.assertTrue(third.failed)
        self.assertIn("budget", str(third.error_message))
        self.assertEqual(len(transport.sent), 2, "no request may be sent past the budget")
        self.assertTrue(client.budget_exhausted)
        self.assertEqual(client.budget_remaining, 0)

        # The refusal is retained, so the gap in coverage is explicable rather
        # than looking like a provider that simply had nothing to say.
        body = json.loads(
            (self.store.root / third.evidence.raw.relative_path).read_text()
        )
        self.assertTrue(body["budget_exhausted"])
        self.assertEqual(body["limit"], 2)

    async def test_retries_consume_the_budget(self) -> None:
        transport = ScriptedStatusTransport([rpc_error(-32005)])
        client = self.client(transport, max_requests=2)

        call = await client.call("getSlot", [])

        self.assertEqual(len(transport.sent), 2)
        self.assertTrue(call.failed)
        self.assertEqual(client.budget_remaining, 0)

    async def test_an_unset_budget_is_unlimited(self) -> None:
        client = self.client(ScriptedStatusTransport([ok(1)]))

        self.assertIsNone(client.budget_remaining)
        await client.call("getSlot", [])
        self.assertFalse(client.budget_exhausted)


class RateLimitTests(TransportTestCase):
    async def test_the_configured_rate_is_applied_after_the_initial_burst(self) -> None:
        now = 100.0

        async def advance(delay: float) -> None:
            nonlocal now
            self.delays.append(delay)
            now += delay

        client = AuditRpcClient(
            provider="provider-a",
            url="https://provider.invalid/rpc",
            endpoint_fingerprint="f" * 64,
            transport=ScriptedStatusTransport([ok(1)]),
            evidence=self.store,
            rps=2.0,
            sleep=advance,
            monotonic=lambda: now,
        )

        await client.call("getSlot", [])
        await client.call("getSlot", [])
        await client.call("getSlot", [])

        # The bucket allows a burst of `rps` before metering, so the first two
        # calls ride the initial tokens and only the third waits for a refill.
        self.assertEqual(len(self.delays), 1)
        self.assertAlmostEqual(self.delays[0], 0.5, places=9)

    async def test_an_invalid_rate_is_refused(self) -> None:
        for rps in (0, -1.0):
            with self.subTest(rps=rps), self.assertRaises(ValueError):
                self.client(ScriptedStatusTransport([ok(1)]), rps=rps)


class ScriptedTransportTests(TransportTestCase):
    async def test_the_fixture_transport_builds_real_json_rpc_envelopes(self) -> None:
        def handler(url: str, method: str, params: list[Any]) -> Any:
            if method == "getSlot":
                return 42
            raise ScriptedRpcError(-32601, "Method not found")

        client = self.client(ScriptedTransport(handler))

        good = await client.call("getSlot", [])
        bad = await client.call("getNothing", [])

        self.assertEqual(good.result, 42)
        self.assertEqual(bad.error_code, -32601)
        body = json.loads((self.store.root / good.evidence.raw.relative_path).read_text())
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["result"], 42)

    async def test_the_request_record_never_holds_the_url(self) -> None:
        client = self.client(ScriptedStatusTransport([ok(1)]))

        call = await client.call("getSlot", [])

        record = (self.store.root / call.evidence.request.relative_path).read_text()
        self.assertNotIn("secret", record)
        self.assertNotIn("https://", record)
        self.assertIn("f" * 64, record)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
