"""Configuration must state everything and may assume nothing."""

from __future__ import annotations

import copy
import unittest
from decimal import Decimal
from pathlib import Path

import yaml

from slot_audit.config import (
    ConfigError,
    EpochAuditConfig,
    load_epoch_config,
    resolve_epoch_config,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

VALID: dict[str, object] = {
    "schema_version": 1,
    "population": {
        "definition": "every scheduled slot position of epoch 100",
        "unit": "scheduled slot position",
        "description": "complete population, not a sample",
    },
    "scope": {
        "epoch": 100,
        "first_slot": 43_200_000,
        "last_slot": 43_631_999,
        "scheduled_slot_positions": 432_000,
        "commitment": "finalized",
        "pinned_slot": 43_631_999,
        "exact_context_policy": "require_exact_pinned_slot",
    },
    "thresholds": {
        "indeterminate_threshold": "0.01",
        "denominator_policy": "determinate_positions_only",
        "materiality_threshold": "0.0001",
        "minimum_provider_agreement": "0.99",
    },
    "token": {
        "mint": "So11111111111111111111111111111111111111112",
        "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "account_size": 165,
        "mint_offset": 0,
        "amount_offset": 64,
        "state_offset": 108,
        "supply_offset": 36,
        "included_account_states": ["initialized", "frozen"],
        "zero_balance_policy": "include",
        "duplicate_pubkey_policy": "reject",
    },
    "continuity": {"hash_link_validation_population": "all_produced_blocks"},
    "limits": {
        "max_requests_per_provider": 500_000,
        "max_concurrency": 8,
        "max_retries": 3,
    },
    "ground_truth": {
        "source": "old_faithful_car",
        "car_path_env": "OLD_FAITHFUL_EPOCH_100_CAR",
        "car_sha256": (
            "9f6d631833a8dfe0a4253ceede8e4af18a63603f0131a71ca5e947ba77eaec5a"
        ),
        "car_root_cid": "bafyreibqt2nvroysxlxctgb52xxn27ectsllv2xyka4qar7ga6vupmbs3i",
        "source_commit": "a69a0d2e189006608e3b73b7659a957b00b3567e",
        "slots_file_name": "100.slots.txt",
        "predecessor_boundary_slot": 43_199_999,
        "produced_blocks": 402_076,
        "skipped_slots": 29_924,
        "extractor": "car_block_header",
        "endpoint_env": None,
    },
    "providers": [
        {"name": "provider-a", "url_env": "PROVIDER_A_URL", "rps": 10.0},
        {"name": "provider-b", "url_env": "PROVIDER_B_URL", "rps": 10.0},
    ],
}

ENVIRONMENT = {
    "PROVIDER_A_URL": "https://alpha.invalid/rpc?api-key=alpha",
    "PROVIDER_B_URL": "https://bravo.invalid/rpc?api-key=bravo",
    "OLD_FAITHFUL_EPOCH_100_CAR": "/tmp/epoch-100.car",
}


def payload(**overrides: object) -> dict[str, object]:
    value = copy.deepcopy(VALID)
    for key, override in overrides.items():
        if isinstance(override, dict) and isinstance(value.get(key), dict):
            value[key] = {**value[key], **override}  # type: ignore[dict-item]
        else:
            value[key] = override
    return value


class NoSilentDefaultsTests(unittest.TestCase):
    def _leaf_paths(self, value: object, prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
        if isinstance(value, dict):
            paths: list[tuple[str, ...]] = []
            for key, item in value.items():
                paths.extend(self._leaf_paths(item, (*prefix, key)))
            return paths or [prefix]
        return [prefix]

    def test_every_required_field_fails_when_omitted(self) -> None:
        """No scoping or judgment value may fall back to a code default."""

        checked = 0
        for path in self._leaf_paths(VALID):
            if not path or path[0] == "providers":
                continue
            with self.subTest(field=".".join(path)):
                candidate = copy.deepcopy(VALID)
                cursor: object = candidate
                for key in path[:-1]:
                    cursor = cursor[key]  # type: ignore[index]
                del cursor[path[-1]]  # type: ignore[index]

                with self.assertRaises(ValueError):
                    EpochAuditConfig.model_validate(candidate)
                checked += 1
        # Guard against the loop silently checking nothing.
        self.assertGreaterEqual(checked, 30)

    def test_every_required_provider_field_fails_when_omitted(self) -> None:
        for field in ("name", "url_env", "rps"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(VALID)
                del candidate["providers"][0][field]  # type: ignore[index]

                with self.assertRaises(ValueError):
                    EpochAuditConfig.model_validate(candidate)

    def test_an_unknown_key_is_a_hard_failure_at_every_level(self) -> None:
        cases = [
            payload(unexpected_top_level=1),
            payload(scope={"unexpected": 1}),
            payload(thresholds={"unexpected": 1}),
            payload(token={"unexpected": 1}),
            payload(ground_truth={"unexpected": 1}),
            payload(continuity={"unexpected": 1}),
            payload(population={"unexpected": 1}),
        ]
        for candidate in cases:
            with self.subTest(candidate=sorted(candidate)), self.assertRaises(ValueError):
                EpochAuditConfig.model_validate(candidate)

    def test_a_misspelled_threshold_is_not_silently_ignored(self) -> None:
        candidate = payload(thresholds={"indeterminate_treshold": "0.01"})

        with self.assertRaises(ValueError):
            EpochAuditConfig.model_validate(candidate)


class ExactDecimalTests(unittest.TestCase):
    def test_thresholds_are_exact_decimals(self) -> None:
        model = EpochAuditConfig.model_validate(VALID)

        self.assertEqual(model.thresholds.indeterminate_threshold, Decimal("0.01"))
        self.assertIsInstance(model.thresholds.indeterminate_threshold, Decimal)

    def test_an_unquoted_yaml_float_threshold_is_refused(self) -> None:
        candidate = payload(thresholds={"indeterminate_threshold": 0.01})

        with self.assertRaisesRegex(ValueError, "decimal string"):
            EpochAuditConfig.model_validate(candidate)

    def test_a_threshold_outside_zero_to_one_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            EpochAuditConfig.model_validate(
                payload(thresholds={"indeterminate_threshold": "1.5"})
            )


class ScopeValidationTests(unittest.TestCase):
    def test_bounds_must_match_the_declared_scheduled_positions(self) -> None:
        with self.assertRaisesRegex(ValueError, "scheduled_slot_positions"):
            EpochAuditConfig.model_validate(payload(scope={"last_slot": 43_631_998}))

    def test_the_pinned_slot_must_lie_inside_the_epoch(self) -> None:
        with self.assertRaisesRegex(ValueError, "pinned_slot"):
            EpochAuditConfig.model_validate(payload(scope={"pinned_slot": 43_632_000}))

    def test_exactly_two_providers_are_required(self) -> None:
        for providers in ([VALID["providers"][0]], [*VALID["providers"], VALID["providers"][0]]):
            with self.subTest(count=len(providers)), self.assertRaises(ValueError):
                EpochAuditConfig.model_validate(payload(providers=providers))


class ProviderDistinctnessTests(unittest.TestCase):
    def test_equal_provider_names_are_rejected(self) -> None:
        providers = [
            {"name": "same", "url_env": "PROVIDER_A_URL", "rps": 10.0},
            {"name": "SAME", "url_env": "PROVIDER_B_URL", "rps": 10.0},
        ]

        with self.assertRaisesRegex(ValueError, "different names"):
            EpochAuditConfig.model_validate(payload(providers=providers))

    def test_equal_provider_environment_variables_are_rejected(self) -> None:
        providers = [
            {"name": "provider-a", "url_env": "SHARED_URL", "rps": 10.0},
            {"name": "provider-b", "url_env": "SHARED_URL", "rps": 10.0},
        ]

        with self.assertRaisesRegex(ValueError, "different environment variables"):
            EpochAuditConfig.model_validate(payload(providers=providers))

    def test_ground_truth_may_not_reuse_a_provider_environment_variable(self) -> None:
        with self.assertRaisesRegex(ValueError, "car_path_env"):
            EpochAuditConfig.model_validate(
                payload(ground_truth={"car_path_env": "PROVIDER_A_URL"})
            )
        with self.assertRaisesRegex(ValueError, "endpoint_env"):
            EpochAuditConfig.model_validate(
                payload(ground_truth={"endpoint_env": "PROVIDER_B_URL"})
            )

    def test_equal_resolved_provider_urls_are_rejected(self) -> None:
        model = EpochAuditConfig.model_validate(VALID)
        environment = {
            **ENVIRONMENT,
            "PROVIDER_B_URL": ENVIRONMENT["PROVIDER_A_URL"],
        }

        with self.assertRaisesRegex(ConfigError, "same endpoint"):
            resolve_epoch_config(model, environment=environment)

    def test_two_credentials_on_one_host_are_not_two_providers(self) -> None:
        model = EpochAuditConfig.model_validate(VALID)
        environment = {
            **ENVIRONMENT,
            "PROVIDER_B_URL": "https://alpha.invalid/rpc?api-key=a-different-key",
        }

        with self.assertRaisesRegex(ConfigError, "same host"):
            resolve_epoch_config(model, environment=environment)

    def test_an_anchor_equal_to_a_provider_endpoint_is_rejected(self) -> None:
        model = EpochAuditConfig.model_validate(
            payload(ground_truth={"endpoint_env": "ANCHOR_URL"})
        )
        environment = {
            **ENVIRONMENT,
            "ANCHOR_URL": ENVIRONMENT["PROVIDER_A_URL"],
        }

        with self.assertRaisesRegex(ConfigError, "resolves to provider"):
            resolve_epoch_config(model, environment=environment)

    def test_an_anchor_sharing_a_host_with_a_provider_is_rejected(self) -> None:
        model = EpochAuditConfig.model_validate(
            payload(ground_truth={"endpoint_env": "ANCHOR_URL"})
        )
        environment = {
            **ENVIRONMENT,
            "ANCHOR_URL": "https://bravo.invalid/faithful",
        }

        with self.assertRaisesRegex(ConfigError, "shares a host"):
            resolve_epoch_config(model, environment=environment)

    def test_a_missing_environment_variable_is_reported_without_values(self) -> None:
        model = EpochAuditConfig.model_validate(VALID)
        environment = {k: v for k, v in ENVIRONMENT.items() if k != "PROVIDER_B_URL"}

        with self.assertRaises(ConfigError) as raised:
            resolve_epoch_config(model, environment=environment)

        self.assertIn("PROVIDER_B_URL", str(raised.exception))
        self.assertNotIn("alpha", str(raised.exception))

    def test_a_non_http_provider_url_is_rejected(self) -> None:
        model = EpochAuditConfig.model_validate(VALID)
        environment = {**ENVIRONMENT, "PROVIDER_B_URL": "not-a-url"}

        with self.assertRaisesRegex(ConfigError, "absolute HTTP"):
            resolve_epoch_config(model, environment=environment)


class ResolvedEchoTests(unittest.TestCase):
    def resolved(self):
        return resolve_epoch_config(
            EpochAuditConfig.model_validate(VALID), environment=ENVIRONMENT
        )

    def test_every_scoping_value_is_echoed_into_machine_readable_output(self) -> None:
        scope = self.resolved().scope_payload()

        self.assertEqual(scope["population"]["definition"], VALID["population"]["definition"])
        self.assertEqual(scope["scope"]["epoch"], 100)
        self.assertEqual(scope["scope"]["inclusive_slot_bounds"], [43_200_000, 43_631_999])
        self.assertEqual(scope["scope"]["commitment"], "finalized")
        self.assertEqual(scope["scope"]["pinned_slot"], 43_631_999)
        self.assertEqual(
            scope["scope"]["exact_context_policy"], "require_exact_pinned_slot"
        )
        self.assertEqual(scope["thresholds"]["indeterminate_threshold"], "0.01")
        self.assertEqual(
            scope["thresholds"]["denominator_policy"], "determinate_positions_only"
        )
        self.assertEqual(scope["thresholds"]["materiality_threshold"], "0.0001")
        self.assertEqual(scope["token"]["program_id"], VALID["token"]["program_id"])
        self.assertEqual(scope["token"]["account_size"], 165)
        self.assertEqual(scope["token"]["mint_offset"], 0)
        self.assertEqual(scope["token"]["amount_offset"], 64)
        self.assertEqual(scope["token"]["state_offset"], 108)
        self.assertEqual(
            scope["token"]["included_account_states"], ["initialized", "frozen"]
        )
        self.assertEqual(scope["token"]["zero_balance_policy"], "include")
        self.assertEqual(scope["token"]["duplicate_pubkey_policy"], "reject")
        self.assertEqual(
            scope["continuity"]["hash_link_validation_population"], "all_produced_blocks"
        )
        self.assertEqual(
            scope["ground_truth"]["car_sha256"], VALID["ground_truth"]["car_sha256"]
        )
        self.assertEqual(
            scope["ground_truth"]["car_root_cid"], VALID["ground_truth"]["car_root_cid"]
        )

    def test_the_echo_never_contains_a_secret_url(self) -> None:
        rendered = repr(self.resolved().scope_payload())

        self.assertNotIn("alpha.invalid", rendered)
        self.assertNotIn("api-key", rendered)
        for provider in self.resolved().scope_payload()["providers"]:
            self.assertEqual(len(provider["endpoint_fingerprint"]), 64)
            self.assertEqual(len(provider["host_fingerprint"]), 64)

    def test_the_config_hash_is_stable_and_scope_sensitive(self) -> None:
        first = self.resolved().config_sha256()
        again = self.resolved().config_sha256()
        changed = resolve_epoch_config(
            EpochAuditConfig.model_validate(
                payload(thresholds={"indeterminate_threshold": "0.02"})
            ),
            environment=ENVIRONMENT,
        ).config_sha256()

        self.assertEqual(first, again)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, changed)


class ShippedConfigTests(unittest.TestCase):
    def test_the_shipped_epoch_100_config_loads_and_restates_the_pinned_constants(
        self,
    ) -> None:
        model = load_epoch_config(REPO_ROOT / "config.epoch-100.yaml")

        self.assertEqual(model.scope.epoch, 100)
        self.assertEqual(model.scope.first_slot, 43_200_000)
        self.assertEqual(model.scope.last_slot, 43_631_999)
        self.assertEqual(model.ground_truth.produced_blocks, 402_076)
        self.assertEqual(model.ground_truth.skipped_slots, 29_924)
        self.assertEqual(model.ground_truth.predecessor_boundary_slot, 43_199_999)
        self.assertEqual(len(model.providers), 2)

    def test_the_shipped_config_uses_quoted_thresholds(self) -> None:
        raw = yaml.safe_load(
            (REPO_ROOT / "config.epoch-100.yaml").read_text(encoding="utf-8")
        )

        for key, value in raw["thresholds"].items():
            with self.subTest(threshold=key):
                self.assertIsInstance(value, str)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
