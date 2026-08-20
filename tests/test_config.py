from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from slot_audit.config import (
    AuditConfig,
    ConfigError,
    RangeConfig,
    load_config,
    redact_text,
    url_redaction_values,
)


def _write_config(path: Path, *, url: str = "${RPC_URL}", extra: str = "") -> None:
    path.write_text(
        f"""
providers:
  - name: provider-a
    url: "{url}"
    rps: 2.5
    archive: true
range:
  mode: last_days
  last_days: 0.01
sampling:
  content_check_slots: 10
  seed: 7
limits:
  max_requests_per_provider: 50
  tip_safety_margin_slots: 150
{extra}
""".lstrip(),
        encoding="utf-8",
    )


class TempDirTestCase(unittest.TestCase):
    """Provide the per-test temporary directory the old fixtures relied on."""

    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp_path = Path(self._temporary.name)


class LoadConfigTests(TempDirTestCase):
    def test_load_config_expands_dotenv_without_exposing_url(self) -> None:
        config_path = self.tmp_path / "config.yaml"
        _write_config(config_path)
        (self.tmp_path / ".env").write_text(
            "RPC_URL=https://rpc.example/?api-key=dotenv-secret\n", encoding="utf-8"
        )

        config = load_config(config_path, environment={})

        self.assertTrue(config.providers[0].rpc_url.endswith("dotenv-secret"))
        self.assertNotIn("dotenv-secret", repr(config))

    def test_process_environment_wins_over_dotenv(self) -> None:
        config_path = self.tmp_path / "config.yaml"
        _write_config(config_path)
        (self.tmp_path / ".env").write_text(
            "RPC_URL=https://dotenv.example/?key=wrong\n", encoding="utf-8"
        )

        config = load_config(
            config_path,
            environment={"RPC_URL": "https://environment.example/?key=right"},
        )

        self.assertEqual(
            config.providers[0].rpc_url, "https://environment.example/?key=right"
        )

    def test_missing_environment_names_are_clear_and_values_are_not_leaked(self) -> None:
        config_path = self.tmp_path / "config.yaml"
        _write_config(config_path, url="https://example.invalid/?key=${MISSING_KEY}")

        with self.assertRaises(ConfigError) as raised:
            load_config(config_path, environment={})

        self.assertEqual(
            str(raised.exception),
            "Missing environment variable(s) referenced by config: MISSING_KEY",
        )
        self.assertNotIn("https://", str(raised.exception))

    def test_validation_error_does_not_echo_secret_input(self) -> None:
        config_path = self.tmp_path / "config.yaml"
        _write_config(config_path)
        secret = "not-a-url-super-secret-token"

        with self.assertRaises(ConfigError) as raised:
            load_config(config_path, environment={"RPC_URL": secret})

        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("providers.0.url", str(raised.exception))


class ConfigValidationTests(unittest.TestCase):
    def test_config_rejects_invalid_collections_rates_ranges_and_budgets(self) -> None:
        cases: list[tuple[dict[str, object], str]] = [
            ({"providers": []}, "providers"),
            (
                {
                    "providers": [
                        {"name": "same", "url": "https://one.invalid", "rps": 1},
                        {"name": "SAME", "url": "https://two.invalid", "rps": 1},
                    ]
                },
                "unique",
            ),
            (
                {"providers": [{"name": "provider", "url": "https://x.invalid", "rps": 0}]},
                "greater than 0",
            ),
            ({"limits": {"max_requests_per_provider": 0}}, "greater than 0"),
            (
                {
                    "limits": {
                        "max_requests_per_provider": 1,
                        "tip_safety_margin_slots": 149,
                    }
                },
                "greater than or equal to 150",
            ),
            (
                {"range": {"mode": "explicit", "start_slot": 20, "end_slot": 10}},
                "less than or equal",
            ),
        ]
        for change, expected in cases:
            with self.subTest(change=change):
                valid: dict[str, object] = {
                    "providers": [
                        {"name": "provider", "url": "https://x.invalid", "rps": 1}
                    ],
                    "range": {"mode": "last_days", "last_days": 1},
                    "limits": {
                        "max_requests_per_provider": 1,
                        "tip_safety_margin_slots": 150,
                    },
                }
                valid.update(change)

                with self.assertRaises(ValueError) as raised:
                    AuditConfig.model_validate(valid)

                self.assertIn(expected, str(raised.exception))

    def test_fractional_last_days_resolves_an_inclusive_window(self) -> None:
        audit_range = RangeConfig(mode="last_days", last_days=0.01)

        self.assertEqual(audit_range.resolve(1_000_000), (997_841, 1_000_000))

    def test_explicit_range_is_capped_at_safe_tip(self) -> None:
        audit_range = RangeConfig(mode="explicit", start_slot=100, end_slot=300)

        self.assertEqual(audit_range.resolve(250), (100, 250))

    def test_public_fingerprint_omits_url_but_detects_endpoint_change(self) -> None:
        def make(url: str) -> AuditConfig:
            return AuditConfig.model_validate(
                {
                    "providers": [{"name": "same", "url": url, "rps": 1}],
                    "range": {"mode": "last_days", "last_days": 1},
                }
            )

        first = make("https://first.invalid/?api-key=one")
        second = make("https://second.invalid/?api-key=two")

        self.assertNotEqual(first.public_fingerprint(), second.public_fingerprint())
        self.assertNotIn("one", first.public_fingerprint())
        self.assertNotIn("two", second.public_fingerprint())

    def test_redaction_covers_bare_query_credentials_and_long_path_tokens(self) -> None:
        url = "https://user:password@example.invalid/long-secret-token/?api-key=abc"
        secrets = url_redaction_values([url])

        redacted = redact_text(
            "invalid key abc for user password at long-secret-token", secrets=secrets
        )

        self.assertNotIn("abc", redacted)
        self.assertNotIn("password", redacted)
        self.assertNotIn("long-secret-token", redacted)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
