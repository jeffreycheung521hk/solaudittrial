"""Configuration for the single-epoch audit.

Errors here never include expanded input values: RPC URLs commonly carry
credentials, so a message that echoes one turns a validation failure into a
disclosure.

This module previously also held the reconnaissance pass's configuration -- a
second set of models with a different, looser contract. They were removed with
that pass; what remains has one shape and one standard.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import yaml
from dotenv import dotenv_values
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

_PROVIDER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ConfigError(ValueError):
    """Raised for readable, credential-safe configuration failures."""


def _read_dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        values = dotenv_values(path)
    except Exception as exc:  # python-dotenv exposes several parser failure modes
        error_type = type(exc).__name__
        raise ConfigError(f"Could not read environment file {path.name}: {error_type}") from None
    return {key: value for key, value in values.items() if value is not None}


# ---------------------------------------------------------------------------
# Epoch-audit configuration.
#
# Every scoping and judgment value below is *required*.  There are no defaults,
# because a default is an unstated assumption, and an unstated assumption is not
# auditable.  ``extra="forbid"`` on every model means an unknown key is a hard
# failure rather than a silently ignored typo -- a misspelled threshold that is
# quietly ignored is worse than a crash.
# ---------------------------------------------------------------------------

_STRICT_INT = Annotated[int, Field(strict=True)]


def _exact_decimal(value: Any) -> Any:
    """Accept only exact spellings of a threshold.

    A YAML ``0.01`` is parsed as a binary float before this code ever sees it,
    so it is rejected: the whole point of the Decimal pipeline is that the
    configured threshold and the compared threshold are the same number.
    """

    if isinstance(value, bool):
        raise ValueError("must be a decimal string such as '0.01', not a boolean")
    if isinstance(value, float):
        raise ValueError(
            "must be quoted as a decimal string (for example '0.01') so the threshold "
            "is exact; a YAML float is binary and cannot be compared exactly"
        )
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        try:
            return Decimal(value.strip())
        except InvalidOperation:
            raise ValueError("must be a decimal string such as '0.01'") from None
    raise ValueError("must be a decimal string such as '0.01'")


ExactDecimal = Annotated[Decimal, BeforeValidator(_exact_decimal)]

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class PopulationConfig(BaseModel):
    """What, exactly, is being audited."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    definition: str = Field(min_length=1)
    unit: str = Field(min_length=1)
    description: str = Field(min_length=1)


class ScopeConfig(BaseModel):
    """The epoch, its inclusive bounds, and the exact-context policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    epoch: _STRICT_INT
    first_slot: _STRICT_INT
    last_slot: _STRICT_INT
    scheduled_slot_positions: _STRICT_INT
    commitment: Literal["finalized"]
    pinned_slot: _STRICT_INT
    exact_context_policy: Literal["require_exact_pinned_slot"]

    @model_validator(mode="after")
    def validate_bounds(self) -> ScopeConfig:
        if self.first_slot < 0 or self.last_slot < self.first_slot:
            raise ValueError("first_slot and last_slot must form a non-empty ascending range")
        span = self.last_slot - self.first_slot + 1
        if span != self.scheduled_slot_positions:
            raise ValueError(
                f"the inclusive slot bounds span {span} positions but "
                f"scheduled_slot_positions is {self.scheduled_slot_positions}"
            )
        if not self.first_slot <= self.pinned_slot <= self.last_slot:
            raise ValueError("pinned_slot must lie inside the audited epoch")
        return self


class ThresholdConfig(BaseModel):
    """Judgment values, all exact decimals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    indeterminate_threshold: ExactDecimal
    denominator_policy: Literal[
        "determinate_positions_only", "all_scheduled_positions"
    ]
    materiality_threshold: ExactDecimal
    minimum_provider_agreement: ExactDecimal

    @model_validator(mode="after")
    def validate_ranges(self) -> ThresholdConfig:
        for name in (
            "indeterminate_threshold",
            "materiality_threshold",
            "minimum_provider_agreement",
        ):
            value = getattr(self, name)
            if not Decimal(0) <= value <= Decimal(1):
                raise ValueError(f"{name} must be between 0 and 1 inclusive")
        return self


class TokenConfig(BaseModel):
    """The single legacy SPL Token mint and its exact decoding contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mint: str = Field(min_length=32, max_length=44)
    program_id: str = Field(min_length=32, max_length=44)
    account_size: _STRICT_INT
    mint_offset: _STRICT_INT
    amount_offset: _STRICT_INT
    state_offset: _STRICT_INT
    supply_offset: _STRICT_INT
    included_account_states: Annotated[list[str], Field(min_length=1)]
    zero_balance_policy: Literal["include", "exclude"]
    duplicate_pubkey_policy: Literal["reject", "first_wins"]

    @model_validator(mode="after")
    def validate_layout(self) -> TokenConfig:
        if self.account_size <= 0:
            raise ValueError("account_size must be positive")
        for name, width in (
            ("mint_offset", 32),
            ("amount_offset", 8),
            ("state_offset", 1),
        ):
            offset = getattr(self, name)
            if offset < 0 or offset + width > self.account_size:
                raise ValueError(f"{name} does not fit inside a {self.account_size}-byte account")
        if self.supply_offset < 0:
            raise ValueError("supply_offset must be non-negative")
        seen: set[str] = set()
        for state in self.included_account_states:
            key = state.strip().casefold()
            if key not in {"uninitialized", "initialized", "frozen"}:
                raise ValueError(f"unknown token account state {state!r}")
            if key in seen:
                raise ValueError(f"token account state {state!r} is listed twice")
            seen.add(key)
        return self


class EpochLimitsConfig(BaseModel):
    """Request policy. It bounds what the run can observe, so it is required.

    A budget cut-off manufactures indeterminate positions and a retry ceiling
    decides whether a transient error is recorded as missing data. Neither may
    be an unstated default.

    There is no concurrency setting. The audit issues calls one at a time on
    purpose -- see :class:`slot_audit.transport.AuditRpcClient` -- and a knob
    that is required but ignored is the defect this project already had to fix
    once with ``materiality_threshold``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_requests_per_provider: _STRICT_INT
    max_retries: _STRICT_INT

    @model_validator(mode="after")
    def validate_limits(self) -> EpochLimitsConfig:
        if self.max_requests_per_provider < 1:
            raise ValueError("max_requests_per_provider must be at least one")
        if not 0 <= self.max_retries <= 3:
            raise ValueError("max_retries must be between 0 and 3")
        return self


class ContinuityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hash_link_validation_population: Literal[
        "all_produced_blocks", "findings_and_adjacent"
    ]


class GroundTruthConfig(BaseModel):
    """The declared anchor.  These values must equal the pinned constants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Literal["old_faithful_car"]
    car_path_env: str = Field(min_length=1)
    car_sha256: str = Field(min_length=64, max_length=64)
    car_root_cid: str = Field(min_length=1)
    source_commit: str = Field(min_length=40, max_length=40)
    slots_file_name: str = Field(min_length=1)
    predecessor_boundary_slot: _STRICT_INT
    produced_blocks: _STRICT_INT
    skipped_slots: _STRICT_INT
    extractor: Literal["car_block_header"]
    # Required, but explicitly nullable: "there is no separate anchor endpoint"
    # is a decision that must be stated, not one that may be omitted.
    endpoint_env: str | None

    @field_validator("car_path_env", "endpoint_env")
    @classmethod
    def validate_env_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ENV_NAME.fullmatch(value):
            raise ValueError("must be an UPPER_SNAKE_CASE environment variable name")
        return value

    @field_validator("car_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        lowered = value.strip().lower()
        if any(character not in "0123456789abcdef" for character in lowered):
            raise ValueError("must be 64 lowercase hexadecimal characters")
        return lowered


class EpochProviderConfig(BaseModel):
    """One RPC provider, addressed only by the environment variable holding it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=100)
    url_env: str = Field(min_length=1)
    rps: Annotated[float, Field(gt=0, allow_inf_nan=False, strict=True)]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not _PROVIDER_NAME.fullmatch(value):
            raise ValueError(
                "must contain only letters, numbers, '.', '_' or '-', and start "
                "with a letter or number"
            )
        return value

    @field_validator("url_env")
    @classmethod
    def validate_env_name(cls, value: str) -> str:
        if not _ENV_NAME.fullmatch(value):
            raise ValueError("must be an UPPER_SNAKE_CASE environment variable name")
        return value


class EpochAuditConfig(BaseModel):
    """A complete, explicitly-scoped single-epoch audit configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    population: PopulationConfig
    scope: ScopeConfig
    thresholds: ThresholdConfig
    token: TokenConfig
    continuity: ContinuityConfig
    limits: EpochLimitsConfig
    ground_truth: GroundTruthConfig
    providers: Annotated[list[EpochProviderConfig], Field(min_length=2, max_length=2)]

    @model_validator(mode="after")
    def validate_providers_and_anchor(self) -> EpochAuditConfig:
        first, second = self.providers
        if first.name.casefold() == second.name.casefold():
            raise ValueError("the two providers must have different names")
        if first.url_env == second.url_env:
            raise ValueError(
                "the two providers must read different environment variables; reusing one "
                "variable guarantees a single upstream"
            )
        provider_envs = {first.url_env, second.url_env}
        if self.ground_truth.car_path_env in provider_envs:
            raise ValueError(
                "ground_truth.car_path_env must not reuse a provider environment variable"
            )
        if (
            self.ground_truth.endpoint_env is not None
            and self.ground_truth.endpoint_env in provider_envs
        ):
            raise ValueError(
                "ground_truth.endpoint_env must not reuse a provider environment variable"
            )
        if self.ground_truth.endpoint_env == self.ground_truth.car_path_env:
            raise ValueError("ground truth must not read one variable for two purposes")
        return self


@dataclass(frozen=True, slots=True)
class ResolvedProvider:
    """A provider after environment resolution, addressed by fingerprint."""

    name: str
    url_env: str
    url: SecretStr
    rps: float
    endpoint_fingerprint: str
    host_fingerprint: str

    @property
    def rpc_url(self) -> str:
        return self.url.get_secret_value()

    def to_payload(self) -> dict[str, object]:
        return {
            "name": self.name,
            "url_env": self.url_env,
            "rps": self.rps,
            "endpoint_fingerprint": self.endpoint_fingerprint,
            "host_fingerprint": self.host_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ResolvedEpochAuditConfig:
    """The audit's fully-resolved, credential-free scoping record."""

    config: EpochAuditConfig
    providers: tuple[ResolvedProvider, ...]
    car_path: str
    anchor_endpoint: SecretStr | None
    anchor_endpoint_fingerprint: str | None
    anchor_host_fingerprint: str | None

    def scope_payload(self) -> dict[str, object]:
        """The machine-readable echo of every scoping and judgment value."""

        model = self.config
        return {
            "schema_version": model.schema_version,
            "population": model.population.model_dump(mode="json"),
            "scope": {
                **model.scope.model_dump(mode="json"),
                "inclusive_slot_bounds": [model.scope.first_slot, model.scope.last_slot],
            },
            "thresholds": {
                "indeterminate_threshold": str(model.thresholds.indeterminate_threshold),
                "denominator_policy": model.thresholds.denominator_policy,
                "materiality_threshold": str(model.thresholds.materiality_threshold),
                "minimum_provider_agreement": str(
                    model.thresholds.minimum_provider_agreement
                ),
            },
            "token": model.token.model_dump(mode="json"),
            "continuity": model.continuity.model_dump(mode="json"),
            "limits": model.limits.model_dump(mode="json"),
            "ground_truth": model.ground_truth.model_dump(mode="json"),
            "providers": [provider.to_payload() for provider in self.providers],
            "anchor": {
                "car_path_env": model.ground_truth.car_path_env,
                "endpoint_env": model.ground_truth.endpoint_env,
                "endpoint_fingerprint": self.anchor_endpoint_fingerprint,
                "host_fingerprint": self.anchor_host_fingerprint,
            },
        }

    def config_sha256(self) -> str:
        payload = json.dumps(self.scope_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve_epoch_config(
    config: EpochAuditConfig,
    *,
    environment: Mapping[str, str] | None = None,
) -> ResolvedEpochAuditConfig:
    """Resolve environment references and reject non-independent sources.

    Two providers that differ only by API key are one provider wearing two
    names, so the host fingerprint -- not just the URL -- must differ.
    """

    from .evidence import endpoint_fingerprint, endpoint_host_fingerprint

    source = os.environ if environment is None else environment
    missing = [
        name
        for name in (
            *(provider.url_env for provider in config.providers),
            config.ground_truth.car_path_env,
            *(
                (config.ground_truth.endpoint_env,)
                if config.ground_truth.endpoint_env
                else ()
            ),
        )
        if not source.get(name)
    ]
    if missing:
        raise ConfigError(
            "Missing environment variable(s) required by config: " + ", ".join(sorted(set(missing)))
        )

    resolved: list[ResolvedProvider] = []
    for provider in config.providers:
        url = source[provider.url_env]
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ConfigError(
                f"Environment variable {provider.url_env} is not an absolute HTTP(S) URL"
            )
        resolved.append(
            ResolvedProvider(
                name=provider.name,
                url_env=provider.url_env,
                url=SecretStr(url),
                rps=provider.rps,
                endpoint_fingerprint=endpoint_fingerprint(url),
                host_fingerprint=endpoint_host_fingerprint(url),
            )
        )

    first, second = resolved
    if first.endpoint_fingerprint == second.endpoint_fingerprint:
        raise ConfigError(
            f"Providers {first.name!r} and {second.name!r} resolve to the same endpoint; "
            "two names for one URL are not two providers"
        )
    if first.host_fingerprint == second.host_fingerprint:
        raise ConfigError(
            f"Providers {first.name!r} and {second.name!r} resolve to the same host; "
            "differing only by credential does not make them independent sources"
        )

    anchor_url: SecretStr | None = None
    anchor_fingerprint: str | None = None
    anchor_host: str | None = None
    if config.ground_truth.endpoint_env:
        raw_anchor = source[config.ground_truth.endpoint_env]
        anchor_url = SecretStr(raw_anchor)
        anchor_fingerprint = endpoint_fingerprint(raw_anchor)
        anchor_host = endpoint_host_fingerprint(raw_anchor)
        for provider in resolved:
            if anchor_fingerprint == provider.endpoint_fingerprint:
                raise ConfigError(
                    f"The ground-truth anchor resolves to provider {provider.name!r}; an "
                    "anchor that is one of the audited providers proves nothing"
                )
            if anchor_host == provider.host_fingerprint:
                raise ConfigError(
                    f"The ground-truth anchor shares a host with provider {provider.name!r}; "
                    "an anchor must be an independent source"
                )

    return ResolvedEpochAuditConfig(
        config=config,
        providers=tuple(resolved),
        car_path=source[config.ground_truth.car_path_env],
        anchor_endpoint=anchor_url,
        anchor_endpoint_fingerprint=anchor_fingerprint,
        anchor_host_fingerprint=anchor_host,
    )


def load_epoch_config(
    path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    dotenv_path: str | Path | None = None,
) -> EpochAuditConfig:
    """Load and validate an epoch-audit YAML file without expanding secrets."""

    config_path = Path(path)
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(
            f"Could not read config file {config_path}: {exc.strerror or type(exc).__name__}"
        ) from None
    try:
        payload = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigError(f"Invalid YAML in {config_path.name}{location}") from None
    if not isinstance(payload, dict):
        raise ConfigError(f"Config {config_path.name} must contain a YAML mapping")
    try:
        return EpochAuditConfig.model_validate(payload)
    except ValidationError as exc:
        details: list[str] = []
        for error in exc.errors(include_url=False, include_input=False):
            location = ".".join(str(part) for part in error["loc"]) or "config"
            details.append(f"{location}: {error['msg']}")
        raise ConfigError("Invalid configuration: " + "; ".join(details)) from None


def read_environment(
    config_path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    dotenv_path: str | Path | None = None,
) -> dict[str, str]:
    """Merge a ``.env`` file with the process environment, env winning."""

    base = Path(config_path)
    env_file = Path(dotenv_path) if dotenv_path is not None else base.parent / ".env"
    merged: dict[str, str] = _read_dotenv(env_file)
    merged.update(dict(os.environ if environment is None else environment))
    return merged


__all__ = [
    "ConfigError",
    "ContinuityConfig",
    "EpochAuditConfig",
    "EpochLimitsConfig",
    "EpochProviderConfig",
    "ExactDecimal",
    "GroundTruthConfig",
    "PopulationConfig",
    "ResolvedEpochAuditConfig",
    "ResolvedProvider",
    "ScopeConfig",
    "ThresholdConfig",
    "TokenConfig",
    "load_epoch_config",
    "read_environment",
    "resolve_epoch_config",
]
