"""Reconcile enumerated legacy SPL Token accounts against the mint's supply.

The measurement is a subtraction, and the sign of that subtraction is the whole
point: ``enumerated_total - mint_supply``.  A provider that truncates its
``getProgramAccounts`` answer under-reports, so the difference goes negative by
exactly the balance of whatever it dropped.  Reporting the signed difference --
rather than an absolute discrepancy or a boolean -- is what makes the omission
attributable.

Every layout constant (program id, account size, field offsets, which account
states count) is supplied by the caller from configuration.  There are no
defaults here on purpose: a silently assumed offset would silently change what
the number means.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum

from .evidence import EvidenceRef

#: The original (non-2022) SPL Token program.
LEGACY_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


class TokenError(ValueError):
    """Token account or mint data could not be decoded as declared."""


class AccountState(IntEnum):
    UNINITIALIZED = 0
    INITIALIZED = 1
    FROZEN = 2


ACCOUNT_STATE_NAMES: Mapping[str, AccountState] = {
    "uninitialized": AccountState.UNINITIALIZED,
    "initialized": AccountState.INITIALIZED,
    "frozen": AccountState.FROZEN,
}


class ZeroBalancePolicy(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class DuplicatePubkeyPolicy(StrEnum):
    REJECT = "reject"
    FIRST_WINS = "first_wins"


@dataclass(frozen=True, slots=True)
class TokenScope:
    """The explicitly configured shape of the token population."""

    program_id: str
    account_size: int
    mint_offset: int
    amount_offset: int
    state_offset: int
    supply_offset: int
    included_account_states: tuple[AccountState, ...]
    zero_balance_policy: ZeroBalancePolicy
    duplicate_pubkey_policy: DuplicatePubkeyPolicy

    def __post_init__(self) -> None:
        if not self.program_id:
            raise TokenError("token program id must be configured")
        if self.account_size <= 0:
            raise TokenError("token account size must be positive")
        for name, offset, width in (
            ("mint_offset", self.mint_offset, 32),
            ("amount_offset", self.amount_offset, 8),
            ("state_offset", self.state_offset, 1),
        ):
            if offset < 0 or offset + width > self.account_size:
                raise TokenError(f"{name} does not fit inside a {self.account_size}-byte account")
        if self.supply_offset < 0:
            raise TokenError("supply_offset must be non-negative")
        if not self.included_account_states:
            raise TokenError("at least one account state must be included")

    def to_payload(self) -> dict[str, object]:
        return {
            "program_id": self.program_id,
            "account_size": self.account_size,
            "mint_offset": self.mint_offset,
            "amount_offset": self.amount_offset,
            "state_offset": self.state_offset,
            "supply_offset": self.supply_offset,
            "included_account_states": [
                state.name.lower() for state in self.included_account_states
            ],
            "zero_balance_policy": self.zero_balance_policy.value,
            "duplicate_pubkey_policy": self.duplicate_pubkey_policy.value,
        }


@dataclass(frozen=True, slots=True)
class TokenAccountRecord:
    pubkey: str
    mint: str
    amount: int
    state: AccountState

    def to_payload(self) -> dict[str, object]:
        return {
            "pubkey": self.pubkey,
            "mint": self.mint,
            "amount": self.amount,
            "state": self.state.name.lower(),
        }


def _account_bytes(value: object, *, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        items = list(value)
        if len(items) == 2 and isinstance(items[0], str) and items[1] == "base64":
            try:
                return base64.b64decode(items[0], validate=True)
            except Exception:
                raise TokenError(f"{label} data is not valid base64") from None
    raise TokenError(f"{label} data must be a [base64, 'base64'] pair")


def decode_token_account(
    pubkey: str,
    raw: object,
    *,
    scope: TokenScope,
    encoded_mint: str,
) -> TokenAccountRecord:
    """Decode one 165-byte legacy token account exactly as configured."""

    data = _account_bytes(raw, label=f"token account {pubkey}")
    if len(data) != scope.account_size:
        raise TokenError(
            f"token account {pubkey} is {len(data)} bytes, expected {scope.account_size}"
        )
    mint = base58_encode(data[scope.mint_offset : scope.mint_offset + 32])
    if mint != encoded_mint:
        raise TokenError(
            f"token account {pubkey} belongs to mint {mint}, not the audited mint"
        )
    amount = int.from_bytes(
        data[scope.amount_offset : scope.amount_offset + 8], "little", signed=False
    )
    raw_state = data[scope.state_offset]
    try:
        state = AccountState(raw_state)
    except ValueError:
        raise TokenError(f"token account {pubkey} has unknown state byte {raw_state}") from None
    return TokenAccountRecord(pubkey=pubkey, mint=mint, amount=amount, state=state)


def decode_mint_supply(raw: object, *, scope: TokenScope) -> int:
    data = _account_bytes(raw, label="mint account")
    end = scope.supply_offset + 8
    if len(data) < end:
        raise TokenError(f"mint account is {len(data)} bytes; supply offset does not fit")
    return int.from_bytes(data[scope.supply_offset : end], "little", signed=False)


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    digits = ""
    while number:
        number, remainder = divmod(number, 58)
        digits = _B58_ALPHABET[remainder] + digits
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + digits


@dataclass(frozen=True, slots=True)
class TokenReconciliation:
    """The signed reconciliation of one mint at one exact context slot."""

    mint: str
    pinned_slot: int
    context_slot: int | None
    scope: TokenScope
    returned_accounts: int
    included_accounts: int
    excluded_accounts: int
    duplicate_pubkeys: tuple[str, ...]
    enumerated_total: int
    mint_supply: int | None
    evidence: tuple[EvidenceRef, ...] = ()
    indeterminate_reasons: tuple[str, ...] = ()

    @property
    def signed_difference(self) -> int | None:
        """``enumerated_total - mint_supply``; negative means under-reporting."""

        if self.mint_supply is None:
            return None
        return self.enumerated_total - self.mint_supply

    @property
    def reconciled(self) -> bool:
        return self.signed_difference == 0 and not self.indeterminate_reasons

    @property
    def exact_context(self) -> bool:
        return self.context_slot == self.pinned_slot

    def to_payload(self) -> dict[str, object]:
        return {
            "mint": self.mint,
            "pinned_slot": self.pinned_slot,
            "context_slot": self.context_slot,
            "exact_context": self.exact_context,
            "scope": self.scope.to_payload(),
            "returned_accounts": self.returned_accounts,
            "included_accounts": self.included_accounts,
            "excluded_accounts": self.excluded_accounts,
            "duplicate_pubkeys": list(self.duplicate_pubkeys),
            "enumerated_total_base_units": self.enumerated_total,
            "mint_supply_base_units": self.mint_supply,
            "signed_difference_base_units": self.signed_difference,
            "reconciled": self.reconciled,
            "indeterminate_reasons": list(self.indeterminate_reasons),
            "evidence": [ref.to_payload() for ref in self.evidence],
        }


def reconcile_mint(
    *,
    mint: str,
    pinned_slot: int,
    scope: TokenScope,
    program_accounts: object,
    mint_account: object,
    context_slot: int | None,
    evidence: Sequence[EvidenceRef] = (),
    indeterminate_reasons: Sequence[str] = (),
) -> TokenReconciliation:
    """Sum the configured token population and subtract the declared supply."""

    reasons = list(indeterminate_reasons)
    records: list[TokenAccountRecord] = []
    seen: dict[str, TokenAccountRecord] = {}
    duplicates: list[str] = []
    returned = 0

    if not isinstance(program_accounts, Sequence) or isinstance(program_accounts, (str, bytes)):
        reasons.append("getProgramAccounts did not return a list of accounts")
        program_accounts = []

    for entry in program_accounts:
        returned += 1
        if not isinstance(entry, Mapping):
            raise TokenError("each program account entry must be an object")
        pubkey = entry.get("pubkey")
        account = entry.get("account")
        if not isinstance(pubkey, str) or not isinstance(account, Mapping):
            raise TokenError("program account entry is missing pubkey or account")
        record = decode_token_account(pubkey, account.get("data"), scope=scope, encoded_mint=mint)
        if pubkey in seen:
            duplicates.append(pubkey)
            if scope.duplicate_pubkey_policy is DuplicatePubkeyPolicy.REJECT:
                raise TokenError(
                    f"duplicate pubkey {pubkey} returned by getProgramAccounts and the "
                    "configured duplicate_pubkey_policy is 'reject'"
                )
            continue
        seen[pubkey] = record
        records.append(record)

    included: list[TokenAccountRecord] = []
    excluded = 0
    for record in records:
        if record.state not in scope.included_account_states:
            excluded += 1
            continue
        if record.amount == 0 and scope.zero_balance_policy is ZeroBalancePolicy.EXCLUDE:
            excluded += 1
            continue
        included.append(record)

    total = sum(record.amount for record in included)

    supply: int | None
    try:
        supply = _extract_mint_supply(mint_account, scope=scope)
    except TokenError as exc:
        supply = None
        reasons.append(str(exc))

    if context_slot is None:
        reasons.append("no response context slot was returned for the token enumeration")
    elif context_slot != pinned_slot:
        reasons.append(
            f"token enumeration context slot {context_slot} is not the pinned slot {pinned_slot}"
        )

    return TokenReconciliation(
        mint=mint,
        pinned_slot=pinned_slot,
        context_slot=context_slot,
        scope=scope,
        returned_accounts=returned,
        included_accounts=len(included),
        excluded_accounts=excluded,
        duplicate_pubkeys=tuple(duplicates),
        enumerated_total=total,
        mint_supply=supply,
        evidence=tuple(evidence),
        indeterminate_reasons=tuple(reasons),
    )


def _extract_mint_supply(mint_account: object, *, scope: TokenScope) -> int:
    if mint_account is None:
        raise TokenError("getAccountInfo returned null for the mint")
    if not isinstance(mint_account, Mapping):
        raise TokenError("mint account payload is not an object")
    return decode_mint_supply(mint_account.get("data"), scope=scope)


def encode_token_account(
    *,
    mint: str,
    owner: str,
    amount: int,
    state: AccountState,
    scope: TokenScope,
) -> bytes:
    """Build a byte-accurate token account; used by fixtures and controls."""

    from .car import base58_decode

    data = bytearray(scope.account_size)
    data[scope.mint_offset : scope.mint_offset + 32] = base58_decode(mint).rjust(32, b"\x00")
    owner_bytes = base58_decode(owner).rjust(32, b"\x00")
    data[32:64] = owner_bytes
    data[scope.amount_offset : scope.amount_offset + 8] = int(amount).to_bytes(8, "little")
    data[scope.state_offset] = int(state)
    return bytes(data)


def encode_mint_account(*, supply: int, scope: TokenScope, size: int = 82) -> bytes:
    data = bytearray(size)
    data[scope.supply_offset : scope.supply_offset + 8] = int(supply).to_bytes(8, "little")
    data[scope.supply_offset + 8] = 9  # decimals
    data[scope.supply_offset + 9] = 1  # is_initialized
    return bytes(data)


def encode_account_payload(data: bytes, *, owner: str) -> dict[str, object]:
    return {
        "data": [base64.b64encode(data).decode("ascii"), "base64"],
        "executable": False,
        "lamports": 2_039_280,
        "owner": owner,
        "rentEpoch": 0,
        "space": len(data),
    }


def parse_account_states(names: Iterable[str]) -> tuple[AccountState, ...]:
    states: list[AccountState] = []
    for name in names:
        key = str(name).strip().casefold()
        if key not in ACCOUNT_STATE_NAMES:
            raise TokenError(f"unknown token account state {name!r}")
        state = ACCOUNT_STATE_NAMES[key]
        if state in states:
            raise TokenError(f"token account state {name!r} is listed twice")
        states.append(state)
    return tuple(states)


__all__ = [
    "ACCOUNT_STATE_NAMES",
    "LEGACY_TOKEN_PROGRAM_ID",
    "AccountState",
    "DuplicatePubkeyPolicy",
    "TokenAccountRecord",
    "TokenError",
    "TokenReconciliation",
    "TokenScope",
    "ZeroBalancePolicy",
    "base58_encode",
    "decode_mint_supply",
    "decode_token_account",
    "encode_account_payload",
    "encode_mint_account",
    "encode_token_account",
    "parse_account_states",
    "reconcile_mint",
]
