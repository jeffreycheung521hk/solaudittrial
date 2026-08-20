"""One table for what a Solana JSON-RPC error code means to this audit.

Knowing which code constitutes a denial, which is transient, and which is a
retention limit is the most safety-critical domain knowledge in the tool: get it
wrong and the instrument either invents findings or suppresses real ones. It was
previously spread across three modules -- ``confirms_absence`` in ``audit``,
``RETRYABLE_RPC_CODES`` in ``rpc``, and the ``-32001`` message parsing -- with no
single place stating the reasoning. This module is that place.

**Provenance of the table.** The codes and names below are transcribed from
Solana's ``RpcCustomError`` enum. They have **not** been verified against a live
node from this repository, and the semantic classifications are this project's
reading of them, not an upstream guarantee. That gap is exactly what a live
preflight probe would close; until one exists, treat the classifications as
declared-and-testable rather than confirmed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class RpcErrorCode(IntEnum):
    """Solana's custom JSON-RPC error codes."""

    BLOCK_CLEANED_UP = -32001
    SEND_TRANSACTION_PREFLIGHT_FAILURE = -32002
    TRANSACTION_SIGNATURE_VERIFICATION_FAILURE = -32003
    BLOCK_NOT_AVAILABLE = -32004
    NODE_UNHEALTHY = -32005
    TRANSACTION_PRECOMPILE_VERIFICATION_FAILURE = -32006
    SLOT_SKIPPED = -32007
    NO_SNAPSHOT = -32008
    LONG_TERM_STORAGE_SLOT_SKIPPED = -32009
    KEY_EXCLUDED_FROM_SECONDARY_INDEX = -32010
    TRANSACTION_HISTORY_NOT_AVAILABLE = -32011
    SCAN_ERROR = -32012
    TRANSACTION_SIGNATURE_LEN_MISMATCH = -32013
    BLOCK_STATUS_NOT_AVAILABLE_YET = -32014
    UNSUPPORTED_TRANSACTION_VERSION = -32015
    MIN_CONTEXT_SLOT_NOT_REACHED = -32016


@dataclass(frozen=True, slots=True)
class CodeSemantics:
    """What one code licenses this audit to conclude.

    The three flags are mutually exclusive by construction: a code cannot both
    deny a block and be worth retrying, and a retention limit is a statement
    about the provider's storage window rather than about the block.
    """

    code: int
    name: str
    #: The provider is answering that no block exists at this slot. Only these
    #: may found a conclusive PROVIDER_HOLE.
    denies_block: bool
    #: Transient. The audit failed to get an answer, and should ask again.
    retryable: bool
    #: The provider has pruned it. A storage-window limitation, never a hole.
    retention_limit: bool
    meaning: str

    def __post_init__(self) -> None:
        flags = (self.denies_block, self.retryable, self.retention_limit)
        if sum(flags) > 1:
            raise ValueError(f"{self.name} claims more than one exclusive semantic")


def _s(code: RpcErrorCode, meaning: str, **flags: bool) -> CodeSemantics:
    return CodeSemantics(
        code=int(code),
        name=code.name,
        denies_block=flags.get("denies_block", False),
        retryable=flags.get("retryable", False),
        retention_limit=flags.get("retention_limit", False),
        meaning=meaning,
    )


CODE_SEMANTICS: dict[int, CodeSemantics] = {
    int(item.code): item
    for item in (
        _s(
            RpcErrorCode.BLOCK_CLEANED_UP,
            "the block existed but this provider has pruned it; the message "
            "carries the current first available block",
            retention_limit=True,
        ),
        _s(
            RpcErrorCode.SEND_TRANSACTION_PREFLIGHT_FAILURE,
            "transaction submission concern; never produced by a read-only audit",
        ),
        _s(
            RpcErrorCode.TRANSACTION_SIGNATURE_VERIFICATION_FAILURE,
            "transaction submission concern; never produced by a read-only audit",
        ),
        _s(
            RpcErrorCode.BLOCK_NOT_AVAILABLE,
            "the block is not available *right now*; says nothing about whether "
            "it exists, so it is retried and, if it persists, indeterminate",
            retryable=True,
        ),
        _s(
            RpcErrorCode.NODE_UNHEALTHY,
            "the node is behind or unwell; an answer from it would not be "
            "evidence, so it is retried and never classified",
            retryable=True,
        ),
        _s(
            RpcErrorCode.TRANSACTION_PRECOMPILE_VERIFICATION_FAILURE,
            "transaction submission concern; never produced by a read-only audit",
        ),
        _s(
            RpcErrorCode.SLOT_SKIPPED,
            "the provider states this slot was skipped, or is missing after a "
            "ledger jump; a denial that no block exists here",
            denies_block=True,
        ),
        _s(
            RpcErrorCode.NO_SNAPSHOT,
            "snapshot concern, unrelated to block presence",
        ),
        _s(
            RpcErrorCode.LONG_TERM_STORAGE_SLOT_SKIPPED,
            "the provider's long-term storage states this slot was skipped; a "
            "denial that no block exists here",
            denies_block=True,
        ),
        _s(
            RpcErrorCode.KEY_EXCLUDED_FROM_SECONDARY_INDEX,
            "the account index cannot serve this query; affects token "
            "enumeration, not block presence",
        ),
        _s(
            RpcErrorCode.TRANSACTION_HISTORY_NOT_AVAILABLE,
            "transaction history is outside this provider's window; a storage "
            "limitation, not a statement about the block",
            retention_limit=True,
        ),
        _s(RpcErrorCode.SCAN_ERROR, "an account scan failed mid-flight"),
        _s(
            RpcErrorCode.TRANSACTION_SIGNATURE_LEN_MISMATCH,
            "malformed request; a defect in this client if it ever appears",
        ),
        _s(
            RpcErrorCode.BLOCK_STATUS_NOT_AVAILABLE_YET,
            "the block's status is not yet computed; transient by definition",
            retryable=True,
        ),
        _s(
            RpcErrorCode.UNSUPPORTED_TRANSACTION_VERSION,
            "the request did not permit a transaction version present in the "
            "block; a client defect, since this audit always sends "
            "maxSupportedTransactionVersion",
        ),
        _s(
            RpcErrorCode.MIN_CONTEXT_SLOT_NOT_REACHED,
            "the node has not yet reached the requested context slot; transient, "
            "and directly relevant to the exact-pinned-slot policy",
            retryable=True,
        ),
    )
}

#: Codes on which a direct read constitutes a denial that the block exists.
DENIAL_CODES: frozenset[int] = frozenset(
    code for code, item in CODE_SEMANTICS.items() if item.denies_block
)

#: Codes worth another attempt. Exhausting them leaves the matter indeterminate.
RETRYABLE_CODES: frozenset[int] = frozenset(
    code for code, item in CODE_SEMANTICS.items() if item.retryable
)

#: Codes describing the provider's storage window rather than the block.
RETENTION_CODES: frozenset[int] = frozenset(
    code for code, item in CODE_SEMANTICS.items() if item.retention_limit
)


def semantics_for(code: int | None) -> CodeSemantics | None:
    return None if code is None else CODE_SEMANTICS.get(int(code))


def denies_block(code: int | None) -> bool:
    return code is not None and int(code) in DENIAL_CODES


def is_retryable(code: int | None) -> bool:
    return code is not None and int(code) in RETRYABLE_CODES


def is_retention_limit(code: int | None) -> bool:
    return code is not None and int(code) in RETENTION_CODES


def describe(code: int | None) -> str:
    item = semantics_for(code)
    if item is None:
        return f"unrecognised RPC error code {code}"
    return f"{item.name} ({item.code}): {item.meaning}"


__all__ = [
    "CODE_SEMANTICS",
    "DENIAL_CODES",
    "RETENTION_CODES",
    "RETRYABLE_CODES",
    "CodeSemantics",
    "RpcErrorCode",
    "denies_block",
    "describe",
    "is_retention_limit",
    "is_retryable",
    "semantics_for",
]
