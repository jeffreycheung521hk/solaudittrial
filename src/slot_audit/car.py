"""A minimal, strict CAR v1 / DAG-CBOR reader used to bind ground truth.

The audit refuses to accept a "ground truth" file merely because its digest
matches something a user typed into a config file.  Instead the archive itself
must be structurally what it claims to be:

1. the file's SHA-256 equals the digest pinned *in this source tree*;
2. it parses as CAR v1 and declares exactly the pinned root CID;
3. the root CID's multihash matches the bytes of the block carrying it;
4. every block's CID matches its own payload.

Only then may records be extracted from it.  This module implements just enough
CBOR and multiformats to make those checks real, and nothing more: unsupported
CBOR features are hard errors, never best-effort guesses.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO

#: No legitimate CAR block approaches this size. A varint can claim 2**63-1
#: bytes, so the reader refuses rather than attempting the allocation.
MAX_CAR_SECTION_BYTES = 128 * 1024 * 1024

#: The header is a small map of roots. Anything larger is a hostile length claim.
MAX_CAR_HEADER_BYTES = 1024 * 1024

#: DAG-CBOR in this application is shallow. A deeply nested payload would
#: otherwise exhaust the interpreter stack and escape as RecursionError rather
#: than as the CarError the callers handle.
MAX_CBOR_DEPTH = 64

DAG_CBOR_CODEC = 0x71
RAW_CODEC = 0x55
SHA2_256 = 0x12
CID_TAG = 42

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {character: index for index, character in enumerate(_B58_ALPHABET)}


class CarError(ValueError):
    """The archive is not a well-formed, verifiable CAR v1 file."""


class CborError(CarError):
    """The payload is not the strict DAG-CBOR subset this reader accepts."""


def base58_decode(value: str) -> bytes:
    """Decode a Bitcoin-alphabet base58 string, rejecting stray characters."""

    if not isinstance(value, str) or not value:
        raise CarError("base58 value must be a non-empty string")
    number = 0
    for character in value:
        digit = _B58_INDEX.get(character)
        if digit is None:
            raise CarError("base58 value contains an invalid character")
        number = number * 58 + digit
    leading = len(value) - len(value.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * leading + body


def is_base58_hash(value: object) -> bool:
    """True only for a 32-byte base58 value, the shape of a Solana blockhash."""

    if not isinstance(value, str) or not value:
        return False
    try:
        return len(base58_decode(value)) == 32
    except CarError:
        return False


@dataclass(frozen=True, slots=True)
class Cid:
    """A CIDv1 with an explicit codec and sha2-256 multihash."""

    version: int
    codec: int
    multihash_code: int
    digest: bytes

    def __post_init__(self) -> None:
        if self.version != 1:
            raise CarError("only CIDv1 is supported")
        if self.multihash_code != SHA2_256:
            raise CarError("only sha2-256 multihashes are supported")
        if len(self.digest) != 32:
            raise CarError("sha2-256 digest must be 32 bytes")

    @property
    def bytes(self) -> bytes:
        return (
            _encode_varint(self.version)
            + _encode_varint(self.codec)
            + _encode_varint(self.multihash_code)
            + _encode_varint(len(self.digest))
            + self.digest
        )

    def encode(self) -> str:
        """Return the ``b``-prefixed base32 multibase spelling."""

        body = base64.b32encode(self.bytes).decode("ascii").rstrip("=").lower()
        return "b" + body

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.encode()

    @classmethod
    def decode(cls, text: str) -> Cid:
        if not isinstance(text, str) or len(text) < 2 or text[0] != "b":
            raise CarError("only base32 ('b'-prefixed) CIDv1 strings are supported")
        body = text[1:].upper()
        padding = (-len(body)) % 8
        try:
            raw = base64.b32decode(body + "=" * padding)
        except Exception:
            raise CarError("CID is not valid base32") from None
        cid, offset = _read_cid(raw, 0)
        if offset != len(raw):
            raise CarError("CID has trailing bytes")
        return cid

    @classmethod
    def for_data(cls, data: bytes, codec: int = DAG_CBOR_CODEC) -> Cid:
        return cls(1, codec, SHA2_256, hashlib.sha256(data).digest())

    def matches(self, data: bytes) -> bool:
        return hashlib.sha256(data).digest() == self.digest


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise CarError("varint values must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_varint_bytes(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise CarError("truncated varint")
        if shift > 63:
            raise CarError("varint is too large")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def _read_varint_stream(stream: BinaryIO) -> int | None:
    result = 0
    shift = 0
    while True:
        chunk = stream.read(1)
        if not chunk:
            if shift == 0:
                return None
            raise CarError("truncated varint at end of archive")
        if shift > 63:
            raise CarError("varint is too large")
        byte = chunk[0]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result
        shift += 7


def _read_cid(data: bytes, offset: int) -> tuple[Cid, int]:
    version, offset = _read_varint_bytes(data, offset)
    if version != 1:
        raise CarError("only CIDv1 is supported inside a CAR")
    codec, offset = _read_varint_bytes(data, offset)
    multihash_code, offset = _read_varint_bytes(data, offset)
    digest_length, offset = _read_varint_bytes(data, offset)
    if offset + digest_length > len(data):
        raise CarError("truncated multihash digest")
    digest = data[offset : offset + digest_length]
    return Cid(version, codec, multihash_code, digest), offset + digest_length


# --------------------------------------------------------------------------
# A deliberately small, strict DAG-CBOR codec.
# --------------------------------------------------------------------------


def cbor_decode(data: bytes) -> Any:
    value, offset = _cbor_decode_at(data, 0, 0)
    if offset != len(data):
        raise CborError("trailing bytes after CBOR value")
    return value


def _cbor_head(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise CborError("truncated CBOR value")
    initial = data[offset]
    offset += 1
    major = initial >> 5
    minor = initial & 0x1F
    if minor < 24:
        return major, minor, offset
    if minor in (24, 25, 26, 27):
        width = 1 << (minor - 24)
        if offset + width > len(data):
            raise CborError("truncated CBOR argument")
        argument = int.from_bytes(data[offset : offset + width], "big")
        return major, argument, offset + width
    raise CborError("indefinite-length and reserved CBOR items are not accepted")


def _cbor_decode_at(data: bytes, offset: int, depth: int = 0) -> tuple[Any, int]:
    if depth > MAX_CBOR_DEPTH:
        raise CborError(f"CBOR nesting exceeds the depth limit of {MAX_CBOR_DEPTH}")
    major, argument, offset = _cbor_head(data, offset)
    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major == 2:
        if offset + argument > len(data):
            raise CborError("truncated CBOR byte string")
        return data[offset : offset + argument], offset + argument
    if major == 3:
        if offset + argument > len(data):
            raise CborError("truncated CBOR text string")
        try:
            text = data[offset : offset + argument].decode("utf-8")
        except UnicodeDecodeError:
            raise CborError("CBOR text string is not valid UTF-8") from None
        return text, offset + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, offset = _cbor_decode_at(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        mapping: dict[str, Any] = {}
        for _ in range(argument):
            key, offset = _cbor_decode_at(data, offset, depth + 1)
            if not isinstance(key, str):
                raise CborError("DAG-CBOR map keys must be text strings")
            if key in mapping:
                raise CborError("DAG-CBOR maps must not repeat a key")
            value, offset = _cbor_decode_at(data, offset, depth + 1)
            mapping[key] = value
        return mapping, offset
    if major == 6:
        if argument != CID_TAG:
            raise CborError(f"unsupported CBOR tag {argument}")
        payload, offset = _cbor_decode_at(data, offset, depth + 1)
        if not isinstance(payload, (bytes, bytearray)) or not payload or payload[0] != 0:
            raise CborError("CID tag payload must be an identity-prefixed byte string")
        cid, consumed = _read_cid(bytes(payload), 1)
        if consumed != len(payload):
            raise CborError("CID tag payload has trailing bytes")
        return cid, offset
    if major == 7:
        if argument == 20:
            return False, offset
        if argument == 21:
            return True, offset
        if argument == 22:
            return None, offset
        raise CborError("floats and undefined are not accepted by this reader")
    raise CborError("unsupported CBOR major type")


def cbor_encode(value: Any) -> bytes:
    """Encode the same strict subset; used to build deterministic fixtures."""

    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, Cid):
        payload = b"\x00" + value.bytes
        return _cbor_head_bytes(6, CID_TAG) + cbor_encode(payload)
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head_bytes(0, value)
        return _cbor_head_bytes(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _cbor_head_bytes(2, len(value)) + bytes(value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _cbor_head_bytes(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _cbor_head_bytes(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        # DAG-CBOR orders map keys by length then bytewise.
        keys = sorted(value, key=lambda key: (len(key.encode("utf-8")), key.encode("utf-8")))
        body = b"".join(cbor_encode(key) + cbor_encode(value[key]) for key in keys)
        return _cbor_head_bytes(5, len(keys)) + body
    raise CborError(f"cannot encode {type(value).__name__} as DAG-CBOR")


def _cbor_head_bytes(major: int, argument: int) -> bytes:
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    if argument < 0x100:
        return bytes([prefix | 24, argument])
    if argument < 0x10000:
        return bytes([prefix | 25]) + argument.to_bytes(2, "big")
    if argument < 0x100000000:
        return bytes([prefix | 26]) + argument.to_bytes(4, "big")
    return bytes([prefix | 27]) + argument.to_bytes(8, "big")


@dataclass(frozen=True, slots=True)
class CarBlock:
    """One addressed block inside a CAR file."""

    cid: Cid
    data: bytes

    def decode(self) -> Any:
        if self.cid.codec != DAG_CBOR_CODEC:
            raise CarError("only DAG-CBOR blocks can be decoded")
        return cbor_decode(self.data)


@dataclass(frozen=True, slots=True)
class CarHeader:
    version: int
    roots: tuple[Cid, ...]


def read_car_header(stream: BinaryIO) -> CarHeader:
    length = _read_varint_stream(stream)
    if length is None or length == 0:
        raise CarError("CAR file has no header")
    if length > MAX_CAR_HEADER_BYTES:
        raise CarError(
            f"CAR header claims {length} bytes, above the "
            f"{MAX_CAR_HEADER_BYTES} byte ceiling"
        )
    header_bytes = stream.read(length)
    if len(header_bytes) != length:
        raise CarError("CAR header is truncated")
    header = cbor_decode(header_bytes)
    if not isinstance(header, dict):
        raise CarError("CAR header must be a map")
    if header.get("version") != 1:
        raise CarError("only CAR v1 is supported")
    roots = header.get("roots")
    if not isinstance(roots, list) or not roots:
        raise CarError("CAR header must declare at least one root")
    for root in roots:
        if not isinstance(root, Cid):
            raise CarError("CAR roots must be CIDs")
    return CarHeader(version=1, roots=tuple(roots))


def iter_car_blocks(stream: BinaryIO, *, verify: bool = True) -> Iterator[CarBlock]:
    """Yield each block, checking that its CID actually addresses its bytes."""

    while True:
        length = _read_varint_stream(stream)
        if length is None:
            return
        if length == 0:
            raise CarError("CAR block section cannot be empty")
        if length > MAX_CAR_SECTION_BYTES:
            raise CarError(
                f"CAR block section claims {length} bytes, above the "
                f"{MAX_CAR_SECTION_BYTES} byte ceiling"
            )
        section = stream.read(length)
        if len(section) != length:
            raise CarError("CAR block section is truncated")
        cid, offset = _read_cid(section, 0)
        data = section[offset:]
        if verify and not cid.matches(data):
            raise CarError(f"CAR block {cid.encode()} does not match its own bytes")
        yield CarBlock(cid=cid, data=data)


def encode_car(roots: list[Cid], blocks: list[CarBlock]) -> bytes:
    """Build a CAR v1 byte string; used to produce deterministic fixtures."""

    header = cbor_encode({"roots": roots, "version": 1})
    out = bytearray(_encode_varint(len(header)) + header)
    for block in blocks:
        section = block.cid.bytes + block.data
        out += _encode_varint(len(section)) + section
    return bytes(out)


__all__ = [
    "CID_TAG",
    "MAX_CAR_HEADER_BYTES",
    "MAX_CAR_SECTION_BYTES",
    "MAX_CBOR_DEPTH",
    "DAG_CBOR_CODEC",
    "RAW_CODEC",
    "SHA2_256",
    "CarBlock",
    "CarError",
    "CarHeader",
    "CborError",
    "Cid",
    "base58_decode",
    "cbor_decode",
    "cbor_encode",
    "encode_car",
    "is_base58_hash",
    "iter_car_blocks",
    "read_car_header",
]
