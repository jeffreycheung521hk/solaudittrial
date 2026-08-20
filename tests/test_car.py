"""The CAR/DAG-CBOR reader that makes the ground-truth binding non-negotiable."""

from __future__ import annotations

import hashlib
import io
import unittest

from slot_audit.car import (
    CarBlock,
    CarError,
    CborError,
    Cid,
    base58_decode,
    cbor_decode,
    cbor_encode,
    encode_car,
    is_base58_hash,
    iter_car_blocks,
    read_car_header,
)
from slot_audit.groundtruth import EPOCH_100_GROUND_TRUTH


class CidTests(unittest.TestCase):
    def test_published_epoch_100_root_cid_decodes_to_a_dag_cbor_sha256_cid(self) -> None:
        cid = Cid.decode(EPOCH_100_GROUND_TRUTH.car_root_cid)

        self.assertEqual(cid.version, 1)
        self.assertEqual(cid.codec, 0x71)
        self.assertEqual(cid.multihash_code, 0x12)
        self.assertEqual(len(cid.digest), 32)
        self.assertEqual(cid.encode(), EPOCH_100_GROUND_TRUTH.car_root_cid)

    def test_cid_addresses_its_own_bytes(self) -> None:
        data = cbor_encode({"kind": 2, "slot": 1})
        cid = Cid.for_data(data)

        self.assertTrue(cid.matches(data))
        self.assertFalse(cid.matches(data + b"\x00"))
        self.assertEqual(cid.digest, hashlib.sha256(data).digest())

    def test_unsupported_cid_spellings_are_rejected(self) -> None:
        for text in ("QmSomethingV0", "zNotBase32", "b"):
            with self.subTest(text=text), self.assertRaises(CarError):
                Cid.decode(text)


class CborTests(unittest.TestCase):
    def test_strict_subset_round_trips(self) -> None:
        value = {
            "kind": 2,
            "slot": 43_200_000,
            "flag": True,
            "absent": None,
            "list": [1, 2, 3],
            "bytes": b"\x01\x02",
            "text": "hello",
        }

        self.assertEqual(cbor_decode(cbor_encode(value)), value)

    def test_indefinite_length_and_floats_are_refused_not_guessed(self) -> None:
        with self.assertRaises(CborError):
            cbor_decode(b"\x9f\x01\xff")  # indefinite-length array
        with self.assertRaises(CborError):
            cbor_decode(b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00")  # float64

    def test_duplicate_map_keys_are_rejected(self) -> None:
        payload = b"\xa2" + cbor_encode("a") + cbor_encode(1) + cbor_encode("a") + cbor_encode(2)

        with self.assertRaises(CborError):
            cbor_decode(payload)

    def test_trailing_bytes_are_rejected(self) -> None:
        with self.assertRaises(CborError):
            cbor_decode(cbor_encode(1) + b"\x00")


class CarTests(unittest.TestCase):
    def _archive(self) -> tuple[bytes, Cid, CarBlock]:
        data = cbor_encode({"kind": 2, "slot": 7})
        block = CarBlock(cid=Cid.for_data(data), data=data)
        return encode_car([block.cid], [block]), block.cid, block

    def test_header_and_blocks_round_trip(self) -> None:
        archive, root, block = self._archive()
        stream = io.BytesIO(archive)

        header = read_car_header(stream)
        blocks = list(iter_car_blocks(stream))

        self.assertEqual(header.version, 1)
        self.assertEqual(header.roots, (root,))
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].cid, block.cid)
        self.assertEqual(blocks[0].decode(), {"kind": 2, "slot": 7})

    def test_a_flipped_byte_anywhere_breaks_content_addressing(self) -> None:
        archive, _root, _block = self._archive()
        corrupted = bytearray(archive)
        corrupted[-1] ^= 0xFF
        stream = io.BytesIO(bytes(corrupted))
        read_car_header(stream)

        with self.assertRaisesRegex(CarError, "does not match its own bytes"):
            list(iter_car_blocks(stream))

    def test_truncated_archive_is_an_error_not_a_short_read(self) -> None:
        archive, _root, _block = self._archive()
        stream = io.BytesIO(archive[:-3])
        read_car_header(stream)

        with self.assertRaises(CarError):
            list(iter_car_blocks(stream))

    def test_an_archive_without_a_header_is_rejected(self) -> None:
        with self.assertRaises(CarError):
            read_car_header(io.BytesIO(b""))


class SectionCeilingTests(unittest.TestCase):
    def test_an_absurd_section_length_is_refused_before_allocating(self) -> None:
        from slot_audit.car import MAX_CAR_SECTION_BYTES, _encode_varint

        data = cbor_encode({"kind": 2, "slot": 7})
        block = CarBlock(cid=Cid.for_data(data), data=data)
        archive = encode_car([block.cid], [block])
        stream = io.BytesIO(archive)
        read_car_header(stream)
        # Replace the block section with one claiming far more than exists.
        hostile = io.BytesIO(_encode_varint(MAX_CAR_SECTION_BYTES + 1) + b"\x00")

        with self.assertRaisesRegex(CarError, "ceiling"):
            list(iter_car_blocks(hostile))


class Base58Tests(unittest.TestCase):
    def test_only_32_byte_values_look_like_blockhashes(self) -> None:
        self.assertTrue(is_base58_hash("1" * 32))
        self.assertFalse(is_base58_hash("abc"))
        self.assertFalse(is_base58_hash(""))
        self.assertFalse(is_base58_hash(None))
        self.assertFalse(is_base58_hash("0OIl"))

    def test_invalid_alphabet_is_rejected(self) -> None:
        with self.assertRaises(CarError):
            base58_decode("0")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
