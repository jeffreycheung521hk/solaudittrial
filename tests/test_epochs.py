from __future__ import annotations

import unittest

from slot_audit.epochs import EpochSchedule


class NormalEpochTests(unittest.TestCase):
    def test_normal_epoch_mapping(self) -> None:
        schedule = EpochSchedule.from_rpc(
            {
                "slotsPerEpoch": 432_000,
                "leaderScheduleSlotOffset": 432_000,
                "warmup": False,
                "firstNormalEpoch": 0,
                "firstNormalSlot": 0,
            }
        )

        self.assertEqual(schedule.epoch_and_slot_index(0), (0, 0))
        self.assertEqual(schedule.epoch_and_slot_index(431_999), (0, 431_999))
        self.assertEqual(schedule.epoch_and_slot_index(432_000), (1, 0))
        self.assertEqual(schedule.epoch_for_slot(340_123_456), 787)

    def test_epoch_100_bounds_match_the_published_constants(self) -> None:
        """Epoch 100 is the audited epoch; its arithmetic must be exact."""

        schedule = EpochSchedule.from_rpc(
            {
                "slotsPerEpoch": 432_000,
                "leaderScheduleSlotOffset": 432_000,
                "warmup": False,
                "firstNormalEpoch": 0,
                "firstNormalSlot": 0,
            }
        )

        self.assertEqual(schedule.epoch_and_slot_index(43_200_000), (100, 0))
        self.assertEqual(schedule.epoch_and_slot_index(43_631_999), (100, 431_999))
        self.assertEqual(schedule.epoch_for_slot(43_199_999), 99)
        self.assertEqual(schedule.epoch_for_slot(43_632_000), 101)


class WarmupEpochTests(unittest.TestCase):
    def test_warmup_epoch_mapping_matches_solana_boundaries(self) -> None:
        schedule = EpochSchedule(
            slots_per_epoch=432_000,
            leader_schedule_slot_offset=432_000,
            warmup=True,
            first_normal_epoch=14,
            first_normal_slot=524_256,
        )

        self.assertEqual(schedule.epoch_and_slot_index(0), (0, 0))
        self.assertEqual(schedule.epoch_and_slot_index(31), (0, 31))
        self.assertEqual(schedule.epoch_and_slot_index(32), (1, 0))
        self.assertEqual(schedule.epoch_and_slot_index(95), (1, 63))
        self.assertEqual(schedule.epoch_and_slot_index(96), (2, 0))
        self.assertEqual(schedule.epoch_and_slot_index(524_255), (13, 262_143))
        self.assertEqual(schedule.epoch_and_slot_index(524_256), (14, 0))


class InvalidScheduleTests(unittest.TestCase):
    def test_invalid_epoch_schedule_is_rejected(self) -> None:
        payloads: list[dict[str, object]] = [
            {},
            {
                "slotsPerEpoch": 0,
                "leaderScheduleSlotOffset": 1,
                "warmup": False,
                "firstNormalEpoch": 0,
                "firstNormalSlot": 0,
            },
            {
                "slotsPerEpoch": 10,
                "leaderScheduleSlotOffset": 10,
                "warmup": 0,
                "firstNormalEpoch": 0,
                "firstNormalSlot": 0,
            },
        ]
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                EpochSchedule.from_rpc(payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
