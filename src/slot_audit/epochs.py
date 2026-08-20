"""Validated Solana epoch-schedule arithmetic for evidence rows."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MINIMUM_SLOTS_PER_EPOCH = 32


@dataclass(frozen=True, slots=True)
class EpochSchedule:
    """The fields returned by ``getEpochSchedule``."""

    slots_per_epoch: int
    leader_schedule_slot_offset: int
    warmup: bool
    first_normal_epoch: int
    first_normal_slot: int

    def __post_init__(self) -> None:
        _require_int(self.slots_per_epoch, "slotsPerEpoch", positive=True)
        _require_int(
            self.leader_schedule_slot_offset,
            "leaderScheduleSlotOffset",
            positive=True,
        )
        if not isinstance(self.warmup, bool):
            raise ValueError("warmup must be a boolean")
        _require_int(self.first_normal_epoch, "firstNormalEpoch")
        _require_int(self.first_normal_slot, "firstNormalSlot")

    @classmethod
    def from_rpc(cls, value: Mapping[str, Any]) -> EpochSchedule:
        """Parse a schedule without accepting missing or bool-as-int fields."""

        if not isinstance(value, Mapping):
            raise ValueError("getEpochSchedule result must be an object")
        try:
            return cls(
                slots_per_epoch=value["slotsPerEpoch"],
                leader_schedule_slot_offset=value["leaderScheduleSlotOffset"],
                warmup=value["warmup"],
                first_normal_epoch=value["firstNormalEpoch"],
                first_normal_slot=value["firstNormalSlot"],
            )
        except KeyError as exc:
            raise ValueError(f"getEpochSchedule result is missing {exc.args[0]}") from None

    def epoch_and_slot_index(self, slot: int) -> tuple[int, int]:
        """Return the epoch and zero-based index for an absolute slot.

        The warmup branch mirrors Solana's ``EpochSchedule`` arithmetic. Modern
        mainnet slots take the constant-time normal branch.
        """

        _require_int(slot, "slot")
        if slot >= self.first_normal_slot:
            normal_index = slot - self.first_normal_slot
            epoch_offset, slot_index = divmod(normal_index, self.slots_per_epoch)
            return self.first_normal_epoch + epoch_offset, slot_index

        # During warmup, epoch lengths are 32, 64, 128, ... slots. Solana's
        # implementation finds the next power of two above slot + 32.
        power = (slot + MINIMUM_SLOTS_PER_EPOCH).bit_length()
        epoch = power - MINIMUM_SLOTS_PER_EPOCH.bit_length()
        epoch_length = 1 << (epoch + (MINIMUM_SLOTS_PER_EPOCH.bit_length() - 1))
        first_slot = epoch_length - MINIMUM_SLOTS_PER_EPOCH
        return epoch, slot - first_slot

    def epoch_for_slot(self, slot: int) -> int:
        return self.epoch_and_slot_index(slot)[0]


def _require_int(value: object, name: str, *, positive: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{name} must be {qualifier}")


__all__ = ["MINIMUM_SLOTS_PER_EPOCH", "EpochSchedule"]
