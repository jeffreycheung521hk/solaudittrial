"""Atomic, credential-free checkpoints for Pass A enumeration."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .config import redact_text

CHECKPOINT_VERSION = 3


class CheckpointError(RuntimeError):
    """A checkpoint is corrupt, incomplete, or cannot be used safely."""


class CheckpointMismatch(CheckpointError):
    """The existing checkpoint belongs to a different public configuration."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _atomic_json_write(path: Path, value: object) -> None:
    """Write JSON durably and replace ``path`` in one filesystem operation."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        # Persist the directory entry when the platform permits it.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


@dataclass(frozen=True, slots=True)
class SavedChunk:
    """The data required to resume one attempted inclusive ``getBlocks`` range."""

    provider: str
    start_slot: int
    end_slot: int
    present_slots: tuple[int, ...]
    error: str | None = None

    @property
    def successful(self) -> bool:
        return self.error is None

    @classmethod
    def from_payload(cls, payload: object) -> SavedChunk:
        if not isinstance(payload, dict):
            raise CheckpointError("Checkpoint chunk must be a JSON object")
        try:
            provider = payload["provider"]
            start_slot = payload["start_slot"]
            end_slot = payload["end_slot"]
            present = payload["present_slots"]
            error = payload.get("error")
        except KeyError as exc:
            raise CheckpointError(f"Checkpoint chunk is missing field {exc.args[0]}") from None
        if not isinstance(provider, str) or not provider:
            raise CheckpointError("Checkpoint chunk has an invalid provider")
        invalid_range = (
            not isinstance(start_slot, int)
            or not isinstance(end_slot, int)
            or start_slot > end_slot
        )
        if invalid_range:
            raise CheckpointError("Checkpoint chunk has an invalid slot range")
        if not isinstance(present, (list, tuple)) or any(
            not isinstance(slot, int) or isinstance(slot, bool) for slot in present
        ):
            raise CheckpointError("Checkpoint chunk has an invalid present_slots list")
        slots = tuple(present)
        previous: int | None = None
        for slot in slots:
            if previous is not None and slot <= previous:
                raise CheckpointError("Checkpoint present_slots must be sorted and unique")
            previous = slot
        if any(slot < start_slot or slot > end_slot for slot in slots):
            raise CheckpointError("Checkpoint present_slots contains a slot outside its range")
        if error is not None and not isinstance(error, str):
            raise CheckpointError("Checkpoint chunk error must be a string or null")
        return cls(provider, start_slot, end_slot, slots, error)

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "start_slot": self.start_slot,
            "end_slot": self.end_slot,
            "present_slots": self.present_slots,
            "error": self.error,
        }


@dataclass(slots=True)
class CheckpointState:
    config_fingerprint: str
    start_slot: int
    end_slot: int
    providers: tuple[str, ...]
    chunk_files: dict[str, str] = field(default_factory=dict)
    request_counts: dict[str, int] = field(default_factory=dict)
    finalized_tips: dict[str, int] = field(default_factory=dict)
    first_available_blocks: dict[str, int] = field(default_factory=dict)
    epoch_schedule: dict[str, int | bool] | None = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

    def to_payload(self) -> dict[str, object]:
        return {
            "version": CHECKPOINT_VERSION,
            "config_fingerprint": self.config_fingerprint,
            "range": {"start_slot": self.start_slot, "end_slot": self.end_slot},
            "providers": list(self.providers),
            "chunks": dict(sorted(self.chunk_files.items())),
            "request_counts": dict(sorted(self.request_counts.items())),
            "finalized_tips": dict(sorted(self.finalized_tips.items())),
            "first_available_blocks": dict(sorted(self.first_available_blocks.items())),
            "epoch_schedule": self.epoch_schedule,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class CheckpointStore:
    """Manage a small atomic manifest plus one immutable payload per chunk.

    The manifest is replaced after every attempted chunk, including a successful
    empty response.  Chunk payloads make large 500,000-slot responses practical
    without rewriting all prior results on each checkpoint.
    """

    def __init__(
        self,
        results_dir: str | Path,
        config_fingerprint: str,
        *,
        redact: Callable[[object], str] = redact_text,
    ) -> None:
        self.results_dir = Path(results_dir)
        self.path = self.results_dir / ".checkpoint.json"
        self.chunks_dir = self.results_dir / ".checkpoint-chunks"
        self.config_fingerprint = config_fingerprint
        self._redact = redact
        self._state: CheckpointState | None = None
        self._lock = threading.RLock()

    @staticmethod
    def _chunk_key(provider: str, start_slot: int, end_slot: int) -> str:
        return f"{provider}:{start_slot}:{end_slot}"

    @staticmethod
    def _chunk_filename(provider: str, start_slot: int, end_slot: int) -> str:
        # Provider names are constrained by config.py; also make this safe if the
        # class is used directly.
        safe_provider = "".join(
            character if character.isalnum() or character in "._-" else "_"
            for character in provider
        )
        return f"{safe_provider}-{start_slot}-{end_slot}.json"

    def load(self) -> CheckpointState | None:
        """Read and validate the manifest, without loading large chunk files."""

        if not self.path.exists():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CheckpointError(
                f"Could not read {self.path.name}: {type(exc).__name__}"
            ) from None
        if not isinstance(payload, dict) or payload.get("version") != CHECKPOINT_VERSION:
            raise CheckpointError("Unsupported or invalid checkpoint version")
        try:
            fingerprint = payload["config_fingerprint"]
            range_payload = payload["range"]
            providers_payload = payload["providers"]
            chunks_payload = payload["chunks"]
            request_counts_payload = payload["request_counts"]
            finalized_tips_payload = payload["finalized_tips"]
            first_available_payload = payload["first_available_blocks"]
            epoch_schedule_payload = payload.get("epoch_schedule")
            created_at = payload["created_at"]
            updated_at = payload["updated_at"]
        except KeyError as exc:
            raise CheckpointError(f"Checkpoint is missing field {exc.args[0]}") from None
        if not isinstance(fingerprint, str):
            raise CheckpointError("Checkpoint fingerprint is invalid")
        if not isinstance(range_payload, dict):
            raise CheckpointError("Checkpoint range is invalid")
        start = range_payload.get("start_slot")
        end = range_payload.get("end_slot")
        if not isinstance(start, int) or not isinstance(end, int) or start > end:
            raise CheckpointError("Checkpoint range is invalid")
        if (
            not isinstance(providers_payload, list)
            or any(not isinstance(provider, str) for provider in providers_payload)
            or len(set(providers_payload)) != len(providers_payload)
        ):
            raise CheckpointError("Checkpoint providers are invalid")
        if not isinstance(chunks_payload, dict) or any(
            not isinstance(key, str) or not isinstance(filename, str)
            for key, filename in chunks_payload.items()
        ):
            raise CheckpointError("Checkpoint chunk index is invalid")
        provider_set = set(providers_payload)
        for key in chunks_payload:
            try:
                provider, chunk_start_text, chunk_end_text = key.rsplit(":", 2)
                chunk_start = int(chunk_start_text)
                chunk_end = int(chunk_end_text)
            except (ValueError, TypeError):
                raise CheckpointError("Checkpoint chunk index is invalid") from None
            if (
                provider not in provider_set
                or chunk_start < start
                or chunk_end > end
                or chunk_start > chunk_end
            ):
                raise CheckpointError("Checkpoint chunk index lies outside the manifest range")
        if not isinstance(request_counts_payload, dict) or any(
            provider not in provider_set
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            for provider, count in request_counts_payload.items()
        ):
            raise CheckpointError("Checkpoint request counts are invalid")
        if set(request_counts_payload) != provider_set:
            raise CheckpointError("Checkpoint request counts do not cover every provider")
        if not isinstance(finalized_tips_payload, dict) or any(
            provider not in provider_set
            or not isinstance(slot, int)
            or isinstance(slot, bool)
            or slot < 0
            for provider, slot in finalized_tips_payload.items()
        ):
            raise CheckpointError("Checkpoint finalized tips are invalid")
        if not isinstance(first_available_payload, dict) or any(
            provider not in provider_set
            or not isinstance(slot, int)
            or isinstance(slot, bool)
            or slot < 0
            for provider, slot in first_available_payload.items()
        ):
            raise CheckpointError("Checkpoint retention boundaries are invalid")
        if epoch_schedule_payload is not None and not isinstance(epoch_schedule_payload, dict):
            raise CheckpointError("Checkpoint epoch schedule is invalid")
        if not isinstance(created_at, str) or not isinstance(updated_at, str):
            raise CheckpointError("Checkpoint timestamps are invalid")
        state = CheckpointState(
            config_fingerprint=fingerprint,
            start_slot=start,
            end_slot=end,
            providers=tuple(providers_payload),
            chunk_files=dict(chunks_payload),
            request_counts=dict(request_counts_payload),
            finalized_tips=dict(finalized_tips_payload),
            first_available_blocks=dict(first_available_payload),
            epoch_schedule=epoch_schedule_payload,
            created_at=created_at,
            updated_at=updated_at,
        )
        self._state = state
        return state

    def initialize(
        self,
        start_slot: int,
        end_slot: int,
        providers: Iterable[str],
        *,
        resume: bool = True,
        initial_request_counts: Mapping[str, int] | None = None,
        finalized_tips: Mapping[str, int] | None = None,
    ) -> CheckpointState:
        """Create a run manifest or validate the one being resumed."""

        provider_tuple = tuple(providers)
        if start_slot < 0 or end_slot < start_slot:
            raise ValueError("invalid checkpoint slot range")
        if not provider_tuple or len(set(provider_tuple)) != len(provider_tuple):
            raise ValueError("checkpoint providers must be non-empty and unique")
        with self._lock:
            existing = self.load() if resume else None
            if existing is not None:
                matches = (
                    existing.config_fingerprint == self.config_fingerprint
                    and existing.start_slot == start_slot
                    and existing.end_slot == end_slot
                    and existing.providers == provider_tuple
                )
                if not matches:
                    raise CheckpointMismatch(
                        "Existing checkpoint does not match this configuration and slot range; "
                        "use --no-resume or a different results directory"
                    )
                return existing

            counts = (
                {provider: 0 for provider in provider_tuple}
                if initial_request_counts is None
                else dict(initial_request_counts)
            )
            if set(counts) != set(provider_tuple) or any(
                not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
                for count in counts.values()
            ):
                raise ValueError("initial request counts must cover every provider")
            tips = {} if finalized_tips is None else dict(finalized_tips)
            if any(
                provider not in provider_tuple
                or not isinstance(slot, int)
                or isinstance(slot, bool)
                or slot < 0
                for provider, slot in tips.items()
            ):
                raise ValueError("finalized tips must contain valid configured providers")
            self._state = CheckpointState(
                self.config_fingerprint,
                start_slot,
                end_slot,
                provider_tuple,
                request_counts=counts,
                finalized_tips=tips,
            )
            _atomic_json_write(self.path, self._state.to_payload())
            return self._state

    def record_chunk(
        self,
        provider: str,
        start_slot: int,
        end_slot: int,
        present_slots: Sequence[int],
        *,
        error: object | None = None,
        request_count: int | None = None,
    ) -> SavedChunk:
        """Atomically checkpoint one attempted chunk and update the manifest."""

        with self._lock:
            if self._state is None:
                raise CheckpointError("CheckpointStore must be initialized before recording chunks")
            if provider not in self._state.providers:
                raise CheckpointError(f"Unknown checkpoint provider {provider!r}")
            if start_slot < self._state.start_slot or end_slot > self._state.end_slot:
                raise CheckpointError("Checkpoint chunk lies outside the manifest slot range")
            sanitized_error = None if error is None else self._redact(error)
            chunk = SavedChunk(
                provider,
                start_slot,
                end_slot,
                tuple(present_slots),
                sanitized_error,
            )
            # Apply the same strict checks on write as on read.
            chunk = SavedChunk.from_payload(chunk.to_payload())
            filename = self._chunk_filename(provider, start_slot, end_slot)
            _atomic_json_write(self.chunks_dir / filename, chunk.to_payload())
            key = self._chunk_key(provider, start_slot, end_slot)
            self._state.chunk_files[key] = filename
            if request_count is not None:
                self._set_request_count(provider, request_count)
            self._state.updated_at = _utc_now()
            _atomic_json_write(self.path, self._state.to_payload())
            return chunk

    def iter_chunks_for_provider(
        self, provider: str, *, successful_only: bool = False
    ) -> Iterable[SavedChunk]:
        """Stream indexed chunks for ``provider`` in slot order.

        Callers preparing ``resume_chunks`` should pass ``successful_only=True``:
        failed attempts remain auditable in the checkpoint but must be retried.
        """

        with self._lock:
            if self._state is None:
                self.load()
            if self._state is None:
                return
            prefix = f"{provider}:"
            indexed = sorted(
                (
                    (key, filename)
                    for key, filename in self._state.chunk_files.items()
                    if key.startswith(prefix)
                ),
                key=lambda item: tuple(int(value) for value in item[0].rsplit(":", 2)[1:]),
            )
        for key, filename in indexed:
            with self._lock:
                path = self.chunks_dir / filename
                try:
                    # Resolving first prevents a malicious manifest from escaping
                    # the results directory.
                    if path.resolve().parent != self.chunks_dir.resolve():
                        raise CheckpointError("Checkpoint chunk path escapes its directory")
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except CheckpointError:
                    raise
                except (OSError, json.JSONDecodeError) as exc:
                    raise CheckpointError(
                        f"Could not read checkpoint chunk {filename}: {type(exc).__name__}"
                    ) from None
                chunk = SavedChunk.from_payload(payload)
                del payload
                if chunk.provider != provider:
                    raise CheckpointError("Checkpoint chunk provider does not match its index")
                expected = self._chunk_key(provider, chunk.start_slot, chunk.end_slot)
                if key != expected:
                    raise CheckpointError("Checkpoint chunk range does not match its index")
                if not successful_only or chunk.successful:
                    yield chunk

    def chunks_for_provider(
        self, provider: str, *, successful_only: bool = False
    ) -> tuple[SavedChunk, ...]:
        """Compatibility wrapper that materializes streamed chunks."""

        return tuple(
            self.iter_chunks_for_provider(provider, successful_only=successful_only)
        )

    def update_provider_progress(
        self,
        provider: str,
        *,
        request_count: int,
        finalized_tip: int | None = None,
        first_available_block: int | None = None,
    ) -> None:
        """Persist cumulative actual attempts and an optional retention boundary."""

        with self._lock:
            if self._state is None:
                raise CheckpointError("CheckpointStore must be initialized before progress updates")
            if provider not in self._state.providers:
                raise CheckpointError(f"Unknown checkpoint provider {provider!r}")
            self._set_request_count(provider, request_count)
            if finalized_tip is not None:
                if (
                    not isinstance(finalized_tip, int)
                    or isinstance(finalized_tip, bool)
                    or finalized_tip < 0
                ):
                    raise ValueError("finalized_tip must be a non-negative integer")
                self._state.finalized_tips[provider] = finalized_tip
            if first_available_block is not None:
                if (
                    not isinstance(first_available_block, int)
                    or isinstance(first_available_block, bool)
                    or first_available_block < 0
                ):
                    raise ValueError("first_available_block must be a non-negative integer")
                self._state.first_available_blocks[provider] = first_available_block
            self._state.updated_at = _utc_now()
            _atomic_json_write(self.path, self._state.to_payload())

    def set_epoch_schedule(self, schedule: dict[str, int | bool]) -> None:
        """Persist the public network epoch schedule for deterministic resume."""

        allowed = {
            "slotsPerEpoch",
            "leaderScheduleSlotOffset",
            "warmup",
            "firstNormalEpoch",
            "firstNormalSlot",
        }
        if set(schedule) != allowed or any(
            not isinstance(value, (int, bool)) for value in schedule.values()
        ):
            raise ValueError("invalid epoch schedule payload")
        with self._lock:
            if self._state is None:
                raise CheckpointError("CheckpointStore must be initialized before schedule updates")
            self._state.epoch_schedule = dict(schedule)
            self._state.updated_at = _utc_now()
            _atomic_json_write(self.path, self._state.to_payload())

    def _set_request_count(self, provider: str, request_count: int) -> None:
        assert self._state is not None
        invalid_count = (
            not isinstance(request_count, int)
            or isinstance(request_count, bool)
            or request_count < 0
        )
        if invalid_count:
            raise ValueError("request_count must be a non-negative integer")
        previous = self._state.request_counts[provider]
        if request_count < previous:
            raise CheckpointError("Cumulative request count cannot decrease")
        self._state.request_counts[provider] = request_count


__all__ = [
    "CHECKPOINT_VERSION",
    "CheckpointError",
    "CheckpointMismatch",
    "CheckpointState",
    "CheckpointStore",
    "SavedChunk",
]
