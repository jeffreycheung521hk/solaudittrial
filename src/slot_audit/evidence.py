"""Self-contained, re-performable evidence retention.

Every supporting RPC call is stored twice: the exact response bytes as they left
the provider, and a sanitized request record that never contains a credential.
A run therefore stands on its own -- a reviewer can recompute every digest in the
summary without contacting a provider and without trusting this process.

Three properties are load-bearing for audit use:

* **Byte fidelity.** Raw payloads are written verbatim.  Nothing is re-encoded,
  re-ordered, or pretty-printed, so a SHA-256 in the summary is a digest of what
  the provider actually returned.
* **Closed-world verification.** :meth:`EvidenceStore.verify` reports missing,
  modified *and* unexpected unmanifested files.  An artifact that nobody
  declared is a finding, not a curiosity.

  The manifest is **not signed**, and without a key it cannot be. It detects
  accidental corruption, partial loss and naive editing -- someone who changes a
  retained response but not the manifest. It does **not** detect an editor who
  also recomputes the affected digest and rewrites the manifest, and the same
  applies to ``write_order``, which is ordinary JSON inside that manifest. The
  guarantee is integrity against damage and casual tampering, not authenticity
  against a motivated forger with write access to the directory.
* **Append-only runs.** A store refuses to open on a directory that already
  holds evidence, so a re-run can never quietly overwrite the record it is
  supposed to be checked against.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

MANIFEST_NAME = "manifest.json"
PROVENANCE_NAME = "provenance.json"
MANIFEST_VERSION = 1

_RAW_DIR = "raw"
_META_DIR = "meta"
_ARTIFACT_DIR = "artifacts"


class EvidenceError(RuntimeError):
    """Evidence could not be retained, located, or verified."""


#: Read granularity for digesting files that do not fit in memory.
STREAM_CHUNK_BYTES = 4 * 1024 * 1024


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, *, chunk_bytes: int = STREAM_CHUNK_BYTES) -> str:
    """Digest a file without loading it.

    The epoch-100 archive is reported to be 62.9 GB. Reading a file that size
    into memory would put the anchor out of reach of the machines most likely to
    be checking it, so every read path here is incremental.
    """

    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def endpoint_fingerprint(url: str) -> str:
    """Fingerprint a full endpoint, credentials included, without disclosing it.

    Two providers that differ only by API key produce different values here but
    the same :func:`endpoint_host_fingerprint`, which is what actually decides
    whether they are independent sources.
    """

    if not isinstance(url, str) or not url:
        raise EvidenceError("endpoint URL must be a non-empty string")
    return hashlib.sha256(b"slot-audit-endpoint\x00" + url.encode("utf-8")).hexdigest()


def endpoint_host_fingerprint(url: str) -> str:
    """Fingerprint only scheme, host and port: the upstream identity."""

    from urllib.parse import urlsplit

    if not isinstance(url, str) or not url:
        raise EvidenceError("endpoint URL must be a non-empty string")
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold()
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.casefold() == "https" else 80
    identity = f"{parsed.scheme.casefold()}://{host}:{port}"
    return hashlib.sha256(b"slot-audit-host\x00" + identity.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A pointer that is sufficient on its own to re-verify one artifact."""

    relative_path: str
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        if not self.relative_path or self.relative_path.startswith("/"):
            raise EvidenceError("evidence path must be a non-empty relative path")
        if ".." in Path(self.relative_path).parts:
            raise EvidenceError("evidence path must not traverse outside the store")
        if len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256):
            raise EvidenceError("evidence sha256 must be 64 lowercase hex characters")
        if self.byte_length < 0:
            raise EvidenceError("evidence byte_length cannot be negative")

    def to_payload(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> EvidenceRef:
        try:
            return cls(
                relative_path=str(payload["relative_path"]),
                sha256=str(payload["sha256"]),
                byte_length=int(payload["byte_length"]),  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(f"invalid evidence reference: {type(exc).__name__}") from None

    def describe(self) -> str:
        """Render the three fields the summary is required to display."""

        return f"{self.relative_path} (sha256={self.sha256}, {self.byte_length} bytes)"


@dataclass(frozen=True, slots=True)
class CallEvidence:
    """Both halves of one recorded RPC call."""

    sequence: int
    provider: str
    method: str
    raw: EvidenceRef
    request: EvidenceRef

    def refs(self) -> tuple[EvidenceRef, EvidenceRef]:
        return (self.raw, self.request)


@dataclass(frozen=True, slots=True)
class ManifestVerification:
    """The closed-world comparison of a manifest against the filesystem."""

    missing: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()
    unexpected: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not (self.missing or self.modified or self.unexpected)

    def to_payload(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "missing": list(self.missing),
            "modified": list(self.modified),
            "unexpected": list(self.unexpected),
        }

    def describe(self) -> str:
        if self.ok:
            return (
                "manifest verified: no missing, modified or unexpected files "
                "(unsigned: this rules out damage and naive edits, not a forger "
                "who also rewrote the manifest)"
            )
        parts = []
        if self.missing:
            parts.append(f"missing={list(self.missing)}")
        if self.modified:
            parts.append(f"modified={list(self.modified)}")
        if self.unexpected:
            parts.append(f"unexpected={list(self.unexpected)}")
        return "manifest verification failed: " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class ToolProvenance:
    """Everything needed to identify the instrument that produced a run."""

    package_version: str
    source_tree_sha256: str
    python_version: str
    platform: str
    resolved_config_sha256: str
    run_started_at: str
    run_completed_at: str | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "package_version": self.package_version,
            "source_tree_sha256": self.source_tree_sha256,
            "python_version": self.python_version,
            "platform": self.platform,
            "resolved_config_sha256": self.resolved_config_sha256,
            "run_started_at": self.run_started_at,
            "run_completed_at": self.run_completed_at,
        }

    def completed(self, timestamp: str) -> ToolProvenance:
        return ToolProvenance(
            package_version=self.package_version,
            source_tree_sha256=self.source_tree_sha256,
            python_version=self.python_version,
            platform=self.platform,
            resolved_config_sha256=self.resolved_config_sha256,
            run_started_at=self.run_started_at,
            run_completed_at=timestamp,
        )

    @property
    def is_complete(self) -> bool:
        return bool(
            self.package_version
            and len(self.source_tree_sha256) == 64
            and self.python_version
            and len(self.resolved_config_sha256) == 64
            and self.run_started_at
            and self.run_completed_at
        )


def source_tree_sha256(package_root: Path | None = None) -> str:
    """Hash the instrument's own source so a run pins the code that made it.

    An immutable VCS revision would be preferable, but this repository is not
    guaranteed to be a checkout, so the content hash is the honest fallback and
    is recorded as such.
    """

    root = Path(__file__).resolve().parent if package_root is None else Path(package_root)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def build_provenance(*, resolved_config_sha256: str, started_at: str) -> ToolProvenance:
    from . import __version__

    return ToolProvenance(
        package_version=__version__,
        source_tree_sha256=source_tree_sha256(),
        python_version=f"{platform.python_implementation()} {sys.version.split()[0]}",
        platform=f"{platform.system()} {platform.release()} {platform.machine()}",
        resolved_config_sha256=resolved_config_sha256,
        run_started_at=started_at,
    )


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class EvidenceStore:
    """An append-only, manifest-backed directory of audit evidence."""

    def __init__(self, root: str | Path, *, allow_existing: bool = False) -> None:
        self.root = Path(root)
        if self.root.exists():
            existing = [child for child in self.root.iterdir()]
            if existing and not allow_existing:
                raise EvidenceError(
                    f"evidence directory {self.root} is not empty; a previous run must "
                    "never be overwritten. Choose a new directory."
                )
        self.root.mkdir(parents=True, exist_ok=True)
        self._entries: dict[str, EvidenceRef] = {}
        self._calls: list[CallEvidence] = []
        self._sequence = 0
        self._provenance: ToolProvenance | None = None
        self._finalized = False

    @property
    def call_count(self) -> int:
        return len(self._calls)

    @property
    def calls(self) -> tuple[CallEvidence, ...]:
        return tuple(self._calls)

    @property
    def entries(self) -> Mapping[str, EvidenceRef]:
        return dict(self._entries)

    def set_provenance(self, provenance: ToolProvenance) -> None:
        self._provenance = provenance

    @property
    def provenance(self) -> ToolProvenance | None:
        return self._provenance

    def _store(self, relative_path: str, data: bytes) -> EvidenceRef:
        if self._finalized:
            raise EvidenceError("evidence store is finalized; no further writes are allowed")
        if relative_path in self._entries:
            raise EvidenceError(f"evidence path {relative_path!r} is already recorded")
        ref = EvidenceRef(relative_path, sha256_hex(data), len(data))
        _atomic_write_bytes(self.root / relative_path, data)
        self._entries[relative_path] = ref
        return ref

    def record_artifact(self, name: str, data: bytes) -> EvidenceRef:
        """Retain a derived artifact (frozen inference, ground truth, controls)."""

        if not isinstance(data, (bytes, bytearray)):
            raise EvidenceError("artifact data must be bytes")
        return self._store(f"{_ARTIFACT_DIR}/{name}", bytes(data))

    def record_json_artifact(self, name: str, value: object) -> EvidenceRef:
        return self.record_artifact(name, canonical_json(value) + b"\n")

    def record_artifact_stream(self, name: str, chunks: Iterable[bytes]) -> EvidenceRef:
        """Retain a derived artifact that is produced incrementally.

        Used for the derived ground-truth records: an epoch can carry hundreds
        of thousands of rows, and materializing them only to hash them would
        reintroduce the memory ceiling streaming exists to remove.
        """

        if self._finalized:
            raise EvidenceError("evidence store is finalized; no further writes are allowed")
        relative_path = f"{_ARTIFACT_DIR}/{name}"
        if relative_path in self._entries:
            raise EvidenceError(f"evidence path {relative_path!r} is already recorded")
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        length = 0
        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                for chunk in chunks:
                    stream.write(chunk)
                    digest.update(chunk)
                    length += len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        ref = EvidenceRef(relative_path, digest.hexdigest(), length)
        self._entries[relative_path] = ref
        return ref

    def record_call(
        self,
        *,
        provider: str,
        method: str,
        params: Sequence[object],
        endpoint_fingerprint: str,
        raw_response: bytes,
        http_status: int,
        started_at: str,
        completed_at: str,
        error: str | None = None,
    ) -> CallEvidence:
        """Retain the exact response bytes plus credential-free call metadata."""

        self._sequence += 1
        sequence = self._sequence
        safe_provider = "".join(
            character if character.isalnum() or character in "._-" else "_"
            for character in provider
        )
        stem = f"{sequence:06d}-{safe_provider}-{method}"
        raw_ref = self._store(f"{_RAW_DIR}/{stem}.json", bytes(raw_response))
        request_payload = {
            "sequence": sequence,
            "provider": provider,
            "method": method,
            "params": json.loads(json.dumps(params, default=str)),
            "endpoint_fingerprint": endpoint_fingerprint,
            "http_status": http_status,
            "started_at": started_at,
            "completed_at": completed_at,
            "response": raw_ref.to_payload(),
            "error": error,
        }
        request_ref = self._store(
            f"{_META_DIR}/{stem}.json", canonical_json(request_payload) + b"\n"
        )
        call = CallEvidence(
            sequence=sequence,
            provider=provider,
            method=method,
            raw=raw_ref,
            request=request_ref,
        )
        self._calls.append(call)
        return call

    def finalize(self, *, provenance: ToolProvenance | None = None) -> EvidenceRef:
        """Write provenance and the manifest, then seal the store."""

        if self._finalized:
            raise EvidenceError("evidence store is already finalized")
        chosen = provenance if provenance is not None else self._provenance
        if chosen is None:
            raise EvidenceError("tool provenance must be recorded before finalizing")
        self._provenance = chosen
        self._store(PROVENANCE_NAME, canonical_json(chosen.to_payload()) + b"\n")
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "generated_at": utc_now(),
            "entry_count": len(self._entries),
            # Entries are sorted so the manifest is stable and diffable, but the
            # order in which evidence was *created* is itself audit-relevant:
            # it is what shows that a frozen inference preceded the ground truth
            # it is later compared against.
            "write_order": list(self._entries),
            "entries": [
                self._entries[path].to_payload() for path in sorted(self._entries)
            ],
        }
        data = canonical_json(manifest) + b"\n"
        manifest_ref = EvidenceRef(MANIFEST_NAME, sha256_hex(data), len(data))
        _atomic_write_bytes(self.root / MANIFEST_NAME, data)
        self._finalized = True
        return manifest_ref

    def verify(self) -> ManifestVerification:
        return verify_manifest(self.root)


def verify_manifest(root: str | Path) -> ManifestVerification:
    """Compare a manifest against the directory in both directions.

    Unsigned, so this establishes that the directory is internally consistent
    with its own manifest -- not that either is authentic. See the module
    docstring for what that does and does not rule out.
    """

    base = Path(root)
    manifest_path = base / MANIFEST_NAME
    if not manifest_path.is_file():
        raise EvidenceError(f"no {MANIFEST_NAME} in {base}")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"could not read {MANIFEST_NAME}: {type(exc).__name__}") from None
    if not isinstance(payload, dict) or payload.get("manifest_version") != MANIFEST_VERSION:
        raise EvidenceError("unsupported or invalid manifest version")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise EvidenceError("manifest entries are invalid")
    declared: dict[str, EvidenceRef] = {}
    for item in raw_entries:
        if not isinstance(item, Mapping):
            raise EvidenceError("manifest entries are invalid")
        ref = EvidenceRef.from_payload(item)
        declared[ref.relative_path] = ref

    present: set[str] = set()
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(base).as_posix()
        if relative == MANIFEST_NAME:
            continue
        present.add(relative)

    missing = sorted(set(declared) - present)
    unexpected = sorted(present - set(declared))
    modified: list[str] = []
    for relative in sorted(set(declared) & present):
        data = (base / relative).read_bytes()
        ref = declared[relative]
        if sha256_hex(data) != ref.sha256 or len(data) != ref.byte_length:
            modified.append(relative)
    return ManifestVerification(
        missing=tuple(missing),
        modified=tuple(modified),
        unexpected=tuple(unexpected),
    )


def describe_refs(refs: Iterable[EvidenceRef]) -> list[str]:
    return [ref.describe() for ref in refs]


__all__ = [
    "MANIFEST_NAME",
    "MANIFEST_VERSION",
    "PROVENANCE_NAME",
    "CallEvidence",
    "EvidenceError",
    "EvidenceRef",
    "EvidenceStore",
    "ManifestVerification",
    "ToolProvenance",
    "build_provenance",
    "canonical_json",
    "describe_refs",
    "endpoint_fingerprint",
    "endpoint_host_fingerprint",
    "STREAM_CHUNK_BYTES",
    "sha256_file",
    "sha256_hex",
    "source_tree_sha256",
    "utc_now",
    "verify_manifest",
]
