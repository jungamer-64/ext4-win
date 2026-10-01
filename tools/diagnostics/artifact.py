"""Read an immutable analysis snapshot from a production manifest.

Hashes establish which recorded artifact was inspected, not that it was built
from the current checkout, signed by a trusted party, or loaded by Windows.
"""

from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType


@dataclass(frozen=True)
class ArtifactSnapshot:
    identity: str
    source_digest: str
    contents: Mapping[str, bytes]
    digests: Mapping[str, str]


def read_bundle(directory, kinds):
    directory = Path(directory).resolve(strict=True)
    records = {}
    for line in (directory / "manifest-v1.txt").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in records:
            raise ValueError("malformed or duplicate manifest record")
        records[key] = value
    if records.get("manifest_version") != "1":
        raise ValueError("unsupported production manifest version")
    identity = records.get("artifact_id", "")
    source = records.get("source_snapshot_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{32}", identity) or identity == "0" * 32:
        raise ValueError("invalid production artifact identity")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", source):
        raise ValueError("invalid source snapshot digest")
    contents, digests = {}, {}
    for kind in kinds:
        name = records.get(f"artifact.{kind}.path", "")
        relative = PurePosixPath(name)
        if not name or "\\" in name or ":" in name or relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid bundle-relative {kind} path")
        path = (directory / relative).resolve(strict=True)
        if not path.is_relative_to(directory):
            raise ValueError(f"{kind} path escapes the bundle")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != records.get(f"artifact.{kind}.sha256", "").lower():
            raise ValueError(f"{kind} identity mismatch")
        contents[kind], digests[kind] = data, digest
    return ArtifactSnapshot(identity, source.lower(), MappingProxyType(contents), MappingProxyType(digests))
