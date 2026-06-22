"""Utility helpers for local recording paths and file hashing."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional


def ensure_recording_root(folder: str) -> Path:
    """Create the secure recording root directory if missing."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        # Some filesystems do not support chmod in expected ways.
        pass
    return root


def build_recording_path(
    folder: str,
    when: Optional[datetime] = None,
    extension: str = ".wav.enc",
) -> Path:
    """Build a year/month timestamped recording output path and create parent dirs."""
    now = when or datetime.now()
    root = ensure_recording_root(folder)
    year_dir = root / f"{now.year:04d}"
    month_dir = year_dir / f"{now.month:02d}"
    month_dir.mkdir(parents=True, exist_ok=True)

    timestamp = now.strftime("%Y%m%d_%H%M%S")
    return month_dir / f"meeting_{timestamp}{extension}"


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file without loading it all into memory."""
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_sha256_bytes(payload: bytes) -> str:
    """Compute SHA-256 hash of an in-memory payload."""
    return hashlib.sha256(payload).hexdigest()
