"""Microphone recording API for secure local-only capture."""

from __future__ import annotations

import io
from datetime import datetime
from types import SimpleNamespace
from typing import Sequence

try:
    import sounddevice as sd
except ModuleNotFoundError:
    sd = SimpleNamespace(rec=None, wait=None)

try:
    import soundfile as sf
except ModuleNotFoundError:
    sf = SimpleNamespace(write=None)

from .metadata import RecordingMetadata, RetentionPolicy
from .artifacts import encrypt_recording_stream
from .security import EncryptionManager
from .storage import enforce_retention_policy, save_metadata
from .utils import build_recording_path, compute_sha256_bytes


def _require_audio_backends() -> tuple[object, object]:
    """Ensure runtime audio dependencies are available before record operations."""
    if not callable(getattr(sd, "rec", None)) or not callable(getattr(sd, "wait", None)):
        raise RuntimeError("sounddevice is required for recording")
    if not callable(getattr(sf, "write", None)):
        raise RuntimeError("soundfile is required for recording")
    return sd, sf


def record_meeting(
    duration_seconds: float,
    folder: str = "recordings",
    samplerate: int = 44100,
    channels: int = 1,
    subtype: str = "PCM_16",
    encryption_keys: Sequence[str] | str | None = None,
    retention_policy: RetentionPolicy | None = None,
) -> str:
    """Record microphone audio, encrypt WAV bytes, and log protected metadata."""
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be > 0")
    if samplerate <= 0:
        raise ValueError("samplerate must be > 0")
    if channels <= 0:
        raise ValueError("channels must be > 0")

    sounddevice_backend, soundfile_backend = _require_audio_backends()
    crypto = EncryptionManager(encryption_keys)
    output_path = build_recording_path(folder)
    frames = int(duration_seconds * samplerate)
    if frames <= 0:
        raise ValueError("duration_seconds * samplerate must produce at least 1 frame")

    audio = sounddevice_backend.rec(frames, samplerate=samplerate, channels=channels, dtype="float32")
    sounddevice_backend.wait()

    wav_buffer = io.BytesIO()
    wav_buffer.name = output_path.with_suffix(".wav").name
    soundfile_backend.write(wav_buffer, audio, samplerate, subtype=subtype, format="WAV")
    wav_buffer.seek(0)
    plaintext_wav = wav_buffer.read()

    with output_path.open("wb") as handle:
        encrypt_recording_stream(io.BytesIO(plaintext_wav), handle, crypto)

    file_sha256 = compute_sha256_bytes(plaintext_wav)
    metadata = RecordingMetadata(
        filename=str(output_path),
        duration_seconds=duration_seconds,
        sha256=file_sha256,
        created_at=datetime.now(),
        samplerate=samplerate,
        channels=channels,
        frames=frames,
        file_size_bytes=output_path.stat().st_size,
    )
    save_metadata(metadata, base_folder=folder, encryption_keys=encryption_keys)
    enforce_retention_policy(
        base_folder=folder,
        encryption_keys=encryption_keys,
        policy=retention_policy,
    )

    return str(output_path)
