"""Playback APIs for encrypted SecureMeet recordings."""

from __future__ import annotations

import io
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, Sequence

from cryptography.fernet import InvalidToken
from cryptography.exceptions import InvalidTag

try:
    import sounddevice as sd
except ModuleNotFoundError:
    sd = SimpleNamespace(play=None, wait=None, OutputStream=None, CallbackStop=RuntimeError)

try:
    import soundfile as sf
except ModuleNotFoundError:
    sf = SimpleNamespace(read=None)

from .artifacts import load_recording_bytes as load_recording_artifact_bytes, open_decrypted_recording
from .security import EncryptionManager
from .storage import get_recording, log_audit_event, resolve_recording_root


def _require_audio_backends() -> tuple[object, object]:
    """Ensure runtime audio dependencies are available before playback operations."""
    if not callable(getattr(sd, "play", None)) or not callable(getattr(sd, "wait", None)):
        raise RuntimeError("sounddevice is required for playback")
    if not callable(getattr(sf, "read", None)):
        raise RuntimeError("soundfile is required for playback")
    return sd, sf


def _resolve_recording_path(
    *,
    recording_id: int | None,
    path: str | None,
    base_folder: str,
    encryption_keys: Sequence[str] | str | None,
) -> str:
    if (recording_id is None) == (path is None):
        raise ValueError("exactly one of recording_id or path must be provided")
    if path is not None:
        return path

    record = get_recording(
        int(recording_id),
        base_folder=base_folder,
        encryption_keys=encryption_keys,
    )
    if record is None:
        raise KeyError(f"recording {recording_id} not found")
    return str(record["filename"])


def load_recording_bytes(
    path: str,
    encryption_keys: Sequence[str] | str | None = None,
    base_folder: str | None = None,
) -> bytes:
    """Decrypt an encrypted recording file into plaintext WAV bytes."""
    recording_path = Path(path)
    resolved_base_folder = str(resolve_recording_root(recording_path)) if base_folder is None else base_folder
    if not recording_path.exists():
        log_audit_event(
            event_type="missing_file_artifact",
            event_status="error",
            base_folder=resolved_base_folder,
            encryption_keys=encryption_keys,
            details={"filename": str(recording_path), "source": "load_recording_bytes"},
        )
        raise FileNotFoundError(f"recording file not found: {recording_path}")

    try:
        return load_recording_artifact_bytes(recording_path, EncryptionManager(encryption_keys))
    except (InvalidTag, InvalidToken) as exc:
        log_audit_event(
            event_type="decrypt_failure",
            event_status="error",
            base_folder=resolved_base_folder,
            encryption_keys=encryption_keys,
            details={"filename": str(recording_path), "error": type(exc).__name__},
        )
        raise


def load_recording(
    *,
    recording_id: int | None = None,
    path: str | None = None,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> tuple[Any, int]:
    """Load decrypted audio samples and samplerate for an encrypted recording."""
    _, soundfile_backend = _require_audio_backends()
    target_path = _resolve_recording_path(
        recording_id=recording_id,
        path=path,
        base_folder=base_folder,
        encryption_keys=encryption_keys,
    )

    wav_bytes = load_recording_bytes(
        str(target_path),
        encryption_keys=encryption_keys,
        base_folder=base_folder,
    )
    wav_buffer = io.BytesIO(wav_bytes)
    wav_buffer.name = "recording.wav"
    data, samplerate = soundfile_backend.read(wav_buffer, always_2d=False)
    return data, int(samplerate)


def read_recording_frames(
    *,
    recording_id: int | None = None,
    path: str | None = None,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    start_frame: int = 0,
    frames: int = -1,
    dtype: str = "float32",
    always_2d: bool = False,
) -> tuple[Any, int]:
    """Read a frame range from an encrypted recording without materializing the full WAV."""
    if start_frame < 0:
        raise ValueError("start_frame must be >= 0")
    _, soundfile_backend = _require_audio_backends()
    target_path = _resolve_recording_path(
        recording_id=recording_id,
        path=path,
        base_folder=base_folder,
        encryption_keys=encryption_keys,
    )
    reader = open_decrypted_recording(target_path, EncryptionManager(encryption_keys))
    try:
        with soundfile_backend.SoundFile(reader) as handle:
            if start_frame:
                handle.seek(start_frame)
            data = handle.read(frames=frames, dtype=dtype, always_2d=always_2d)
            return data, int(handle.samplerate)
    finally:
        reader.close()


def iter_recording_blocks(
    *,
    recording_id: int | None = None,
    path: str | None = None,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    start_frame: int = 0,
    frames: int = -1,
    blocksize: int = 1024,
    dtype: str = "float32",
    always_2d: bool = False,
) -> Iterator[Any]:
    """Yield decrypted audio blocks from an encrypted recording."""
    if start_frame < 0:
        raise ValueError("start_frame must be >= 0")
    if blocksize < 1:
        raise ValueError("blocksize must be >= 1")

    _, soundfile_backend = _require_audio_backends()
    target_path = _resolve_recording_path(
        recording_id=recording_id,
        path=path,
        base_folder=base_folder,
        encryption_keys=encryption_keys,
    )
    reader = open_decrypted_recording(target_path, EncryptionManager(encryption_keys))
    try:
        with soundfile_backend.SoundFile(reader) as handle:
            if start_frame:
                handle.seek(start_frame)
            for block in handle.blocks(
                blocksize=blocksize,
                frames=frames,
                dtype=dtype,
                always_2d=always_2d,
            ):
                yield block
    finally:
        reader.close()


def play_recording(
    *,
    recording_id: int | None = None,
    path: str | None = None,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    blocking: bool = True,
) -> dict[str, int]:
    """Decrypt and play back an encrypted recording."""
    sounddevice_backend, _ = _require_audio_backends()
    data, samplerate = load_recording(
        recording_id=recording_id,
        path=path,
        base_folder=base_folder,
        encryption_keys=encryption_keys,
    )
    sounddevice_backend.play(data, samplerate=samplerate)
    if blocking:
        sounddevice_backend.wait()
    return {"samplerate": samplerate, "frames": len(data)}


def stream_play_recording(
    *,
    recording_id: int | None = None,
    path: str | None = None,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    start_frame: int = 0,
    frames: int = -1,
    blocksize: int = 1024,
    dtype: str = "float32",
) -> dict[str, int]:
    """Play an encrypted recording through a callback stream without full in-memory decode."""
    if start_frame < 0:
        raise ValueError("start_frame must be >= 0")
    if blocksize < 1:
        raise ValueError("blocksize must be >= 1")

    sounddevice_backend, soundfile_backend = _require_audio_backends()
    if getattr(sounddevice_backend, "OutputStream", None) is None:
        raise RuntimeError("sounddevice OutputStream is required for streaming playback")

    target_path = _resolve_recording_path(
        recording_id=recording_id,
        path=path,
        base_folder=base_folder,
        encryption_keys=encryption_keys,
    )
    reader = open_decrypted_recording(target_path, EncryptionManager(encryption_keys))
    finished = threading.Event()
    frames_played = 0

    try:
        with soundfile_backend.SoundFile(reader) as handle:
            if start_frame:
                handle.seek(start_frame)
            if frames >= 0:
                remaining_frames = frames
            else:
                remaining_frames = max(0, int(handle.frames) - start_frame)

            callback_stop = getattr(sounddevice_backend, "CallbackStop", StopIteration)

            def callback(outdata, frame_count, time_info, status) -> None:
                nonlocal frames_played, remaining_frames
                if remaining_frames == 0:
                    outdata[:] = 0
                    raise callback_stop()

                read_count = frame_count if remaining_frames < 0 else min(frame_count, remaining_frames)
                data = handle.read(read_count, dtype=dtype, always_2d=True, fill_value=0.0)
                actual_frames = len(data)
                outdata[:actual_frames] = data
                if actual_frames < frame_count:
                    outdata[actual_frames:] = 0
                    frames_played += actual_frames
                    remaining_frames = 0
                    raise callback_stop()
                frames_played += actual_frames
                if remaining_frames > 0:
                    remaining_frames -= actual_frames

            stream = sounddevice_backend.OutputStream(
                samplerate=handle.samplerate,
                channels=handle.channels,
                dtype=dtype,
                callback=callback,
                blocksize=blocksize,
                finished_callback=finished.set,
            )
            with stream:
                finished.wait()

            return {"samplerate": int(handle.samplerate), "frames": frames_played}
    finally:
        reader.close()