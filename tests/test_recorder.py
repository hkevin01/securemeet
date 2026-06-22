from __future__ import annotations

import io
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from securemeet.metadata import RetentionPolicy
from securemeet.playback import load_recording_bytes, play_recording
from securemeet.recorder import record_meeting
from securemeet.security import (
    EncryptionManager,
    create_password_protected_key,
    generate_encryption_key,
    unlock_password_protected_key,
)
from securemeet.storage import (
    fetch_audit_events,
    fetch_recordings,
    rotate_encryption_keys,
    search_recordings,
    search_recordings_page,
)


def test_record_meeting_creates_wav_and_metadata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()

    class FakeSD:
        @staticmethod
        def rec(frames: int, samplerate: int, channels: int, dtype: str):
            return b"fake-audio-buffer"

        @staticmethod
        def wait() -> None:
            return None

    def fake_sf_write(file, data, samplerate: int, subtype: str, format: str) -> None:
        file.write(b"RIFFFAKEWAVDATA")

    import securemeet.recorder as recorder

    monkeypatch.setattr(recorder, "sd", FakeSD)
    monkeypatch.setattr(recorder.sf, "write", fake_sf_write)

    output = record_meeting(
        duration_seconds=1,
        folder=str(recordings_dir),
        samplerate=8000,
        encryption_keys=encryption_key,
    )

    assert output.endswith(".wav.enc")
    assert Path(output).exists()
    encrypted_payload = Path(output).read_bytes()
    assert encrypted_payload != b"RIFFFAKEWAVDATA"
    assert encrypted_payload.startswith(b"SME1")

    db_bytes = (recordings_dir / "metadata.db").read_bytes()
    assert b"RIFFFAKEWAVDATA" not in db_bytes
    assert str(Path(output)).encode("utf-8") not in db_bytes

    rows = fetch_recordings(base_folder=str(recordings_dir), encryption_keys=encryption_key)
    assert len(rows) == 1
    assert rows[0]["filename"] == output
    assert rows[0]["duration_seconds"] == 1
    assert len(rows[0]["sha256"]) == 64
    assert load_recording_bytes(output, encryption_keys=encryption_key) == b"RIFFFAKEWAVDATA"


def test_record_meeting_rejects_non_positive_duration() -> None:
    with pytest.raises(ValueError):
        record_meeting(0)


def test_search_recordings_filters_by_sha_and_duration(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()

    record_one = record_meeting.__globals__["RecordingMetadata"](
        filename=str(recordings_dir / "2026/06/meeting_one.wav.enc"),
        duration_seconds=30,
        sha256="a" * 64,
        created_at=datetime.now() - timedelta(days=2),
        samplerate=16000,
        channels=1,
        frames=480000,
        file_size_bytes=100,
    )
    record_two = record_meeting.__globals__["RecordingMetadata"](
        filename=str(recordings_dir / "2026/06/meeting_two.wav.enc"),
        duration_seconds=90,
        sha256="b" * 64,
        created_at=datetime.now(),
        samplerate=44100,
        channels=2,
        frames=3969000,
        file_size_bytes=200,
    )

    recordings_dir.mkdir(parents=True, exist_ok=True)
    Path(record_one.filename).parent.mkdir(parents=True, exist_ok=True)
    Path(record_one.filename).write_bytes(b"one")
    Path(record_two.filename).write_bytes(b"two")

    from securemeet.storage import save_metadata

    save_metadata(record_one, base_folder=str(recordings_dir), encryption_keys=encryption_key)
    save_metadata(record_two, base_folder=str(recordings_dir), encryption_keys=encryption_key)

    rows = search_recordings(
        base_folder=str(recordings_dir),
        encryption_keys=encryption_key,
        min_duration_seconds=60,
        sha256="b" * 64,
    )

    assert len(rows) == 1
    assert rows[0]["channels"] == 2
    assert rows[0]["sha256"] == "b" * 64


def test_search_recordings_page_supports_pagination_and_richer_filters(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()

    from securemeet.metadata import RecordingMetadata
    from securemeet.storage import save_metadata

    recordings_dir.mkdir(parents=True, exist_ok=True)
    created_base = datetime.now() - timedelta(days=5)
    inserted_ids: list[int] = []
    for index in range(3):
        target = recordings_dir / f"2026/06/meeting_{index}.wav.enc"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"payload" + bytes([index]))
        inserted_ids.append(
            save_metadata(
                RecordingMetadata(
                    filename=str(target),
                    duration_seconds=30 + (index * 15),
                    sha256=str(index) * 64,
                    created_at=created_base + timedelta(days=index),
                    samplerate=16000 if index < 2 else 44100,
                    channels=1,
                    frames=1000 + index,
                    file_size_bytes=target.stat().st_size,
                ),
                base_folder=str(recordings_dir),
                encryption_keys=encryption_key,
            )
        )

    page = search_recordings_page(
        base_folder=str(recordings_dir),
        encryption_keys=encryption_key,
        samplerate=16000,
        min_duration_seconds=20,
        max_duration_seconds=60,
        recording_ids=inserted_ids[:2],
        page=1,
        page_size=1,
        sort_by="duration_seconds",
        sort_desc=False,
    )

    assert page["total"] == 2
    assert page["total_pages"] == 2
    assert page["has_next"] is True
    assert len(page["items"]) == 1
    assert page["items"][0]["duration_seconds"] == 30
    assert page["leakage_model"]["exact_match_blind_index_fields"] == ["filename", "sha256"]


def test_play_recording_decrypts_before_audio_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()
    target = recordings_dir / "2026/06/meeting_test.wav.enc"
    target.parent.mkdir(parents=True, exist_ok=True)

    import securemeet.playback as playback
    from securemeet.security import EncryptionManager

    target.write_bytes(EncryptionManager(encryption_key).encrypt_bytes(b"RIFFFAKEWAVDATA"))

    read_calls: list[bytes] = []
    played: list[tuple[object, int]] = []

    def fake_sf_read(file, always_2d: bool = False):
        assert always_2d is False
        read_calls.append(file.read())
        return [0.1, 0.2, 0.3], 8000

    class FakeSD:
        @staticmethod
        def play(data, samplerate: int) -> None:
            played.append((data, samplerate))

        @staticmethod
        def wait() -> None:
            return None

    monkeypatch.setattr(playback.sf, "read", fake_sf_read)
    monkeypatch.setattr(playback, "sd", FakeSD)

    info = play_recording(path=str(target), encryption_keys=encryption_key)

    assert read_calls == [b"RIFFFAKEWAVDATA"]
    assert played == [([0.1, 0.2, 0.3], 8000)]
    assert info == {"samplerate": 8000, "frames": 3}


def test_retention_policy_removes_oldest_recordings(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()

    from securemeet.metadata import RecordingMetadata
    from securemeet.storage import enforce_retention_policy, save_metadata

    older_path = recordings_dir / "2026/06/meeting_old.wav.enc"
    newer_path = recordings_dir / "2026/06/meeting_new.wav.enc"
    older_path.parent.mkdir(parents=True, exist_ok=True)
    older_path.write_bytes(b"older")
    newer_path.write_bytes(b"newer")

    save_metadata(
        RecordingMetadata(
            filename=str(older_path),
            duration_seconds=10,
            sha256="1" * 64,
            created_at=datetime.now() - timedelta(days=3),
            samplerate=8000,
            channels=1,
            frames=80000,
            file_size_bytes=older_path.stat().st_size,
        ),
        base_folder=str(recordings_dir),
        encryption_keys=encryption_key,
    )
    save_metadata(
        RecordingMetadata(
            filename=str(newer_path),
            duration_seconds=10,
            sha256="2" * 64,
            created_at=datetime.now(),
            samplerate=8000,
            channels=1,
            frames=80000,
            file_size_bytes=newer_path.stat().st_size,
        ),
        base_folder=str(recordings_dir),
        encryption_keys=encryption_key,
    )

    deleted = enforce_retention_policy(
        base_folder=str(recordings_dir),
        encryption_keys=encryption_key,
        policy=RetentionPolicy(max_recordings=1),
    )

    assert [row["filename"] for row in deleted] == [str(older_path)]
    assert not older_path.exists()
    assert newer_path.exists()
    assert len(fetch_recordings(base_folder=str(recordings_dir), encryption_keys=encryption_key)) == 1


def test_legacy_plaintext_database_is_migrated_on_write(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    recordings_dir.mkdir(parents=True, exist_ok=True)
    encryption_key = generate_encryption_key()
    db_path = recordings_dir / "metadata.db"

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                samplerate INTEGER NOT NULL,
                channels INTEGER NOT NULL,
                frames INTEGER NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                logged_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            INSERT INTO recordings (
                filename,
                duration_seconds,
                sha256,
                created_at,
                samplerate,
                channels,
                frames,
                file_size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(recordings_dir / "2026/06/legacy.wav.enc"),
                5,
                "c" * 64,
                datetime.now().isoformat(timespec="seconds"),
                8000,
                1,
                40000,
                128,
            ),
        )
        conn.commit()

    rows = fetch_recordings(base_folder=str(recordings_dir), encryption_keys=encryption_key)

    assert len(rows) == 1
    assert rows[0]["sha256"] == "c" * 64
    assert str(recordings_dir / "2026/06/legacy.wav.enc").encode("utf-8") not in db_path.read_bytes()


def test_rotate_encryption_keys_rewraps_files_and_metadata(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    old_key = generate_encryption_key()
    new_key = generate_encryption_key()

    from securemeet.metadata import RecordingMetadata
    from securemeet.storage import save_metadata

    target = recordings_dir / "2026/06/meeting_rotate.wav.enc"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(EncryptionManager(old_key).encrypt_bytes(b"RIFFROTATEME"))

    save_metadata(
        RecordingMetadata(
            filename=str(target),
            duration_seconds=42,
            sha256="d" * 64,
            created_at=datetime.now(),
            samplerate=16000,
            channels=1,
            frames=672000,
            file_size_bytes=target.stat().st_size,
        ),
        base_folder=str(recordings_dir),
        encryption_keys=old_key,
    )

    result = rotate_encryption_keys(
        new_primary_key=new_key,
        base_folder=str(recordings_dir),
        encryption_keys=old_key,
    )

    assert result["rotated_files"] == 1
    assert result["rotated_rows"] == 1
    assert result["primary_key"] == new_key

    rows = fetch_recordings(base_folder=str(recordings_dir), encryption_keys=new_key)
    assert len(rows) == 1
    assert rows[0]["filename"] == str(target)

    matches = search_recordings(
        base_folder=str(recordings_dir),
        encryption_keys=new_key,
        sha256="d" * 64,
    )
    assert len(matches) == 1
    assert matches[0]["duration_seconds"] == 42
    assert load_recording_bytes(str(target), encryption_keys=new_key) == b"RIFFROTATEME"

    with pytest.raises(InvalidToken):
        load_recording_bytes(str(target), encryption_keys=old_key)


def test_password_protected_key_round_trip_and_wrong_password() -> None:
    encryption_key = generate_encryption_key()
    protected = create_password_protected_key("correct horse battery staple", encryption_key=encryption_key)

    unlocked = unlock_password_protected_key("correct horse battery staple", protected)
    assert unlocked == encryption_key

    with pytest.raises(InvalidUnwrap):
        unlock_password_protected_key("wrong password", protected)


def test_corrupted_chunked_ciphertext_logs_decrypt_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()

    class FakeSD:
        @staticmethod
        def rec(frames: int, samplerate: int, channels: int, dtype: str):
            return b"fake-audio-buffer"

        @staticmethod
        def wait() -> None:
            return None

    def fake_sf_write(file, data, samplerate: int, subtype: str, format: str) -> None:
        file.write(b"RIFFFAKEWAVDATA")

    import securemeet.recorder as recorder

    monkeypatch.setattr(recorder, "sd", FakeSD)
    monkeypatch.setattr(recorder.sf, "write", fake_sf_write)

    output = record_meeting(
        duration_seconds=1,
        folder=str(recordings_dir),
        samplerate=8000,
        encryption_keys=encryption_key,
    )

    payload = bytearray(Path(output).read_bytes())
    payload[-1] ^= 0x01
    Path(output).write_bytes(bytes(payload))

    with pytest.raises(Exception):
        load_recording_bytes(output, encryption_keys=encryption_key)

    events = fetch_audit_events(base_folder=str(recordings_dir), encryption_keys=encryption_key)
    assert events["items"][0]["event_type"] == "decrypt_failure"


def test_missing_file_artifact_is_audited(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    encryption_key = generate_encryption_key()
    target = recordings_dir / "2026/06/missing.wav.enc"
    target.parent.mkdir(parents=True, exist_ok=True)

    with pytest.raises(FileNotFoundError):
        load_recording_bytes(str(target), encryption_keys=encryption_key, base_folder=str(recordings_dir))

    events = fetch_audit_events(base_folder=str(recordings_dir), encryption_keys=encryption_key)
    assert events["items"][0]["event_type"] == "missing_file_artifact"


def test_rotation_failure_restores_previous_files_and_audits(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    old_key = generate_encryption_key()
    new_key = generate_encryption_key()

    from securemeet.metadata import RecordingMetadata
    from securemeet.storage import save_metadata

    first = recordings_dir / "2026/06/meeting_ok.wav.enc"
    second = recordings_dir / "2026/06/meeting_missing.wav.enc"
    first.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(EncryptionManager(old_key).encrypt_bytes(b"RIFFOK"))

    save_metadata(
        RecordingMetadata(
            filename=str(first),
            duration_seconds=1,
            sha256="e" * 64,
            created_at=datetime.now(),
            samplerate=8000,
            channels=1,
            frames=1,
            file_size_bytes=first.stat().st_size,
        ),
        base_folder=str(recordings_dir),
        encryption_keys=old_key,
    )
    save_metadata(
        RecordingMetadata(
            filename=str(second),
            duration_seconds=1,
            sha256="f" * 64,
            created_at=datetime.now(),
            samplerate=8000,
            channels=1,
            frames=1,
            file_size_bytes=0,
        ),
        base_folder=str(recordings_dir),
        encryption_keys=old_key,
    )

    with pytest.raises(FileNotFoundError):
        rotate_encryption_keys(
            new_primary_key=new_key,
            base_folder=str(recordings_dir),
            encryption_keys=old_key,
        )

    assert load_recording_bytes(str(first), encryption_keys=old_key) == b"RIFFOK"
    events = fetch_audit_events(base_folder=str(recordings_dir), encryption_keys=old_key)
    event_types = [item["event_type"] for item in events["items"]]
    assert "key_rotation" in event_types
    assert "missing_file_artifact" in event_types


def test_mixed_keyset_supports_old_and_new_artifacts(tmp_path: Path) -> None:
    recordings_dir = tmp_path / "recordings"
    old_key = generate_encryption_key()
    new_key = generate_encryption_key()

    old_path = recordings_dir / "2026/06/legacy_token.wav.enc"
    new_path = recordings_dir / "2026/06/new_token.wav.enc"
    old_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.write_bytes(EncryptionManager(old_key).encrypt_bytes(b"RIFFOLD"))
    new_path.write_bytes(EncryptionManager(new_key).encrypt_bytes(b"RIFFNEW"))

    assert load_recording_bytes(str(old_path), encryption_keys=[new_key, old_key]) == b"RIFFOLD"
    assert load_recording_bytes(str(new_path), encryption_keys=[new_key, old_key]) == b"RIFFNEW"
