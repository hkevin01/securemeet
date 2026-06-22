"""SQLite storage for recording metadata."""

from __future__ import annotations

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .metadata import AuditRetentionPolicy, DEFAULT_SEARCH_POLICY, RecordingMetadata, RetentionPolicy, SearchPolicy
from .security import EncryptionManager, build_rotation_keyset
from .utils import ensure_recording_root

DB_FILENAME = "metadata.db"


def _db_path(base_folder: str = "recordings") -> Path:
    return ensure_recording_root(base_folder) / DB_FILENAME


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS recordings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_filename TEXT NOT NULL,
            filename_hmac TEXT NOT NULL,
            encrypted_sha256 TEXT NOT NULL,
            sha256_hmac TEXT NOT NULL,
            encrypted_created_at TEXT NOT NULL,
            created_at_epoch INTEGER NOT NULL,
            duration_seconds REAL NOT NULL,
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
        CREATE INDEX IF NOT EXISTS idx_recordings_created_at
        ON recordings (created_at_epoch DESC, id DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_recordings_sha256_hmac
        ON recordings (sha256_hmac)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_recordings_filename_hmac
        ON recordings (filename_hmac)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            event_status TEXT NOT NULL,
            recording_id INTEGER,
            encrypted_details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
        ON audit_events (created_at DESC, id DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_events_type
        ON audit_events (event_type, created_at DESC)
        """
    )


def _recording_columns(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("PRAGMA table_info(recordings)").fetchall()
    return {str(row[1]) for row in rows}


def _insert_encrypted_row(
    conn: sqlite3.Connection,
    metadata: RecordingMetadata,
    crypto: EncryptionManager,
    *,
    row_id: int | None = None,
    logged_at: str | None = None,
) -> None:
    created_at_iso = metadata.created_at.isoformat(timespec="seconds")
    conn.execute(
        """
        INSERT INTO recordings (
            id,
            encrypted_filename,
            filename_hmac,
            encrypted_sha256,
            sha256_hmac,
            encrypted_created_at,
            created_at_epoch,
            duration_seconds,
            samplerate,
            channels,
            frames,
            file_size_bytes,
            logged_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
        """,
        (
            row_id,
            crypto.encrypt_text(metadata.filename),
            crypto.blind_index(metadata.filename),
            crypto.encrypt_text(metadata.sha256),
            crypto.blind_index(metadata.sha256),
            crypto.encrypt_text(created_at_iso),
            int(metadata.created_at.timestamp()),
            metadata.duration_seconds,
            metadata.samplerate,
            metadata.channels,
            metadata.frames,
            metadata.file_size_bytes,
            logged_at,
        ),
    )


def _migrate_legacy_schema(
    conn: sqlite3.Connection,
    encryption_keys: Sequence[str] | str | None,
) -> None:
    legacy_rows = conn.execute(
        """
        SELECT
            id,
            filename,
            duration_seconds,
            sha256,
            created_at,
            samplerate,
            channels,
            frames,
            file_size_bytes,
            logged_at
        FROM recordings
        ORDER BY id ASC
        """
    ).fetchall()
    conn.execute("ALTER TABLE recordings RENAME TO recordings_legacy")
    _create_schema(conn)

    if legacy_rows:
        crypto = EncryptionManager(encryption_keys)
        for row in legacy_rows:
            metadata = RecordingMetadata(
                filename=str(row[1]),
                duration_seconds=float(row[2]),
                sha256=str(row[3]),
                created_at=datetime.fromisoformat(str(row[4])),
                samplerate=int(row[5]),
                channels=int(row[6]),
                frames=int(row[7]),
                file_size_bytes=int(row[8]),
            )
            _insert_encrypted_row(
                conn,
                metadata,
                crypto,
                row_id=int(row[0]),
                logged_at=None if row[9] is None else str(row[9]),
            )

    conn.execute("DROP TABLE recordings_legacy")


def _ensure_schema(
    conn: sqlite3.Connection,
    encryption_keys: Sequence[str] | str | None,
) -> None:
    columns = _recording_columns(conn)
    if not columns:
        _create_schema(conn)
        return
    if "encrypted_filename" in columns:
        _create_schema(conn)
        return
    _migrate_legacy_schema(conn, encryption_keys)


def _decode_row(row: sqlite3.Row, crypto: EncryptionManager) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "filename": crypto.decrypt_text(row["encrypted_filename"]),
        "duration_seconds": row["duration_seconds"],
        "sha256": crypto.decrypt_text(row["encrypted_sha256"]),
        "created_at": crypto.decrypt_text(row["encrypted_created_at"]),
        "samplerate": row["samplerate"],
        "channels": row["channels"],
        "frames": row["frames"],
        "file_size_bytes": row["file_size_bytes"],
        "logged_at": row["logged_at"],
    }


def resolve_recording_root(file_path: str | Path) -> Path:
    """Infer the recording root by walking parents until metadata.db is found."""
    target = Path(file_path)
    for parent in [target.parent, *target.parents]:
        if (parent / DB_FILENAME).exists():
            return parent
    return target.parent


def _log_audit_event_with_connection(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    event_status: str,
    base_folder: str,
    encryption_keys: Sequence[str] | str | None,
    recording_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    encrypted_details = None
    if details is not None:
        crypto = EncryptionManager(encryption_keys)
        encrypted_details = crypto.encrypt_text(json.dumps(details, sort_keys=True))
    cursor = conn.execute(
        """
        INSERT INTO audit_events (event_type, event_status, recording_id, encrypted_details)
        VALUES (?, ?, ?, ?)
        """,
        (event_type, event_status, recording_id, encrypted_details),
    )
    return int(cursor.lastrowid)


def _update_encrypted_row(
    conn: sqlite3.Connection,
    recording_id: int,
    metadata: RecordingMetadata,
    crypto: EncryptionManager,
) -> None:
    created_at_iso = metadata.created_at.isoformat(timespec="seconds")
    conn.execute(
        """
        UPDATE recordings
        SET encrypted_filename = ?,
            filename_hmac = ?,
            encrypted_sha256 = ?,
            sha256_hmac = ?,
            encrypted_created_at = ?,
            created_at_epoch = ?,
            duration_seconds = ?,
            samplerate = ?,
            channels = ?,
            frames = ?,
            file_size_bytes = ?
        WHERE id = ?
        """,
        (
            crypto.encrypt_text(metadata.filename),
            crypto.blind_index(metadata.filename),
            crypto.encrypt_text(metadata.sha256),
            crypto.blind_index(metadata.sha256),
            crypto.encrypt_text(created_at_iso),
            int(metadata.created_at.timestamp()),
            metadata.duration_seconds,
            metadata.samplerate,
            metadata.channels,
            metadata.frames,
            metadata.file_size_bytes,
            recording_id,
        ),
    )


def init_db(
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> Path:
    """Create SQLite DB and recordings table if they do not exist."""
    db_path = _db_path(base_folder)
    with sqlite3.connect(db_path) as conn:
        _ensure_schema(conn, encryption_keys)
        conn.commit()
    return db_path


def log_audit_event(
    *,
    event_type: str,
    event_status: str,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    recording_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    """Persist an encrypted audit event."""
    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    with sqlite3.connect(db_path) as conn:
        row_id = _log_audit_event_with_connection(
            conn,
            event_type=event_type,
            event_status=event_status,
            base_folder=base_folder,
            encryption_keys=encryption_keys,
            recording_id=recording_id,
            details=details,
        )
        conn.commit()
    return row_id


def fetch_audit_events(
    *,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    event_type: str | None = None,
    event_status: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> Dict[str, Any]:
    """Fetch paginated decrypted audit events."""
    if page < 1:
        raise ValueError("page must be >= 1")
    if page_size < 1:
        raise ValueError("page_size must be >= 1")

    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    crypto = EncryptionManager(encryption_keys)
    params: List[Any] = []
    conditions: List[str] = []
    if event_type is not None:
        conditions.append("event_type = ?")
        params.append(event_type)
    if event_status is not None:
        conditions.append("event_status = ?")
        params.append(event_status)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    offset = (page - 1) * page_size
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        total = int(conn.execute(f"SELECT COUNT(*) FROM audit_events {where}", params).fetchone()[0])
        rows = conn.execute(
            f"""
            SELECT id, event_type, event_status, recording_id, encrypted_details, created_at
            FROM audit_events
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()

    items = []
    for row in rows:
        details = None
        if row["encrypted_details"] is not None:
            details = json.loads(crypto.decrypt_text(row["encrypted_details"]))
        items.append(
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "event_status": row["event_status"],
                "recording_id": row["recording_id"],
                "details": details,
                "created_at": row["created_at"],
            }
        )

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
    }


def enforce_audit_retention_policy(
    *,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    policy: AuditRetentionPolicy | None = None,
) -> int:
    """Delete old audit events according to the configured retention policy."""
    if policy is None:
        return 0
    policy.validate()

    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    deleted = 0
    with sqlite3.connect(db_path) as conn:
        conditions: List[str] = []
        params: List[Any] = []
        if policy.max_age_days is not None:
            cutoff = datetime.now() - timedelta(days=policy.max_age_days)
            conditions.append("created_at < ?")
            params.append(cutoff.isoformat(timespec="seconds"))
        if conditions:
            cursor = conn.execute(
                f"DELETE FROM audit_events WHERE {' AND '.join(conditions)}",
                params,
            )
            deleted += int(cursor.rowcount)

        if policy.max_events is not None:
            row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
            total = int(row[0]) if row is not None else 0
            overflow = max(0, total - policy.max_events)
            if overflow:
                cursor = conn.execute(
                    """
                    DELETE FROM audit_events
                    WHERE id IN (
                        SELECT id FROM audit_events
                        ORDER BY created_at ASC, id ASC
                        LIMIT ?
                    )
                    """,
                    (overflow,),
                )
                deleted += int(cursor.rowcount)

        conn.commit()
    return deleted


def save_metadata(
    metadata: RecordingMetadata,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> int:
    """Persist a recording metadata row and return inserted row id."""
    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    crypto = EncryptionManager(encryption_keys)
    with sqlite3.connect(db_path) as conn:
        _ensure_schema(conn, encryption_keys)
        _insert_encrypted_row(conn, metadata, crypto)
        cursor = conn.execute("SELECT last_insert_rowid()")
        conn.commit()
        row = cursor.fetchone()
        return int(row[0]) if row is not None else 0


def fetch_recordings(
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> List[Dict[str, Any]]:
    """Fetch metadata rows ordered newest-first for local inspection/tests."""
    return search_recordings(base_folder=base_folder, encryption_keys=encryption_keys)


def _build_recording_search_conditions(
    crypto: EncryptionManager,
    search_policy: SearchPolicy,
    *,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    samplerate: int | None = None,
    channels: int | None = None,
    sha256: str | None = None,
    filename: str | None = None,
    min_frames: int | None = None,
    max_frames: int | None = None,
    min_file_size_bytes: int | None = None,
    max_file_size_bytes: int | None = None,
    recording_ids: Sequence[int] | None = None,
    logged_after: str | None = None,
    logged_before: str | None = None,
) -> tuple[List[str], List[Any]]:
    conditions: List[str] = []
    params: List[Any] = []

    search_policy.validate()

    def require_plaintext(field_name: str) -> None:
        if not search_policy.allows_plaintext_field(field_name):
            raise ValueError(f"search policy blocks plaintext filtering on {field_name}")

    def require_blind_index(field_name: str) -> None:
        if not search_policy.allows_blind_index_field(field_name):
            raise ValueError(f"search policy blocks blind-index filtering on {field_name}")

    if created_after is not None:
        require_plaintext("created_at")
        conditions.append("created_at_epoch >= ?")
        params.append(int(created_after.timestamp()))
    if created_before is not None:
        require_plaintext("created_at")
        conditions.append("created_at_epoch <= ?")
        params.append(int(created_before.timestamp()))
    if min_duration_seconds is not None:
        require_plaintext("duration_seconds")
        conditions.append("duration_seconds >= ?")
        params.append(min_duration_seconds)
    if max_duration_seconds is not None:
        require_plaintext("duration_seconds")
        conditions.append("duration_seconds <= ?")
        params.append(max_duration_seconds)
    if samplerate is not None:
        require_plaintext("samplerate")
        conditions.append("samplerate = ?")
        params.append(samplerate)
    if channels is not None:
        require_plaintext("channels")
        conditions.append("channels = ?")
        params.append(channels)
    if sha256 is not None:
        require_blind_index("sha256")
        conditions.append("sha256_hmac = ?")
        params.append(crypto.blind_index(sha256))
    if filename is not None:
        require_blind_index("filename")
        conditions.append("filename_hmac = ?")
        params.append(crypto.blind_index(filename))
    if min_frames is not None:
        require_plaintext("frames")
        conditions.append("frames >= ?")
        params.append(min_frames)
    if max_frames is not None:
        require_plaintext("frames")
        conditions.append("frames <= ?")
        params.append(max_frames)
    if min_file_size_bytes is not None:
        require_plaintext("file_size_bytes")
        conditions.append("file_size_bytes >= ?")
        params.append(min_file_size_bytes)
    if max_file_size_bytes is not None:
        require_plaintext("file_size_bytes")
        conditions.append("file_size_bytes <= ?")
        params.append(max_file_size_bytes)
    if recording_ids is not None:
        require_plaintext("id")
        ids = [int(recording_id) for recording_id in recording_ids]
        if ids:
            placeholders = ", ".join(["?"] * len(ids))
            conditions.append(f"id IN ({placeholders})")
            params.extend(ids)
    if logged_after is not None:
        require_plaintext("logged_at")
        conditions.append("logged_at >= ?")
        params.append(logged_after)
    if logged_before is not None:
        require_plaintext("logged_at")
        conditions.append("logged_at <= ?")
        params.append(logged_before)
    return conditions, params


def get_recording(
    recording_id: int,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> Dict[str, Any] | None:
    """Fetch a single decrypted recording row by id."""
    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    crypto = EncryptionManager(encryption_keys)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT
                id,
                encrypted_filename,
                duration_seconds,
                encrypted_sha256,
                encrypted_created_at,
                samplerate,
                channels,
                frames,
                file_size_bytes,
                logged_at
            FROM recordings
            WHERE id = ?
            """
            ,
            (recording_id,),
        ).fetchall()
    if not row:
        return None
    return _decode_row(row[0], crypto)


def search_recordings(
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    *,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    samplerate: int | None = None,
    channels: int | None = None,
    sha256: str | None = None,
    filename: str | None = None,
    min_frames: int | None = None,
    max_frames: int | None = None,
    min_file_size_bytes: int | None = None,
    max_file_size_bytes: int | None = None,
    recording_ids: Sequence[int] | None = None,
    logged_after: str | None = None,
    logged_before: str | None = None,
    search_policy: SearchPolicy = DEFAULT_SEARCH_POLICY,
    limit: int | None = None,
) -> List[Dict[str, Any]]:
    """Search decrypted recording metadata using filterable indexes."""
    page = search_recordings_page(
        base_folder=base_folder,
        encryption_keys=encryption_keys,
        created_after=created_after,
        created_before=created_before,
        min_duration_seconds=min_duration_seconds,
        max_duration_seconds=max_duration_seconds,
        samplerate=samplerate,
        channels=channels,
        sha256=sha256,
        filename=filename,
        min_frames=min_frames,
        max_frames=max_frames,
        min_file_size_bytes=min_file_size_bytes,
        max_file_size_bytes=max_file_size_bytes,
        recording_ids=recording_ids,
        logged_after=logged_after,
        logged_before=logged_before,
        search_policy=search_policy,
        page=1,
        page_size=limit or 100,
        include_total=False,
    )
    items = list(page["items"])
    return items[:limit] if limit is not None else items


def search_recordings_page(
    *,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    samplerate: int | None = None,
    channels: int | None = None,
    sha256: str | None = None,
    filename: str | None = None,
    min_frames: int | None = None,
    max_frames: int | None = None,
    min_file_size_bytes: int | None = None,
    max_file_size_bytes: int | None = None,
    recording_ids: Sequence[int] | None = None,
    logged_after: str | None = None,
    logged_before: str | None = None,
    search_policy: SearchPolicy = DEFAULT_SEARCH_POLICY,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "created_at",
    sort_desc: bool = True,
    include_total: bool = True,
) -> Dict[str, Any]:
    """Search decrypted metadata with pagination and explicit leakage notes."""
    if page < 1:
        raise ValueError("page must be >= 1")
    if page_size < 1:
        raise ValueError("page_size must be >= 1")

    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    crypto = EncryptionManager(encryption_keys)
    conditions, params = _build_recording_search_conditions(
        crypto,
        search_policy,
        created_after=created_after,
        created_before=created_before,
        min_duration_seconds=min_duration_seconds,
        max_duration_seconds=max_duration_seconds,
        samplerate=samplerate,
        channels=channels,
        sha256=sha256,
        filename=filename,
        min_frames=min_frames,
        max_frames=max_frames,
        min_file_size_bytes=min_file_size_bytes,
        max_file_size_bytes=max_file_size_bytes,
        recording_ids=recording_ids,
        logged_after=logged_after,
        logged_before=logged_before,
    )

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sort_map = {
        "channels": "channels",
        "created_at": "created_at_epoch",
        "duration_seconds": "duration_seconds",
        "file_size_bytes": "file_size_bytes",
        "frames": "frames",
        "id": "id",
        "logged_at": "logged_at",
        "samplerate": "samplerate",
    }
    if sort_by not in sort_map:
        raise ValueError(f"unsupported sort_by: {sort_by}")
    search_policy.validate()
    if not search_policy.allows_sort(sort_by):
        raise ValueError(f"search policy blocks sorting on {sort_by}")
    direction = "DESC" if sort_desc else "ASC"
    offset = (page - 1) * page_size

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        total = 0
        if include_total:
            total = int(conn.execute(f"SELECT COUNT(*) FROM recordings {where_clause}", params).fetchone()[0])
        rows = conn.execute(
            f"""
            SELECT
                id,
                encrypted_filename,
                duration_seconds,
                encrypted_sha256,
                encrypted_created_at,
                samplerate,
                channels,
                frames,
                file_size_bytes,
                logged_at
            FROM recordings
            {where_clause}
            ORDER BY {sort_map[sort_by]} {direction}, id {direction}
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()

    items = [_decode_row(row, crypto) for row in rows]
    total_pages = (total + page_size - 1) // page_size if include_total and total else 0
    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "sort_by": sort_by,
        "sort_desc": sort_desc,
        "total": total,
        "total_pages": total_pages,
        "has_next": include_total and page < total_pages,
        "leakage_model": search_policy.leakage_model(),
    }


def delete_recording(
    recording_id: int,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> Dict[str, Any] | None:
    """Delete one recording row and its encrypted file, returning deleted metadata."""
    record = get_recording(recording_id, base_folder=base_folder, encryption_keys=encryption_keys)
    if record is None:
        return None

    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM recordings WHERE id = ?", (recording_id,))
        _log_audit_event_with_connection(
            conn,
            event_type="recording_deleted",
            event_status="info",
            base_folder=base_folder,
            encryption_keys=encryption_keys,
            recording_id=recording_id,
            details={"filename": str(record["filename"]), "reason": "explicit_delete"},
        )
        conn.commit()

    file_path = Path(record["filename"])
    if file_path.exists():
        file_path.unlink()
    else:
        log_audit_event(
            event_type="missing_file_artifact",
            event_status="warning",
            base_folder=base_folder,
            encryption_keys=encryption_keys,
            recording_id=recording_id,
            details={"filename": str(file_path), "source": "delete_recording"},
        )
    return record


def enforce_retention_policy(
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    policy: RetentionPolicy | None = None,
) -> List[Dict[str, Any]]:
    """Delete old recordings that exceed the configured retention policy."""
    if policy is None:
        return []
    policy.validate()

    rows = list(
        reversed(
            search_recordings(
                base_folder=base_folder,
                encryption_keys=encryption_keys,
            )
        )
    )
    if not rows:
        return []

    to_delete: Dict[int, Dict[str, Any]] = {}

    if policy.max_age_days is not None:
        cutoff = datetime.now() - timedelta(days=policy.max_age_days)
        for row in rows:
            if datetime.fromisoformat(str(row["created_at"])) < cutoff:
                to_delete[int(row["id"])] = row

    survivors = [row for row in rows if int(row["id"]) not in to_delete]

    if policy.max_recordings is not None and len(survivors) > policy.max_recordings:
        overflow = len(survivors) - policy.max_recordings
        for row in survivors[:overflow]:
            to_delete[int(row["id"])] = row
        survivors = [row for row in survivors if int(row["id"]) not in to_delete]

    if policy.max_total_bytes is not None:
        total_bytes = sum(int(row["file_size_bytes"]) for row in survivors)
        for row in survivors:
            if total_bytes <= policy.max_total_bytes:
                break
            to_delete[int(row["id"])] = row
            total_bytes -= int(row["file_size_bytes"])

    deleted: List[Dict[str, Any]] = []
    for recording_id in sorted(to_delete):
        removed = delete_recording(
            recording_id,
            base_folder=base_folder,
            encryption_keys=encryption_keys,
        )
        if removed is not None:
            log_audit_event(
                event_type="retention_deletion",
                event_status="info",
                base_folder=base_folder,
                encryption_keys=encryption_keys,
                recording_id=int(removed["id"]),
                details={
                    "filename": str(removed["filename"]),
                    "policy": policy.__dict__,
                },
            )
            deleted.append(removed)
    return deleted


def rotate_encryption_keys(
    *,
    new_primary_key: str,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
) -> Dict[str, Any]:
    """Rotate encrypted files and metadata to a new primary key."""
    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    source_crypto = EncryptionManager(encryption_keys)
    target_keys = build_rotation_keyset(new_primary_key, encryption_keys)
    target_crypto = EncryptionManager(target_keys)

    rotated_files = 0
    rotated_rows = 0
    backup_paths: List[tuple[Path, Path]] = []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                id,
                encrypted_filename,
                encrypted_sha256,
                encrypted_created_at,
                duration_seconds,
                samplerate,
                channels,
                frames,
                file_size_bytes
            FROM recordings
            ORDER BY id ASC
            """
        ).fetchall()

        try:
            for row in rows:
                file_path = Path(source_crypto.decrypt_text(row["encrypted_filename"]))
                if not file_path.exists():
                    _log_audit_event_with_connection(
                        conn,
                        event_type="missing_file_artifact",
                        event_status="error",
                        base_folder=base_folder,
                        encryption_keys=encryption_keys,
                        recording_id=int(row["id"]),
                        details={"filename": str(file_path), "source": "rotate_encryption_keys"},
                    )
                    raise FileNotFoundError(f"recording file not found during rotation: {file_path}")

            from .artifacts import rotate_recording_artifact

            for row in rows:
                file_path = Path(source_crypto.decrypt_text(row["encrypted_filename"]))
                backup_path = file_path.with_suffix(f"{file_path.suffix}.bak")
                backup_path.write_bytes(file_path.read_bytes())
                backup_paths.append((file_path, backup_path))

                rotate_recording_artifact(file_path, source_crypto, target_crypto)
                rotated_files += 1

                metadata = RecordingMetadata(
                    filename=str(file_path),
                    duration_seconds=float(row["duration_seconds"]),
                    sha256=source_crypto.decrypt_text(row["encrypted_sha256"]),
                    created_at=datetime.fromisoformat(
                        source_crypto.decrypt_text(row["encrypted_created_at"])
                    ),
                    samplerate=int(row["samplerate"]),
                    channels=int(row["channels"]),
                    frames=int(row["frames"]),
                    file_size_bytes=int(file_path.stat().st_size),
                )
                _update_encrypted_row(conn, int(row["id"]), metadata, target_crypto)
                rotated_rows += 1

            _log_audit_event_with_connection(
                conn,
                event_type="key_rotation",
                event_status="info",
                base_folder=base_folder,
                encryption_keys=target_keys,
                details={"rotated_files": rotated_files, "rotated_rows": rotated_rows},
            )
            conn.commit()
        except Exception as exc:
            for file_path, backup_path in backup_paths:
                if backup_path.exists():
                    backup_path.replace(file_path)
            _log_audit_event_with_connection(
                conn,
                event_type="key_rotation",
                event_status="error",
                base_folder=base_folder,
                encryption_keys=encryption_keys,
                details={"error": str(exc), "rotated_files": rotated_files, "rotated_rows": rotated_rows},
            )
            conn.commit()
            raise
        finally:
            for _, backup_path in backup_paths:
                if backup_path.exists():
                    backup_path.unlink()

    return {
        "rotated_files": rotated_files,
        "rotated_rows": rotated_rows,
        "primary_key": target_crypto.primary_key,
    }


def migrate_recording_artifacts(
    *,
    base_folder: str = "recordings",
    encryption_keys: Sequence[str] | str | None = None,
    target_version: int = 1,
    recording_ids: Sequence[int] | None = None,
) -> Dict[str, Any]:
    """Upgrade recording artifacts to the target container version with audit trails."""
    db_path = init_db(base_folder, encryption_keys=encryption_keys)
    crypto = EncryptionManager(encryption_keys)
    where = ""
    params: List[Any] = []
    if recording_ids:
        ids = [int(recording_id) for recording_id in recording_ids]
        placeholders = ", ".join(["?"] * len(ids))
        where = f"WHERE id IN ({placeholders})"
        params.extend(ids)

    from .artifacts import inspect_recording_artifact, migrate_recording_artifact

    migrated = 0
    skipped = 0
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT id, encrypted_filename
            FROM recordings
            {where}
            ORDER BY id ASC
            """,
            params,
        ).fetchall()

        for row in rows:
            file_path = Path(crypto.decrypt_text(row["encrypted_filename"]))
            try:
                before = inspect_recording_artifact(file_path)
                summary = migrate_recording_artifact(
                    file_path,
                    crypto,
                    target_version=target_version,
                )
                if summary["migrated"]:
                    migrated += 1
                    _log_audit_event_with_connection(
                        conn,
                        event_type="artifact_migration",
                        event_status="info",
                        base_folder=base_folder,
                        encryption_keys=encryption_keys,
                        recording_id=int(row["id"]),
                        details={
                            "filename": str(file_path),
                            "from_version": before["version"],
                            "to_version": summary["to_version"],
                        },
                    )
                else:
                    skipped += 1
            except Exception as exc:
                _log_audit_event_with_connection(
                    conn,
                    event_type="artifact_migration",
                    event_status="error",
                    base_folder=base_folder,
                    encryption_keys=encryption_keys,
                    recording_id=int(row["id"]),
                    details={"filename": str(file_path), "error": str(exc), "target_version": target_version},
                )
                conn.commit()
                raise
        conn.commit()

    return {"migrated": migrated, "skipped": skipped, "target_version": target_version}
