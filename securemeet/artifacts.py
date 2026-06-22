"""Versioned encrypted recording artifact helpers."""

from __future__ import annotations

import base64
import io
import json
import struct
from bisect import bisect_right
from pathlib import Path
from typing import BinaryIO, Iterator

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .security import EncryptionManager

ARTIFACT_MAGIC = b"SME1"
ARTIFACT_VERSION = 1
LEGACY_ARTIFACT_VERSION = 0
DEFAULT_CHUNK_SIZE = 64 * 1024
FORMAT_NAME = "securemeet-chunked-chacha20poly1305-v1"


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def is_chunked_recording_bytes(payload: bytes) -> bool:
    """Return whether a payload uses the SecureMeet chunked artifact format."""
    return payload.startswith(ARTIFACT_MAGIC)


def _derive_chunk_aad(header: dict[str, object]) -> bytes:
    aad_context = {
        "chunk_size": header["chunk_size"],
        "format": header["format"],
        "nonce_prefix": header["nonce_prefix"],
        "version": header["version"],
    }
    return json.dumps(aad_context, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _build_header(
    *,
    chunk_size: int,
    file_key: bytes,
    crypto: EncryptionManager,
    nonce_prefix: bytes,
) -> dict[str, object]:
    wrap_salt = crypto.generate_salt()
    wrapping_key = crypto.derive_material(
        info=b"securemeet-recording-file-wrap-v1",
        length=32,
        salt=wrap_salt,
    )
    wrapped_file_key = crypto.wrap_key_material(file_key, wrapping_key=wrapping_key)
    return {
        "chunk_size": chunk_size,
        "format": FORMAT_NAME,
        "nonce_prefix": _encode_bytes(nonce_prefix),
        "version": ARTIFACT_VERSION,
        "wrap_salt": _encode_bytes(wrap_salt),
        "wrapped_file_key": _encode_bytes(wrapped_file_key),
    }


def _serialize_header(header: dict[str, object]) -> bytes:
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return ARTIFACT_MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes


def _parse_header_bytes(payload: bytes) -> tuple[dict[str, object], int]:
    stream = io.BytesIO(payload)
    header = _read_header(stream)
    return header, stream.tell()


def _read_header(handle: BinaryIO) -> dict[str, object]:
    magic = handle.read(len(ARTIFACT_MAGIC))
    if magic != ARTIFACT_MAGIC:
        raise InvalidToken("not a chunked SecureMeet artifact")
    header_len_bytes = handle.read(4)
    if len(header_len_bytes) != 4:
        raise InvalidToken("truncated SecureMeet artifact header")
    header_len = struct.unpack(">I", header_len_bytes)[0]
    header_bytes = handle.read(header_len)
    if len(header_bytes) != header_len:
        raise InvalidToken("truncated SecureMeet artifact metadata")
    return json.loads(header_bytes.decode("utf-8"))


def _chunk_plaintext_length(ciphertext_length: int) -> int:
    if ciphertext_length < 16:
        raise InvalidToken("invalid SecureMeet artifact chunk size")
    return ciphertext_length - 16


def _index_chunk_layout(payload: bytes) -> tuple[dict[str, object], int, list[tuple[int, int, int]], int]:
    header, data_offset = _parse_header_bytes(payload)
    stream = io.BytesIO(payload)
    stream.seek(data_offset)
    chunk_index: list[tuple[int, int, int]] = []
    plaintext_offset = 0
    while True:
        chunk_len_offset = stream.tell()
        chunk_len_bytes = stream.read(4)
        if chunk_len_bytes == b"":
            break
        if len(chunk_len_bytes) != 4:
            raise InvalidToken("truncated SecureMeet artifact chunk length")
        ciphertext_length = struct.unpack(">I", chunk_len_bytes)[0]
        ciphertext_offset = stream.tell()
        ciphertext = stream.read(ciphertext_length)
        if len(ciphertext) != ciphertext_length:
            raise InvalidToken("truncated SecureMeet artifact chunk")
        plaintext_length = _chunk_plaintext_length(ciphertext_length)
        chunk_index.append((ciphertext_offset, ciphertext_length, plaintext_offset))
        plaintext_offset += plaintext_length
    return header, data_offset, chunk_index, plaintext_offset


class DecryptedArtifactReader:
    """Seekable file-like view over an encrypted recording artifact."""

    def __init__(self, path: str | Path, crypto: EncryptionManager) -> None:
        self._path = Path(path)
        self._crypto = crypto
        self._closed = False
        self._position = 0
        self._payload = self._path.read_bytes()
        self._is_chunked = is_chunked_recording_bytes(self._payload)
        self._legacy_buffer: io.BytesIO | None = None
        self._header: dict[str, object] | None = None
        self._chunk_index: list[tuple[int, int, int]] = []
        self._chunk_starts: list[int] = []
        self._total_plaintext_bytes = 0
        self._chunk_cache: dict[int, bytes] = {}
        self._aad_prefix = b""
        self._nonce_prefix = b""
        self._file_key = b""

        if not self._is_chunked:
            self._legacy_buffer = io.BytesIO(crypto.decrypt_bytes(self._payload))
            return

        header, _, chunk_index, total_plaintext_bytes = _index_chunk_layout(self._payload)
        if header.get("format") != FORMAT_NAME or int(header.get("version", 0)) != ARTIFACT_VERSION:
            raise InvalidToken("unsupported SecureMeet artifact version")
        self._header = header
        self._chunk_index = chunk_index
        self._chunk_starts = [plaintext_offset for _, _, plaintext_offset in chunk_index]
        self._total_plaintext_bytes = total_plaintext_bytes
        self._aad_prefix = _derive_chunk_aad(header)
        self._nonce_prefix = _decode_bytes(str(header["nonce_prefix"]))
        self._file_key = _unwrap_file_key(header, crypto)

    @property
    def samplerate(self) -> int | None:
        return None

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    @property
    def closed(self) -> bool:
        return self._closed

    def tell(self) -> int:
        if self._legacy_buffer is not None:
            return self._legacy_buffer.tell()
        return self._position

    def close(self) -> None:
        self._closed = True
        if self._legacy_buffer is not None:
            self._legacy_buffer.close()

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if self._legacy_buffer is not None:
            return self._legacy_buffer.seek(offset, whence)
        if whence == io.SEEK_SET:
            new_position = offset
        elif whence == io.SEEK_CUR:
            new_position = self._position + offset
        elif whence == io.SEEK_END:
            new_position = self._total_plaintext_bytes + offset
        else:
            raise ValueError("unsupported whence")
        self._position = max(0, min(new_position, self._total_plaintext_bytes))
        return self._position

    def _decrypt_chunk(self, chunk_number: int) -> bytes:
        cached = self._chunk_cache.get(chunk_number)
        if cached is not None:
            return cached
        ciphertext_offset, ciphertext_length, _ = self._chunk_index[chunk_number]
        ciphertext = self._payload[ciphertext_offset : ciphertext_offset + ciphertext_length]
        nonce = self._nonce_prefix + chunk_number.to_bytes(8, "big")
        aad = self._aad_prefix + chunk_number.to_bytes(8, "big")
        plaintext = ChaCha20Poly1305(self._file_key).decrypt(nonce, ciphertext, aad)
        self._chunk_cache = {chunk_number: plaintext}
        return plaintext

    def read(self, size: int = -1) -> bytes:
        if self._legacy_buffer is not None:
            return self._legacy_buffer.read(size)
        if size is None or size < 0:
            size = self._total_plaintext_bytes - self._position
        if size == 0 or self._position >= self._total_plaintext_bytes:
            return b""

        end_position = min(self._position + size, self._total_plaintext_bytes)
        remaining = end_position - self._position
        cursor = self._position
        segments: list[bytes] = []
        while remaining > 0:
            chunk_number = max(0, bisect_right(self._chunk_starts, cursor) - 1)
            chunk_start = self._chunk_starts[chunk_number]
            chunk_plaintext = self._decrypt_chunk(chunk_number)
            offset_in_chunk = cursor - chunk_start
            take = min(len(chunk_plaintext) - offset_in_chunk, remaining)
            segments.append(chunk_plaintext[offset_in_chunk : offset_in_chunk + take])
            cursor += take
            remaining -= take

        self._position = end_position
        return b"".join(segments)


def open_decrypted_recording(path: str | Path, crypto: EncryptionManager) -> DecryptedArtifactReader:
    """Open an encrypted recording as a seekable decrypted file-like object."""
    return DecryptedArtifactReader(path, crypto)


def _unwrap_file_key(header: dict[str, object], crypto: EncryptionManager) -> bytes:
    wrapping_key = crypto.derive_material(
        info=b"securemeet-recording-file-wrap-v1",
        length=32,
        salt=_decode_bytes(str(header["wrap_salt"])),
    )
    return crypto.unwrap_key_material(
        _decode_bytes(str(header["wrapped_file_key"])),
        wrapping_key=wrapping_key,
    )


def encrypt_recording_stream(
    source: BinaryIO,
    target: BinaryIO,
    crypto: EncryptionManager,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, int]:
    """Encrypt a plaintext stream into the SecureMeet chunked artifact format."""
    file_key = ChaCha20Poly1305.generate_key()
    nonce_prefix = crypto.generate_salt(length=4)
    header = _build_header(
        chunk_size=chunk_size,
        file_key=file_key,
        crypto=crypto,
        nonce_prefix=nonce_prefix,
    )
    aad_prefix = _derive_chunk_aad(header)
    target.write(_serialize_header(header))

    cipher = ChaCha20Poly1305(file_key)
    chunk_index = 0
    plaintext_bytes = 0
    while True:
        chunk = source.read(chunk_size)
        if chunk == b"":
            break
        nonce = nonce_prefix + chunk_index.to_bytes(8, "big")
        aad = aad_prefix + chunk_index.to_bytes(8, "big")
        ciphertext = cipher.encrypt(nonce, chunk, aad)
        target.write(struct.pack(">I", len(ciphertext)))
        target.write(ciphertext)
        plaintext_bytes += len(chunk)
        chunk_index += 1

    return {"chunk_count": chunk_index, "plaintext_bytes": plaintext_bytes}


def iter_decrypted_recording_chunks(
    source: BinaryIO,
    crypto: EncryptionManager,
) -> Iterator[bytes]:
    """Yield decrypted plaintext chunks from a SecureMeet artifact stream."""
    header = _read_header(source)
    if header.get("format") != FORMAT_NAME or int(header.get("version", 0)) != ARTIFACT_VERSION:
        raise InvalidToken("unsupported SecureMeet artifact version")

    nonce_prefix = _decode_bytes(str(header["nonce_prefix"]))
    file_key = _unwrap_file_key(header, crypto)
    aad_prefix = _derive_chunk_aad(header)
    cipher = ChaCha20Poly1305(file_key)
    chunk_index = 0

    while True:
        chunk_len_bytes = source.read(4)
        if chunk_len_bytes == b"":
            break
        if len(chunk_len_bytes) != 4:
            raise InvalidToken("truncated SecureMeet artifact chunk length")
        chunk_len = struct.unpack(">I", chunk_len_bytes)[0]
        ciphertext = source.read(chunk_len)
        if len(ciphertext) != chunk_len:
            raise InvalidToken("truncated SecureMeet artifact chunk")
        nonce = nonce_prefix + chunk_index.to_bytes(8, "big")
        aad = aad_prefix + chunk_index.to_bytes(8, "big")
        yield cipher.decrypt(nonce, ciphertext, aad)
        chunk_index += 1


def inspect_recording_artifact(path: str | Path) -> dict[str, object]:
    """Inspect the stored artifact without decrypting plaintext audio."""
    payload = Path(path).read_bytes()
    if not is_chunked_recording_bytes(payload):
        return {
            "chunk_count": None,
            "chunk_size": None,
            "format": "securemeet-fernet-legacy",
            "plaintext_bytes": None,
            "version": LEGACY_ARTIFACT_VERSION,
        }
    header, _, chunk_index, total_plaintext_bytes = _index_chunk_layout(payload)
    return {
        "chunk_count": len(chunk_index),
        "chunk_size": int(header["chunk_size"]),
        "format": str(header["format"]),
        "plaintext_bytes": total_plaintext_bytes,
        "version": int(header["version"]),
    }


def decrypt_recording_stream(source: BinaryIO, target: BinaryIO, crypto: EncryptionManager) -> int:
    """Decrypt a SecureMeet artifact stream into plaintext bytes."""
    total = 0
    for chunk in iter_decrypted_recording_chunks(source, crypto):
        target.write(chunk)
        total += len(chunk)
    return total


def load_recording_bytes(path: str | Path, crypto: EncryptionManager) -> bytes:
    """Load either a legacy Fernet token or a chunked SecureMeet artifact."""
    file_path = Path(path)
    payload = file_path.read_bytes()
    if is_chunked_recording_bytes(payload):
        sink = io.BytesIO()
        decrypt_recording_stream(io.BytesIO(payload), sink, crypto)
        return sink.getvalue()
    return crypto.decrypt_bytes(payload)


def migrate_recording_artifact(
    path: str | Path,
    source_crypto: EncryptionManager,
    target_crypto: EncryptionManager | None = None,
    *,
    target_version: int = ARTIFACT_VERSION,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, object]:
    """Upgrade a recording artifact to the target container version in place."""
    if target_version != ARTIFACT_VERSION:
        raise ValueError(f"unsupported target_version: {target_version}")

    file_path = Path(path)
    payload = file_path.read_bytes()
    effective_target_crypto = target_crypto or source_crypto
    original = inspect_recording_artifact(file_path)
    original_version = int(original["version"])
    if original_version == ARTIFACT_VERSION and effective_target_crypto is source_crypto:
        return {
            "format": str(original["format"]),
            "from_version": original_version,
            "migrated": False,
            "to_version": target_version,
        }

    temp_path = file_path.with_suffix(f"{file_path.suffix}.migrating")
    if not is_chunked_recording_bytes(payload):
        plaintext = source_crypto.decrypt_bytes(payload)
        with temp_path.open("wb") as target:
            encrypt_recording_stream(io.BytesIO(plaintext), target, effective_target_crypto, chunk_size=chunk_size)
        temp_path.replace(file_path)
        return {
            "format": FORMAT_NAME,
            "from_version": original_version,
            "migrated": True,
            "to_version": target_version,
        }

    reader = open_decrypted_recording(file_path, source_crypto)
    try:
        with temp_path.open("wb") as target:
            encrypt_recording_stream(reader, target, effective_target_crypto, chunk_size=chunk_size)
    finally:
        reader.close()
    temp_path.replace(file_path)
    return {
        "format": FORMAT_NAME,
        "from_version": original_version,
        "migrated": True,
        "to_version": target_version,
    }


def rotate_recording_artifact(
    path: str | Path,
    source_crypto: EncryptionManager,
    target_crypto: EncryptionManager,
) -> None:
    """Rotate a recording artifact to a new primary key."""
    file_path = Path(path)
    payload = file_path.read_bytes()
    if not is_chunked_recording_bytes(payload):
        rotated = target_crypto.rotate_token(payload)
        temp_path = file_path.with_suffix(f"{file_path.suffix}.rotating")
        temp_path.write_bytes(rotated)
        temp_path.replace(file_path)
        return

    source = io.BytesIO(payload)
    header = _read_header(source)
    file_key = _unwrap_file_key(header, source_crypto)
    new_header = _build_header(
        chunk_size=int(header["chunk_size"]),
        file_key=file_key,
        crypto=target_crypto,
        nonce_prefix=_decode_bytes(str(header["nonce_prefix"])),
    )

    temp_path = file_path.with_suffix(f"{file_path.suffix}.rotating")
    with temp_path.open("wb") as target:
        target.write(_serialize_header(new_header))
        while True:
            chunk_len_bytes = source.read(4)
            if chunk_len_bytes == b"":
                break
            if len(chunk_len_bytes) != 4:
                raise InvalidToken("truncated SecureMeet artifact during rotation")
            chunk_len = struct.unpack(">I", chunk_len_bytes)[0]
            ciphertext = source.read(chunk_len)
            if len(ciphertext) != chunk_len:
                raise InvalidToken("truncated SecureMeet artifact chunk during rotation")
            target.write(chunk_len_bytes)
            target.write(ciphertext)

    temp_path.replace(file_path)