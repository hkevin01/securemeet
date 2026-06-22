"""Encryption helpers for protected recordings and metadata."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Any, Iterable, List, Sequence

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

ENCRYPTION_KEYS_ENV = "SECUREMEET_ENCRYPTION_KEYS"
DEFAULT_ARGON2ID_ITERATIONS = 3
DEFAULT_ARGON2ID_LANES = 4
DEFAULT_ARGON2ID_MEMORY_COST = 64 * 1024


@dataclass(frozen=True)
class PasswordProtectedKey:
    """Serialized password-based custody for one SecureMeet encryption key."""

    algorithm: str
    wrapped_key: str
    salt: str
    iterations: int
    lanes: int
    memory_cost: int

    def to_dict(self) -> dict[str, Any]:
        """Convert the custody bundle to a plain dictionary."""
        return {
            "algorithm": self.algorithm,
            "wrapped_key": self.wrapped_key,
            "salt": self.salt,
            "iterations": self.iterations,
            "lanes": self.lanes,
            "memory_cost": self.memory_cost,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PasswordProtectedKey":
        """Rehydrate a password custody bundle from a dictionary."""
        return cls(
            algorithm=str(payload["algorithm"]),
            wrapped_key=str(payload["wrapped_key"]),
            salt=str(payload["salt"]),
            iterations=int(payload["iterations"]),
            lanes=int(payload["lanes"]),
            memory_cost=int(payload["memory_cost"]),
        )


def generate_encryption_key() -> str:
    """Generate a new Fernet key for SecureMeet callers to persist securely."""
    return Fernet.generate_key().decode("ascii")


def _normalize_keys(encryption_keys: Sequence[str] | str | None) -> List[bytes]:
    if encryption_keys is None:
        raw_keys = os.getenv(ENCRYPTION_KEYS_ENV, "")
        candidates = raw_keys.split(",") if raw_keys else []
    elif isinstance(encryption_keys, str):
        candidates = encryption_keys.split(",")
    else:
        candidates = list(encryption_keys)

    normalized = [candidate.strip().encode("ascii") for candidate in candidates if candidate.strip()]
    if not normalized:
        raise ValueError(
            "encryption keys are required - pass encryption_keys or set "
            f"{ENCRYPTION_KEYS_ENV}"
        )
    return normalized


class EncryptionManager:
    """Encrypt and decrypt SecureMeet file and metadata payloads."""

    def __init__(self, encryption_keys: Sequence[str] | str | None = None) -> None:
        self._keys = _normalize_keys(encryption_keys)
        self._cipher = MultiFernet([Fernet(key) for key in self._keys])
        self._index_key = base64.urlsafe_b64decode(self._keys[0])

    @property
    def primary_key(self) -> str:
        """Return the active primary key as an ASCII string."""
        return self._keys[0].decode("ascii")

    @property
    def primary_key_material(self) -> bytes:
        """Return the decoded primary key material for derivation operations."""
        return self._index_key

    def encrypt_bytes(self, payload: bytes) -> bytes:
        """Encrypt a bytes payload."""
        return self._cipher.encrypt(payload)

    def decrypt_bytes(self, payload: bytes | str) -> bytes:
        """Decrypt a previously encrypted payload."""
        return self._cipher.decrypt(payload)

    def rotate_token(self, payload: bytes | str) -> bytes:
        """Re-encrypt an existing Fernet token under the current primary key."""
        return self._cipher.rotate(payload)

    def encrypt_text(self, value: str) -> str:
        """Encrypt a UTF-8 string and return an ASCII token."""
        return self.encrypt_bytes(value.encode("utf-8")).decode("ascii")

    def decrypt_text(self, value: bytes | str) -> str:
        """Decrypt an ASCII token into a UTF-8 string."""
        return self.decrypt_bytes(value).decode("utf-8")

    def blind_index(self, value: str) -> str:
        """Create an HMAC digest usable for exact-match lookups."""
        normalized = value.strip().lower().encode("utf-8")
        return hmac.new(self._index_key, normalized, hashlib.sha256).hexdigest()

    def generate_salt(self, *, length: int = 16) -> bytes:
        """Generate random salt bytes."""
        return os.urandom(length)

    def derive_material(self, *, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
        """Derive cryptographic material from the primary key using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(self.primary_key_material)

    def wrap_key_material(self, key_material: bytes, *, wrapping_key: bytes) -> bytes:
        """Wrap key material with AES key wrap."""
        return aes_key_wrap(wrapping_key, key_material)

    def unwrap_key_material(self, wrapped_key: bytes, *, wrapping_key: bytes) -> bytes:
        """Unwrap key material with AES key wrap."""
        return aes_key_unwrap(wrapping_key, wrapped_key)


def resolve_encryption_keys(encryption_keys: Sequence[str] | str | None = None) -> Iterable[str]:
    """Normalize configured keys into their string form."""
    return [key.decode("ascii") for key in _normalize_keys(encryption_keys)]


def build_rotation_keyset(
    new_primary_key: str,
    encryption_keys: Sequence[str] | str | None = None,
) -> List[str]:
    """Build a de-duplicated MultiFernet key list with a new primary first."""
    candidate = new_primary_key.strip()
    if not candidate:
        raise ValueError("new_primary_key must not be empty")

    ordered_keys = [candidate, *resolve_encryption_keys(encryption_keys)]
    deduplicated: List[str] = []
    for key in ordered_keys:
        if key not in deduplicated:
            deduplicated.append(key)
    return deduplicated


def _derive_password_wrapping_key(
    password: str,
    *,
    salt: bytes,
    iterations: int,
    lanes: int,
    memory_cost: int,
) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
        ad=None,
        secret=None,
    )
    return kdf.derive(password.encode("utf-8"))


def create_password_protected_key(
    password: str,
    *,
    encryption_key: str | None = None,
    iterations: int = DEFAULT_ARGON2ID_ITERATIONS,
    lanes: int = DEFAULT_ARGON2ID_LANES,
    memory_cost: int = DEFAULT_ARGON2ID_MEMORY_COST,
) -> PasswordProtectedKey:
    """Protect a SecureMeet Fernet key with Argon2id and AES key wrap."""
    if not password:
        raise ValueError("password must not be empty")

    key_text = encryption_key or generate_encryption_key()
    raw_key = base64.urlsafe_b64decode(key_text.encode("ascii"))
    salt = os.urandom(16)
    wrapping_key = _derive_password_wrapping_key(
        password,
        salt=salt,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    wrapped_key = aes_key_wrap(wrapping_key, raw_key)
    return PasswordProtectedKey(
        algorithm="argon2id-aes-key-wrap-v1",
        wrapped_key=base64.urlsafe_b64encode(wrapped_key).decode("ascii"),
        salt=base64.urlsafe_b64encode(salt).decode("ascii"),
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )


def unlock_password_protected_key(
    password: str,
    payload: PasswordProtectedKey | dict[str, Any],
) -> str:
    """Recover a SecureMeet Fernet key from password-protected local custody."""
    if not password:
        raise ValueError("password must not be empty")

    protected = payload if isinstance(payload, PasswordProtectedKey) else PasswordProtectedKey.from_dict(payload)
    if protected.algorithm != "argon2id-aes-key-wrap-v1":
        raise ValueError(f"unsupported password protection algorithm: {protected.algorithm}")

    wrapping_key = _derive_password_wrapping_key(
        password,
        salt=base64.urlsafe_b64decode(protected.salt.encode("ascii")),
        iterations=protected.iterations,
        lanes=protected.lanes,
        memory_cost=protected.memory_cost,
    )
    raw_key = aes_key_unwrap(
        wrapping_key,
        base64.urlsafe_b64decode(protected.wrapped_key.encode("ascii")),
    )
    return base64.urlsafe_b64encode(raw_key).decode("ascii")


__all__ = [
    "DEFAULT_ARGON2ID_ITERATIONS",
    "DEFAULT_ARGON2ID_LANES",
    "DEFAULT_ARGON2ID_MEMORY_COST",
    "ENCRYPTION_KEYS_ENV",
    "EncryptionManager",
    "InvalidUnwrap",
    "PasswordProtectedKey",
    "build_rotation_keyset",
    "create_password_protected_key",
    "generate_encryption_key",
    "resolve_encryption_keys",
    "unlock_password_protected_key",
]