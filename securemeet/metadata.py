"""Metadata models for recording persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Tuple


@dataclass(frozen=True)
class RecordingMetadata:
    """Canonical metadata for one locally recorded meeting file."""

    filename: str
    duration_seconds: float
    sha256: str
    created_at: datetime
    samplerate: int
    channels: int
    frames: int
    file_size_bytes: int


@dataclass(frozen=True)
class RetentionPolicy:
    """Automatic retention controls for encrypted recording artifacts."""

    max_recordings: int | None = None
    max_age_days: int | None = None
    max_total_bytes: int | None = None

    def validate(self) -> None:
        """Reject invalid retention policy values."""
        if self.max_recordings is not None and self.max_recordings < 1:
            raise ValueError("max_recordings must be >= 1")
        if self.max_age_days is not None and self.max_age_days < 1:
            raise ValueError("max_age_days must be >= 1")
        if self.max_total_bytes is not None and self.max_total_bytes < 1:
            raise ValueError("max_total_bytes must be >= 1")


@dataclass(frozen=True)
class AuditRetentionPolicy:
    """Retention controls for encrypted audit events."""

    max_events: int | None = None
    max_age_days: int | None = None

    def validate(self) -> None:
        """Reject invalid audit retention values."""
        if self.max_events is not None and self.max_events < 1:
            raise ValueError("max_events must be >= 1")
        if self.max_age_days is not None and self.max_age_days < 1:
            raise ValueError("max_age_days must be >= 1")


@dataclass(frozen=True)
class SearchPolicy:
    """Field-level search policy for recording metadata queries."""

    plaintext_filterable_fields: Tuple[str, ...] = (
        "channels",
        "created_at",
        "duration_seconds",
        "file_size_bytes",
        "frames",
        "id",
        "logged_at",
        "samplerate",
    )
    blind_index_filterable_fields: Tuple[str, ...] = ("filename", "sha256")
    sortable_fields: Tuple[str, ...] = (
        "channels",
        "created_at",
        "duration_seconds",
        "file_size_bytes",
        "frames",
        "id",
        "logged_at",
        "samplerate",
    )

    def allows_plaintext_field(self, field_name: str) -> bool:
        """Return whether a plaintext operational field may be queried directly."""
        return field_name in self.plaintext_filterable_fields

    def allows_blind_index_field(self, field_name: str) -> bool:
        """Return whether a blind-indexed sensitive field may be queried."""
        return field_name in self.blind_index_filterable_fields

    def allows_sort(self, field_name: str) -> bool:
        """Return whether a field may be used for ordering."""
        return field_name in self.sortable_fields

    def validate(self) -> None:
        """Ensure the search policy is internally consistent."""
        overlap = set(self.plaintext_filterable_fields).intersection(self.blind_index_filterable_fields)
        if overlap:
            raise ValueError(f"fields cannot be both plaintext and blind-indexed: {sorted(overlap)}")
        sortable = set(self.sortable_fields)
        allowed = set(self.plaintext_filterable_fields)
        if not sortable.issubset(allowed):
            raise ValueError("sortable_fields must be a subset of plaintext_filterable_fields")

    def leakage_model(self) -> dict[str, object]:
        """Describe the allowed query surfaces for callers and docs."""
        return {
            "exact_match_blind_index_fields": list(self.blind_index_filterable_fields),
            "plaintext_filterable_fields": list(self.plaintext_filterable_fields),
            "sortable_fields": list(self.sortable_fields),
            "notes": (
                "Encrypted string fields may only be queried through blind indexes when "
                "explicitly allowed by policy. Plaintext operational metadata remains directly queryable."
            ),
        }


DEFAULT_SEARCH_POLICY = SearchPolicy()
