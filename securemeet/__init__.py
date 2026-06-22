"""SecureMeet local-only recording library."""

from .metadata import RetentionPolicy
from .playback import load_recording, load_recording_bytes, play_recording
from .recorder import record_meeting
from .security import (
	ENCRYPTION_KEYS_ENV,
	PasswordProtectedKey,
	create_password_protected_key,
	generate_encryption_key,
	unlock_password_protected_key,
)
from .storage import (
	fetch_audit_events,
	fetch_recordings,
	get_recording,
	init_db,
	rotate_encryption_keys,
	search_recordings,
	search_recordings_page,
)

__all__ = [
	"ENCRYPTION_KEYS_ENV",
	"PasswordProtectedKey",
	"RetentionPolicy",
	"create_password_protected_key",
	"fetch_audit_events",
	"fetch_recordings",
	"generate_encryption_key",
	"get_recording",
	"init_db",
	"load_recording",
	"load_recording_bytes",
	"play_recording",
	"record_meeting",
	"rotate_encryption_keys",
	"search_recordings",
	"search_recordings_page",
	"unlock_password_protected_key",
]
__version__ = "1.0.0"
