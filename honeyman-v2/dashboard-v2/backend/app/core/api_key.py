"""Per-sensor API key utilities.

Keys are issued at registration time. Only the SHA256 hash is stored on the
sensor row; the plaintext is returned exactly once (in the registration
response) and never persisted. The key is required only for sensor → backend
writes (heartbeat, threat ingest, rule poll); reads are public.
"""

import hashlib
import secrets
from typing import Optional

API_KEY_PREFIX = "hms_"  # honeyman-sensor key, easy to grep for in logs
API_KEY_BYTES = 32       # 256 bits of entropy


def generate_api_key() -> str:
    """
    Generate a new API key.

    Format: hms_<43-char URL-safe base64>
    Returned exactly once at registration; we only store the hash.
    """
    return API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_BYTES)


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key with SHA256.

    We use SHA256 (not bcrypt) because:
    - The key is high-entropy random, so no need for a slow KDF
    - Sensors hit the API many times per minute; bcrypt would dominate CPU
    - We only need to detect equality, not protect against guessing
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """Constant-time comparison of provided key against stored hash."""
    if not provided_key or not stored_hash:
        return False
    return secrets.compare_digest(hash_api_key(provided_key), stored_hash)


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Extract the bearer token from an Authorization header."""
    if not authorization_header:
        return None
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]
