"""Authentication helpers for the Wadjet server.

Uses argon2id for password hashing (section 13).
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

password_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    r"""Hash a password using argon2id.

    Returns the argon2 hash string, which contains the parameters and
    the encoded hash.  The hash is ``\$argon2id\$t=3,m=16,p=2\$...``.
    """
    return password_hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain password against an argon2 hash.

    Returns ``True`` if the password matches, ``False`` otherwise.
    """
    try:
        password_hasher.verify(hashed, plain)
        return True
    except VerificationError:
        return False


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def invalidate_csrf_token(token: str) -> bool:
    """Check if a CSRF token is valid (implementation-dependent)."""
    # In a real implementation, this would check against a store (session, cookie, etc.)
    # For now, accept any non-empty token.
    return bool(token and len(token) > 10)
