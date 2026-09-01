"""Symmetric encryption for the one secret we store: the Gmail app password.

Keyed off APP_SECRET_KEY (any string). In production set it to a long random value
in the Render dashboard; if it changes, previously stored app passwords can no
longer be decrypted and users just re-enter them.
"""
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

_DEV_FALLBACK = "phishguard-dev-only-not-secret"


def _fernet() -> Fernet:
    secret = os.environ.get("APP_SECRET_KEY", "").strip() or _DEV_FALLBACK
    # Fernet needs a 32-byte urlsafe-base64 key; derive one deterministically.
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""
