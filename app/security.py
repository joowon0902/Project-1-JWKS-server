from __future__ import annotations

import time
from typing import Tuple

import jwt
from cryptography.hazmat.primitives import serialization

from .keys import KeyRecord


def load_private_key(private_pem: bytes):
    return serialization.load_pem_private_key(private_pem, password=None)

def sign_jwt(key: KeyRecord, subject: str, expires_in_seconds: int, now: int | None = None,
             expired_override: bool = False) -> Tuple[str, int, int]:
    now = int(time.time()) if now is None else now
    if expired_override:
        iat = now - 300
        exp = now - 60
    else:
        iat = now
        exp = now + expires_in_seconds
    payload = {'sub': subject, 'iat': iat, 'exp': exp, 'iss': 'edu-jwks-server', 'nbf': iat}
    headers = {'kid': key.kid, 'alg': 'RS256'}
    private_key = load_private_key(key.private_pem)
    token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    return token, iat, exp
