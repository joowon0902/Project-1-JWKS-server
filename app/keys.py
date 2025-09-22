from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def _b64url_uint(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    data = n.to_bytes(byte_length, byteorder='big')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

@dataclass
class KeyRecord:
    kid: str
    private_pem: bytes
    public_pem: bytes
    n: str
    e: str
    expires_at: int

class KeyStore:
    def __init__(self) -> None:
        self._keys: Dict[str, KeyRecord] = {}

    @staticmethod
    def generate_rsa_key(expires_in_seconds: int) -> KeyRecord:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        n_b64 = _b64url_uint(numbers.n)
        e_b64 = _b64url_uint(numbers.e)

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyRecord(
            kid=str(uuid.uuid4()),
            private_pem=private_pem,
            public_pem=public_pem,
            n=n_b64,
            e=e_b64,
            expires_at=int(time.time()) + expires_in_seconds,
        )

    def add(self, rec: KeyRecord) -> None:
        self._keys[rec.kid] = rec

    def get(self, kid: str) -> Optional[KeyRecord]:
        return self._keys.get(kid)

    def unexpired(self) -> List[KeyRecord]:
        now = int(time.time())
        return [k for k in self._keys.values() if k.expires_at > now]

    def expired(self) -> List[KeyRecord]:
        now = int(time.time())
        return [k for k in self._keys.values() if k.expires_at <= now]

    def jwks(self, kid: Optional[str] = None) -> Dict[str, list]:
        keys = self.unexpired()
        if kid is not None:
            keys = [k for k in keys if k.kid == kid]
        return {
            'keys': [
                {
                    'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': k.kid,
                    'n': k.n, 'e': k.e, 'x-exp': k.expires_at
                } for k in keys
            ]
        }
