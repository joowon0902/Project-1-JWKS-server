from __future__ import annotations

import time
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from .keys import KeyStore, KeyRecord
from .security import sign_jwt

app = FastAPI(title='Educational JWKS Server', version='1.0.0')

store = KeyStore()
ACTIVE_TTL = 60 * 60
active_key: KeyRecord = store.generate_rsa_key(expires_in_seconds=ACTIVE_TTL)
store.add(active_key)
expired_key: KeyRecord = store.generate_rsa_key(expires_in_seconds=1)
expired_key.expires_at = int(time.time()) - 300
store.add(expired_key)

@app.get('/jwks')
def get_jwks(kid: Optional[str] = Query(default=None)):
    return JSONResponse(store.jwks(kid=kid))

@app.post('/auth')
def auth(expired: Optional[bool] = Query(default=False)):
    truthy = (True, 1, '1', 'true', 'True')
    if expired in truthy:
        key = expired_key
        token, iat, exp = sign_jwt(key, subject='user123', expires_in_seconds=900, expired_override=True)
        return {'token': token, 'kid': key.kid, 'issued_at': iat, 'expires_at': exp, 'expired_key': True}
    key = active_key
    token, iat, exp = sign_jwt(key, subject='user123', expires_in_seconds=900, expired_override=False)
    return {'token': token, 'kid': key.kid, 'issued_at': iat, 'expires_at': exp, 'expired_key': False}
