import json
from jwt.algorithms import RSAAlgorithm
import time
import jwt
from fastapi.testclient import TestClient

from app.main import app, active_key, expired_key

client = TestClient(app)

def _find_jwk_by_kid(jwks, kid):
    for k in jwks.get('keys', []):
        if k.get('kid') == kid:
            return k
    return None

def test_jwks_contains_only_unexpired_key():
    resp = client.get('/jwks')
    assert resp.status_code == 200
    jwks = resp.json()
    assert _find_jwk_by_kid(jwks, active_key.kid) is not None
    assert _find_jwk_by_kid(jwks, expired_key.kid) is None

def test_jwks_filter_by_kid():
    resp = client.get(f'/jwks?kid={active_key.kid}')
    assert resp.status_code == 200
    jwks = resp.json()
    assert len(jwks['keys']) in (0, 1)
    if jwks['keys']:
        assert jwks['keys'][0]['kid'] == active_key.kid

def test_auth_issues_valid_jwt_and_kid():
    resp = client.post('/auth')
    assert resp.status_code == 200
    body = resp.json()
    token = body['token']
    kid_used = body['kid']
    assert kid_used == active_key.kid
    jwks_resp = client.get('/jwks')
    jwks = jwks_resp.json()
    jwk = [k for k in jwks['keys'] if k['kid'] == kid_used]
    assert jwk
    jwk = jwk[0]
    public_key = RSAAlgorithm.from_jwk(json.dumps({'kty': 'RSA', 'n': jwk['n'], 'e': jwk['e']}))
    decoded = jwt.decode(token, key=public_key, algorithms=['RS256'], options={'verify_aud': False})
    assert decoded['sub'] == 'user123'
    assert decoded['iss'] == 'edu-jwks-server'
    assert decoded['exp'] > int(time.time())

def test_auth_expired_token_and_key_not_in_jwks():
    resp = client.post('/auth?expired=1')
    assert resp.status_code == 200
    body = resp.json()
    token = body['token']
    kid_used = body['kid']
    assert kid_used == expired_key.kid
    jwks = client.get('/jwks').json()
    assert _find_jwk_by_kid(jwks, kid_used) is None

    # 여기만 변경
    expired_pubkey = RSAAlgorithm.from_jwk(json.dumps({'kty': 'RSA', 'n': expired_key.n, 'e': expired_key.e}))
    try:
        jwt.decode(token, key=expired_pubkey, algorithms=['RS256'], options={'verify_aud': False})
        assert False, 'Expected token to be expired'
    except jwt.ExpiredSignatureError:
        pass

def test_http_methods_and_status_codes():
    resp = client.get('/auth')
    assert resp.status_code in (405, 404)
    resp = client.post('/jwks')
    assert resp.status_code in (405, 404)
