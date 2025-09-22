# JWKS Server (FastAPI, RS256)

A minimal educational JWKS server that:

- Generates RSA key pairs with `kid` and expiry timestamps.
- Serves **only unexpired** public keys at a RESTful `/jwks` endpoint (JWKS format).
- Exposes an `/auth` endpoint: POST returns a signed JWT (RS256) with `kid` in the header.
  - If you add the `?expired=1` query parameter, the server issues a **JWT signed with an expired key** and includes an **expired `exp`** claim.
- Listens on port **8080** by default.

> ⚠️ For classroom use only. Do not deploy as-is to production.

## Quickstart

1) Create a virtual environment

   `python -m venv .venv`

   Activate it:

   - macOS/Linux: `source .venv/bin/activate`
   - Windows: `.venv\\Scripts\\activate`

2) Install deps: `pip install -r requirements.txt`

3) Run server: `uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload`

Open:
- JWKS: http://localhost:8080/jwks
- Auth (valid): POST http://localhost:8080/auth
- Auth (expired): POST http://localhost:8080/auth?expired=1

The `/auth` endpoint requires no request body.

## Endpoints

### GET /jwks
Returns a JWKS with only unexpired keys. Optional filter: `?kid=...`.

### POST /auth
Returns JSON `{ "token": "<JWT>" }`. Use `?expired=1` for an already-expired token signed with an expired key.

## Project Layout
app/
  main.py
  keys.py
  security.py
tests/
  test_app.py
.coveragerc, Makefile, pyproject.toml, requirements.txt

## Linting & Tests
- `ruff check .`
- `black --check .`
- `pytest --maxfail=1 --disable-warnings -q --cov=app --cov-report=term-missing`
