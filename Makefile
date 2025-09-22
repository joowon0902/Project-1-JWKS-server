.PHONY: run test lint fmt cov

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

test:
	pytest --maxfail=1 --disable-warnings -q

cov:
	pytest --cov=app --cov-report=term-missing

lint:
	ruff check .
	black --check .

fmt:
	black .
