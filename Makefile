.PHONY: api web test smoke

api:
	uv run uvicorn backend.main:app --reload --port 8000

web:
	cd frontend && npm run dev

test:
	uv run pytest -q

smoke:
	uv run python -I target_app/harness/run_case.py --smoke
