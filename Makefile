.PHONY: api web test smoke

# backend/data holds the patched workspace copy; watching it would restart the API mid-job.
# uvicorn matches excluded dirs against absolute paths, so this must be absolute.
api:
	mkdir -p backend/data
	uv run uvicorn backend.main:app --reload --reload-dir backend --reload-dir engine --reload-exclude $(CURDIR)/backend/data --port 8000

web:
	cd frontend && npm run dev

test:
	uv run pytest -q

smoke:
	uv run python -I target_app/harness/run_case.py --smoke
