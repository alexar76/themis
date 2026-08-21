.PHONY: configure dev test validate audit publish-dry-run

configure:
	uv run python configure_provider.py

dev: configure
	uv run python agent.py

test:
	uv run pytest -q

validate: configure
	uv run python validate_manifest.py

audit:
	curl --fail-with-body -sS -X POST http://127.0.0.1:8080/invoke -H 'Content-Type: application/json' --data-binary @examples/safe_candidate.json

publish-dry-run: validate
	@echo "Dry run only: aimarket publish capability.json --hub $${AIMARKET_HUB_URL:-http://127.0.0.1:9083}"

