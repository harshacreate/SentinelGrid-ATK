.PHONY: help setup test eval eval-json lab-up lab-down clean

help:
	@echo "setup      - install test dependencies"
	@echo "test       - run the unit tests"
	@echo "eval       - run the detection evaluation report"
	@echo "eval-json  - run the evaluation, emit JSON"
	@echo "lab-up     - start the optional isolated log-shipper lab (Docker)"
	@echo "lab-down   - stop the lab"

setup:
	python3 -m pip install -r requirements.txt

test:
	python3 -m pytest -q

eval:
	python3 -m harness.evaluate

eval-json:
	python3 -m harness.evaluate --json

lab-up:
	docker compose up -d

lab-down:
	docker compose down -v

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
