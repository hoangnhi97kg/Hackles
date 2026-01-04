.PHONY: check fix test lint format install dev clean

# Run all checks (same as CI)
check:
	@./scripts/check.sh

# Auto-fix formatting issues
fix:
	@./scripts/check.sh --fix

# Run tests only
test:
	pytest tests/ -v

# Run linting only
lint:
	flake8 hackles/ tests/ --count --select=E9,F63,F7,F82,F824 --show-source
	@echo "Lint passed!"

# Format code
format:
	black hackles/ tests/
	isort hackles/ tests/
	@echo "Formatting complete!"

# Install package in development mode
install:
	pip install -e .

# Install dev dependencies
dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install
	@echo "Dev environment ready!"

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .ruff_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "Cleaned!"
