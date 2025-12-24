# MCPB bundle configuration
BUNDLE_NAME = mcp-ipinfo
VERSION ?= 1.0.0

# Docker image configuration (legacy)
IMAGE_NAME = nimbletools/mcp-ipinfo

.PHONY: help install dev-install format format-check lint test test-integration test-all clean run check all bundle bundle-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	uv pip install -e .

dev-install: ## Install the package with dev dependencies
	uv pip install -e ".[dev]"

format: ## Format code with ruff
	uv run ruff format src/ tests/ tests-integration/

format-check: ## Check code formatting with ruff
	uv run ruff format --check src/ tests/ tests-integration/

lint: ## Lint code with ruff
	uv run ruff check src/ tests/ tests-integration/

lint-fix: ## Lint and fix code with ruff
	uv run ruff check --fix src/ tests/ tests-integration/

typecheck: ## Type check code with mypy
	uv run mypy src/

test: ## Run tests with pytest
	uv run pytest tests/ -v

test-cov: ## Run tests with coverage
	uv run pytest tests/ -v --cov=src/mcp_ipinfo --cov-report=term-missing

test-integration: ## Run integration tests (requires IPINFO_API_TOKEN)
	@if [ -z "$${IPINFO_API_TOKEN}" ]; then \
		echo "ERROR: IPINFO_API_TOKEN environment variable is required."; \
		echo "Set it before running integration tests:"; \
		echo "  export IPINFO_API_TOKEN=your_token_here"; \
		echo "  make test-integration"; \
		exit 1; \
	fi
	uv run pytest tests-integration/ -v

test-integration-verbose: ## Run integration tests with full output
	@if [ -z "$${IPINFO_API_TOKEN}" ]; then \
		echo "ERROR: IPINFO_API_TOKEN required. Run: export IPINFO_API_TOKEN=your_token"; \
		exit 1; \
	fi
	uv run pytest tests-integration/ -v -s

test-use-cases: ## Run only use case scenario tests
	@if [ -z "$${IPINFO_API_TOKEN}" ]; then \
		echo "ERROR: IPINFO_API_TOKEN required."; \
		exit 1; \
	fi
	uv run pytest tests-integration/test_use_cases.py -v -s

test-all: test test-integration ## Run all tests (unit + integration)

build-push:
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):latest \
		--push .

# Login to Docker Hub
login:
	docker login

# Clean up local images
clean-docker:
	docker rmi $(IMAGE_NAME):$(VERSION) $(IMAGE_NAME):latest 2>/dev/null || true
	
clean: ## Clean up build artifacts and cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
	rm -rf bundle/ *.mcpb

run: ## Run the MCP server
	uv run python -m mcp_ipinfo.server

run-http: ## Run the MCP server with HTTP transport
	IPINFO_API_TOKEN=$${IPINFO_API_TOKEN} uv run python -m mcp_ipinfo.server

check: format-check lint typecheck test ## Run all checks

all: clean install format lint typecheck test ## Clean, install, format, lint, type check, and test

# MCPB bundle commands
bundle: ## Build MCPB bundle locally
	@./scripts/build-bundle.sh . $(VERSION)

bundle-run: bundle ## Build and run MCPB bundle locally
	@echo "Starting bundle with mcpb-python base image..."
	@python -m http.server 9999 --directory . &
	@sleep 1
	docker run --rm \
		--add-host host.docker.internal:host-gateway \
		-p 8000:8000 \
		-e BUNDLE_URL=http://host.docker.internal:9999/$(BUNDLE_NAME)-v$(VERSION).mcpb \
		ghcr.io/nimblebrain/mcpb-python:3.14

# Development shortcuts
fmt: format ## Alias for format
t: test ## Alias for test
l: lint ## Alias for lint