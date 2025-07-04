all: ci

lint:
	flake8
	# mypy tronpy

checkformat:
	black --check .
	isort --check .

format:
	black .
	isort .

test:
	pytest tests/ ${TEST_ARGS}

ci: checkformat lint test


generate-proto: ## Generate proto files
	cd tronpy/proto/src && \
	$(py) python -m grpc_tools.protoc -I=. \
		--python_out=. \
		--pyi_out=. \
		tron.proto