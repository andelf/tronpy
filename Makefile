all: ci

lint:
	ruff check
	# mypy tronpy

checkformat:
	ruff format --check

format:
	ruff format

test:
	pytest tests/ ${TEST_ARGS}

ci: checkformat lint

generate-proto:
	cd tronpy/proto && \
	protoc -I=. \
		--python_out=. \
		--pyi_out=. \
		tron.proto && \
	cd -
