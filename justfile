set no-exit-message := true

test-args := env("TEST_ARGS", "")

[private]
default:
    @just --list --unsorted --justfile {{ justfile() }}

# run linters with autofix
[group("Linting")]
lint:
    ruff format . && ruff check --fix .

# run linters (check only)
[group("Linting")]
lint-check:
    ruff format --check . && ruff check .

# run type checking
[group("Linting")]
lint-types:
    mypy tronpy

# run tests
[group("Testing")]
test *args:
    pytest {{ trim(test-args + " " + args) }}

# run ci checks (without tests)
[group("CI")]
ci-lint: lint-check

# run ci checks
[group("CI")]
ci *args: ci-lint (test args)

# build documentation
[group("Documentation")]
docs:
    zensical build

# serve documentation
[group("Documentation")]
docs-serve:
    zensical serve

# develop documentation with live reload
[group("Documentation")]
docs-dev:
    zensical serve

# regenerate protobuf bindings
[group("Development")]
generate-proto:
    cd tronpy/proto && protoc -I=. --python_out=. --pyi_out=. tron.proto
