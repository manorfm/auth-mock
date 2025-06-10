.PHONY: deps test build run clean lint swagger migrate migrate-up migrate-down migrate-force migrate-reset

# Variables
BINARY_NAME=auth-mock
BIN_DIR=bin
BINARY_PATH=$(BIN_DIR)/$(BINARY_NAME)
MIGRATION_UP_DIR=migrations/up
MIGRATION_DOWN_DIR=migrations/down
MIGRATE_CMD=go run cmd/migrate/main.go

# Install dependencies
deps:
	go mod tidy
	go mod download

# Run tests
test:
	go test -timeout=240s -v ./... -cover

# Build the application (ensure bin/ exists)
build:
	mkdir -p $(BIN_DIR)
	go build -o $(BINARY_PATH) cmd/main.go

# Run the application (builds first)
run: build
	./$(BINARY_PATH)

# Clean build artifacts
clean:
	go clean
	rm -rf $(BIN_DIR)

# Lint the code
lint:
	golangci-lint run

# Generate Swagger documentation
swagger:
	swag init -g cmd/main.go -o docs

# Run all checks
check: lint test
