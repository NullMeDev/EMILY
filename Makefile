# EMILY Makefile

BINARY_NAME=emily
VERSION=1.0.0-dev
COMMIT=$(shell git rev-parse --short HEAD || echo "unknown")
DATE=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building ${BINARY_NAME}..."
	go build ${LDFLAGS} -o bin/${BINARY_NAME} cmd/emily/main.go

# Build for Android (ARM64)
.PHONY: build-android
build-android:
	@echo "Building ${BINARY_NAME} for Android..."
	GOOS=android GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-android cmd/emily/main.go

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-amd64 cmd/emily/main.go
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-arm64 cmd/emily/main.go
	GOOS=android GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-android-arm64 cmd/emily/main.go
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-darwin-amd64 cmd/emily/main.go
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-darwin-arm64 cmd/emily/main.go

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test ./...

# Run with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	go test -race ./...

# Generate code coverage
.PHONY: coverage
coverage:
	@echo "Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run the application
.PHONY: run
run: build
	./bin/${BINARY_NAME}

# Install the binary
.PHONY: install
install: build
	cp bin/${BINARY_NAME} /usr/local/bin/

# Development server with hot reload
.PHONY: dev
dev:
	@echo "Starting development mode..."
	go run cmd/emily/main.go

# Initialize configuration
.PHONY: init-config
init-config: build
	./bin/${BINARY_NAME} config init

# Lint the code
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run

# Format the code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Security scan
.PHONY: security
security:
	@echo "Running security scan..."
	gosec ./...

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	go doc -all > docs/api.md

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t emily:${VERSION} .

# Create release package
.PHONY: release
release: clean build-all
	@echo "Creating release package..."
	mkdir -p release/
	cp bin/* release/
	cp README.md release/
	cp LICENSE release/ || true
	tar -czf release/emily-${VERSION}.tar.gz -C release .

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  build-android - Build for Android"
	@echo "  build-all    - Build for all platforms"
	@echo "  deps         - Install dependencies"
	@echo "  test         - Run tests"
	@echo "  test-race    - Run tests with race detection"
	@echo "  coverage     - Generate coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Build and run"
	@echo "  install      - Install binary to /usr/local/bin"
	@echo "  dev          - Run in development mode"
	@echo "  init-config  - Initialize configuration"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  security     - Run security scan"
	@echo "  docs         - Generate documentation"
	@echo "  docker-build - Build Docker image"
	@echo "  release      - Create release package"
	@echo "  help         - Show this help"

# Default goal
.DEFAULT_GOAL := help
