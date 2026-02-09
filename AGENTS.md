# Repository Guidelines

Welcome to the Vault project! This guide provides essential information for contributors working on our Go-based secret management application.

## Project Structure & Module Organization

The project follows a clean architecture pattern:

- **cmd/** - Application entry points (cmd/vault/main.go)
- **internal/** - Core business logic and implementation:
  - uth/ - Authentication and authorization
  - cli/ - CLI commands and interfaces
  - commands/ - Command implementations
  - config/ - Configuration management
  - crypto/ - Encryption and security utilities
  - domain/ - Core business models and data structures
  - storage/ - Data persistence layer
  - 	ui/ - Terminal user interface
- **docs/** - Documentation and architecture guides
- **in/** - Build artifacts (gitignored)
- **.gitignore** - Git ignore patterns (in/, docs/internal/)

## Build, Test, and Development Commands

Use either Make or Task for build automation:

**Make commands:**
- make build - Build binary (in/vault.exe)
- make build-all - Build for all platforms
- make test - Run tests with race detection and coverage
- make test-coverage - Generate HTML coverage report
- make lint - Run golangci-lint
- make fmt - Format code
- make run - Build and run application
- make clean - Clean build artifacts
- make dev - Development mode with live reload (requires air)

**Task commands:**
- 	ask build - Alternative build command
- 	ask test - Alternative test command
- 	ask --list - Show all available tasks

## Coding Style & Naming Conventions

- **Go formatting**: Use gofmt for code formatting (run make fmt)
- **Linting**: golangci-lint is configured (run make lint)
- **Package structure**: Lowercase package names, clear separation of concerns
- **Code style**: Follow Go community conventions and effective Go guidelines
- **Naming**: Use camelCase for variables/functions, PascalCase for exported types
- **Imports**: Use go mod tidy to maintain clean imports

## Testing Guidelines

**Testing Framework**: Standard Go testing package

**Current Status**: No tests exist yet - this is a priority for new contributors

**Test Commands:**
- go test ./... - Run all tests
- go test -v -race ./... - Run tests with verbose output and race detection
- go test -coverprofile=coverage.out ./... - Generate coverage data

**Testing Goals:**
- Write unit tests for domain models in internal/domain/`n- Add integration tests for storage layer in internal/storage/`n- Test CLI commands in internal/cli/`n- Achieve >80% code coverage

## Commit & Pull Request Guidelines

**Current Commit Style** (from project history):
- Use clear, descriptive subject lines
- Provide detailed body explaining what and why
- Reference affected files with @internal/... notation
- List multiple changes with bullet points

**Pull Request Requirements**:
- Clear description of changes and rationale
- Link related issues
- Add tests for new functionality
- Ensure make lint and make test pass
- Update documentation as needed
- Follow existing code style and patterns

**Example PR workflow**:
1. Create feature branch from master`n2. Make changes with clear commits
3. Run make test and make lint`n4. Submit PR with description and testing notes
5. Address review feedback
6. Merge after approval

## Architecture Overview

**Core Components:**
- **Domain Models** (internal/domain/): Secret, Project, Environment, Permission structures
- **Storage Layer** (internal/storage/): SQLite-based persistence with encryption
- **CLI Interface** (internal/cli/): Cobra-based command structure
- **Security** (internal/crypto/): Encryption, hashing, and security utilities

**Key Features**:
- Multi-environment secret management (development/staging/production)
- Role-based access control
- Secret rotation and versioning
- Sync status tracking
- SQLite storage with encryption at rest

## Getting Started

1. **Clone and setup**: git clone https://github.com/Akshay2642005/vault.git
2. **Install dependencies**: make deps
3. **Build**: make build
4. **Run**: make run or in/vault.exe
5. **Develop**: make dev for live reload (install air first)
6. **Contribute**: Pick an issue, create tests, implement features

**First contribution ideas**:
- Add missing CLI command implementations
- Write unit tests for domain models
- Implement storage layer functionality
- Add encryption utilities

## Security & Configuration Tips

- **Configuration**: Uses Viper for configuration management
- **Storage**: SQLite database with encryption
- **Environment variables**: Support for environment-based configuration
- **Security considerations**: All secrets are encrypted at rest
- **MFA support**: Production environments can require multi-factor authentication

For questions or help, refer to the documentation in docs/ or open an issue.
