# Vault Project

  Welcome to the Vault project! This repository contains a Go-based secret management application designed to securely manage secrets across different environments and
  projects.

  ## Table of Contents

  - [Project Structure](#project-structure)
  - [Build, Test, and Development Commands](#build-test-and-development-commands)
  - [Coding Style & Naming Conventions](#coding-style--naming-conventions)
  - [Testing Guidelines](#testing-guidelines)
  - [Commit & Pull Request Guidelines](#commit--pull-request-guidelines)
  - [Architecture Overview](#architecture-overview)
  - [Getting Started](#getting-started)
  - [Security & Configuration Tips](#security--configuration-tips)
  - [Usage](#usage)

  ## Project Structure

  The project follows a clean architecture pattern, organized as follows:

  - **cmd/**: Application entry points.
  - **internal/**: Core business logic and implementation.
    - **auth/**: Authentication and authorization.
    - **cli/**: CLI commands and interfaces.
    - **commands/**: Command implementations.
    - **config/**: Configuration management.
    - **crypto/**: Encryption and security utilities.
    - **domain/**: Core business models and data structures.
    - **storage/**: Data persistence layer.
    - **ui/**: Terminal user interface.
  - **docs/**: Documentation and architecture guides.
  - **bin/**: Build artifacts (gitignored).
  - **.gitignore**: Git ignore patterns.

  ## Build, Test, and Development Commands

  Use either Make or Task for build automation:

  ## Usage

  ### Running Commands with Secrets

  Use the new `run` command to execute any command with secrets injected for a specific project/environment:

  ```sh
  vault run myapp/dev -- npm run dev
  vault run myapp/production -- python app.py
  ```

  This replaces the previous `env --exec` usage. The `run` command handles shell detection, signal forwarding, and environment variable injection.

  > **Note:** The `vault env` command is deprecated and no longer registered. Use `vault run` for all new workflows.

  ### Environment Aliasing

  You can use either canonical or alias names for environments in all commands:

  | Alias | Canonical Name |
  |-------|---------------|
  | dev   | development   |
  | prod  | production    |
  | stage | staging       |

  Example: `vault get myapp/dev/API_KEY` and `vault get myapp/development/API_KEY` are equivalent.

  **Make commands(Not Tested):**
  - `make build`: Build binary (`bin/vault.exe`).
  - `make build-all`: Build for all platforms.
  - `make test`: Run tests with race detection and coverage.
  - `make test-coverage`: Generate HTML coverage report.
  - `make lint`: Run golangci-lint.
  - `make fmt`: Format code.
  - `make run`: Build and run application.
  - `make clean`: Clean build artifacts.
  - `make dev`: Development mode with live reload (requires air).

  **Task commands:**
  - `task build`: Alternative build command.
  - `task test`: Alternative test command.
  - `task list`: Show all available tasks.
  - `task bench`: Run benchmarks
  - `task build-all`: Build for all platforms
  - `task clean`: Clean build artifacts
  - `task deps`:  Download and tidy dependencies
  - `task docker-build`: Build Docker image
  - `task fmt`: Format code
  - `task lint`: Run golangci-lint
  - `task run`: Build and run the application
  - `task test-coverage`: Run tests with coverage report

  ## Coding Style & Naming Conventions

  - **Go formatting**: Use gofmt for code formatting (`make fmt`).
  - **Linting**: golangci-lint is configured (`make lint`).
  - **Package structure**: Lowercase package names, clear separation of concerns.
  - **Code style**: Follow Go community conventions and effective Go guidelines.
  - **Naming**: Use camelCase for variables/functions, PascalCase for exported types.
  - **Imports**: Use `go mod tidy` to maintain clean imports.

  ## Password Handling

  All password prompts, validation, and confirmation logic have been centralized in `internal/auth/password.go`. All CLI commands now use these utilities for consistent and secure password handling.

  ## Testing Guidelines

  **Testing Framework**: Standard Go testing package.

  **Current Status**: No tests exist yet - this is a priority for new contributors.

  **Test Commands:**
  - `go test ./...`: Run all tests.
  - `go test -v -race ./...`: Run tests with verbose output and race detection.
  - `go test -coverprofile=coverage.out ./...`: Generate coverage data.

  **Testing Goals:**
  - Write unit tests for domain models in `internal/domain/`.
  - Add integration tests for storage layer in `internal/storage/`.
  - Test CLI commands in `internal/cli/`.
  - Achieve >80% code coverage.

  ## Commit & Pull Request Guidelines

  **Current Commit Style**: Use clear, descriptive subject lines and provide detailed body explaining what and why. Reference affected files with `@internal/...` notation.
  List multiple changes with bullet points.

  **Pull Request Requirements**:
  - Clear description of changes and rationale.
  - Link related issues.
  - Add tests for new functionality.
  - Ensure `make lint` and `make test` pass.
  - Update documentation as needed.
  - Follow existing code style and patterns.

  **Example PR workflow**:
  1. Create feature branch from master.
  2. Make changes with clear commits.
  3. Run `make test` and `make lint`.
  4. Submit PR with description and testing notes.
  5. Address review feedback.
  6. Merge after approval.

  ## Architecture Overview

  **Core Components:**
  - **Domain Models**: Secret, Project, Environment, Permission structures.
  - **Storage Layer**: SQLite-based persistence with encryption.
  - **CLI Interface**: Cobra-based command structure.
  - **Security**: Encryption, hashing, and security utilities.

  **Key Features:**
  - Multi-environment secret management (development/staging/production).
  - Role-based access control.
  - Secret rotation and versioning.
  - Sync status tracking.
  - SQLite storage with encryption at rest.

  ## Getting Started

  1. **Clone and setup**: `git clone https://github.com/Akshay2642005/vault.git`
  2. **Install dependencies**: `make deps`
  3. **Build**: `make build`
  4. **Run**: `make run` or `bin/vault.exe`
  5. **Develop**: `make dev` for live reload (install air first)
  6. **Contribute**: Pick an issue, create tests, implement features.

  **First contribution ideas**:
  - Add missing CLI command implementations.
  - Write unit tests for domain models.
  - Implement storage layer functionality.
  - Add encryption utilities.

  ## Security & Configuration Tips

  - **Configuration**: Uses Viper for configuration management.
  - **Storage**: SQLite database with encryption.
  - **Environment variables**: Support for environment-based configuration.
  - **Security considerations**: All secrets are encrypted at rest.
  - **MFA support**: Production environments can require multi-factor authentication.

