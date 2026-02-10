# Repository Guidelines

Welcome to the Vault project! This guide provides essential information for contributors working on our Go-based secret management application.

## Project Structure & Module Organization

The project follows a clean architecture pattern:

- **cmd/** - Application entry points (cmd/vault/main.go)
- **internal/** - Core business logic and implementation:
  - auth/ - Authentication and authorization
  - cli/ - CLI commands and interfaces
  - commands/ - Command implementations
  - config/ - Configuration management
  - crypto/ - Encryption and security utilities
  - domain/ - Core business models and data structures
  - storage/ - Data persistence layer
  - ui/ - Terminal user interface
- **docs/** - Documentation and architecture guides
- **bin/** - Build artifacts (gitignored)
- **.gitignore** - Git ignore patterns (bin/, docs/internal/)

## Build, Test, and Development Commands

Use either Make or Task for build automation.

### Docker Compose

A `docker-compose.yml` is provided for local development and testing with PostgreSQL 16:

```yaml
version: '3.8'
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: vaultpass
      POSTGRES_DB: vaultdb
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

- Start with: `docker-compose up -d`
- Default credentials: user `vault`, password `vaultpass`, db `vaultdb`

### GoReleaser

A `.goreleaser.yaml` is included for automated builds and releases.  
See the file for configuration details and CI/CD integration.


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
- task build - Alternative build command
- task test - Alternative test command
- task --list - Show all available tasks

## Coding Style & Naming Conventions

- **Go formatting**: Use gofmt for code formatting (run make fmt)
- **Linting**: golangci-lint is configured (run make lint)
- **Package structure**: Lowercase package names, clear separation of concerns
- **Code style**: Follow Go community conventions and effective Go guidelines
- **Naming**: Use camelCase for variables/functions, PascalCase for exported types
- **Imports**: Use go mod tidy to maintain clean imports

## Environment Aliasing

Vault supports both canonical and short aliases for environments in all commands. This means you can use either the full name or its alias, and Vault will always map it to the correct environment internally.

| Alias | Canonical Name |
|-------|---------------|
| dev   | development   |
| prod  | production    |
| stage | staging       |

**Example:**  
`vault get myapp/dev/API_KEY` and `vault get myapp/development/API_KEY` are equivalent.

**Note:**  
All lookups and storage use the canonical environment names (`development`, `staging`, `production`). Aliases are only for user convenience.


## Testing Guidelines

**Testing Framework**: Standard Go testing package

**Current Status**: No tests exist yet - this is a priority for new contributors

**Test Commands:**
- go test ./... - Run all tests
- go test -v -race ./... - Run tests with verbose output and race detection
- go test -coverprofile=coverage.out ./... - Generate coverage data

**Testing Goals:**
- Write unit tests for domain models in internal/domain/
- Add integration tests for storage layer in internal/storage/
- Test CLI commands in internal/cli/
- Achieve >80% code coverage

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
1. Create feature branch from master
2. Make changes with clear commits
3. Run make test and make lint
4. Submit PR with description and testing notes
5. Address review feedback
6. Merge after approval

---

## Architecture Overview

**Core Components:**
- **Domain Models** (internal/domain/): Secret, Project, Environment, Permission structures
- **Storage Layer** (internal/storage/): SQLite-based persistence with encryption
- **CLI Interface** (internal/cli/): Cobra-based command structure
- **Security** (internal/crypto/): Encryption, hashing, and security utilities

**Key Features**:
- Multi-environment secret management (development/staging/production) with alias support (dev, prod, stage)
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

---

## Recent Major Changes

- **Environment aliasing**: All commands accept both canonical and alias environment names.
- **Password refactor**: Centralized password logic for all prompts and validation in `internal/auth/password.go`.
- **Project deletion**: New `project delete` and `project rm` commands.
- **Command aliases**: Added `ls`, `pr`, `rm` for common commands.
- **Docker Compose**: PostgreSQL 16 service for local development.
- **GoReleaser**: Automated build and release configuration.

---

## Password Handling

All password prompts, validation, and confirmation logic have been centralized in `internal/auth/password.go`. This ensures:

- Consistent password rules (minimum 8 characters, etc.)
- Secure, non-echoed input for all password prompts
- Centralized error handling and messaging

**Affected Commands:**  
- `init`
- `project create`
- `project delete`
- Any command requiring vault unlock

---

## Project Deletion Command

You can now delete entire projects (and all their environments/secrets) using:

```sh
vault project delete <name>
# or using the alias:
vault project rm <name>
```

- Prompts for your vault password before deletion.
- Only deletes if the project exists and password is correct.
- Success is confirmed with a message.

---

## Command Aliases

To improve usability, Vault CLI now supports the following command aliases:

| Command         | Alias |
|-----------------|-------|
| list            | ls    |
| project         | pr    |
| project delete  | rm    |
| (environments)  | dev, prod, stage |

You can use either the full command or its alias interchangeably.

---

## Infrastructure: Docker Compose & GoReleaser

See above for details on `docker-compose.yml` and `.goreleaser.yaml`.

---

For more details, see `DOCUMENTATION.md` and the codebase.

## Security & Configuration Tips

- **Configuration**: Uses Viper for configuration management
- **Storage**: SQLite database with encryption
- **Environment variables**: Support for environment-based configuration
- **Security considerations**: All secrets are encrypted at rest
- **MFA support**: Production environments can require multi-factor authentication

For questions or help, refer to the documentation in docs/ or open an issue.
