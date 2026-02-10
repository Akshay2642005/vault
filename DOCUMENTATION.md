# Vault CLI Documentation

## Overview

Vault is a Go-based secret management CLI that provides secure, multi-environment secret storage with encryption at rest, role-based access control, and robust project/environment management. This documentation covers the latest features, including environment aliasing, password handling refactor, project deletion, and new infrastructure support.

---

## Table of Contents

- [Environment Aliasing](#environment-aliasing)
- [Password Handling Refactor](#password-handling-refactor)
- [Project Deletion Command](#project-deletion-command)
- [Command Aliases](#command-aliases)
- [Infrastructure: Docker Compose & GoReleaser](#infrastructure-docker-compose--goreleaser)
- [Usage Examples](#usage-examples)
- [Contributing](#contributing)
- [Changelog](#changelog)

---

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

---

## Password Handling Refactor

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

---

## Usage Examples

### Get a Secret

```sh
vault get myapp/dev/API_KEY
vault get myapp/production/DB_PASSWORD --show
```

### Set a Secret

```sh
vault set myapp/stage/NEW_SECRET supersecretvalue
```

### List Secrets

```sh
vault list myapp/prod
vault ls myapp/dev
```

### Delete a Project

```sh
vault project delete myapp
vault pr rm myapp
```

---

## Contributing

- Use canonical environment names in code, but aliases are accepted in the CLI.
- Follow the commit and PR guidelines in `AGENTS.md`.
- Run `make lint` and `make test` before submitting changes.
- See `docker-compose.yml` and `.goreleaser.yaml` for infra and release automation.

---

## Changelog

### Latest Changes

- **Environment aliasing**: All commands accept both canonical and alias environment names.
- **Password refactor**: Centralized password logic for all prompts and validation.
- **Project deletion**: New `project delete` and `project rm` commands.
- **Command aliases**: Added `ls`, `pr`, `rm` for common commands.
- **Docker Compose**: PostgreSQL 16 service for local development.
- **GoReleaser**: Automated build and release configuration.

---

For more details, see `AGENTS.md` and the codebase.