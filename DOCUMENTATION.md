# Vault CLI Documentation

## Overview

Vault is a Go-based secret management CLI that provides secure, multi-environment secret storage with encryption at rest, role-based access control, and robust project/environment management. This documentation covers the latest features, including environment aliasing, bidirectional sync to a Postgres target, password handling, project deletion, and new infrastructure support.

---

## Table of Contents

- [Environment Aliasing](#environment-aliasing)
- [Password Handling Refactor](#password-handling-refactor)
- [Project Deletion Command](#project-deletion-command)
- [Command Aliases](#command-aliases)
- [Sync (Primary ↔ Postgres)](#sync-primary--postgres)
- [Infrastructure: Docker Compose & GoReleaser](#infrastructure-docker-compose--goreleaser)
- [Run Command](#run-command)
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

## Run Command

The `run` command allows you to execute any shell command with secrets loaded for a given project/environment:

```sh
vault run myapp/dev -- npm run dev
vault run myapp/production -- python app.py
```

- Secrets are injected into the child process environment.
- Handles shell detection and signal forwarding.
- Use aliases or canonical environment names (`dev` or `development`).

**Note:**  
The previous `vault env` command is deprecated and no longer registered. Use `vault run` for all new workflows.

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

## Sync (Primary ↔ Postgres)

Vault syncs your **PRIMARY** SQLite vault (the system of record) with an optional **SYNC** Postgres target using the **same master password** for both vaults. Secrets stay encrypted at rest on both sides; the Postgres target is initialized with the same key derived from your master password.

### Configuration

Sync is enabled by configuring `storage.sync.postgres` in `config.yaml`. Without it, sync commands report that sync is disabled.

```yaml
storage:
  sync:
    postgres:
      host: <pooler-host>
      port: 5432
      database: postgres
      user: postgres.<ref>
      password: <password>
      sslmode: require
```

Only `host`, `database`, and `user` are required for sync to be considered configured; `port` defaults to `5432` and `sslmode` defaults to `disable`.

### Enable

```sh
vault sync enable
```

Initializes the Postgres sync target with the same master password as the primary vault. Idempotent: if the target is already initialized it verifies the password and exits.

### Run

```sh
vault sync run [project/environment]
```

Reconciles the primary vault with the sync target. Unless `--approve` is given, the plan is printed and applied only after interactive confirmation.

| Flag | Default | Description |
|------|---------|-------------|
| `--direction` | `both` | `push` (local → remote), `pull` (remote → local), `both` (bidirectional) |
| `--conflict` | `fail` | `fail`, `prefer-local`, `prefer-remote`, `prefer-latest` (newest `UpdatedAt` wins; exact ties error) |
| `--dry-run` | `false` | Print the plan without applying anything |
| `--since` | — | Only consider changes after an RFC3339 time (e.g. `2026-03-01T00:00:00Z`) |
| `--approve` | `false` | Skip the confirmation prompt |
| `--delete-remote` | `false` | DANGEROUS: when pushing, delete remote secrets missing locally |
| `--delete-local` | `false` | DANGEROUS: when pulling, delete local secrets deleted on the remote |

A scope argument (`vault sync run myapp` or `vault sync run myapp/dev`) limits the run to one project or one project/environment. Environment aliases (`dev`, `prod`, `stage`) are accepted.

### Conflict detection & resolution

A conflict is a secret that changed on **both** sides since the last sync. The engine detects conflicts before any resolution. `fail` (the default) aborts on a conflict; the other strategies fold the resolution into the plan as a normal operation. A strategy-resolved conflict is still reported as *detected* in the run output and history, so observability stays truthful.

### Tombstones & deletion propagation

Deleting a secret records a **tombstone** (identity + pre-delete checksum) in the same transaction. Tombstones make deletion propagate in **one** direction only — never silently in both:

- A pull never resurrects a secret you deleted locally.
- A push never restores a secret deleted on the remote.
- Recreating a deleted secret clears the stale tombstone after the next sync.

By default, sync never deletes anything — it only adds and updates. To remove copies that were deleted on the *other* side you must opt in per run with `--delete-remote` (push side) or `--delete-local` (pull side). Both flags:

- are **refused when combined with `--approve`** (interactive confirmation is mandatory), and
- always show the pending deletions for confirmation before applying.

### Status

```sh
vault sync status [--limit 10]
```

Shows the most recent sync runs recorded on the primary vault: start time, direction/strategy, pushed/pulled operation counts, conflicts detected, dry-run flag, and any error. Sync runs are metadata only — no secret material — so this works without unlocking the vault.

### Usage examples

```sh
# Initialize the Postgres target
vault sync enable

# Full bidirectional reconcile with confirmation
vault sync run

# Push only, for one project
vault sync run myapp --direction push

# Pull only, dry run first
vault sync run --direction pull --dry-run

# Resolve conflicts in favor of the remote value
vault sync run --conflict prefer-remote

# Delete remote copies that were deleted locally (interactive confirm required)
vault sync run --delete-remote
```

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

### Run a Command with Secrets

```sh
vault run myapp/dev -- npm run dev
vault run myapp/production -- python app.py
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
- **Run command**: New `vault run <project>/<environment> -- <command>` for running commands with secrets injected.
- **Deprecated**: The `vault env` command is no longer registered; use `vault run` instead.
- **Sync engine**: Bidirectional sync (push/pull/both) with real conflict detection and `fail`, `prefer-local`, `prefer-remote`, `prefer-latest` strategies, plus project/environment scoping and `--since` filtering.
- **Tombstones**: Deletions recorded as tombstones prevent resurrection; propagation is opt-in via `--delete-remote` / `--delete-local`, never with `--approve`.
- **Sync observability**: Every run recorded as metadata-only `SyncRun`; `vault sync status` shows history without unlocking.
- **Docker Compose**: PostgreSQL 16 service for local development.
- **GoReleaser**: Automated build and release configuration.

---

For more details, see `AGENTS.md` and the codebase.