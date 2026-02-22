package postgres

import (
	"vault/internal/storage"
)

func init() {
	// Auto-register PostgreSQL backend when package is imported
	storage.Register(storage.BackendTypePostgreSQL, func(cfg *storage.Config) (storage.Backend, error) {
		return New(cfg)
	})
}
