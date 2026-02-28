package sqlite

import (
	"vault/internal/storage"
)

func init() {
	storage.Register(storage.BackendTypeSQLite, func(cfg *storage.Config) (storage.Backend, error) {
		return New(cfg)
	})
}
