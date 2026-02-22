package storage

import (
	"context"
	"fmt"
	"sync"
)

// BackendType represents the type of storage backend
type BackendType string

const (
	// BackendTypeSQLite represents SQLite storage
	BackendTypeSQLite BackendType = "sqlite"

	// BackendTypePostgreSQL represents PostgreSQL storage
	BackendTypePostgreSQL BackendType = "postgres"
)

// BackendFactory creates storage backend instances
type BackendFactory struct {
	mu           sync.RWMutex
	constructors map[BackendType]BackendConstructor
}

// BackendConstructor is a function that creates a backend instance
type BackendConstructor func(cfg *Config) (Backend, error)

var (
	// globalFactory is the global backend factory instance
	globalFactory = &BackendFactory{
		constructors: make(map[BackendType]BackendConstructor),
	}
)

// Register registers a backend constructor with the factory
func Register(backendType BackendType, constructor BackendConstructor) {
	globalFactory.mu.Lock()
	defer globalFactory.mu.Unlock()

	globalFactory.constructors[backendType] = constructor
}

// NewBackend creates a new backend instance based on configuration
func NewBackend(cfg *Config) (Backend, error) {
	globalFactory.mu.RLock()
	defer globalFactory.mu.RUnlock()

	backendType := BackendType(cfg.Type)

	constructor, exists := globalFactory.constructors[backendType]
	if !exists {
		return nil, fmt.Errorf("unknown storage backend type: %s", cfg.Type)
	}

	backend, err := constructor(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s backend: %w", cfg.Type, err)
	}

	// Initialize the backend
	if err := backend.Initialize(context.Background(), cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize %s backend: %w", cfg.Type, err)
	}

	return backend, nil
}

// GetRegisteredBackends returns a list of all registered backend types
func GetRegisteredBackends() []BackendType {
	globalFactory.mu.RLock()
	defer globalFactory.mu.RUnlock()

	types := make([]BackendType, 0, len(globalFactory.constructors))
	for backendType := range globalFactory.constructors {
		types = append(types, backendType)
	}

	return types
}

// IsBackendRegistered checks if a backend type is registered
func IsBackendRegistered(backendType BackendType) bool {
	globalFactory.mu.RLock()
	defer globalFactory.mu.RUnlock()

	_, exists := globalFactory.constructors[backendType]
	return exists
}
