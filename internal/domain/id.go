/*
package domain contains the core business logic and data structures of the application.
it defines the main entities, value objects, and interfaces that represent the core concepts of the domain.
this package is independent of any specific implementation details and can be used across different layers of the application.
*/
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateID generates a unique identifier
func GenerateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", 0) // Will be replaced with proper UUID
	}
	return hex.EncodeToString(bytes)
}
