package sync

import "time"

type Conflict struct {
	ID           string            `json:"id"`
	SecretID     string            `json:"secred_id"`
	LocalChange  *Change           `json:"local_change"`
	RemoteChange *Change           `json:"remote_change"`
	DetectedAt   time.Time         `json:"detected_at"`
	Resolved     bool              `json:"resolved"`
	ResolvedAt   *time.Time        `json:"resolved_at,omitempty"`
	Resolution   *Resolution       `json:"resolution,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type Resolution struct {
	Strategy     string    `json:"strategy"`
	ChosenChange *Change   `json:"chosen_change"`
	ResolvedBy   string    `json:"resolved_by"`
	Timestamp    time.Time `json:"timestamp"`
}
