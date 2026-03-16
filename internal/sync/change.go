package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"time"
)

type OperationType string

const (
	OpCreate OperationType = "create"
	OpUpdate OperationType = "update"
	OpDelete OperationType = "delete"
)

type Change struct {
	ID          string            `json:"id"`
	SecretID    string            `json:"secret_id"`
	Operation   OperationType     `json:"operation"`
	Timestamp   time.Time         `json:"timestamp"`
	Author      string            `json:"author"`
	NodeID      string            `json:"node_id"`
	Version     int               `json:"version"`
	Data        []byte            `json:"data,omitempty"`
	VectorClock VectorClock       `json:"vector_clock"`
	Checksum    string            `json:"checksum"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
type VectorClock map[string]int64

func NewChange(secretID string, op OperationType, author string, nodeID string, version int, data []byte, metadata map[string]string) *Change {
	now := time.Now()

	change := &Change{
		ID:          generateChangeID(secretID, op, now),
		SecretID:    secretID,
		Operation:   op,
		Timestamp:   now,
		Author:      author,
		NodeID:      nodeID,
		Version:     version,
		Data:        data,
		VectorClock: make(VectorClock),
		Checksum:    computeChecksum(data),
		Metadata:    make(map[string]string),
	}
	return change
}

func computeChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func generateChangeID(secretID string, operation OperationType, timestamp time.Time) string {
	data := secretID + string(operation) + timestamp.Format(time.RFC3339Nano)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:32]
}

func (c *Change) VerifyChecksum() bool {
	if c.Checksum == "" {
		return len(c.Data) == 0
	}
	return c.Checksum == computeChecksum(c.Data)
}

func (c *Change) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

func UnmarshalChange(data []byte) (*Change, error) {
	var change Change
	if err := json.Unmarshal(data, &change); err != nil {
		return nil, err
	}
	return &change, nil
}

func (c *Change) Clone() *Change {
	clone := &Change{
		ID:          c.ID,
		SecretID:    c.SecretID,
		Operation:   c.Operation,
		Timestamp:   c.Timestamp,
		Author:      c.Author,
		NodeID:      c.NodeID,
		Version:     c.Version,
		Checksum:    c.Checksum,
		VectorClock: make(VectorClock),
		Metadata:    make(map[string]string),
	}

	if len(c.Data) > 0 {
		clone.Data = make([]byte, len(c.Data))
		copy(clone.Data, c.Data)
	}

	maps.Copy(clone.VectorClock, c.VectorClock)

	maps.Copy(clone.Metadata, c.Metadata)

	return clone
}

func (vc VectorClock) Increment(nodeID string) {
	vc[nodeID]++
}

func (vc VectorClock) Merge(other VectorClock) {
	for nodeID, clock := range other {
		if vc[nodeID] < clock {
			vc[nodeID] = clock
		}
	}
}

func (vc VectorClock) HappenedBefore(other VectorClock) bool {
	for nodeID, thisClock := range vc {
		otherClock, exists := other[nodeID]
		if !exists || thisClock > otherClock {
			return false
		}
	}
	return true
}

func (vc VectorClock) IsConcurrent(other VectorClock) bool {
	return !vc.HappenedBefore(other) && !other.HappenedBefore(vc)
}

func (vc VectorClock) Clone() VectorClock {
	clone := make(VectorClock)
	maps.Copy(clone, vc)
	return clone
}

func (vc VectorClock) Equal(other VectorClock) bool {
	if len(vc) != len(other) {
		return false
	}
	for nodeID, clock := range vc {
		if other[nodeID] != clock {
			return false
		}
	}
	return true
}

type ChangeSet struct {
	Changes []*Change   `json:"changes"`
	From    time.Time   `json:"from"`
	To      time.Time   `json:"to"`
	NodeID  string      `json:"node_id"`
	Vector  VectorClock `json:"vector_clock"`
}

func NewChangeSet(nodeID string) *ChangeSet {
	return &ChangeSet{
		Changes: make([]*Change, 0),
		NodeID:  nodeID,
		Vector:  make(VectorClock),
	}
}

func (cs *ChangeSet) Add(change *Change) {
	cs.Changes = append(cs.Changes, change)

	if cs.From.IsZero() || change.Timestamp.Before(cs.From) {
		cs.From = change.Timestamp
	}
	if cs.To.IsZero() || change.Timestamp.After(cs.To) {
		cs.To = change.Timestamp
	}
	cs.Vector.Merge(change.VectorClock)
}

func (cs *ChangeSet) Len() int {
	return len(cs.Changes)
}

func (cs *ChangeSet) IsEmpty() bool {
	return len(cs.Changes) == 0
}

func (cs *ChangeSet) Marshal() ([]byte, error) {
	return json.Marshal(cs)
}

func UnmarshalChangeSet(data []byte) (*ChangeSet, error) {
	var cs ChangeSet
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, err
	}
	return &cs, nil
}
