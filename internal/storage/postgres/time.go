package postgres

import "time"

// utc normalizes a timestamp for storage in a `timestamp without time zone`
// column.
//
// Postgres drops any zone offset on input and lib/pq parses the (zone-less)
// output as UTC, so a value written from a non-UTC location — e.g. a machine
// running IST — would otherwise be stored as its wall clock and read back as
// that same wall clock in UTC, shifting the instant by the writer's offset.
// The sync engine compares UpdatedAt/LastSyncedAt instants across the SQLite
// and Postgres backends, so a shift would skew conflict detection and
// prefer-latest for any user whose machine does not run UTC.
func utc(t time.Time) time.Time { return t.UTC() }

// utcPtr is utc for nullable timestamp columns.
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
