package models

import "time"

// AppOpenEvent logs one "app opened" occurrence (one row per check-in call).
type AppOpenEvent struct {
	ID uint `gorm:"primaryKey"`
	// The composite (user_id, created_at) index backs the analytics queries, which
	// always constrain both together — counting distinct users inside a time window
	// (DAU/WAU/MAU) or a single user's events inside one (retention cohorts). The
	// single-column indexes are kept for the plain per-user and per-range lookups.
	CreatedAt time.Time `gorm:"index;index:idx_open_user_created,priority:2"`
	UserID    uint      `gorm:"index;index:idx_open_user_created,priority:1"`
}
