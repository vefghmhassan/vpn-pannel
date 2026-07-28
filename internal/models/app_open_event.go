package models

import "time"

// AppOpenEvent logs one "app opened" occurrence (one row per check-in call).
type AppOpenEvent struct {
	ID        uint      `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"index"`
	UserID    uint      `gorm:"index"`
}
