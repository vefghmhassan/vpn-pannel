package models

import "time"

// OnlineSnapshot is a periodic point-in-time count of users online (active in the
// last 5 minutes), used to draw the admin stats trend chart.
type OnlineSnapshot struct {
	ID        uint      `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"index"`
	Count     int64
}
