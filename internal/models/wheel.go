package models

import "time"

// WheelSegment is a single slice of the lucky wheel (گردونه شانس).
// Segments are managed from the admin panel and served to the mobile app.
// The winning slice and reward handling are performed on the client using the
// relative Weight of each segment; the server only stores/serves configuration.
type WheelSegment struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	// Display order of the slice on the wheel
	Position int `gorm:"not null;default:0" json:"position"`
	// What to render: "text" or "icon"
	DisplayType string `gorm:"size:16;not null;default:'text'" json:"displayType"`
	// Text label (also used for accessibility)
	Label string `gorm:"size:128" json:"label"`
	// Emoji or image URL, used when DisplayType == "icon"
	Icon string `gorm:"size:255" json:"icon"`
	// Reward kind: "time" (RewardValue = minutes), "premium", or "none"
	RewardType string `gorm:"size:16;not null;default:'none'" json:"rewardType"`
	// Reward amount; minutes for "time", optional duration for "premium", 0 for "none"
	RewardValue int `gorm:"not null;default:0" json:"rewardValue"`
	// Hex color like #22c55e; empty means "assign a random color"
	Color string `gorm:"size:16" json:"color"`
	// Relative chance weight (not required to sum to 100).
	// No GORM default: 0 is a meaningful value ("never wins") and a default
	// tag would make GORM skip the zero value and substitute the default.
	Weight int `gorm:"not null" json:"weight"`
	// Whether this segment is shown on the wheel.
	// No GORM default for the same zero-value reason (false must persist).
	IsActive bool `gorm:"not null" json:"isActive"`
}
