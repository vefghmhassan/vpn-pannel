package models

import "time"

type V2RayNode struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Name        string `gorm:"uniqueIndex;size:100;not null"`
	Address     string `gorm:"size:255;not null"` // host or IP
	Port        int    `gorm:"not null"`
	Protocol    string `gorm:"size:32;not null"` // vmess, vless, trojan
	Tags        string `gorm:"size:255"`         // comma separated
	Ads         bool   `gorm:"default:false"`
	CountryCode string `gorm:"size:8"`
	CountryFlag string `gorm:"size:255"`
	// No GORM default: IsActive's zero value (false) must persist (deactivating
	// a node) — a `default:true` tag would make GORM skip false on save and let
	// the DB substitute true instead. See internal/models/user.go for the same fix.
	IsActive bool
	Capacity int    `gorm:"default:0"` // optional capacity indicator
	RawLink  string `gorm:"type:text"` // optional original config link
}
