package models

import "time"

type V2RayLease struct {
	ID         uint      `gorm:"primaryKey"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	RequestKey string    `gorm:"size:128;index:idx_req_ads,unique"`
	Ads        bool      `gorm:"index:idx_req_ads,unique"`
	NodeID     uint      `gorm:"index"`
	ExpiresAt  time.Time `gorm:"index"`
}
