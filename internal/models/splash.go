package models

import "time"

// SplashProtocol represents a single item from the splash protocols API.
type SplashProtocol struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Price     int       `json:"price"`
	Usage     int       `json:"usage"`
	ServerID  int       `json:"serverId"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (SplashProtocol) TableName() string { return "splash_protocols" }



