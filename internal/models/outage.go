package models

import "time"

const (
    OutageOpen     = "OPEN"
    OutageAcknowledged = "ACK"
    OutageResolved = "RESOLVED"
)

type OutageReport struct {
    ID        uint      `gorm:"primaryKey"`
    CreatedAt time.Time
    UpdatedAt time.Time

    UserID    *uint `gorm:"index"`
    NodeID    *uint `gorm:"index"`
    Title     string `gorm:"size:120"`
    Description string `gorm:"size:1000"`
    Status    string `gorm:"size:16;index;default:OPEN"`
}


