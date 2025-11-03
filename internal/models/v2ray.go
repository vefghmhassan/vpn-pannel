package models

import "time"

type V2RayNode struct {
    ID        uint      `gorm:"primaryKey"`
    CreatedAt time.Time
    UpdatedAt time.Time

    Name      string `gorm:"uniqueIndex;size:100;not null"`
    Address   string `gorm:"size:255;not null"` // host or IP
    Port      int    `gorm:"not null"`
    Protocol  string `gorm:"size:32;not null"` // vmess, vless, trojan
    Tags      string `gorm:"size:255"`         // comma separated
    IsActive  bool   `gorm:"default:true"`
    Capacity  int    `gorm:"default:0"` // optional capacity indicator
    RawLink   string `gorm:"size:1024"` // optional original config link
}


