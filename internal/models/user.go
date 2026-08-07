package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	RoleSuperAdmin = "SUPER_ADMIN"
	RoleAdmin      = "ADMIN"
	RoleSupport    = "SUPPORT"
	RoleUser       = "USER"
)

type User struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Username     string `gorm:"uniqueIndex;size:64;not null"`
	Email        string `gorm:"uniqueIndex;size:120;not null"`
	PasswordHash string `gorm:"size:128;not null"`
	Role         string `gorm:"size:32;index;not null"`
	// No GORM default: IsActive's zero value (false) must persist (deactivating
	// a user) — a `default:true` tag would make GORM skip false on save and let
	// the DB substitute true instead.
	IsActive    bool
	LastSeenAt  *time.Time
	ClientToken *string `gorm:"size:36;uniqueIndex"`

	// Referral program: a user's own shareable code, and who referred them (if anyone).
	InviteCode       *string `gorm:"size:6;uniqueIndex"`
	ReferredByUserID *uint   `gorm:"index"`

	// Absolute end of this user's ad-free window. Referral rewards stack onto it
	// rather than overwriting, so a second referral extends the window.
	RewardExpiresAt *time.Time
	// How many referrals have already paid a reward to this user, used to enforce
	// AppSettings.ReferralMaxRewardedInvites.
	RewardedReferralCount int `gorm:"not null;default:0"`
}

// WARNING: For demo simplicity we use SHA256 hash. In production use bcrypt/argon2.
func (u *User) SetPassword(plain string) error {
	h := sha256.Sum256([]byte(plain))
	u.PasswordHash = hex.EncodeToString(h[:])
	return nil
}

func (u *User) CheckPassword(plain string) bool {
	h := sha256.Sum256([]byte(plain))
	return u.PasswordHash == hex.EncodeToString(h[:])
}

type MobileDevice struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	UserID     uint   `gorm:"uniqueIndex:uniq_user_device"`
	DeviceID   string `gorm:"size:128;uniqueIndex:uniq_user_device"`
	FCMToken   string `gorm:"size:512"`
	LastSeenAt *time.Time
}
