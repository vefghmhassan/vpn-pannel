package models

import "time"

// AppSettings stores configurable application flags editable from the admin UI.
// This is a singleton table; we always use the record with ID=1.
type AppSettings struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	// Whether ads should be enabled in the splash section
	AdsEnabledInSplash bool `gorm:"not null;default:false" json:"adsEnabledInSplash"`
	// Whether to show an ad immediately after the splash
	ShowAdsAfterSplash bool `gorm:"not null;default:false" json:"showAdsAfterSplash"`
	// Whether to show ads on the application's main page
	ShowAdsOnMainPage bool `gorm:"not null;default:false" json:"showAdsOnMainPage"`
	// Current application version string (e.g., 1.0.0)
	CurrentVersion string `gorm:"size:32;not null;default:'1.0.0'" json:"currentVersion"`
}
