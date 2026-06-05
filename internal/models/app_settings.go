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
	// Whether rewarded ads are enabled
	AdsRewardEnabled bool `gorm:"not null;default:false" json:"adsRewardEnabled"`
	// Whether app-open ads are enabled
	AdsAppOpenEnabled bool `gorm:"not null;default:false" json:"adsAppOpenEnabled"`
	// Percent (0-100) of times to show reward ads
	RewardDisplayPercent int  `gorm:"not null;default:100" json:"rewardDisplayPercent"`
	UpdateEnable         bool `gorm:"not null;default:true" json:"updateEnable"`
	// Current application version string (e.g., 1.0.0)
	CurrentVersion string `gorm:"size:32;not null;default:'1.0.0'" json:"currentVersion"`

	// Mobile ads unit id (if any)
	AdUnitID string `gorm:"size:128" json:"adUnitId"`
	// Mobile rewarded ads unit id (if any)
	AdsRewardUnit string `gorm:"size:128" json:"adsRewardUnit"`
	// Mobile app-open ads unit id (if any)
	AdsUnitOpen string `gorm:"size:128" json:"adsUnitOpen"`
	// Mobile ads application id (if any)
	AdsApplicationID string `gorm:"size:128" json:"adsApplicationId"`
	// Privacy policy URL for the app
	PrivacyURL string `gorm:"size:255" json:"privacyUrl"`
	// Timeout (seconds) for considering a connection as established
	ConnectedTimeoutSeconds int `gorm:"not null;default:15" json:"connectedTimeout"`
	// Number of configs to return per splash/conf request (per ads/no-ads)
	SplashConfCount int    `gorm:"not null;default:4" json:"splashConfCount"`
	AppTimer        int    `gorm:"not null;default:30" json:"appTimer"`
	Domain          string `gorm:"size:128" json:"domain"`
}
