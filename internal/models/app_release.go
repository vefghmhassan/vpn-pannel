package models

import "time"

// AppVersion represents an application release version (metadata only)
type AppVersion struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

    PackageName string `gorm:"size:128;index;uniqueIndex:uniq_pkg_ver"`
    VersionCode int    `gorm:"not null;uniqueIndex:uniq_pkg_ver"`
	VersionName string `gorm:"size:64"`
	Changelog   string `gorm:"type:text"`
	IsMandatory bool   `gorm:"default:false"`

	Builds []AppBuild `gorm:"foreignKey:AppVersionID"`
}

// AppBuild represents a build artifact for a specific ABI
type AppBuild struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	AppVersionID uint   `gorm:"index;not null"`
	ABI          string `gorm:"size:32;index;not null"` // e.g., arm64-v8a, armeabi-v7a, x86, x86_64, universal
	FilePath     string `gorm:"size:512;not null"`      // served under /uploads
	FileSize     int64  `gorm:"not null"`
	Sha256       string `gorm:"size:64"`
}
