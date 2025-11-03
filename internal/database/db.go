package database

import (
	"errors"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"vpnpannel/internal/config"
	"vpnpannel/internal/models"
)

var DB *gorm.DB

func Connect(dsn string) error {
	if dsn == "" {
		return errors.New("empty DSN")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(60 * time.Minute)

	DB = db
	return nil
}

func AutoMigrateAndSeed() error {
	if err := DB.AutoMigrate(
		&models.User{},
		&models.MobileDevice{},
		&models.V2RayNode{},
		&models.OutageReport{},
		&models.SplashProtocol{},
		&models.AppSettings{},
	); err != nil {
		return err
	}
	if err := seedAdmin(); err != nil {
		return err
	}
	if err := seedSettings(); err != nil {
		return err
	}
	return nil
}

func seedAdmin() error {
	var count int64
	DB.Model(&models.User{}).Where("role = ?", models.RoleSuperAdmin).Count(&count)
	if count > 0 {
		return nil
	}
	user := models.User{
		Email:    config.Current.AdminEmail,
		Username: "admin",
		Role:     models.RoleSuperAdmin,
		IsActive: true,
	}
	if err := user.SetPassword(config.Current.AdminPassword); err != nil {
		return err
	}
	return DB.Create(&user).Error
}

func seedSettings() error {
	var count int64
	DB.Model(&models.AppSettings{}).Count(&count)
	if count > 0 {
		return nil
	}
	defaults := models.AppSettings{
		ID:                 1,
		AdsEnabledInSplash: false,
		ShowAdsAfterSplash: false,
		ShowAdsOnMainPage:  false,
		CurrentVersion:     "1.0.0",
	}
	return DB.Create(&defaults).Error
}
