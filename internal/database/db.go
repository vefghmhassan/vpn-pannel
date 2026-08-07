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
		&models.V2RayLease{},
		&models.OutageReport{},
		&models.SplashProtocol{},
		&models.AppSettings{},
		&models.AppVersion{},
		&models.AppBuild{},
		&models.WheelSegment{},
		&models.AppOpenEvent{},
		&models.OnlineSnapshot{},
		&models.AppMessage{},
	); err != nil {
		return err
	}
	if err := seedAdmin(); err != nil {
		return err
	}
	if err := seedSettings(); err != nil {
		return err
	}
	if err := backfillSplashDiverseServers(); err != nil {
		return err
	}
	if err := backfillRewardExpiry(); err != nil {
		return err
	}
	return nil
}

// backfillSplashDiverseServers turns the splash address-spreading toggle on for
// installs that already have a settings row. seedSettings only runs on a fresh
// database, and AutoMigrate adds the column as NULL, so without this the
// feature would silently stay off everywhere it matters after a deploy.
func backfillSplashDiverseServers() error {
	return DB.Model(&models.AppSettings{}).
		Where("splash_diverse_servers IS NULL").
		Update("splash_diverse_servers", true).Error
}

// backfillRewardExpiry fills users.reward_expires_at for anyone who earned a reward
// under the old scheme, where the window was derived on the fly as
// reward_activated_at + AppSettings.ReferralRewardDays. Without this, existing
// reward holders would silently lose their remaining ad-free time on deploy.
//
// Both of those columns have since been dropped from the models along with the
// threshold task. AutoMigrate never drops columns, so they still exist on databases
// created before that change — but never on a fresh one, where this SQL would
// otherwise fail and take AutoMigrateAndSeed down with it. Hence the existence
// guard: on a new install the whole block is skipped.
//
// Idempotent: only touches rows that have an activation but no expiry yet.
func backfillRewardExpiry() error {
	return DB.Exec(`
		DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.columns
			           WHERE table_name = 'users' AND column_name = 'reward_activated_at')
			AND EXISTS (SELECT 1 FROM information_schema.columns
			           WHERE table_name = 'app_settings' AND column_name = 'referral_reward_days')
			THEN
				UPDATE users
				SET reward_expires_at = reward_activated_at
					+ COALESCE((SELECT referral_reward_days FROM app_settings WHERE id = 1), 0) * INTERVAL '1 day'
				WHERE reward_expires_at IS NULL AND reward_activated_at IS NOT NULL;
			END IF;
		END $$;
	`).Error
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
		ID:                      1,
		AdsEnabledInSplash:      false,
		ShowAdsAfterSplash:      false,
		ShowAdsOnMainPage:       false,
		AdsRewardEnabled:        false,
		AdsAppOpenEnabled:       false,
		RewardDisplayPercent:    100,
		UpdateEnable:            true,
		CurrentVersion:          "1.0.0",
		AdUnitID:                "",
		AdsRewardUnit:           "",
		AdsUnitOpen:             "",
		AdsApplicationID:        "",
		PrivacyURL:              "",
		ConnectedTimeoutSeconds: 15,
		SplashConfCount:         4,
		SplashDiverseServers:    true,
		LinkApp:                 "",
		ReleaseNotes:            "",
		ConnectionTimer:         1000,
		CurrentVersionCode:      4000011,
		WheelEnabled:            true,

		ReferralEnabled:              false,
		ReferralInstantRewardEnabled: false,
		ReferralInviterRewardMinutes: 1440,
		ReferralInviteeRewardMinutes: 1440,
		ReferralMaxRewardedInvites:   0,
	}
	return DB.Create(&defaults).Error
}
