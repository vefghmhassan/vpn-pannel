package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

const (
	backupVersion = 1
	maxBackupSize = 10 << 20 // 10MB
)

type BackupPayload struct {
	Version         int                    `json:"version"`
	ExportedAt      time.Time              `json:"exported_at"`
	AppSettings     AppSettingsBackup      `json:"app_settings"`
	V2RayNodes      []V2RayNodeBackup      `json:"v2ray_nodes"`
	SplashProtocols []SplashProtocolBackup `json:"splash_protocols"`
}

type AppSettingsBackup struct {
	AdsEnabledInSplash      bool   `json:"ads_enabled_in_splash"`
	ShowAdsAfterSplash      bool   `json:"show_ads_after_splash"`
	ShowAdsOnMainPage       bool   `json:"show_ads_on_main_page"`
	AdsRewardEnabled        bool   `json:"ads_reward_enabled"`
	AdsAppOpenEnabled       bool   `json:"ads_app_open_enabled"`
	RewardDisplayPercent    int    `json:"reward_display_percent"`
	UpdateEnable            bool   `json:"update_enable"`
	CurrentVersion          string `json:"current_version"`
	AdUnitID                string `json:"ad_unit_id"`
	AdsRewardUnit           string `json:"ads_reward_unit"`
	AdsUnitOpen             string `json:"ads_unit_open"`
	AdsApplicationID        string `json:"ads_application_id"`
	PrivacyURL              string `json:"privacy_url"`
	ConnectedTimeoutSeconds int    `json:"connected_timeout"`
	SplashConfCount         int    `json:"splash_conf_count"`
	LinkApp                 string `json:"link_app"`
	ReleaseNotes            string `json:"release_notes"`
	ConnectionTimer         int64  `json:"connection_timer"`
	CurrentVersionCode      int    `json:"current_version_code"`
	WheelEnabled            bool   `json:"wheel_enabled"`
}

type V2RayNodeBackup struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Tags        string `json:"tags"`
	Ads         bool   `json:"ads"`
	CountryCode string `json:"country_code"`
	CountryFlag string `json:"country_flag"`
	IsActive    bool   `json:"is_active"`
	Capacity    int    `json:"capacity"`
	RawLink     string `json:"raw_link"`
}

type SplashProtocolBackup struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Price    int    `json:"price"`
	Usage    int    `json:"usage"`
	ServerID int    `json:"server_id"`
	PingMs   int    `json:"ping_ms"`
}

type validationError struct {
	msg string
}

func (e validationError) Error() string {
	return e.msg
}

func SettingsExport(c *fiber.Ctx) error {
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		s = models.AppSettings{ID: 1, CurrentVersion: "1.0.0"}
		if err := database.DB.FirstOrCreate(&s, models.AppSettings{ID: 1}).Error; err != nil {
			return fiber.ErrInternalServerError
		}
	}

	var nodes []models.V2RayNode
	if err := database.DB.Order("id asc").Find(&nodes).Error; err != nil {
		return fiber.ErrInternalServerError
	}

	var splash []models.SplashProtocol
	if err := database.DB.Order("id asc").Find(&splash).Error; err != nil {
		return fiber.ErrInternalServerError
	}

	payload := BackupPayload{
		Version:    backupVersion,
		ExportedAt: time.Now().UTC(),
		AppSettings: AppSettingsBackup{
			AdsEnabledInSplash:      s.AdsEnabledInSplash,
			ShowAdsAfterSplash:      s.ShowAdsAfterSplash,
			ShowAdsOnMainPage:       s.ShowAdsOnMainPage,
			AdsRewardEnabled:        s.AdsRewardEnabled,
			AdsAppOpenEnabled:       s.AdsAppOpenEnabled,
			RewardDisplayPercent:    s.RewardDisplayPercent,
			UpdateEnable:            s.UpdateEnable,
			CurrentVersion:          s.CurrentVersion,
			AdUnitID:                s.AdUnitID,
			AdsRewardUnit:           s.AdsRewardUnit,
			AdsUnitOpen:             s.AdsUnitOpen,
			AdsApplicationID:        s.AdsApplicationID,
			PrivacyURL:              s.PrivacyURL,
			ConnectedTimeoutSeconds: s.ConnectedTimeoutSeconds,
			SplashConfCount:         s.SplashConfCount,
			LinkApp:                 s.LinkApp,
			ReleaseNotes:            s.ReleaseNotes,
			ConnectionTimer:         s.ConnectionTimer,
			CurrentVersionCode:      s.CurrentVersionCode,
			WheelEnabled:            s.WheelEnabled,
		},
		V2RayNodes:      make([]V2RayNodeBackup, 0, len(nodes)),
		SplashProtocols: make([]SplashProtocolBackup, 0, len(splash)),
	}

	for _, n := range nodes {
		payload.V2RayNodes = append(payload.V2RayNodes, V2RayNodeBackup{
			Name:        n.Name,
			Address:     n.Address,
			Port:        n.Port,
			Protocol:    n.Protocol,
			Tags:        n.Tags,
			Ads:         n.Ads,
			CountryCode: n.CountryCode,
			CountryFlag: n.CountryFlag,
			IsActive:    n.IsActive,
			Capacity:    n.Capacity,
			RawLink:     n.RawLink,
		})
	}

	for _, sp := range splash {
		payload.SplashProtocols = append(payload.SplashProtocols, SplashProtocolBackup{
			ID:       sp.ID,
			Name:     sp.Name,
			Value:    sp.Value,
			Price:    sp.Price,
			Usage:    sp.Usage,
			ServerID: sp.ServerID,
			PingMs:   sp.PingMs,
		})
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fiber.ErrInternalServerError
	}

	filename := fmt.Sprintf("vpnpannel-backup-%s.json", time.Now().Format("20060102-150405"))
	c.Set("Content-Type", "application/json")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	return c.Send(data)
}

func SettingsImport(c *fiber.Ctx) error {
	fh, err := c.FormFile("backup_file")
	if err != nil || fh == nil {
		return fiber.NewError(fiber.StatusBadRequest, "backup_file required")
	}
	f, err := fh.Open()
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "failed to open file")
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBackupSize+1))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "failed to read file")
	}
	if int64(len(data)) > maxBackupSize {
		return fiber.NewError(fiber.StatusBadRequest, "file too large")
	}

	var payload BackupPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid json")
	}
	if payload.Version != backupVersion {
		return fiber.NewError(fiber.StatusBadRequest, "unsupported backup version")
	}

	if err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := upsertAppSettings(tx, payload.AppSettings); err != nil {
			return err
		}
		if err := upsertV2RayNodes(tx, payload.V2RayNodes); err != nil {
			return err
		}
		if err := upsertSplashProtocols(tx, payload.SplashProtocols); err != nil {
			return err
		}
		return nil
	}); err != nil {
		var vErr validationError
		if errors.As(err, &vErr) {
			return fiber.NewError(fiber.StatusBadRequest, vErr.Error())
		}
		return fiber.ErrInternalServerError
	}

	return c.Redirect("/admin/settings")
}

func upsertAppSettings(tx *gorm.DB, in AppSettingsBackup) error {
	var existing models.AppSettings
	if err := tx.First(&existing, 1).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		s := models.AppSettings{ID: 1}
		applyAppSettings(&s, in)
		return tx.Create(&s).Error
	}
	applyAppSettings(&existing, in)
	return tx.Save(&existing).Error
}

func applyAppSettings(dst *models.AppSettings, in AppSettingsBackup) {
	dst.AdsEnabledInSplash = in.AdsEnabledInSplash
	dst.ShowAdsAfterSplash = in.ShowAdsAfterSplash
	dst.ShowAdsOnMainPage = in.ShowAdsOnMainPage
	dst.AdsRewardEnabled = in.AdsRewardEnabled
	dst.AdsAppOpenEnabled = in.AdsAppOpenEnabled
	dst.RewardDisplayPercent = in.RewardDisplayPercent
	dst.UpdateEnable = in.UpdateEnable
	dst.CurrentVersion = in.CurrentVersion
	dst.AdUnitID = in.AdUnitID
	dst.AdsRewardUnit = in.AdsRewardUnit
	dst.AdsUnitOpen = in.AdsUnitOpen
	dst.AdsApplicationID = in.AdsApplicationID
	dst.PrivacyURL = in.PrivacyURL
	dst.ConnectedTimeoutSeconds = in.ConnectedTimeoutSeconds
	dst.SplashConfCount = in.SplashConfCount
	dst.LinkApp = in.LinkApp
	dst.ReleaseNotes = in.ReleaseNotes
	dst.ConnectionTimer = in.ConnectionTimer
	dst.CurrentVersionCode = in.CurrentVersionCode
	dst.WheelEnabled = in.WheelEnabled
}

func upsertV2RayNodes(tx *gorm.DB, items []V2RayNodeBackup) error {
	for _, in := range items {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return validationError{msg: "v2ray node name required"}
		}
		var node models.V2RayNode
		if err := tx.Where("name = ?", name).First(&node).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			node = models.V2RayNode{
				Name:        name,
				Address:     in.Address,
				Port:        in.Port,
				Protocol:    in.Protocol,
				Tags:        in.Tags,
				Ads:         in.Ads,
				CountryCode: in.CountryCode,
				CountryFlag: in.CountryFlag,
				IsActive:    in.IsActive,
				Capacity:    in.Capacity,
				RawLink:     in.RawLink,
			}
			if err := tx.Create(&node).Error; err != nil {
				return err
			}
			continue
		}
		node.Name = name
		node.Address = in.Address
		node.Port = in.Port
		node.Protocol = in.Protocol
		node.Tags = in.Tags
		node.Ads = in.Ads
		node.CountryCode = in.CountryCode
		node.CountryFlag = in.CountryFlag
		node.IsActive = in.IsActive
		node.Capacity = in.Capacity
		node.RawLink = in.RawLink
		if err := tx.Save(&node).Error; err != nil {
			return err
		}
	}
	return nil
}

func upsertSplashProtocols(tx *gorm.DB, items []SplashProtocolBackup) error {
	for _, in := range items {
		if in.ID == 0 {
			return validationError{msg: "splash protocol id required"}
		}
		var rec models.SplashProtocol
		if err := tx.First(&rec, in.ID).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			rec = models.SplashProtocol{
				ID:       in.ID,
				Name:     in.Name,
				Value:    in.Value,
				Price:    in.Price,
				Usage:    in.Usage,
				ServerID: in.ServerID,
				PingMs:   in.PingMs,
			}
			if err := tx.Create(&rec).Error; err != nil {
				return err
			}
			continue
		}
		rec.Name = in.Name
		rec.Value = in.Value
		rec.Price = in.Price
		rec.Usage = in.Usage
		rec.ServerID = in.ServerID
		rec.PingMs = in.PingMs
		if err := tx.Save(&rec).Error; err != nil {
			return err
		}
	}
	return nil
}
