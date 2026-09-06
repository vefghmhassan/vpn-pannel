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
	// backupVersion 2 added every section beyond app settings, v2ray nodes and
	// splash protocols. Version 1 files are still accepted: their missing
	// sections simply decode as empty and are skipped.
	backupVersion         = 2
	minSupportedBackupVer = 1
	// maxBackupSize matches the server's BodyLimit in cmd/server/main.go, so
	// anything this panel can export and the client can upload can also be
	// imported. A full backup including the statistics sections is unbounded in
	// principle — it grows by one row per app launch.
	maxBackupSize     = 200 << 20 // 200MB
	backupSectionsKey = "sections"
)

// Backup section keys. Each maps to one checkbox on the settings page and to one
// or more tables in the payload.
const (
	sectionConfig   = "config"   // app_settings
	sectionNodes    = "nodes"    // v2ray_nodes
	sectionSplash   = "splash"   // splash_protocols
	sectionWheel    = "wheel"    // wheel_segments
	sectionMessages = "messages" // app_messages
	sectionReleases = "releases" // app_versions + app_builds
	sectionOutages  = "outages"  // outage_reports
	sectionUsers    = "users"    // users + mobile_devices
	sectionStats    = "stats"    // app_open_events + online_snapshots
)

// BackupSection describes one checkbox. Order is display order.
type BackupSection struct {
	Key   string
	Label string
	Note  string
}

// BackupSections drives both the export form and the handler's validation, so
// the two can never drift apart.
var BackupSections = []BackupSection{
	{sectionConfig, "تنظیمات برنامه", "همه‌ی گزینه‌های این صفحه"},
	{sectionNodes, "نودهای V2Ray", "سرورها و کانفیگ‌ها"},
	{sectionSplash, "پروتکل‌های Splash", ""},
	{sectionWheel, "گردونه شانس", "بخش‌ها، جوایز و وزن‌ها"},
	{sectionMessages, "پیام‌های یادآور", ""},
	{sectionReleases, "نسخه‌های اپ", "فقط اطلاعات نسخه‌ها، نه خود فایل APK"},
	{sectionOutages, "گزارش‌های قطعی", ""},
	{sectionUsers, "کاربران و دستگاه‌ها", "شامل کد دعوت، زیرمجموعه‌ها و زمان جایزه"},
	{sectionStats, "آمار", "بازشدن اپ و نمودار آنلاین — می‌تواند بسیار حجیم باشد"},
}

// selectedSections reports which sections to export. A request that names no
// section at all — the plain /admin/settings/export link, or an old bookmark —
// gets everything, so the export never silently shrinks.
func selectedSections(c *fiber.Ctx) map[string]bool {
	out := make(map[string]bool, len(BackupSections))
	// The form posts this hidden marker, which distinguishes "the admin
	// unchecked every box" from "nobody chose anything".
	explicit := c.Query(backupSectionsKey) != ""
	for _, s := range BackupSections {
		if explicit {
			out[s.Key] = c.Query(s.Key) != ""
		} else {
			out[s.Key] = true
		}
	}
	return out
}

type BackupPayload struct {
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	// Sections lists which sections this file was exported with, in the order of
	// BackupSections. It makes the file self-describing: an empty table is
	// omitted from the body by omitempty, so without this an operator could not
	// tell "this section was not included" from "this section had no rows".
	Sections []string `json:"sections"`

	// Every section is omitted entirely when it was not selected for export, and
	// decodes as nil when absent from the file — which is what makes an import
	// skip it rather than wipe the corresponding table.
	AppSettings     *AppSettingsBackup     `json:"app_settings,omitempty"`
	V2RayNodes      []V2RayNodeBackup      `json:"v2ray_nodes,omitempty"`
	SplashProtocols []SplashProtocolBackup `json:"splash_protocols,omitempty"`
	WheelSegments   []WheelSegmentBackup   `json:"wheel_segments,omitempty"`
	AppMessages     []AppMessageBackup     `json:"app_messages,omitempty"`
	AppVersions     []AppVersionBackup     `json:"app_versions,omitempty"`
	OutageReports   []OutageReportBackup   `json:"outage_reports,omitempty"`
	Users           []UserBackup           `json:"users,omitempty"`
	AppOpenEvents   []AppOpenEventBackup   `json:"app_open_events,omitempty"`
	OnlineSnapshots []OnlineSnapshotBackup `json:"online_snapshots,omitempty"`
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
	// Pointer so a backup taken before this setting existed can be told apart
	// from one that genuinely has it off — see applyAppSettings.
	SplashDiverseServers *bool `json:"splash_diverse_servers"`
	// Pointers for the same reason as SplashDiverseServers above: a backup taken
	// before multi-config ads existed must not switch it off or zero the count.
	AdsMultiConfigEnabled *bool  `json:"ads_multi_config_enabled"`
	AdsConfigCount        *int   `json:"ads_config_count"`
	LinkApp               string `json:"link_app"`
	ReleaseNotes          string `json:"release_notes"`
	ConnectionTimer       int64  `json:"connection_timer"`
	CurrentVersionCode    int    `json:"current_version_code"`
	WheelEnabled          bool   `json:"wheel_enabled"`
	AppTimer              int    `json:"app_timer"`
	Domain                string `json:"domain"`

	// The whole referral block, which earlier backups did not carry at all. Every
	// field with a non-zero meaning is a pointer for the same reason as
	// SplashDiverseServers: importing a backup taken before these existed must
	// leave the live values alone rather than resetting the program to zero.
	ReferralEnabled              *bool  `json:"referral_enabled"`
	ReferralTaskText             string `json:"referral_task_text"`
	ReferralShareText            string `json:"referral_share_text"`
	ReferralInstantRewardEnabled *bool  `json:"referral_instant_reward_enabled"`
	ReferralInviterRewardMinutes *int   `json:"referral_inviter_reward_minutes"`
	ReferralInviteeRewardMinutes *int   `json:"referral_invitee_reward_minutes"`
	ReferralMaxRewardedInvites   *int   `json:"referral_max_rewarded_invites"`
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
	want := selectedSections(c)
	payload := BackupPayload{
		Version:    backupVersion,
		ExportedAt: time.Now().UTC(),
		Sections:   make([]string, 0, len(BackupSections)),
	}
	for _, section := range BackupSections {
		if want[section.Key] {
			payload.Sections = append(payload.Sections, section.Key)
		}
	}

	if want[sectionConfig] {
		var s models.AppSettings
		if err := database.DB.First(&s, 1).Error; err != nil {
			s = models.AppSettings{ID: 1, CurrentVersion: "1.0.0"}
			if err := database.DB.FirstOrCreate(&s, models.AppSettings{ID: 1}).Error; err != nil {
				return fiber.ErrInternalServerError
			}
		}
		payload.AppSettings = &AppSettingsBackup{
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
			SplashDiverseServers:    &s.SplashDiverseServers,
			AdsMultiConfigEnabled:   &s.AdsMultiConfigEnabled,
			AdsConfigCount:          &s.AdsConfigCount,
			LinkApp:                 s.LinkApp,
			ReleaseNotes:            s.ReleaseNotes,
			ConnectionTimer:         s.ConnectionTimer,
			CurrentVersionCode:      s.CurrentVersionCode,
			WheelEnabled:            s.WheelEnabled,
			AppTimer:                s.AppTimer,
			Domain:                  s.Domain,

			ReferralEnabled:              &s.ReferralEnabled,
			ReferralTaskText:             s.ReferralTaskText,
			ReferralShareText:            s.ReferralShareText,
			ReferralInstantRewardEnabled: &s.ReferralInstantRewardEnabled,
			ReferralInviterRewardMinutes: &s.ReferralInviterRewardMinutes,
			ReferralInviteeRewardMinutes: &s.ReferralInviteeRewardMinutes,
			ReferralMaxRewardedInvites:   &s.ReferralMaxRewardedInvites,
		}
	}

	if want[sectionNodes] {
		var nodes []models.V2RayNode
		if err := database.DB.Order("id asc").Find(&nodes).Error; err != nil {
			return fiber.ErrInternalServerError
		}
		payload.V2RayNodes = make([]V2RayNodeBackup, 0, len(nodes))
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
	}

	if want[sectionSplash] {
		var splash []models.SplashProtocol
		if err := database.DB.Order("id asc").Find(&splash).Error; err != nil {
			return fiber.ErrInternalServerError
		}
		payload.SplashProtocols = make([]SplashProtocolBackup, 0, len(splash))
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
	}

	// The remaining sections each live in settings_backup_sections.go.
	var err error
	if want[sectionWheel] {
		if payload.WheelSegments, err = exportWheelSegments(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
	}
	if want[sectionMessages] {
		if payload.AppMessages, err = exportAppMessages(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
	}
	if want[sectionReleases] {
		if payload.AppVersions, err = exportAppVersions(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
	}
	if want[sectionOutages] {
		if payload.OutageReports, err = exportOutageReports(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
	}
	if want[sectionUsers] {
		if payload.Users, err = exportUsers(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
	}
	if want[sectionStats] {
		if payload.AppOpenEvents, err = exportAppOpenEvents(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
		if payload.OnlineSnapshots, err = exportOnlineSnapshots(database.DB); err != nil {
			return fiber.ErrInternalServerError
		}
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
	if payload.Version < minSupportedBackupVer || payload.Version > backupVersion {
		return fiber.NewError(fiber.StatusBadRequest, "unsupported backup version")
	}

	// Order matters: users and nodes must exist before the rows that reference
	// them by email or name can be resolved back to ids.
	if err := database.DB.Transaction(func(tx *gorm.DB) error {
		if payload.AppSettings != nil {
			if err := upsertAppSettings(tx, *payload.AppSettings); err != nil {
				return err
			}
		}
		if err := upsertV2RayNodes(tx, payload.V2RayNodes); err != nil {
			return err
		}
		if err := upsertSplashProtocols(tx, payload.SplashProtocols); err != nil {
			return err
		}
		if err := upsertWheelSegments(tx, payload.WheelSegments); err != nil {
			return err
		}
		if err := upsertAppMessages(tx, payload.AppMessages); err != nil {
			return err
		}
		if err := upsertAppVersions(tx, payload.AppVersions); err != nil {
			return err
		}
		if err := upsertUsers(tx, payload.Users); err != nil {
			return err
		}
		if err := upsertOutageReports(tx, payload.OutageReports); err != nil {
			return err
		}
		if err := upsertAppOpenEvents(tx, payload.AppOpenEvents); err != nil {
			return err
		}
		if err := upsertOnlineSnapshots(tx, payload.OnlineSnapshots); err != nil {
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
	// Only applied when the key is present, so importing a backup taken before
	// this setting existed leaves it alone instead of silently turning it off.
	if in.SplashDiverseServers != nil {
		dst.SplashDiverseServers = *in.SplashDiverseServers
	}
	if in.AdsMultiConfigEnabled != nil {
		dst.AdsMultiConfigEnabled = *in.AdsMultiConfigEnabled
	}
	if in.AdsConfigCount != nil {
		dst.AdsConfigCount = *in.AdsConfigCount
	}
	dst.LinkApp = in.LinkApp
	dst.ReleaseNotes = in.ReleaseNotes
	dst.ConnectionTimer = in.ConnectionTimer
	dst.CurrentVersionCode = in.CurrentVersionCode
	dst.WheelEnabled = in.WheelEnabled
	dst.AppTimer = in.AppTimer
	dst.Domain = in.Domain

	dst.ReferralTaskText = in.ReferralTaskText
	dst.ReferralShareText = in.ReferralShareText
	if in.ReferralEnabled != nil {
		dst.ReferralEnabled = *in.ReferralEnabled
	}
	if in.ReferralInstantRewardEnabled != nil {
		dst.ReferralInstantRewardEnabled = *in.ReferralInstantRewardEnabled
	}
	if in.ReferralInviterRewardMinutes != nil {
		dst.ReferralInviterRewardMinutes = *in.ReferralInviterRewardMinutes
	}
	if in.ReferralInviteeRewardMinutes != nil {
		dst.ReferralInviteeRewardMinutes = *in.ReferralInviteeRewardMinutes
	}
	if in.ReferralMaxRewardedInvites != nil {
		dst.ReferralMaxRewardedInvites = *in.ReferralMaxRewardedInvites
	}
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
