package handlers

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"vpnpannel/internal/models"
)

// This file holds one export/import pair per table that a full backup carries
// beyond the original three (app settings, v2ray nodes, splash protocols),
// which stayed in settings_backup.go.
//
// Two rules shape every section here:
//
//  1. Rows are matched by a *natural* key, never by primary key id, except where
//     the id is itself part of the product contract (see AppMessageBackup).
//     Primary keys differ between installs, so an id-based match would either
//     collide with an unrelated row or duplicate everything.
//  2. Cross-table references travel as natural keys too — a user is referenced
//     by email and a node by name — and are resolved back to ids on import.
//
// Import is a merge: an existing row is updated in place, a missing one is
// created, and a row that is not in the file is left alone.

// --- wheel segments -------------------------------------------------------

type WheelSegmentBackup struct {
	Position    int    `json:"position"`
	DisplayType string `json:"display_type"`
	Label       string `json:"label"`
	Icon        string `json:"icon"`
	RewardType  string `json:"reward_type"`
	RewardValue int    `json:"reward_value"`
	Color       string `json:"color"`
	Weight      int    `json:"weight"`
	IsActive    bool   `json:"is_active"`
}

func exportWheelSegments(db *gorm.DB) ([]WheelSegmentBackup, error) {
	var rows []models.WheelSegment
	if err := db.Order("position asc, id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]WheelSegmentBackup, 0, len(rows))
	for _, r := range rows {
		out = append(out, WheelSegmentBackup{
			Position: r.Position, DisplayType: r.DisplayType, Label: r.Label,
			Icon: r.Icon, RewardType: r.RewardType, RewardValue: r.RewardValue,
			Color: r.Color, Weight: r.Weight, IsActive: r.IsActive,
		})
	}
	return out, nil
}

// upsertWheelSegments matches on Position, which is the wheel's own notion of
// identity: it is the slice's place on the wheel and what the admin editor
// assigns from row order.
func upsertWheelSegments(tx *gorm.DB, items []WheelSegmentBackup) error {
	for _, in := range items {
		var seg models.WheelSegment
		err := tx.Where("position = ?", in.Position).First(&seg).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		seg.Position = in.Position
		seg.DisplayType = in.DisplayType
		seg.Label = in.Label
		seg.Icon = in.Icon
		seg.RewardType = in.RewardType
		seg.RewardValue = in.RewardValue
		seg.Color = in.Color
		seg.Weight = in.Weight
		seg.IsActive = in.IsActive
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := tx.Create(&seg).Error; err != nil {
				return err
			}
			continue
		}
		if err := tx.Save(&seg).Error; err != nil {
			return err
		}
	}
	return nil
}

// --- in-app reminder messages ---------------------------------------------

// AppMessageBackup keeps the row ID, unlike every other section. The mobile app
// tracks how often it has shown each message by that id (see models.AppMessage),
// so restoring a message under a new id would reset every user's show count.
type AppMessageBackup struct {
	ID                uint   `json:"id"`
	Position          int    `json:"position"`
	Title             string `json:"title"`
	Body              string `json:"body"`
	InactiveDays      int    `json:"inactive_days"`
	RepeatEveryDays   int    `json:"repeat_every_days"`
	MaxShows          int    `json:"max_shows"`
	ShowInApp         bool   `json:"show_in_app"`
	LocalNotification bool   `json:"local_notification"`
	IsActive          bool   `json:"is_active"`
}

func exportAppMessages(db *gorm.DB) ([]AppMessageBackup, error) {
	var rows []models.AppMessage
	if err := db.Order("position asc, id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]AppMessageBackup, 0, len(rows))
	for _, r := range rows {
		out = append(out, AppMessageBackup{
			ID: r.ID, Position: r.Position, Title: r.Title, Body: r.Body,
			InactiveDays: r.InactiveDays, RepeatEveryDays: r.RepeatEveryDays,
			MaxShows: r.MaxShows, ShowInApp: r.ShowInApp,
			LocalNotification: r.LocalNotification, IsActive: r.IsActive,
		})
	}
	return out, nil
}

func upsertAppMessages(tx *gorm.DB, items []AppMessageBackup) error {
	for _, in := range items {
		if in.ID == 0 {
			return validationError{msg: "app message id required"}
		}
		var msg models.AppMessage
		err := tx.First(&msg, in.ID).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		msg.ID = in.ID
		msg.Position = in.Position
		msg.Title = in.Title
		msg.Body = in.Body
		msg.InactiveDays = in.InactiveDays
		msg.RepeatEveryDays = in.RepeatEveryDays
		msg.MaxShows = in.MaxShows
		msg.ShowInApp = in.ShowInApp
		msg.LocalNotification = in.LocalNotification
		msg.IsActive = in.IsActive
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := tx.Create(&msg).Error; err != nil {
				return err
			}
			continue
		}
		if err := tx.Save(&msg).Error; err != nil {
			return err
		}
	}
	return nil
}

// --- app releases ---------------------------------------------------------

// AppBuildBackup carries the metadata only. FilePath points into ./uploads,
// which is served as static files and is not part of this JSON — restoring onto
// a fresh machine gives you the release rows, but the APKs themselves have to be
// copied across separately.
type AppBuildBackup struct {
	ABI      string `json:"abi"`
	FilePath string `json:"file_path"`
	FileSize int64  `json:"file_size"`
	Sha256   string `json:"sha256"`
}

type AppVersionBackup struct {
	PackageName string           `json:"package_name"`
	VersionCode int              `json:"version_code"`
	VersionName string           `json:"version_name"`
	Changelog   string           `json:"changelog"`
	IsMandatory bool             `json:"is_mandatory"`
	Builds      []AppBuildBackup `json:"builds,omitempty"`
}

func exportAppVersions(db *gorm.DB) ([]AppVersionBackup, error) {
	var rows []models.AppVersion
	if err := db.Preload("Builds").Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]AppVersionBackup, 0, len(rows))
	for _, r := range rows {
		v := AppVersionBackup{
			PackageName: r.PackageName, VersionCode: r.VersionCode,
			VersionName: r.VersionName, Changelog: r.Changelog,
			IsMandatory: r.IsMandatory,
			Builds:      make([]AppBuildBackup, 0, len(r.Builds)),
		}
		for _, b := range r.Builds {
			v.Builds = append(v.Builds, AppBuildBackup{
				ABI: b.ABI, FilePath: b.FilePath, FileSize: b.FileSize, Sha256: b.Sha256,
			})
		}
		out = append(out, v)
	}
	return out, nil
}

// upsertAppVersions matches on (package_name, version_code), which the model
// already declares as a unique index, and each build on its ABI within that
// version.
func upsertAppVersions(tx *gorm.DB, items []AppVersionBackup) error {
	for _, in := range items {
		if in.PackageName == "" {
			return validationError{msg: "app version package_name required"}
		}
		if in.VersionCode <= 0 {
			return validationError{msg: "app version version_code required"}
		}
		var ver models.AppVersion
		err := tx.Where("package_name = ? AND version_code = ?", in.PackageName, in.VersionCode).
			First(&ver).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		ver.PackageName = in.PackageName
		ver.VersionCode = in.VersionCode
		ver.VersionName = in.VersionName
		ver.Changelog = in.Changelog
		ver.IsMandatory = in.IsMandatory
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := tx.Create(&ver).Error; err != nil {
				return err
			}
		} else if err := tx.Save(&ver).Error; err != nil {
			return err
		}

		for _, b := range in.Builds {
			if b.ABI == "" {
				return validationError{msg: "app build abi required"}
			}
			var build models.AppBuild
			bErr := tx.Where("app_version_id = ? AND abi = ?", ver.ID, b.ABI).First(&build).Error
			if bErr != nil && !errors.Is(bErr, gorm.ErrRecordNotFound) {
				return bErr
			}
			build.AppVersionID = ver.ID
			build.ABI = b.ABI
			build.FilePath = b.FilePath
			build.FileSize = b.FileSize
			build.Sha256 = b.Sha256
			if errors.Is(bErr, gorm.ErrRecordNotFound) {
				if err := tx.Create(&build).Error; err != nil {
					return err
				}
				continue
			}
			if err := tx.Save(&build).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// --- users and their devices ----------------------------------------------

// MobileDeviceBackup is nested inside its owner rather than living in its own
// top-level list, so the user it belongs to never has to be looked up by id.
type MobileDeviceBackup struct {
	DeviceID   string     `json:"device_id"`
	FCMToken   string     `json:"fcm_token"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

// UserBackup carries credentials (the password hash) and identity (client token,
// invite code). A backup file containing this section is as sensitive as the
// database itself and should be stored accordingly.
type UserBackup struct {
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`

	LastSeenAt  *time.Time `json:"last_seen_at"`
	ClientToken *string    `json:"client_token"`
	InviteCode  *string    `json:"invite_code"`
	// Who referred this user, by email: row ids differ between installs, so the
	// referral graph is rebuilt in a second pass (see upsertUsers).
	ReferredByEmail       *string    `json:"referred_by_email"`
	RewardExpiresAt       *time.Time `json:"reward_expires_at"`
	RewardedReferralCount int        `json:"rewarded_referral_count"`

	Devices []MobileDeviceBackup `json:"devices,omitempty"`
}

func exportUsers(db *gorm.DB) ([]UserBackup, error) {
	var users []models.User
	if err := db.Order("id asc").Find(&users).Error; err != nil {
		return nil, err
	}
	var devices []models.MobileDevice
	if err := db.Order("id asc").Find(&devices).Error; err != nil {
		return nil, err
	}

	emailByID := make(map[uint]string, len(users))
	for _, u := range users {
		emailByID[u.ID] = u.Email
	}
	devicesByUser := make(map[uint][]MobileDeviceBackup, len(users))
	for _, d := range devices {
		devicesByUser[d.UserID] = append(devicesByUser[d.UserID], MobileDeviceBackup{
			DeviceID: d.DeviceID, FCMToken: d.FCMToken, LastSeenAt: d.LastSeenAt,
		})
	}

	out := make([]UserBackup, 0, len(users))
	for _, u := range users {
		b := UserBackup{
			Username: u.Username, Email: u.Email, PasswordHash: u.PasswordHash,
			Role: u.Role, IsActive: u.IsActive, CreatedAt: u.CreatedAt,
			LastSeenAt: u.LastSeenAt, ClientToken: u.ClientToken,
			InviteCode: u.InviteCode, RewardExpiresAt: u.RewardExpiresAt,
			RewardedReferralCount: u.RewardedReferralCount,
			Devices:               devicesByUser[u.ID],
		}
		if u.ReferredByUserID != nil {
			if email, ok := emailByID[*u.ReferredByUserID]; ok {
				b.ReferredByEmail = &email
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// upsertUsers restores users in two passes. The first creates or updates every
// row without touching ReferredByUserID; only once every email is known to the
// database can the second pass resolve the referral graph, since an inviter may
// appear after the friend they invited.
//
// Unique fields other than the match key (username, invite code, client token)
// are dropped rather than fatal when they are already held by a *different*
// user: a merge into a populated database must not fail wholesale because one
// generated username happens to collide.
func upsertUsers(tx *gorm.DB, items []UserBackup) error {
	for _, in := range items {
		if in.Email == "" {
			return validationError{msg: "user email required"}
		}
		var user models.User
		err := tx.Where("email = ?", in.Email).First(&user).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		isNew := errors.Is(err, gorm.ErrRecordNotFound)

		username, uErr := freeUsername(tx, in.Username, in.Email)
		if uErr != nil {
			return uErr
		}
		inviteCode, iErr := freeUniquePtr(tx, "invite_code", in.InviteCode, in.Email)
		if iErr != nil {
			return iErr
		}
		clientToken, cErr := freeUniquePtr(tx, "client_token", in.ClientToken, in.Email)
		if cErr != nil {
			return cErr
		}

		user.Email = in.Email
		user.Username = username
		user.PasswordHash = in.PasswordHash
		user.Role = in.Role
		user.IsActive = in.IsActive
		user.LastSeenAt = in.LastSeenAt
		user.RewardExpiresAt = in.RewardExpiresAt
		user.RewardedReferralCount = in.RewardedReferralCount
		// Only overwrite an existing identity when the file actually carries one,
		// so a partial backup cannot strip a live user's invite code or token.
		if inviteCode != nil {
			user.InviteCode = inviteCode
		}
		if clientToken != nil {
			user.ClientToken = clientToken
		}
		if isNew {
			if !in.CreatedAt.IsZero() {
				user.CreatedAt = in.CreatedAt
			}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}
		} else if err := tx.Save(&user).Error; err != nil {
			return err
		}

		if err := upsertMobileDevices(tx, user.ID, in.Devices); err != nil {
			return err
		}
	}

	// Second pass: the referral graph, now that every email resolves to an id.
	ids, err := userIDsByEmail(tx)
	if err != nil {
		return err
	}
	for _, in := range items {
		if in.ReferredByEmail == nil {
			continue
		}
		selfID, ok := ids[in.Email]
		if !ok {
			continue
		}
		referrerID, ok := ids[*in.ReferredByEmail]
		if !ok || referrerID == selfID {
			// The inviter is not in this database (a partial backup), or the file
			// claims a self-referral, which the API itself refuses.
			continue
		}
		if err := tx.Model(&models.User{}).Where("id = ?", selfID).
			Update("referred_by_user_id", referrerID).Error; err != nil {
			return err
		}
	}
	return nil
}

func upsertMobileDevices(tx *gorm.DB, userID uint, items []MobileDeviceBackup) error {
	for _, in := range items {
		if in.DeviceID == "" {
			continue
		}
		var device models.MobileDevice
		err := tx.Where("user_id = ? AND device_id = ?", userID, in.DeviceID).First(&device).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		device.UserID = userID
		device.DeviceID = in.DeviceID
		device.FCMToken = in.FCMToken
		device.LastSeenAt = in.LastSeenAt
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := tx.Create(&device).Error; err != nil {
				return err
			}
			continue
		}
		if err := tx.Save(&device).Error; err != nil {
			return err
		}
	}
	return nil
}

func userIDsByEmail(tx *gorm.DB) (map[string]uint, error) {
	var rows []struct {
		ID    uint
		Email string
	}
	if err := tx.Model(&models.User{}).Select("id, email").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]uint, len(rows))
	for _, r := range rows {
		out[r.Email] = r.ID
	}
	return out, nil
}

// freeUsername returns a username that is not already taken by a different
// email, appending a numeric suffix if it has to. Username is NOT NULL and
// unique, so unlike the optional identities it cannot simply be dropped.
func freeUsername(tx *gorm.DB, desired, email string) (string, error) {
	if desired == "" {
		desired = "user"
	}
	candidate := desired
	for attempt := 0; attempt < 50; attempt++ {
		var owner models.User
		err := tx.Where("username = ?", candidate).First(&owner).Error
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && owner.Email == email) {
			return candidate, nil
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", err
		}
		candidate = fmt.Sprintf("%s-%d", desired, attempt+2)
	}
	return "", validationError{msg: "could not find a free username for " + email}
}

// freeUniquePtr keeps an optional unique identity only when it is unclaimed or
// already belongs to this same email; otherwise it returns nil so the caller
// leaves the field alone rather than colliding.
func freeUniquePtr(tx *gorm.DB, column string, value *string, email string) (*string, error) {
	if value == nil || *value == "" {
		return nil, nil
	}
	var owner models.User
	err := tx.Where(column+" = ?", *value).First(&owner).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return value, nil
	}
	if err != nil {
		return nil, err
	}
	if owner.Email == email {
		return value, nil
	}
	return nil, nil
}

// --- outage reports -------------------------------------------------------

type OutageReportBackup struct {
	UserEmail   *string   `json:"user_email"`
	NodeName    *string   `json:"node_name"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

func exportOutageReports(db *gorm.DB) ([]OutageReportBackup, error) {
	var rows []models.OutageReport
	if err := db.Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []OutageReportBackup{}, nil
	}
	emails, err := emailsByUserID(db)
	if err != nil {
		return nil, err
	}
	names, err := nodeNamesByID(db)
	if err != nil {
		return nil, err
	}

	out := make([]OutageReportBackup, 0, len(rows))
	for _, r := range rows {
		b := OutageReportBackup{
			Title: r.Title, Description: r.Description,
			Status: r.Status, CreatedAt: r.CreatedAt,
		}
		if r.UserID != nil {
			if email, ok := emails[*r.UserID]; ok {
				b.UserEmail = &email
			}
		}
		if r.NodeID != nil {
			if name, ok := names[*r.NodeID]; ok {
				b.NodeName = &name
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// upsertOutageReports treats a report as identified by when it was filed plus
// its text: reports carry no natural key, and this is what makes re-importing
// the same file a no-op instead of duplicating history.
func upsertOutageReports(tx *gorm.DB, items []OutageReportBackup) error {
	if len(items) == 0 {
		return nil
	}
	userIDs, err := userIDsByEmail(tx)
	if err != nil {
		return err
	}
	nodeIDs, err := nodeIDsByName(tx)
	if err != nil {
		return err
	}

	var existing []models.OutageReport
	if err := tx.Find(&existing).Error; err != nil {
		return err
	}
	seen := make(map[string]bool, len(existing))
	for _, r := range existing {
		seen[outageKey(r.CreatedAt, r.Title, r.Description)] = true
	}

	fresh := make([]models.OutageReport, 0, len(items))
	for _, in := range items {
		key := outageKey(in.CreatedAt, in.Title, in.Description)
		if seen[key] {
			continue
		}
		seen[key] = true
		row := models.OutageReport{
			Title: in.Title, Description: in.Description, Status: in.Status,
		}
		if !in.CreatedAt.IsZero() {
			row.CreatedAt = in.CreatedAt
		}
		if in.UserEmail != nil {
			if id, ok := userIDs[*in.UserEmail]; ok {
				row.UserID = &id
			}
		}
		if in.NodeName != nil {
			if id, ok := nodeIDs[*in.NodeName]; ok {
				row.NodeID = &id
			}
		}
		fresh = append(fresh, row)
	}
	if len(fresh) == 0 {
		return nil
	}
	return tx.CreateInBatches(&fresh, backupInsertBatch).Error
}

func outageKey(at time.Time, title, description string) string {
	return fmt.Sprintf("%d|%s|%s", at.UnixNano(), title, description)
}

// --- statistics -----------------------------------------------------------

// backupInsertBatch bounds how many rows go into one INSERT. The statistics
// sections can run to millions of rows, which as a single statement would
// exhaust Postgres's parameter limit.
const backupInsertBatch = 500

// AppOpenEventBackup is one "app was opened" row, the raw material behind the
// tracker page. This is the only unbounded section: it grows by one row per
// launch per user, so a long-lived install exports a very large file.
type AppOpenEventBackup struct {
	UserEmail string    `json:"user_email"`
	CreatedAt time.Time `json:"created_at"`
}

func exportAppOpenEvents(db *gorm.DB) ([]AppOpenEventBackup, error) {
	var rows []models.AppOpenEvent
	if err := db.Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []AppOpenEventBackup{}, nil
	}
	emails, err := emailsByUserID(db)
	if err != nil {
		return nil, err
	}
	out := make([]AppOpenEventBackup, 0, len(rows))
	for _, r := range rows {
		email, ok := emails[r.UserID]
		if !ok {
			// The owning user is gone; the event can no longer be attributed.
			continue
		}
		out = append(out, AppOpenEventBackup{UserEmail: email, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

// upsertAppOpenEvents deduplicates on (user, timestamp) so importing the same
// backup twice does not double every user's open count. Existing keys are read
// once into a set rather than queried per row, which matters at this volume.
func upsertAppOpenEvents(tx *gorm.DB, items []AppOpenEventBackup) error {
	if len(items) == 0 {
		return nil
	}
	userIDs, err := userIDsByEmail(tx)
	if err != nil {
		return err
	}

	var existing []models.AppOpenEvent
	if err := tx.Find(&existing).Error; err != nil {
		return err
	}
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[fmt.Sprintf("%d|%d", e.UserID, e.CreatedAt.UnixNano())] = true
	}

	fresh := make([]models.AppOpenEvent, 0, len(items))
	for _, in := range items {
		id, ok := userIDs[in.UserEmail]
		if !ok {
			// No such user in this database: the users section was not included,
			// or was deselected. Skipping keeps the tracker's counts honest.
			continue
		}
		key := fmt.Sprintf("%d|%d", id, in.CreatedAt.UnixNano())
		if seen[key] {
			continue
		}
		seen[key] = true
		fresh = append(fresh, models.AppOpenEvent{UserID: id, CreatedAt: in.CreatedAt})
	}
	if len(fresh) == 0 {
		return nil
	}
	return tx.CreateInBatches(&fresh, backupInsertBatch).Error
}

// OnlineSnapshotBackup is one point on the admin stats trend chart.
type OnlineSnapshotBackup struct {
	CreatedAt time.Time `json:"created_at"`
	Count     int64     `json:"count"`
}

func exportOnlineSnapshots(db *gorm.DB) ([]OnlineSnapshotBackup, error) {
	var rows []models.OnlineSnapshot
	if err := db.Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]OnlineSnapshotBackup, 0, len(rows))
	for _, r := range rows {
		out = append(out, OnlineSnapshotBackup{CreatedAt: r.CreatedAt, Count: r.Count})
	}
	return out, nil
}

// upsertOnlineSnapshots deduplicates on the timestamp, which the snapshotter
// writes once per tick.
func upsertOnlineSnapshots(tx *gorm.DB, items []OnlineSnapshotBackup) error {
	if len(items) == 0 {
		return nil
	}
	var existing []models.OnlineSnapshot
	if err := tx.Find(&existing).Error; err != nil {
		return err
	}
	seen := make(map[int64]bool, len(existing))
	for _, s := range existing {
		seen[s.CreatedAt.UnixNano()] = true
	}

	fresh := make([]models.OnlineSnapshot, 0, len(items))
	for _, in := range items {
		key := in.CreatedAt.UnixNano()
		if seen[key] {
			continue
		}
		seen[key] = true
		fresh = append(fresh, models.OnlineSnapshot{CreatedAt: in.CreatedAt, Count: in.Count})
	}
	if len(fresh) == 0 {
		return nil
	}
	return tx.CreateInBatches(&fresh, backupInsertBatch).Error
}

// --- shared lookups -------------------------------------------------------

func emailsByUserID(db *gorm.DB) (map[uint]string, error) {
	var rows []struct {
		ID    uint
		Email string
	}
	if err := db.Model(&models.User{}).Select("id, email").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]string, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Email
	}
	return out, nil
}

func nodeNamesByID(db *gorm.DB) (map[uint]string, error) {
	var rows []struct {
		ID   uint
		Name string
	}
	if err := db.Model(&models.V2RayNode{}).Select("id, name").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[uint]string, len(rows))
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out, nil
}

func nodeIDsByName(db *gorm.DB) (map[string]uint, error) {
	names, err := nodeNamesByID(db)
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint, len(names))
	for id, name := range names {
		out[name] = id
	}
	return out, nil
}
