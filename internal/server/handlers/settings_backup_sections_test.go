package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// exportPayload runs an export (optionally with section query parameters) and
// returns the decoded backup as a generic map, which is how a real operator's
// file is shaped — the test must not depend on the Go DTO types.
func exportPayload(t *testing.T, app *fiber.App, query string) map[string]interface{} {
	t.Helper()
	resp := testutil.DoJSON(t, app, "GET", "/admin/settings/export"+query, nil, adminAuth(t))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read export body: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	return payload
}

func importPayload(t *testing.T, app *fiber.App, payload map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	resp := doMultipartUpload(t, app, "/admin/settings/import", "backup_file", "backup.json", data, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("import returned %d: %s", resp.StatusCode, body)
	}
}

func sectionRows(t *testing.T, payload map[string]interface{}, key string) []interface{} {
	t.Helper()
	raw, ok := payload[key]
	if !ok {
		t.Fatalf("export is missing the %q section", key)
	}
	rows, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("section %q is not a list", key)
	}
	return rows
}

// TestSettingsExport_CoversEverySection is the regression guard for the whole
// point of this feature: a default export must carry every table, not just the
// original three.
func TestSettingsExport_CoversEverySection(t *testing.T) {
	app := apptest.New(t)

	// One row in each of the tables that used to be left out entirely.
	database.DB.Create(&models.WheelSegment{
		Position: 0, DisplayType: "text", Label: "جایزه", RewardType: "time",
		RewardValue: 60, Color: "#22c55e", Weight: 5, IsActive: true,
	})
	database.DB.Create(&models.AppMessage{
		Position: 0, Title: "برگرد", Body: "مدتی است نیامده‌ای",
		InactiveDays: 7, RepeatEveryDays: 1, ShowInApp: true, IsActive: true,
	})
	version := models.AppVersion{
		PackageName: testutil.UniqueName("pkg"), VersionCode: 42,
		VersionName: "4.2.0", Changelog: "بهبود", IsMandatory: true,
	}
	database.DB.Create(&version)
	database.DB.Create(&models.AppBuild{
		AppVersionID: version.ID, ABI: "arm64-v8a",
		FilePath: "/uploads/app.apk", FileSize: 1234, Sha256: "abc",
	})
	user := testutil.CreateUser(t, nil)
	database.DB.Create(&models.MobileDevice{UserID: user.ID, DeviceID: "dev-1", FCMToken: "tok"})
	database.DB.Create(&models.OutageReport{
		UserID: &user.ID, Title: "قطعی", Description: "وصل نمی‌شود", Status: models.OutageOpen,
	})
	database.DB.Create(&models.AppOpenEvent{UserID: user.ID})
	database.DB.Create(&models.OnlineSnapshot{Count: 7})

	payload := exportPayload(t, app, "")

	// The "sections" list is what makes the file self-describing: a section with
	// no rows is omitted from the body, so presence of the key alone cannot tell
	// "not exported" from "exported but empty".
	var exported []string
	for _, raw := range sectionRows(t, payload, "sections") {
		exported = append(exported, raw.(string))
	}
	for _, key := range []string{
		"config", "nodes", "splash", "wheel", "messages",
		"releases", "outages", "users", "stats",
	} {
		found := false
		for _, got := range exported {
			if got == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("a default export should cover the %q section, got %v", key, exported)
		}
	}
	// Every section that actually has rows must also be present in the body.
	for _, key := range []string{
		"app_settings", "wheel_segments", "app_messages", "app_versions",
		"outage_reports", "users", "app_open_events", "online_snapshots",
	} {
		if _, ok := payload[key]; !ok {
			t.Errorf("default export is missing the %q section", key)
		}
	}

	// Spot-check that the rows carry real content rather than empty shells.
	wheel := sectionRows(t, payload, "wheel_segments")
	if len(wheel) == 0 {
		t.Fatalf("expected the wheel segment to be exported")
	}
	seg := wheel[0].(map[string]interface{})
	if seg["label"] != "جایزه" || seg["reward_value"].(float64) != 60 {
		t.Errorf("wheel segment did not round-trip its content: %+v", seg)
	}

	versions := sectionRows(t, payload, "app_versions")
	if len(versions) == 0 {
		t.Fatalf("expected the app version to be exported")
	}
	builds, ok := versions[0].(map[string]interface{})["builds"].([]interface{})
	if !ok || len(builds) == 0 {
		t.Errorf("expected the version's builds to be nested in the export")
	}

	users := sectionRows(t, payload, "users")
	if len(users) == 0 {
		t.Fatalf("expected users to be exported")
	}
}

// TestSettingsExport_HonoursSectionSelection covers the checkboxes: an explicit
// selection exports only what was asked for, while a plain link still exports
// everything.
func TestSettingsExport_HonoursSectionSelection(t *testing.T) {
	app := apptest.New(t)
	database.DB.Create(&models.WheelSegment{Position: 0, Label: "x", Weight: 1, IsActive: true})
	testutil.CreateUser(t, nil)

	only := exportPayload(t, app, "?sections=1&wheel=1")
	if _, ok := only["wheel_segments"]; !ok {
		t.Errorf("expected the selected wheel section to be present")
	}
	if got := sectionRows(t, only, "sections"); len(got) != 1 || got[0] != "wheel" {
		t.Errorf("sections list should name only the wheel, got %v", got)
	}
	for _, key := range []string{"users", "v2ray_nodes", "app_settings", "app_open_events"} {
		if _, ok := only[key]; ok {
			t.Errorf("section %q was not selected but is present in the export", key)
		}
	}

	// No section parameters at all: the plain link must still export everything.
	all := exportPayload(t, app, "")
	for _, key := range []string{"users", "wheel_segments", "app_settings"} {
		if _, ok := all[key]; !ok {
			t.Errorf("an unparameterised export should include %q", key)
		}
	}
}

// TestSettingsImport_RestoresEverySection wipes the tables the export just
// captured and imports the file back, which is the actual disaster-recovery
// path this feature exists for.
func TestSettingsImport_RestoresEverySection(t *testing.T) {
	app := apptest.New(t)

	database.DB.Create(&models.WheelSegment{
		Position: 0, DisplayType: "icon", Label: "چرخ", Icon: "🎁",
		RewardType: "time", RewardValue: 120, Color: "#ef4444", Weight: 9, IsActive: true,
	})
	database.DB.Create(&models.AppMessage{
		Position: 3, Title: "یادآور", Body: "متن", InactiveDays: 5,
		RepeatEveryDays: 2, MaxShows: 4, ShowInApp: true, LocalNotification: true, IsActive: true,
	})
	version := models.AppVersion{
		PackageName: testutil.UniqueName("pkg"), VersionCode: 99, VersionName: "9.9.9",
	}
	database.DB.Create(&version)
	database.DB.Create(&models.AppBuild{
		AppVersionID: version.ID, ABI: "universal", FilePath: "/uploads/u.apk", FileSize: 5,
	})
	database.DB.Create(&models.OnlineSnapshot{Count: 42, CreatedAt: time.Now().Add(-time.Hour)})

	payload := exportPayload(t, app, "")

	// Now destroy them, exactly as a lost database would.
	database.DB.Where("1 = 1").Delete(&models.WheelSegment{})
	database.DB.Where("1 = 1").Delete(&models.AppMessage{})
	database.DB.Where("1 = 1").Delete(&models.AppBuild{})
	database.DB.Where("1 = 1").Delete(&models.AppVersion{})
	database.DB.Where("1 = 1").Delete(&models.OnlineSnapshot{})

	importPayload(t, app, payload)

	var seg models.WheelSegment
	if err := database.DB.Where("position = ?", 0).First(&seg).Error; err != nil {
		t.Fatalf("wheel segment was not restored: %v", err)
	}
	if seg.Label != "چرخ" || seg.Icon != "🎁" || seg.RewardValue != 120 || seg.Weight != 9 || !seg.IsActive {
		t.Errorf("wheel segment restored with wrong content: %+v", seg)
	}

	var msg models.AppMessage
	if err := database.DB.Where("position = ?", 3).First(&msg).Error; err != nil {
		t.Fatalf("app message was not restored: %v", err)
	}
	if msg.Title != "یادآور" || msg.InactiveDays != 5 || msg.MaxShows != 4 || !msg.LocalNotification {
		t.Errorf("app message restored with wrong content: %+v", msg)
	}

	var ver models.AppVersion
	if err := database.DB.Preload("Builds").
		Where("package_name = ? AND version_code = ?", version.PackageName, 99).
		First(&ver).Error; err != nil {
		t.Fatalf("app version was not restored: %v", err)
	}
	if len(ver.Builds) != 1 || ver.Builds[0].ABI != "universal" {
		t.Errorf("app version builds were not restored: %+v", ver.Builds)
	}

	// The dev database also holds snapshots written by the running server, so
	// this looks for the specific row rather than assuming an empty table.
	var snapshots []models.OnlineSnapshot
	database.DB.Where("count = ?", 42).Find(&snapshots)
	if len(snapshots) != 1 {
		t.Errorf("expected exactly one restored snapshot with count 42, got %d", len(snapshots))
	}
}

// TestSettingsImport_RestoresReferralGraphByEmail is the subtle one: row ids
// differ between installs, so the "who invited whom" link has to survive as an
// email and be resolved back to an id on import.
func TestSettingsImport_RestoresReferralGraphByEmail(t *testing.T) {
	app := apptest.New(t)

	code := "ABC123"
	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	inviter := testutil.CreateUser(t, func(u *models.User) {
		u.InviteCode = &code
		u.RewardExpiresAt = &expires
		u.RewardedReferralCount = 2
	})
	invitee := testutil.CreateUser(t, func(u *models.User) {
		u.ReferredByUserID = &inviter.ID
	})
	database.DB.Create(&models.MobileDevice{UserID: invitee.ID, DeviceID: "dev-x", FCMToken: "t-x"})
	database.DB.Create(&models.AppOpenEvent{UserID: invitee.ID})

	payload := exportPayload(t, app, "")

	// Drop the link and the reward, then restore from the file.
	database.DB.Model(&models.User{}).Where("id = ?", invitee.ID).
		Update("referred_by_user_id", nil)
	database.DB.Model(&models.User{}).Where("id = ?", inviter.ID).
		Updates(map[string]interface{}{"reward_expires_at": nil, "rewarded_referral_count": 0})
	database.DB.Where("user_id = ?", invitee.ID).Delete(&models.MobileDevice{})

	importPayload(t, app, payload)

	var restored models.User
	if err := database.DB.Where("email = ?", invitee.Email).First(&restored).Error; err != nil {
		t.Fatalf("invitee vanished: %v", err)
	}
	if restored.ReferredByUserID == nil {
		t.Fatalf("the referral link was not restored")
	}
	if *restored.ReferredByUserID != inviter.ID {
		t.Errorf("referral points at user %d, want %d", *restored.ReferredByUserID, inviter.ID)
	}

	var restoredInviter models.User
	database.DB.Where("email = ?", inviter.Email).First(&restoredInviter)
	if restoredInviter.InviteCode == nil || *restoredInviter.InviteCode != code {
		t.Errorf("invite code was not preserved: %+v", restoredInviter.InviteCode)
	}
	if restoredInviter.RewardExpiresAt == nil {
		t.Errorf("the ad-free reward window was not restored")
	}
	if restoredInviter.RewardedReferralCount != 2 {
		t.Errorf("rewarded referral count = %d, want 2", restoredInviter.RewardedReferralCount)
	}

	var devices []models.MobileDevice
	database.DB.Where("user_id = ?", restored.ID).Find(&devices)
	if len(devices) != 1 || devices[0].DeviceID != "dev-x" {
		t.Errorf("the user's device was not restored: %+v", devices)
	}
}

// TestSettingsImport_StatsAreIdempotent guards the tracker's numbers: importing
// the same backup twice must not double every user's open count.
func TestSettingsImport_StatsAreIdempotent(t *testing.T) {
	app := apptest.New(t)

	user := testutil.CreateUser(t, nil)
	base := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Millisecond)
	for i := 0; i < 5; i++ {
		database.DB.Create(&models.AppOpenEvent{UserID: user.ID, CreatedAt: base.Add(time.Duration(i) * time.Minute)})
	}
	database.DB.Create(&models.OnlineSnapshot{Count: 3, CreatedAt: base})

	payload := exportPayload(t, app, "")

	countEvents := func() int64 {
		var n int64
		database.DB.Model(&models.AppOpenEvent{}).Where("user_id = ?", user.ID).Count(&n)
		return n
	}
	countSnapshots := func() int64 {
		var n int64
		database.DB.Model(&models.OnlineSnapshot{}).Count(&n)
		return n
	}
	eventsBefore, snapshotsBefore := countEvents(), countSnapshots()

	importPayload(t, app, payload)
	importPayload(t, app, payload)

	if got := countEvents(); got != eventsBefore {
		t.Errorf("app open events grew from %d to %d after re-importing the same backup", eventsBefore, got)
	}
	if got := countSnapshots(); got != snapshotsBefore {
		t.Errorf("online snapshots grew from %d to %d after re-importing the same backup", snapshotsBefore, got)
	}
}

// TestSettingsImport_ReferralSettingsRoundTrip covers the settings fields that
// the backup previously dropped on the floor entirely.
func TestSettingsImport_ReferralSettingsRoundTrip(t *testing.T) {
	app := apptest.New(t)

	var s models.AppSettings
	database.DB.First(&s, 1)
	s.ReferralEnabled = true
	s.ReferralInstantRewardEnabled = true
	s.ReferralInviterRewardMinutes = 2880
	s.ReferralInviteeRewardMinutes = 720
	s.ReferralMaxRewardedInvites = 10
	s.ReferralTaskText = "دوستانت را دعوت کن"
	s.ReferralShareText = "کد من: {code}"
	s.AppTimer = 45
	s.Domain = "example.com"
	database.DB.Save(&s)

	payload := exportPayload(t, app, "")

	// Reset everything the export should have captured.
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_enabled":                false,
		"referral_instant_reward_enabled": false,
		"referral_inviter_reward_minutes": 0,
		"referral_invitee_reward_minutes": 0,
		"referral_max_rewarded_invites":   0,
		"referral_task_text":              "",
		"referral_share_text":             "",
		"app_timer":                       0,
		"domain":                          "",
	})

	importPayload(t, app, payload)

	var restored models.AppSettings
	database.DB.First(&restored, 1)
	if !restored.ReferralEnabled || !restored.ReferralInstantRewardEnabled {
		t.Errorf("referral toggles were not restored: %+v", restored)
	}
	if restored.ReferralInviterRewardMinutes != 2880 || restored.ReferralInviteeRewardMinutes != 720 {
		t.Errorf("referral reward durations were not restored: %d / %d",
			restored.ReferralInviterRewardMinutes, restored.ReferralInviteeRewardMinutes)
	}
	if restored.ReferralMaxRewardedInvites != 10 {
		t.Errorf("referral cap = %d, want 10", restored.ReferralMaxRewardedInvites)
	}
	if restored.ReferralTaskText != "دوستانت را دعوت کن" || restored.ReferralShareText != "کد من: {code}" {
		t.Errorf("referral texts were not restored: %q / %q", restored.ReferralTaskText, restored.ReferralShareText)
	}
	if restored.AppTimer != 45 || restored.Domain != "example.com" {
		t.Errorf("app timer/domain were not restored: %d / %q", restored.AppTimer, restored.Domain)
	}
}

// TestSettingsImport_AcceptsVersionOneBackups keeps old files working: a v1
// backup carries only the original three sections, and the tables it says
// nothing about must be left exactly as they are.
func TestSettingsImport_AcceptsVersionOneBackups(t *testing.T) {
	app := apptest.New(t)
	database.DB.Create(&models.WheelSegment{Position: 0, Label: "دست‌نخورده", Weight: 3, IsActive: true})

	payload := exportPayload(t, app, "")
	payload["version"] = 1
	delete(payload, "wheel_segments")
	delete(payload, "app_messages")
	delete(payload, "users")
	delete(payload, "app_open_events")
	delete(payload, "online_snapshots")
	delete(payload, "app_versions")
	delete(payload, "outage_reports")

	importPayload(t, app, payload)

	var seg models.WheelSegment
	if err := database.DB.Where("position = ?", 0).First(&seg).Error; err != nil {
		t.Fatalf("the wheel segment was removed by a v1 import: %v", err)
	}
	if seg.Label != "دست‌نخورده" {
		t.Errorf("a v1 import altered a section it does not carry: %+v", seg)
	}
}

// TestSettingsImport_UsernameCollisionDoesNotFailTheImport covers merging into a
// populated database: two different people can hold the same username, and one
// clash must not abort the whole restore.
func TestSettingsImport_UsernameCollisionDoesNotFailTheImport(t *testing.T) {
	app := apptest.New(t)

	existing := testutil.CreateUser(t, nil)
	payload := exportPayload(t, app, "?sections=1&users=1")

	users := sectionRows(t, payload, "users")
	var target map[string]interface{}
	for _, raw := range users {
		row := raw.(map[string]interface{})
		if row["email"] == existing.Email {
			target = row
			break
		}
	}
	if target == nil {
		t.Fatalf("the seeded user is missing from the export")
	}
	// A different person carrying a username that is already taken here.
	clash := map[string]interface{}{}
	for k, v := range target {
		clash[k] = v
	}
	clash["email"] = "collision-" + existing.Email
	payload["users"] = append(users, clash)

	importPayload(t, app, payload)

	var restored models.User
	if err := database.DB.Where("email = ?", clash["email"]).First(&restored).Error; err != nil {
		t.Fatalf("the colliding user was not imported: %v", err)
	}
	if restored.Username == existing.Username {
		t.Errorf("two users ended up sharing the username %q", restored.Username)
	}
	var stillThere models.User
	if err := database.DB.Where("email = ?", existing.Email).First(&stillThere).Error; err != nil {
		t.Fatalf("the original user was lost: %v", err)
	}
	if stillThere.Username != existing.Username {
		t.Errorf("the original user's username was changed to %q", stillThere.Username)
	}
}
