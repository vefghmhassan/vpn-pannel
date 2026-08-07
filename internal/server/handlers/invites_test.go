package handlers_test

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestInvitesPage_ListsReferrersSortedByCount(t *testing.T) {
	app := apptest.New(t)
	codeLow := testutil.UniqueName("LO")[:6]
	codeHigh := testutil.UniqueName("HI")[:6]
	low := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &codeLow })
	high := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &codeHigh })
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &low.ID })
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &high.ID })
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &high.ID })

	resp := testutil.DoJSON(t, app, "GET", "/admin/invites", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	posHigh := strings.Index(text, high.Username)
	posLow := strings.Index(text, low.Username)
	if posHigh == -1 || posLow == -1 {
		t.Fatalf("expected both referrers to be listed, got body without them")
	}
	if posHigh > posLow {
		t.Errorf("expected the referrer with more referrals (%q) to be listed before %q", high.Username, low.Username)
	}
}

func TestInviteDetailPage_UnknownIDNotFound(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/invites/999999999", nil, adminAuth(t))
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for an unknown referrer id, got %d", resp.StatusCode)
	}
}

func TestInviteDetailPage_ListsReferredUsers(t *testing.T) {
	app := apptest.New(t)
	code := testutil.UniqueName("DT")[:6]
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })
	friend := testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &referrer.ID })

	resp := testutil.DoJSON(t, app, "GET", "/admin/invites/"+strconv.FormatUint(uint64(referrer.ID), 10), nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), friend.Username) {
		t.Errorf("expected the referred user %q to appear on the referrer's detail page", friend.Username)
	}
}

func TestReferralTaskSettingsUpdate_AppliesValidValues(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/invites/task-settings", url.Values{
		"referral_enabled":    {"on"},
		"referral_task_text":  {"invite nine friends"},
		"referral_share_text": {"share this: {code}"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after saving settings, got %d", resp.StatusCode)
	}

	var settings models.AppSettings
	database.DB.First(&settings, 1)
	if !settings.ReferralEnabled {
		t.Errorf("expected the referral feature to be enabled")
	}
	if settings.ReferralTaskText != "invite nine friends" {
		t.Errorf("expected the task text to be saved, got %q", settings.ReferralTaskText)
	}
	if settings.ReferralShareText != "share this: {code}" {
		t.Errorf("expected the share text to be saved, got %q", settings.ReferralShareText)
	}
}

// The master switch follows plain HTML checkbox semantics: an omitted field means
// off, which is how the admin turns the whole feature back off.
func TestReferralTaskSettingsUpdate_OmittedCheckboxDisablesReferral(t *testing.T) {
	app := apptest.New(t)
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Update("referral_enabled", true)

	resp := testutil.DoForm(t, app, "POST", "/admin/invites/task-settings", url.Values{
		"referral_task_text": {"still here"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}

	var after models.AppSettings
	database.DB.First(&after, 1)
	if after.ReferralEnabled {
		t.Errorf("expected an omitted referral_enabled checkbox to disable the feature")
	}
}

func TestReferralTaskSettingsUpdate_CombinesDaysAndHoursIntoMinutes(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/invites/task-settings", url.Values{
		"referral_instant_reward_enabled": {"on"},
		"referral_inviter_reward_days":    {"1"},
		"referral_inviter_reward_hours":   {"6"},
		"referral_invitee_reward_days":    {"0"},
		"referral_invitee_reward_hours":   {"12"},
		"referral_max_rewarded_invites":   {"20"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after saving settings, got %d", resp.StatusCode)
	}

	var settings models.AppSettings
	database.DB.First(&settings, 1)
	if !settings.ReferralInstantRewardEnabled {
		t.Errorf("expected the instant reward to be enabled")
	}
	if settings.ReferralInviterRewardMinutes != 1800 { // 1d 6h
		t.Errorf("expected the inviter reward to be 1800 minutes, got %d", settings.ReferralInviterRewardMinutes)
	}
	if settings.ReferralInviteeRewardMinutes != 720 { // 12h
		t.Errorf("expected the invitee reward to be 720 minutes, got %d", settings.ReferralInviteeRewardMinutes)
	}
	if settings.ReferralMaxRewardedInvites != 20 {
		t.Errorf("expected the cap to be 20, got %d", settings.ReferralMaxRewardedInvites)
	}
}

// Unlike referral_required_invites, 0 is a real choice for the reward durations
// ("give this side nothing") and for the cap ("unlimited"), so it must be saved.
func TestReferralTaskSettingsUpdate_AcceptsZeroDurationsAndCap(t *testing.T) {
	app := apptest.New(t)
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_inviter_reward_minutes": 600,
		"referral_invitee_reward_minutes": 600,
		"referral_max_rewarded_invites":   9,
	})

	resp := testutil.DoForm(t, app, "POST", "/admin/invites/task-settings", url.Values{
		"referral_inviter_reward_days":  {"0"},
		"referral_inviter_reward_hours": {"0"},
		"referral_invitee_reward_days":  {"0"},
		"referral_invitee_reward_hours": {"3"},
		"referral_max_rewarded_invites": {"0"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}

	var settings models.AppSettings
	database.DB.First(&settings, 1)
	if settings.ReferralInviterRewardMinutes != 0 {
		t.Errorf("expected a zeroed inviter reward to be saved, got %d", settings.ReferralInviterRewardMinutes)
	}
	if settings.ReferralInviteeRewardMinutes != 180 {
		t.Errorf("expected the invitee reward to be 180 minutes, got %d", settings.ReferralInviteeRewardMinutes)
	}
	if settings.ReferralMaxRewardedInvites != 0 {
		t.Errorf("expected the cap to be cleared to 0 (unlimited), got %d", settings.ReferralMaxRewardedInvites)
	}
	// An unchecked checkbox is simply absent from the form body.
	if settings.ReferralInstantRewardEnabled {
		t.Errorf("expected an omitted checkbox to turn the instant reward off")
	}
}

func TestInviteTaskStatsPage_ListsReferrersAndActiveRewards(t *testing.T) {
	app := apptest.New(t)

	code := testutil.UniqueName("ST")[:6]
	future := time.Now().Add(3 * time.Hour)
	referrer := testutil.CreateUser(t, func(u *models.User) {
		u.InviteCode = &code
		u.RewardExpiresAt = &future
		u.RewardedReferralCount = 1
	})
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &referrer.ID })

	resp := testutil.DoJSON(t, app, "GET", "/admin/invite-task-stats", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if !strings.Contains(text, referrer.Username) {
		t.Errorf("expected the referrer to appear in the invite stats table")
	}
	// The removed threshold task must leave no trace in the UI.
	if strings.Contains(text, "حد نصاب") {
		t.Errorf("expected no threshold-task wording left on the stats page")
	}
}
