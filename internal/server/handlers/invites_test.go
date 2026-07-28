package handlers_test

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"

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
		"referral_required_invites": {"9"},
		"referral_reward_days":      {"14"},
		"referral_task_text":        {"invite nine friends"},
		"referral_share_text":       {"share this: {code}"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after saving settings, got %d", resp.StatusCode)
	}

	var settings models.AppSettings
	database.DB.First(&settings, 1)
	if settings.ReferralRequiredInvites != 9 {
		t.Errorf("expected ReferralRequiredInvites=9, got %d", settings.ReferralRequiredInvites)
	}
	if settings.ReferralRewardDays != 14 {
		t.Errorf("expected ReferralRewardDays=14, got %d", settings.ReferralRewardDays)
	}
	if settings.ReferralTaskText != "invite nine friends" {
		t.Errorf("expected the task text to be saved, got %q", settings.ReferralTaskText)
	}
}

func TestReferralTaskSettingsUpdate_IgnoresNonPositiveCounts(t *testing.T) {
	app := apptest.New(t)
	var before models.AppSettings
	database.DB.First(&before, 1)
	before.ReferralRequiredInvites = 5
	database.DB.Save(&before)

	resp := testutil.DoForm(t, app, "POST", "/admin/invites/task-settings", url.Values{
		"referral_required_invites": {"0"},
		"referral_reward_days":      {"-3"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}

	var after models.AppSettings
	database.DB.First(&after, 1)
	if after.ReferralRequiredInvites != 5 {
		t.Errorf("expected a non-positive value to be ignored, ReferralRequiredInvites stayed at 5, got %d", after.ReferralRequiredInvites)
	}
}

func TestInviteTaskStatsPage_CountsReachedAndActive(t *testing.T) {
	app := apptest.New(t)
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_required_invites": 1,
		"referral_reward_days":      7,
	})

	code := testutil.UniqueName("ST")[:6]
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &referrer.ID })

	resp := testutil.DoJSON(t, app, "GET", "/admin/invite-task-stats", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), referrer.Username) {
		t.Errorf("expected the referrer to appear in the invite-task stats table")
	}
}
