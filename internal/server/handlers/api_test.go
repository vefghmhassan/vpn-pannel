package handlers_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/config"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// uniqueInviteCode builds a stored invite code that /invite/redeem can actually find.
// The handler upper-cases whatever the client sends before looking it up, so a code
// stored with lower-case characters — which testutil.UniqueName produces, since it
// ends in a base36 timestamp — would never match.
func uniqueInviteCode(prefix string) string {
	return strings.ToUpper(testutil.UniqueName(prefix)[:6])
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	}
}

// --- ApiLogin / ApiNoLogin ---

func TestApiLogin_Success(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, func(u *models.User) {
		u.SetPassword("s3cret-pass")
	})

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "s3cret-pass", "device_id": "dev-1",
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.Token == "" {
		t.Errorf("expected a non-empty token")
	}
}

func TestApiLogin_BadPassword(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, func(u *models.User) { u.SetPassword("correct") })

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "wrong",
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestApiLogin_InactiveUser(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, func(u *models.User) {
		u.SetPassword("correct")
		u.IsActive = false
	})

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "correct",
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for inactive user, got %d", resp.StatusCode)
	}
}

func TestApiNoLogin_CreatesGuestIdempotently(t *testing.T) {
	app := apptest.New(t)
	deviceID := testutil.UniqueName("device")

	resp1 := testutil.DoJSON(t, app, "POST", "/api/v1/auth/no-login", map[string]string{"device_id": deviceID}, nil)
	if resp1.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp1.StatusCode)
	}
	var out1 struct {
		Token string `json:"token"`
	}
	testutil.DecodeJSON(t, resp1, &out1)

	var count int64
	database.DB.Model(&models.User{}).Where("email = ?", deviceID+"@vpnpannel.local").Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 guest user created, got %d", count)
	}

	// second call with the same device_id must not create a second user
	resp2 := testutil.DoJSON(t, app, "POST", "/api/v1/auth/no-login", map[string]string{"device_id": deviceID}, nil)
	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200 on repeat, got %d", resp2.StatusCode)
	}
	database.DB.Model(&models.User{}).Where("email = ?", deviceID+"@vpnpannel.local").Count(&count)
	if count != 1 {
		t.Fatalf("expected still exactly 1 guest user after repeat call, got %d", count)
	}
}

func TestApiNoLogin_RequiresDeviceID(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/auth/no-login", map[string]string{}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 without device_id, got %d", resp.StatusCode)
	}
}

// --- ApiLastConnection ---

func TestApiLastConnection_CreatesUserAndOpenEvent(t *testing.T) {
	app := apptest.New(t)
	token := testutil.UniqueName("client-token")

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/last-connection", map[string]string{"token": token}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var user models.User
	if err := database.DB.Where("client_token = ?", token).First(&user).Error; err != nil {
		t.Fatalf("expected a user to be created for the token: %v", err)
	}
	if user.LastSeenAt == nil {
		t.Errorf("expected LastSeenAt to be set")
	}

	var eventCount int64
	database.DB.Model(&models.AppOpenEvent{}).Where("user_id = ?", user.ID).Count(&eventCount)
	if eventCount != 1 {
		t.Errorf("expected exactly 1 AppOpenEvent after the first check-in, got %d", eventCount)
	}

	// second check-in reuses the same user and adds a second open event
	resp2 := testutil.DoJSON(t, app, "POST", "/api/v1/last-connection", map[string]string{"token": token}, nil)
	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200 on repeat check-in, got %d", resp2.StatusCode)
	}
	var userCount int64
	database.DB.Model(&models.User{}).Where("client_token = ?", token).Count(&userCount)
	if userCount != 1 {
		t.Fatalf("expected still exactly 1 user for the token, got %d", userCount)
	}
	database.DB.Model(&models.AppOpenEvent{}).Where("user_id = ?", user.ID).Count(&eventCount)
	if eventCount != 2 {
		t.Errorf("expected 2 AppOpenEvents after a second check-in, got %d", eventCount)
	}
}

func TestApiLastConnection_RejectsOverlongToken(t *testing.T) {
	app := apptest.New(t)
	longToken := ""
	for i := 0; i < 40; i++ {
		longToken += "a"
	}
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/last-connection", map[string]string{"token": longToken}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for an overlong token, got %d", resp.StatusCode)
	}
}

func TestApiLastConnection_RejectsEmptyToken(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/last-connection", map[string]string{"token": ""}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for an empty token, got %d", resp.StatusCode)
	}
}

func TestApiLastConnection_InactiveUserRejected(t *testing.T) {
	app := apptest.New(t)
	token := testutil.UniqueName("client-token")
	testutil.CreateUser(t, func(u *models.User) {
		u.ClientToken = &token
		u.IsActive = false
	})
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/last-connection", map[string]string{"token": token}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 for an inactive user, got %d", resp.StatusCode)
	}
}

// --- ApiInviteCode ---

func TestApiInviteCode_IdempotentAndSubstitutesShareText(t *testing.T) {
	app := apptest.New(t)
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_enabled":    true,
		"referral_task_text":  "invite some friends",
		"referral_share_text": "use my code {code} to join",
	})

	token := testutil.UniqueName("client-token")
	resp1 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/code", map[string]string{"token": token}, nil)
	if resp1.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp1.StatusCode)
	}
	var out1 struct {
		InviteCode   string `json:"invite_code"`
		InvitesCount int64  `json:"invites_count"`
		TaskText     string `json:"task_text"`
		ShareText    string `json:"share_text"`
	}
	testutil.DecodeJSON(t, resp1, &out1)
	if out1.InviteCode == "" {
		t.Fatalf("expected a non-empty invite code")
	}
	if out1.TaskText != "invite some friends" {
		t.Errorf("expected task_text to come from settings, got %q", out1.TaskText)
	}
	wantShare := "use my code " + out1.InviteCode + " to join"
	if out1.ShareText != wantShare {
		t.Errorf("expected share_text %q, got %q", wantShare, out1.ShareText)
	}

	// repeat call must return the exact same code
	resp2 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/code", map[string]string{"token": token}, nil)
	var out2 struct {
		InviteCode string `json:"invite_code"`
	}
	testutil.DecodeJSON(t, resp2, &out2)
	if out2.InviteCode != out1.InviteCode {
		t.Errorf("expected the same invite code on repeat calls, got %q then %q", out1.InviteCode, out2.InviteCode)
	}
}

// --- ApiInviteRedeem ---

func TestApiInviteRedeem_Success(t *testing.T) {
	app := apptest.New(t)
	setReferralEnabled(true)
	code := testutil.UniqueName("CODE")[:6]
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	friendToken := testutil.UniqueName("friend-token")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": friendToken, "invite_code": code,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var friend models.User
	database.DB.Where("client_token = ?", friendToken).First(&friend)
	if friend.ReferredByUserID == nil || *friend.ReferredByUserID != referrer.ID {
		t.Errorf("expected the friend to be marked as referred by %d, got %+v", referrer.ID, friend.ReferredByUserID)
	}
}

// setInstantReward turns the referral feature on and configures the two-sided
// instant reward. Uses a map update so the boolean flags are written even when
// false (GORM skips zero values on struct updates).
//
// The master switch defaults to off, so every invite test has to enable it — doing
// it here keeps that out of each test body.
func setInstantReward(enabled bool, inviterMinutes, inviteeMinutes, maxRewarded int) {
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_enabled":                true,
		"referral_instant_reward_enabled": enabled,
		"referral_inviter_reward_minutes": inviterMinutes,
		"referral_invitee_reward_minutes": inviteeMinutes,
		"referral_max_rewarded_invites":   maxRewarded,
	})
}

// setReferralEnabled flips only the master switch.
func setReferralEnabled(enabled bool) {
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).
		Update("referral_enabled", enabled)
}

func userByToken(t *testing.T, token string) models.User {
	t.Helper()
	var u models.User
	if err := database.DB.Where("client_token = ?", token).First(&u).Error; err != nil {
		t.Fatalf("expected a user for token %q: %v", token, err)
	}
	return u
}

// rewardWindow mirrors the shared reward/clock block that every /invite endpoint
// returns. Pointers on the two timestamps so tests can tell null from absent.
type rewardWindow struct {
	RewardActive        bool    `json:"reward_active"`
	RewardExpiresAt     *string `json:"reward_expires_at"`
	RewardExpiresAtUnix *int64  `json:"reward_expires_at_unix"`
	RemainingSeconds    int64   `json:"remaining_seconds"`
	RemainingDays       int     `json:"remaining_days"`
	RemainingHours      int     `json:"remaining_hours"`
	RemainingMinutes    int     `json:"remaining_minutes"`
	DaysLeft            int     `json:"days_left"`
	HoursLeft           int     `json:"hours_left"`
	MinutesLeft         int     `json:"minutes_left"`

	ServerTime             string `json:"server_time"`
	ServerTimeUnix         int64  `json:"server_time_unix"`
	ServerTimezone         string `json:"server_timezone"`
	ServerUTCOffsetSeconds int    `json:"server_utc_offset_seconds"`
}

// Regression: an admin who sets a 3-hour reward must get exactly 3 hours. The old
// threshold task ("N invites unlocks M days") ran off the very same referral and
// silently added a whole day on top, so a 3h setting produced 1d 3h.
func TestApiInviteRedeem_HourlyRewardIsNotInflated(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 3*60, 0, 0) // inviter 3h, invitee nothing

	code := uniqueInviteCode("HI")
	inviterToken := testutil.UniqueName("hourly-inviter")
	referrer := testutil.CreateUser(t, func(u *models.User) {
		u.InviteCode = &code
		u.ClientToken = &inviterToken
	})

	friendToken := testutil.UniqueName("hourly-friend")
	testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": friendToken, "invite_code": code,
	}, nil)

	var updated models.User
	database.DB.First(&updated, referrer.ID)
	if updated.RewardExpiresAt == nil {
		t.Fatalf("expected the inviter to receive a reward")
	}
	if d := time.Until(*updated.RewardExpiresAt); d < 2*time.Hour+55*time.Minute || d > 3*time.Hour {
		t.Fatalf("expected exactly ~3h, got %v (a whole extra day means the threshold task is back)", d)
	}

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": inviterToken}, nil)
	var w rewardWindow
	testutil.DecodeJSON(t, resp, &w)
	if w.RemainingDays != 0 || w.RemainingHours != 2 {
		t.Errorf("expected a 3h reward to read as 0d 2h 59m, got %dd %dh %dm",
			w.RemainingDays, w.RemainingHours, w.RemainingMinutes)
	}
	if w.RemainingSeconds < 10500 || w.RemainingSeconds > 10800 {
		t.Errorf("expected remaining_seconds just under 10800, got %d", w.RemainingSeconds)
	}
}

// Two people swapping codes would otherwise each collect both sides' rewards.
func TestApiInviteRedeem_RejectsMutualReferral(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 6*60, 6*60, 0)

	codeA := uniqueInviteCode("MA")
	codeB := uniqueInviteCode("MB")
	tokenA := testutil.UniqueName("mutual-a")
	tokenB := testutil.UniqueName("mutual-b")
	userA := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &codeA; u.ClientToken = &tokenA })
	userB := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &codeB; u.ClientToken = &tokenB })

	// B redeems A's code — fine.
	if resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": tokenB, "invite_code": codeA,
	}, nil); resp.StatusCode != 200 {
		t.Fatalf("expected the first redeem to succeed, got %d", resp.StatusCode)
	}

	var aBefore, bBefore models.User
	database.DB.First(&aBefore, userA.ID)
	database.DB.First(&bBefore, userB.ID)

	// A now tries to redeem B's code — refused.
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": tokenA, "invite_code": codeB,
	}, nil)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 for a mutual referral, got %d", resp.StatusCode)
	}

	var aAfter, bAfter models.User
	database.DB.First(&aAfter, userA.ID)
	database.DB.First(&bAfter, userB.ID)
	if aAfter.ReferredByUserID != nil {
		t.Errorf("expected the refused redeem not to record a referral link")
	}
	if !aAfter.RewardExpiresAt.Equal(*aBefore.RewardExpiresAt) {
		t.Errorf("expected A's reward window to be untouched by the refused redeem")
	}
	if !bAfter.RewardExpiresAt.Equal(*bBefore.RewardExpiresAt) {
		t.Errorf("expected B's reward window to be untouched by the refused redeem")
	}
}

// While the feature is off, no codes and no rewards. (That this is the *shipped*
// default is enforced by the column default in the model, not here — a shared dev
// database will already have whatever the admin last saved.)
func TestInviteEndpoints_Disabled(t *testing.T) {
	app := apptest.New(t)
	setReferralEnabled(false)

	token := testutil.UniqueName("disabled-token")
	for _, path := range []string{"/api/v1/invite/code", "/api/v1/invite/reward-status"} {
		resp := testutil.DoJSON(t, app, "POST", path, map[string]string{"token": token}, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: expected 200 while disabled, got %d", path, resp.StatusCode)
		}
		var out map[string]interface{}
		testutil.DecodeJSON(t, resp, &out)
		if enabled, _ := out["referral_enabled"].(bool); enabled {
			t.Errorf("%s: expected referral_enabled=false", path)
		}
		if _, ok := out["invite_code"]; ok {
			t.Errorf("%s: expected no invite_code while disabled", path)
		}
		// The clock block still ships so the client has a trusted time source.
		if _, ok := out["server_time_unix"]; !ok {
			t.Errorf("%s: expected the server clock even while disabled", path)
		}
	}

	// Nothing may be persisted: no user row should have gained an invite code.
	var codeCount int64
	database.DB.Model(&models.User{}).Where("client_token = ? AND invite_code IS NOT NULL", token).Count(&codeCount)
	if codeCount != 0 {
		t.Errorf("expected no invite code to be minted while the feature is disabled")
	}
}

func TestApiInviteRedeem_DisabledGrantsNothing(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 6*60, 6*60, 0)
	setReferralEnabled(false) // configured, but switched off

	code := uniqueInviteCode("DS")
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	token := testutil.UniqueName("disabled-redeem")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": token, "invite_code": code,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 while disabled, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	testutil.DecodeJSON(t, resp, &out)
	if enabled, _ := out["referral_enabled"].(bool); enabled {
		t.Errorf("expected referral_enabled=false")
	}

	var updated models.User
	database.DB.First(&updated, referrer.ID)
	if updated.RewardExpiresAt != nil || updated.RewardedReferralCount != 0 {
		t.Errorf("expected the code owner to be untouched while disabled, got %+v / %d",
			updated.RewardExpiresAt, updated.RewardedReferralCount)
	}
	var redeemer models.User
	if err := database.DB.Where("client_token = ?", token).First(&redeemer).Error; err == nil {
		if redeemer.ReferredByUserID != nil || redeemer.RewardExpiresAt != nil {
			t.Errorf("expected no referral link or reward for the redeemer while disabled")
		}
	}
}

func TestApiSettings_ExposesReferralEnabled(t *testing.T) {
	app := apptest.New(t)
	setReferralEnabled(true)

	resp := testutil.DoJSON(t, app, "GET", "/api/v1/settings", nil, nil)
	var out map[string]interface{}
	testutil.DecodeJSON(t, resp, &out)
	if enabled, ok := out["referral_enabled"].(bool); !ok || !enabled {
		t.Fatalf("expected referral_enabled=true in /api/v1/settings, got %v", out["referral_enabled"])
	}

	setReferralEnabled(false)
	resp2 := testutil.DoJSON(t, app, "GET", "/api/v1/settings", nil, nil)
	testutil.DecodeJSON(t, resp2, &out)
	if enabled, _ := out["referral_enabled"].(bool); enabled {
		t.Errorf("expected referral_enabled=false after switching it off")
	}
}

// The breakdown fields must be displayable side by side ("1 day, 6 hours, 0 min"),
// unlike the legacy *_left fields which are each a total of the whole remainder.
func TestRewardWindow_BreakdownDoesNotOverlap(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 0, 30*60, 0) // redeemer gets 30h = 1d 6h

	code := uniqueInviteCode("BD")
	testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	token := testutil.UniqueName("breakdown")
	testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": token, "invite_code": code}, nil)

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": token}, nil)
	var w rewardWindow
	testutil.DecodeJSON(t, resp, &w)

	if w.RemainingDays != 1 || w.RemainingHours != 5 || w.RemainingMinutes != 59 {
		t.Errorf("expected a 30h reward to break down to 1d 5h 59m, got %dd %dh %dm",
			w.RemainingDays, w.RemainingHours, w.RemainingMinutes)
	}
	if w.RemainingSeconds < 30*3600-5 || w.RemainingSeconds > 30*3600 {
		t.Errorf("expected remaining_seconds just under 108000, got %d", w.RemainingSeconds)
	}
	// The breakdown must reconstruct the total.
	if got := int64(w.RemainingDays*86400 + w.RemainingHours*3600 + w.RemainingMinutes*60); got > w.RemainingSeconds || w.RemainingSeconds-got >= 60 {
		t.Errorf("breakdown %d s does not reconstruct remaining_seconds %d", got, w.RemainingSeconds)
	}
	// Legacy keys keep their old "each is a total" meaning.
	if w.HoursLeft != 29 || w.DaysLeft != 2 {
		t.Errorf("expected legacy totals hours_left=29 days_left=2, got %d and %d", w.HoursLeft, w.DaysLeft)
	}
}

// Every invite endpoint must expose the same reward+clock block, so the app can
// render the countdown from whichever call it already had to make.
func TestInviteEndpoints_AllReturnRewardWindowAndServerClock(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 0, 6*60, 0)

	code := uniqueInviteCode("AL")
	testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })
	token := testutil.UniqueName("allthree")

	before := time.Now()
	cases := []struct {
		path string
		body map[string]string
	}{
		{"/api/v1/invite/redeem", map[string]string{"token": token, "invite_code": code}},
		{"/api/v1/invite/reward-status", map[string]string{"token": token}},
		{"/api/v1/invite/code", map[string]string{"token": token}},
	}
	for _, tc := range cases {
		resp := testutil.DoJSON(t, app, "POST", tc.path, tc.body, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: expected 200, got %d", tc.path, resp.StatusCode)
		}
		var w rewardWindow
		testutil.DecodeJSON(t, resp, &w)

		if !w.RewardActive || w.RemainingSeconds <= 0 {
			t.Errorf("%s: expected an active reward with time left, got %+v", tc.path, w)
		}
		if w.RewardExpiresAt == nil || w.RewardExpiresAtUnix == nil {
			t.Fatalf("%s: expected both expiry representations, got %+v", tc.path, w)
		}
		// The unix field and the RFC3339 field must denote the same instant —
		// this is what proves the offset is serialised correctly.
		parsed, err := time.Parse(time.RFC3339Nano, *w.RewardExpiresAt)
		if err != nil {
			t.Fatalf("%s: reward_expires_at %q did not parse: %v", tc.path, *w.RewardExpiresAt, err)
		}
		if parsed.Unix() != *w.RewardExpiresAtUnix {
			t.Errorf("%s: reward_expires_at (%d) and reward_expires_at_unix (%d) disagree",
				tc.path, parsed.Unix(), *w.RewardExpiresAtUnix)
		}
		if w.ServerTimeUnix < before.Unix()-5 || w.ServerTimeUnix > time.Now().Unix()+5 {
			t.Errorf("%s: server_time_unix %d is not close to now", tc.path, w.ServerTimeUnix)
		}
		if w.ServerTimezone == "" {
			t.Errorf("%s: expected a server_timezone", tc.path)
		}
		if w.ServerTimezone != config.Current.Timezone {
			t.Errorf("%s: expected server_timezone %q, got %q", tc.path, config.Current.Timezone, w.ServerTimezone)
		}
		// The reported offset must match what the timestamp itself encodes.
		if _, wantOffset := parsed.Zone(); wantOffset != w.ServerUTCOffsetSeconds {
			t.Errorf("%s: server_utc_offset_seconds=%d but the timestamp carries %d",
				tc.path, w.ServerUTCOffsetSeconds, wantOffset)
		}
	}
}

// With no reward at all the counters must be present and zero — not missing — so
// the client can read them unconditionally.
func TestRewardWindow_ZeroedNotAbsentWhenNoReward(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(false, 0, 0, 0)

	token := testutil.UniqueName("noreward")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/code", map[string]string{"token": token}, nil)

	var raw map[string]interface{}
	testutil.DecodeJSON(t, resp, &raw)
	for _, k := range []string{"reward_active", "remaining_seconds", "remaining_days", "remaining_hours",
		"remaining_minutes", "days_left", "hours_left", "minutes_left",
		"reward_expires_at", "reward_expires_at_unix", "server_time_unix", "server_timezone"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("expected key %q to be present even with no reward", k)
		}
	}
	if raw["reward_expires_at"] != nil || raw["reward_expires_at_unix"] != nil {
		t.Errorf("expected both expiry fields to be null with no reward, got %v / %v",
			raw["reward_expires_at"], raw["reward_expires_at_unix"])
	}
	for _, k := range []string{"remaining_seconds", "remaining_days", "days_left", "hours_left", "minutes_left"} {
		if v, _ := raw[k].(float64); v != 0 {
			t.Errorf("expected %q to be 0 with no reward, got %v", k, raw[k])
		}
	}
	if active, _ := raw["reward_active"].(bool); active {
		t.Errorf("expected reward_active=false with no reward")
	}
}

func TestApiInviteRedeem_RewardsBothSides(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 6*60, 24*60, 0) // inviter 6h, invitee 24h, no cap

	code := uniqueInviteCode("BS")
	referrerToken := testutil.UniqueName("inviter-token")
	referrer := testutil.CreateUser(t, func(u *models.User) {
		u.InviteCode = &code
		u.ClientToken = &referrerToken
	})

	friendToken := testutil.UniqueName("friend-token")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": friendToken, "invite_code": code,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		OK                   bool `json:"ok"`
		RewardGrantedMinutes int  `json:"reward_granted_minutes"`
		RewardActive         bool `json:"reward_active"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if !out.OK || out.RewardGrantedMinutes != 24*60 || !out.RewardActive {
		t.Errorf("expected the redeemer to be told they got 1440 minutes and an active reward, got %+v", out)
	}

	now := time.Now()
	friend := userByToken(t, friendToken)
	if friend.RewardExpiresAt == nil {
		t.Fatalf("expected the redeemer to receive a reward window")
	}
	if d := friend.RewardExpiresAt.Sub(now); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("expected the redeemer to get ~24h, got %v", d)
	}

	var updatedReferrer models.User
	database.DB.First(&updatedReferrer, referrer.ID)
	if updatedReferrer.RewardExpiresAt == nil {
		t.Fatalf("expected the code owner to receive a reward window too")
	}
	if d := updatedReferrer.RewardExpiresAt.Sub(now); d < 5*time.Hour || d > 7*time.Hour {
		t.Errorf("expected the code owner to get ~6h, got %v", d)
	}
	if updatedReferrer.RewardedReferralCount != 1 {
		t.Errorf("expected RewardedReferralCount=1, got %d", updatedReferrer.RewardedReferralCount)
	}
}

func TestApiInviteRedeem_InviterRewardStacksAcrossReferrals(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 6*60, 0, 0) // inviter 6h each, invitee nothing

	code := uniqueInviteCode("SK")
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	for _, tok := range []string{testutil.UniqueName("f1"), testutil.UniqueName("f2")} {
		resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
			"token": tok, "invite_code": code,
		}, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200 redeeming with %q, got %d", tok, resp.StatusCode)
		}
	}

	var updated models.User
	database.DB.First(&updated, referrer.ID)
	if updated.RewardExpiresAt == nil {
		t.Fatalf("expected the code owner to have a reward window")
	}
	// Two 6h grants must add up to ~12h, not reset to 6h.
	if d := time.Until(*updated.RewardExpiresAt); d < 11*time.Hour || d > 13*time.Hour {
		t.Errorf("expected two 6h referrals to stack to ~12h, got %v", d)
	}
	if updated.RewardedReferralCount != 2 {
		t.Errorf("expected RewardedReferralCount=2, got %d", updated.RewardedReferralCount)
	}
}

func TestApiInviteRedeem_RespectsRewardedInvitesCap(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 6*60, 24*60, 1) // cap: only the first referral pays the inviter

	code := uniqueInviteCode("CP")
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	firstToken := testutil.UniqueName("cap-f1")
	testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": firstToken, "invite_code": code}, nil)

	var afterFirst models.User
	database.DB.First(&afterFirst, referrer.ID)
	if afterFirst.RewardExpiresAt == nil {
		t.Fatalf("expected the first referral to pay the inviter")
	}
	firstExpiry := *afterFirst.RewardExpiresAt

	secondToken := testutil.UniqueName("cap-f2")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": secondToken, "invite_code": code}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected the second redeem to still succeed, got %d", resp.StatusCode)
	}

	var afterSecond models.User
	database.DB.First(&afterSecond, referrer.ID)
	if afterSecond.RewardExpiresAt == nil {
		t.Fatalf("expected the inviter to keep the reward earned before the cap")
	}
	if !afterSecond.RewardExpiresAt.Equal(firstExpiry) {
		t.Errorf("expected the inviter's reward to be unchanged past the cap: before=%v after=%v", firstExpiry, *afterSecond.RewardExpiresAt)
	}
	if afterSecond.RewardedReferralCount != 1 {
		t.Errorf("expected RewardedReferralCount to stay at the cap of 1, got %d", afterSecond.RewardedReferralCount)
	}

	// The capped inviter must not block the redeemer's own reward.
	second := userByToken(t, secondToken)
	if second.RewardExpiresAt == nil {
		t.Errorf("expected the redeemer to still get their reward even though the inviter is capped")
	}
}

func TestApiInviteRedeem_NoRewardWhenInstantRewardDisabled(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(false, 6*60, 24*60, 0)

	code := uniqueInviteCode("OF")
	referrer := testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	friendToken := testutil.UniqueName("off-friend")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": friendToken, "invite_code": code,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected the redeem itself to succeed, got %d", resp.StatusCode)
	}

	friend := userByToken(t, friendToken)
	if friend.ReferredByUserID == nil {
		t.Errorf("expected the referral link to still be recorded when rewards are off")
	}
	if friend.RewardExpiresAt != nil {
		t.Errorf("expected no reward for the redeemer, got %v", *friend.RewardExpiresAt)
	}

	var updated models.User
	database.DB.First(&updated, referrer.ID)
	if updated.RewardExpiresAt != nil {
		t.Errorf("expected no reward for the code owner, got %v", *updated.RewardExpiresAt)
	}
}

func TestApiInviteRewardStatus_ReportsHourlyReward(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 0, 6*60, 0) // redeemer gets 6h

	code := uniqueInviteCode("HR")
	testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	friendToken := testutil.UniqueName("hourly-friend")
	testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": friendToken, "invite_code": code}, nil)

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": friendToken}, nil)
	var status struct {
		RewardActive bool `json:"reward_active"`
		DaysLeft     int  `json:"days_left"`
		HoursLeft    int  `json:"hours_left"`
		MinutesLeft  int  `json:"minutes_left"`
	}
	testutil.DecodeJSON(t, resp, &status)
	if !status.RewardActive {
		t.Fatalf("expected a sub-day reward to still report as active, got %+v", status)
	}
	if status.HoursLeft != 5 { // 5h59m remaining truncates to 5
		t.Errorf("expected hours_left=5 for a 6h reward, got %d", status.HoursLeft)
	}
	if status.MinutesLeft < 355 || status.MinutesLeft > 360 {
		t.Errorf("expected minutes_left near 360, got %d", status.MinutesLeft)
	}
	if status.DaysLeft != 1 {
		t.Errorf("expected days_left to round a partial day up to 1, got %d", status.DaysLeft)
	}
}

func TestApiInviteRedeem_DoubleRedeemConflict(t *testing.T) {
	app := apptest.New(t)
	setReferralEnabled(true)
	codeA := testutil.UniqueName("CA")[:6]
	codeB := testutil.UniqueName("CB")[:6]
	testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &codeA })
	testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &codeB })

	friendToken := testutil.UniqueName("friend-token")
	resp1 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": friendToken, "invite_code": codeA}, nil)
	if resp1.StatusCode != 200 {
		t.Fatalf("expected first redeem to succeed, got %d", resp1.StatusCode)
	}
	resp2 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": friendToken, "invite_code": codeB}, nil)
	if resp2.StatusCode != 409 {
		t.Fatalf("expected 409 on second redeem, got %d", resp2.StatusCode)
	}
}

func TestApiInviteRedeem_UnknownCode(t *testing.T) {
	app := apptest.New(t)
	setReferralEnabled(true)
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": testutil.UniqueName("t"), "invite_code": "ZZZZZZ",
	}, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for unknown code, got %d", resp.StatusCode)
	}
}

func TestApiInviteRedeem_CannotRedeemOwnCode(t *testing.T) {
	app := apptest.New(t)
	setReferralEnabled(true)
	code := testutil.UniqueName("SELF")[:6]
	token := testutil.UniqueName("client-token")
	testutil.CreateUser(t, func(u *models.User) {
		u.InviteCode = &code
		u.ClientToken = &token
	})
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": token, "invite_code": code,
	}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for self-redemption, got %d", resp.StatusCode)
	}
}

// --- ApiInviteRewardStatus ---

// reward-status is a pure read: repeated polling must never move the expiry, since
// rewards are granted only at redemption time.
func TestApiInviteRewardStatus_PollingDoesNotChangeTheWindow(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 0, 6*60, 0)

	code := uniqueInviteCode("PL")
	testutil.CreateUser(t, func(u *models.User) { u.InviteCode = &code })

	token := testutil.UniqueName("poll-token")
	testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{"token": token, "invite_code": code}, nil)

	read := func() rewardWindow {
		resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": token}, nil)
		var w rewardWindow
		testutil.DecodeJSON(t, resp, &w)
		return w
	}

	first := read()
	if !first.RewardActive || first.RewardExpiresAtUnix == nil {
		t.Fatalf("expected an active reward after redeeming, got %+v", first)
	}
	second := read()
	if second.RewardExpiresAtUnix == nil || *second.RewardExpiresAtUnix != *first.RewardExpiresAtUnix {
		t.Errorf("expected polling not to move the expiry: first=%v second=%v",
			*first.RewardExpiresAtUnix, second.RewardExpiresAtUnix)
	}
}

func TestApiInviteRewardStatus_ExpiredReward(t *testing.T) {
	app := apptest.New(t)
	setInstantReward(true, 0, 0, 0)

	token := testutil.UniqueName("expired-token")
	past := time.Now().Add(-30 * time.Hour)
	testutil.CreateUser(t, func(u *models.User) {
		u.ClientToken = &token
		u.RewardExpiresAt = &past
	})

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": token}, nil)
	var w rewardWindow
	testutil.DecodeJSON(t, resp, &w)

	if w.RewardActive {
		t.Errorf("expected reward_active=false once the reward window has expired")
	}
	if w.RemainingSeconds != 0 {
		t.Errorf("expected remaining_seconds=0 for an expired reward, got %d", w.RemainingSeconds)
	}
	// The expiry itself is still reported — it just sits in the past.
	if w.RewardExpiresAtUnix == nil {
		t.Errorf("expected the past expiry to still be reported")
	}
}

// --- ApiHeartbeat (JWT-in-body, distinct from the client-token endpoints above) ---

func TestApiHeartbeat_UpdatesLastSeen(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, func(u *models.User) {
		old := time.Now().Add(-time.Hour)
		u.LastSeenAt = &old
	})
	jwt := testutil.MobileToken(t, u.ID, "device-xyz")

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/heartbeat", map[string]string{"token": jwt}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var reloaded models.User
	database.DB.First(&reloaded, u.ID)
	if reloaded.LastSeenAt == nil || !reloaded.LastSeenAt.After(time.Now().Add(-time.Minute)) {
		t.Errorf("expected LastSeenAt to be refreshed to ~now, got %v", reloaded.LastSeenAt)
	}
}

func TestApiHeartbeat_RequiresToken(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/heartbeat", map[string]string{}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 without a token, got %d", resp.StatusCode)
	}
}

// --- ApiProfile / ApiNodes (Bearer-authenticated) ---

func TestApiProfile_RequiresAuth(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/api/v1/profile", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without a token, got %d", resp.StatusCode)
	}
}

func TestApiProfile_ReturnsUser(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	jwt := testutil.MobileToken(t, u.ID, "dev-1")

	resp := testutil.DoJSON(t, app, "GET", "/api/v1/profile", nil, bearer(jwt))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		User struct {
			ID uint `json:"ID"`
		} `json:"user"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.User.ID != u.ID {
		t.Errorf("expected profile for user %d, got %d", u.ID, out.User.ID)
	}
}

func TestApiNodes_OnlyReturnsActive(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	jwt := testutil.MobileToken(t, u.ID, "dev-1")

	activeName := testutil.UniqueName("node-active")
	inactiveName := testutil.UniqueName("node-inactive")
	database.DB.Create(&models.V2RayNode{Name: activeName, Address: "1.2.3.4", Port: 443, Protocol: "vless", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: inactiveName, Address: "1.2.3.5", Port: 443, Protocol: "vless", IsActive: false})

	resp := testutil.DoJSON(t, app, "GET", "/api/v1/nodes", nil, bearer(jwt))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Nodes []struct {
			Name string `json:"Name"`
		} `json:"nodes"`
	}
	testutil.DecodeJSON(t, resp, &out)
	for _, n := range out.Nodes {
		if n.Name == inactiveName {
			t.Errorf("expected inactive node %q to be excluded from /api/v1/nodes", inactiveName)
		}
	}
	found := false
	for _, n := range out.Nodes {
		if n.Name == activeName {
			found = true
		}
	}
	if !found {
		t.Errorf("expected active node %q to be present", activeName)
	}
}

// --- ApiSplashConf ---

func TestApiSplashConf_AssignsNodes(t *testing.T) {
	app := apptest.New(t)
	database.DB.Create(&models.V2RayNode{Name: testutil.UniqueName("noads"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true, Ads: false})
	database.DB.Create(&models.V2RayNode{Name: testutil.UniqueName("ads"), Address: "2.2.2.2", Port: 443, Protocol: "vless", IsActive: true, Ads: true})

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/splash/conf", map[string]string{
		"client_key": testutil.UniqueName("ck"), "device_id": "dev-1",
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		NoAdsList []interface{} `json:"no_ads_list"`
		AdsList   []interface{} `json:"ads_list"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if len(out.NoAdsList) == 0 || len(out.AdsList) == 0 {
		t.Errorf("expected at least one node in each list, got %+v", out)
	}
}

// splashConfNodes posts to /api/v1/splash/conf and returns the addresses of the
// nodes in each list. V2RayNode carries no json tags, so the API emits Go field
// names ("Address") rather than snake_case.
func splashConfNodes(t *testing.T, app *fiber.App) (noAds []string, ads []string) {
	t.Helper()
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/splash/conf", map[string]string{
		"client_key": testutil.UniqueName("ck"),
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		NoAdsList []struct {
			Address string
		} `json:"no_ads_list"`
		AdsList []struct {
			Address string
		} `json:"ads_list"`
	}
	testutil.DecodeJSON(t, resp, &out)
	for _, n := range out.NoAdsList {
		noAds = append(noAds, n.Address)
	}
	for _, n := range out.AdsList {
		ads = append(ads, n.Address)
	}
	return noAds, ads
}

// isolateSplashConfNodes deactivates every pre-existing node so a splash test
// only ever sees the ones it creates. The harness runs each test in a
// transaction over the real project database, which in a dev environment is
// full of live nodes that would otherwise be picked up by /api/v1/splash/conf.
// The update is rolled back with the rest of the transaction.
func isolateSplashConfNodes(t *testing.T) {
	t.Helper()
	if err := database.DB.Model(&models.V2RayNode{}).
		Where("is_active = ?", true).
		Update("is_active", false).Error; err != nil {
		t.Fatalf("failed to isolate pre-existing nodes: %v", err)
	}
}

// seedSplashConfNodes isolates the test from pre-existing data, then creates
// `perAddress` non-ads nodes on each of the given addresses plus a single ads
// node so the ads lookup never 503s.
func seedSplashConfNodes(t *testing.T, perAddress int, addresses ...string) {
	t.Helper()
	isolateSplashConfNodes(t)
	for _, addr := range addresses {
		for i := 0; i < perAddress; i++ {
			if err := database.DB.Create(&models.V2RayNode{
				Name: testutil.UniqueName("noads"), Address: addr, Port: 443,
				Protocol: "vless", IsActive: true, Ads: false,
			}).Error; err != nil {
				t.Fatalf("failed to seed non-ads node: %v", err)
			}
		}
	}
	if err := database.DB.Create(&models.V2RayNode{
		Name: testutil.UniqueName("ads"), Address: "ads.example.com", Port: 8443,
		Protocol: "vless", IsActive: true, Ads: true,
	}).Error; err != nil {
		t.Fatalf("failed to seed ads node: %v", err)
	}
}

// setSplashConf configures the singleton settings row for the splash tests.
func setSplashConf(t *testing.T, count int, diverse bool) {
	t.Helper()
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		t.Fatalf("failed to load settings: %v", err)
	}
	s.SplashConfCount = count
	s.SplashDiverseServers = diverse
	if err := database.DB.Save(&s).Error; err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}
}

func TestApiSplashConf_DiverseSpreadsAcrossAddresses(t *testing.T) {
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	// Four addresses, five nodes each: a uniform random pick over the 20 rows
	// would almost always repeat an address across the four returned configs.
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com", "c.example.com", "d.example.com")

	// Repeated because the selection is randomized; a single pass could pass by
	// luck even if the round-robin were broken.
	for attempt := 0; attempt < 10; attempt++ {
		noAds, _ := splashConfNodes(t, app)
		if len(noAds) != 4 {
			t.Fatalf("expected 4 non-ads nodes (splash_conf_count 5 minus the ads node), got %d", len(noAds))
		}
		seen := map[string]bool{}
		for _, addr := range noAds {
			if seen[addr] {
				t.Fatalf("attempt %d: address %q returned more than once in %v", attempt, addr, noAds)
			}
			seen[addr] = true
		}
	}
}

func TestApiSplashConf_DiverseSingleAddressStillFillsCount(t *testing.T) {
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	// Mirrors production today: every node shares one address. Spreading has
	// nothing to spread over, so it must still return the full count rather
	// than collapsing to one node per address.
	seedSplashConfNodes(t, 10, "only.example.com")

	noAds, _ := splashConfNodes(t, app)
	if len(noAds) != 4 {
		t.Fatalf("expected 4 non-ads nodes even with a single address, got %d", len(noAds))
	}
}

func TestApiSplashConf_DiverseOffKeepsPlainRandom(t *testing.T) {
	app := apptest.New(t)
	setSplashConf(t, 5, false)
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com", "c.example.com", "d.example.com")

	noAds, _ := splashConfNodes(t, app)
	if len(noAds) != 4 {
		t.Fatalf("expected 4 non-ads nodes with spreading off, got %d", len(noAds))
	}
}

func TestApiSplashConf_DiverseDoesNotTouchAdsList(t *testing.T) {
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com")

	noAds, ads := splashConfNodes(t, app)
	if len(ads) != 1 {
		t.Fatalf("expected exactly one ads node, got %d", len(ads))
	}
	if ads[0] != "ads.example.com" {
		t.Errorf("expected the ads node to come from the ads pool, got %q", ads[0])
	}
	for _, addr := range noAds {
		if addr == "ads.example.com" {
			t.Errorf("ads address leaked into the non-ads list: %v", noAds)
		}
	}
}

func TestApiSplashConf_NoNodesAvailable(t *testing.T) {
	app := apptest.New(t)
	// The transaction still sees whatever nodes the real database holds, so they
	// have to be deactivated before either lookup can be expected to fail.
	isolateSplashConfNodes(t)
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/splash/conf", map[string]string{
		"client_key": testutil.UniqueName("ck-empty"),
	}, nil)
	if resp.StatusCode != fiberServiceUnavailable {
		t.Fatalf("expected 503 when no nodes are available, got %d", resp.StatusCode)
	}
}

// --- ApiSplashConf multi-config ads ---

// seedAdsNodes creates `perAddress` ads nodes on each of the given addresses.
// seedSplashConfNodes already seeds one ads node on ads.example.com, so a test
// calling both has 1 + len(addresses) distinct ads addresses in total.
func seedAdsNodes(t *testing.T, perAddress int, addresses ...string) {
	t.Helper()
	for _, addr := range addresses {
		for i := 0; i < perAddress; i++ {
			if err := database.DB.Create(&models.V2RayNode{
				Name: testutil.UniqueName("ads"), Address: addr, Port: 8443,
				Protocol: "vless", IsActive: true, Ads: true,
			}).Error; err != nil {
				t.Fatalf("failed to seed ads node: %v", err)
			}
		}
	}
}

// setMultiAds configures the multi-config ads settings, leaving every other
// field (including SplashConfCount and SplashDiverseServers) untouched.
func setMultiAds(t *testing.T, enabled bool, count int) {
	t.Helper()
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		t.Fatalf("failed to load settings: %v", err)
	}
	s.AdsMultiConfigEnabled = enabled
	s.AdsConfigCount = count
	if err := database.DB.Save(&s).Error; err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}
}

// assertDistinct fails when the same address appears twice, which is the whole
// promise of multi-config ads.
func assertDistinct(t *testing.T, label string, addrs []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, addr := range addrs {
		if seen[addr] {
			t.Fatalf("%s: address %q returned more than once in %v", label, addr, addrs)
		}
		seen[addr] = true
	}
}

func TestApiSplashConf_MultiAdsOffKeepsSingleNode(t *testing.T) {
	// The toggle is off, so extra ads servers must change nothing: exactly one
	// ads config, exactly as before the feature existed.
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	setMultiAds(t, false, 3)
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com")
	seedAdsNodes(t, 2, "ads2.example.com", "ads3.example.com")

	_, ads := splashConfNodes(t, app)
	if len(ads) != 1 {
		t.Fatalf("expected exactly one ads node while multi-config is off, got %d (%v)", len(ads), ads)
	}
}

func TestApiSplashConf_MultiAdsSpreadsAcrossAdsAddresses(t *testing.T) {
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	setMultiAds(t, true, 3)
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com")
	// Two more ads addresses on top of seedSplashConfNodes' ads.example.com, four
	// nodes each: a uniform random pick over the rows would often repeat one.
	seedAdsNodes(t, 4, "ads2.example.com", "ads3.example.com")

	// Repeated because the selection is randomized; a single pass could pass by
	// luck even if the per-address dedup were broken.
	for attempt := 0; attempt < 10; attempt++ {
		_, ads := splashConfNodes(t, app)
		if len(ads) != 3 {
			t.Fatalf("attempt %d: expected 3 ads nodes, got %d (%v)", attempt, len(ads), ads)
		}
		assertDistinct(t, fmt.Sprintf("attempt %d", attempt), ads)
	}
}

func TestApiSplashConf_MultiAdsCapsAtDistinctAdsServers(t *testing.T) {
	// Asking for more configs than there are ads servers returns fewer rather
	// than handing out two configs from the same server.
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	setMultiAds(t, true, 6)
	seedSplashConfNodes(t, 5, "a.example.com")
	// One extra ads address, so two distinct ads servers exist against a request
	// for six — each holding plenty of nodes to fill six if dedup were broken.
	seedAdsNodes(t, 5, "ads2.example.com")

	for attempt := 0; attempt < 10; attempt++ {
		_, ads := splashConfNodes(t, app)
		if len(ads) != 2 {
			t.Fatalf("attempt %d: expected 2 ads nodes (one per available ads server), got %d (%v)", attempt, len(ads), ads)
		}
		assertDistinct(t, fmt.Sprintf("attempt %d", attempt), ads)
	}
}

func TestApiSplashConf_MultiAdsIgnoresDiverseToggle(t *testing.T) {
	// splash_diverse_servers governs the non-ads list only; ads spreading is
	// driven purely by the multi-config toggle.
	app := apptest.New(t)
	setSplashConf(t, 5, false)
	setMultiAds(t, true, 3)
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com")
	seedAdsNodes(t, 4, "ads2.example.com", "ads3.example.com")

	for attempt := 0; attempt < 10; attempt++ {
		_, ads := splashConfNodes(t, app)
		if len(ads) != 3 {
			t.Fatalf("attempt %d: expected 3 ads nodes with spreading off, got %d (%v)", attempt, len(ads), ads)
		}
		assertDistinct(t, fmt.Sprintf("attempt %d", attempt), ads)
	}
}

func TestApiSplashConf_MultiAdsDoesNotShrinkNoAdsList(t *testing.T) {
	// The ads count is additive: splash_conf_count still sizes the non-ads list
	// on its own, so turning multi-config ads on must not eat into it.
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	setMultiAds(t, true, 3)
	seedSplashConfNodes(t, 5, "a.example.com", "b.example.com", "c.example.com", "d.example.com")
	seedAdsNodes(t, 4, "ads2.example.com", "ads3.example.com")

	noAds, ads := splashConfNodes(t, app)
	if len(noAds) != 4 {
		t.Fatalf("expected 4 non-ads nodes (splash_conf_count 5 minus one), got %d", len(noAds))
	}
	if len(ads) != 3 {
		t.Fatalf("expected 3 ads nodes alongside them, got %d", len(ads))
	}
	for _, addr := range noAds {
		if strings.HasPrefix(addr, "ads") {
			t.Errorf("ads address leaked into the non-ads list: %v", noAds)
		}
	}
}

func TestApiSplashConf_MultiAdsNoAdsNodesReturns503(t *testing.T) {
	// Non-ads nodes exist but no ads node does, so the ads lookup is what fails.
	app := apptest.New(t)
	setSplashConf(t, 5, true)
	setMultiAds(t, true, 3)
	isolateSplashConfNodes(t)
	for i := 0; i < 4; i++ {
		if err := database.DB.Create(&models.V2RayNode{
			Name: testutil.UniqueName("noads"), Address: "a.example.com", Port: 443,
			Protocol: "vless", IsActive: true, Ads: false,
		}).Error; err != nil {
			t.Fatalf("failed to seed non-ads node: %v", err)
		}
	}

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/splash/conf", map[string]string{
		"client_key": testutil.UniqueName("ck-no-ads"),
	}, nil)
	if resp.StatusCode != fiberServiceUnavailable {
		t.Fatalf("expected 503 when no ads nodes are available, got %d", resp.StatusCode)
	}
}

const fiberServiceUnavailable = 503

// --- ApiCreateOutage ---

func TestApiCreateOutage(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	jwt := testutil.MobileToken(t, u.ID, "dev-1")

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/outages", map[string]string{
		"title": "no connection", "description": "cannot connect at all",
	}, bearer(jwt))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		OK bool `json:"ok"`
		ID uint `json:"id"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if !out.OK || out.ID == 0 {
		t.Fatalf("expected ok=true and a non-zero id, got %+v", out)
	}
	var report models.OutageReport
	database.DB.First(&report, out.ID)
	if report.UserID == nil || *report.UserID != u.ID {
		t.Errorf("expected the outage report to be linked to user %d", u.ID)
	}
	if report.Status != models.OutageOpen {
		t.Errorf("expected a freshly-created outage to be OPEN, got %q", report.Status)
	}
}

// --- ApiSettings ---

func TestApiSettings_ReturnsPublicShape(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/api/v1/settings", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	testutil.DecodeJSON(t, resp, &out)
	for _, key := range []string{"current_version", "wheel_enabled", "splash_conf_count"} {
		if _, ok := out[key]; !ok {
			t.Errorf("expected key %q in /api/v1/settings response", key)
		}
	}
}

// --- ApiCheckUpdate ---

func TestApiCheckUpdate_NoUpdateAvailable(t *testing.T) {
	app := apptest.New(t)
	pkg := testutil.UniqueName("pkg")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/app/check-update", map[string]interface{}{
		"package_name": pkg, "version_code": 999999,
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Update bool `json:"update"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.Update {
		t.Errorf("expected update=false when no newer version exists")
	}
}

func TestApiCheckUpdate_FindsNewerVersionWithUniversalBuild(t *testing.T) {
	app := apptest.New(t)
	pkg := testutil.UniqueName("pkg")
	version := models.AppVersion{PackageName: pkg, VersionCode: 20, VersionName: "2.0.0"}
	database.DB.Create(&version)
	database.DB.Create(&models.AppBuild{AppVersionID: version.ID, ABI: "universal", FilePath: "/uploads/app.apk", FileSize: 1024})

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/app/check-update", map[string]interface{}{
		"package_name": pkg, "version_code": 10, "abi": "arm64-v8a",
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Update      bool   `json:"update"`
		VersionCode int    `json:"version_code"`
		URL         string `json:"url"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if !out.Update || out.VersionCode != 20 {
		t.Fatalf("expected an update to version 20, got %+v", out)
	}
	if out.URL == "" {
		t.Errorf("expected a fallback to the universal build's URL")
	}
}

func TestApiCheckUpdate_RequiresPackageName(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/app/check-update", map[string]interface{}{
		"version_code": 10,
	}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 without package_name, got %d", resp.StatusCode)
	}
}
