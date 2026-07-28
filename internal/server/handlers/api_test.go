package handlers_test

import (
	"net/http"
	"testing"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

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
		"referral_task_text":  "invite some friends",
		"referral_share_text": "use my code {code} to join",
	})

	token := testutil.UniqueName("client-token")
	resp1 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/code", map[string]string{"token": token}, nil)
	if resp1.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp1.StatusCode)
	}
	var out1 struct {
		InviteCode      string `json:"invite_code"`
		InvitesCount    int64  `json:"invites_count"`
		InvitesRequired int    `json:"invites_required"`
		TaskText        string `json:"task_text"`
		ShareText       string `json:"share_text"`
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

func TestApiInviteRedeem_DoubleRedeemConflict(t *testing.T) {
	app := apptest.New(t)
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
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/redeem", map[string]string{
		"token": testutil.UniqueName("t"), "invite_code": "ZZZZZZ",
	}, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for unknown code, got %d", resp.StatusCode)
	}
}

func TestApiInviteRedeem_CannotRedeemOwnCode(t *testing.T) {
	app := apptest.New(t)
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

func TestApiInviteRewardStatus_FullLifecycle(t *testing.T) {
	app := apptest.New(t)
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_required_invites": 2,
		"referral_reward_days":      7,
	})

	referrerToken := testutil.UniqueName("referrer-token")
	referrer := testutil.CreateUser(t, func(u *models.User) { u.ClientToken = &referrerToken })
	code := testutil.UniqueName("RW")[:6]
	referrer.InviteCode = &code
	database.DB.Save(referrer)

	// below threshold: not eligible yet
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": referrerToken}, nil)
	var status struct {
		Eligible        bool   `json:"eligible"`
		InvitesCount    int64  `json:"invites_count"`
		InvitesRequired int    `json:"invites_required"`
		RewardActive    bool   `json:"reward_active"`
		RewardExpiresAt string `json:"reward_expires_at"`
	}
	testutil.DecodeJSON(t, resp, &status)
	if status.Eligible || status.RewardActive {
		t.Fatalf("expected not eligible with 0 referrals, got %+v", status)
	}

	// bring in 2 referrals
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &referrer.ID })
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &referrer.ID })

	resp2 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": referrerToken}, nil)
	testutil.DecodeJSON(t, resp2, &status)
	if !status.Eligible || !status.RewardActive {
		t.Fatalf("expected eligible+active after reaching the threshold, got %+v", status)
	}
	if status.RewardExpiresAt == "" {
		t.Errorf("expected a reward_expires_at timestamp")
	}
	firstExpiry, err := time.Parse(time.RFC3339Nano, status.RewardExpiresAt)
	if err != nil {
		t.Fatalf("failed to parse reward_expires_at %q: %v", status.RewardExpiresAt, err)
	}

	// calling again must not restart the timer. Compare with a small tolerance:
	// the first response reflects the in-memory value (nanosecond precision),
	// the second reflects the same instant reloaded from Postgres (microsecond
	// precision), so the raw strings can legitimately differ in their last digits.
	resp3 := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": referrerToken}, nil)
	testutil.DecodeJSON(t, resp3, &status)
	secondExpiry, err := time.Parse(time.RFC3339Nano, status.RewardExpiresAt)
	if err != nil {
		t.Fatalf("failed to parse reward_expires_at %q: %v", status.RewardExpiresAt, err)
	}
	if diff := secondExpiry.Sub(firstExpiry); diff < -time.Second || diff > time.Second {
		t.Errorf("expected the reward timer not to restart: first=%v second=%v (diff=%v)", firstExpiry, secondExpiry, diff)
	}
}

func TestApiInviteRewardStatus_ExpiredReward(t *testing.T) {
	app := apptest.New(t)
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Updates(map[string]interface{}{
		"referral_required_invites": 1,
		"referral_reward_days":      7,
	})

	token := testutil.UniqueName("expired-token")
	past := time.Now().AddDate(0, 0, -30) // activated 30 days ago, reward is 7 days
	referrer := testutil.CreateUser(t, func(u *models.User) {
		u.ClientToken = &token
		u.RewardActivatedAt = &past
	})
	testutil.CreateUser(t, func(u *models.User) { u.ReferredByUserID = &referrer.ID })

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/invite/reward-status", map[string]string{"token": token}, nil)
	var status struct {
		Eligible     bool `json:"eligible"`
		RewardActive bool `json:"reward_active"`
	}
	testutil.DecodeJSON(t, resp, &status)
	if !status.Eligible {
		t.Errorf("expected eligible even though the reward window already expired")
	}
	if status.RewardActive {
		t.Errorf("expected reward_active=false once the reward window has expired")
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

func TestApiSplashConf_NoNodesAvailable(t *testing.T) {
	app := apptest.New(t)
	// No active nodes exist in this fresh transaction, so both lookups should fail.
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/splash/conf", map[string]string{
		"client_key": testutil.UniqueName("ck-empty"),
	}, nil)
	if resp.StatusCode != fiberServiceUnavailable {
		t.Fatalf("expected 503 when no nodes are available, got %d", resp.StatusCode)
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
