package handlers_test

import (
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestUsersList_ShowsCreatedUser(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)

	resp := testutil.DoJSON(t, app, "GET", "/admin/users", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), u.Username) {
		t.Errorf("expected /admin/users to list %q", u.Username)
	}
}

func TestUserDetail_NotFound(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/users/999999999", nil, adminAuth(t))
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for an unknown user id, got %d", resp.StatusCode)
	}
}

func TestUserDetail_ShowsDevices(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	database.DB.Create(&models.MobileDevice{UserID: u.ID, DeviceID: "device-abc", FCMToken: "tok"})

	resp := testutil.DoJSON(t, app, "GET", "/admin/users/"+strconv.FormatUint(uint64(u.ID), 10), nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "device-abc") {
		t.Errorf("expected the user's device to be listed on their detail page")
	}
}

func TestUsersActive_Only24HourWindow(t *testing.T) {
	app := apptest.New(t)
	recent := time.Now().Add(-1 * time.Hour)
	old := time.Now().Add(-48 * time.Hour)
	recentUser := testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &recent })
	oldUser := testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &old })

	resp := testutil.DoJSON(t, app, "GET", "/admin/users/active", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if !strings.Contains(text, recentUser.Username) {
		t.Errorf("expected the recently-seen user to appear in /admin/users/active")
	}
	if strings.Contains(text, oldUser.Username) {
		t.Errorf("expected the 48h-old user NOT to appear in /admin/users/active")
	}
}

func TestUpdateUserFCM_UpdatesLatestDevice(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	database.DB.Create(&models.MobileDevice{UserID: u.ID, DeviceID: "device-1", FCMToken: "old-token"})

	resp := testutil.DoJSON(t, app, "POST", "/admin/users/"+strconv.FormatUint(uint64(u.ID), 10)+"/fcm",
		map[string]string{"token": "new-token"}, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var device models.MobileDevice
	database.DB.Where("user_id = ?", u.ID).First(&device)
	if device.FCMToken != "new-token" {
		t.Errorf("expected FCMToken to be updated to %q, got %q", "new-token", device.FCMToken)
	}
}

func TestUpdateUserFCM_NoDeviceNotFound(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	resp := testutil.DoJSON(t, app, "POST", "/admin/users/"+strconv.FormatUint(uint64(u.ID), 10)+"/fcm",
		map[string]string{"token": "x"}, adminAuth(t))
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 when the user has no mobile device, got %d", resp.StatusCode)
	}
}
