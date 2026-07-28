package handlers_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// adminAuth returns a request-mutator that attaches a valid SUPER_ADMIN bearer token.
func adminAuth(t *testing.T) func(r *http.Request) {
	t.Helper()
	admin := testutil.CreateUser(t, func(u *models.User) { u.Role = models.RoleSuperAdmin })
	token := testutil.AdminToken(t, admin.ID, models.RoleSuperAdmin)
	return bearer(token)
}

func TestActiveUsersCount_WindowMath(t *testing.T) {
	app := apptest.New(t)
	recentTime := time.Now().Add(-1 * time.Hour)
	oldTime := time.Now().Add(-48 * time.Hour)
	testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &recentTime })
	testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &oldTime })

	resp := testutil.DoJSON(t, app, "GET", "/admin/metrics/active-users?hours=24", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Count int64 `json:"count"`
		Hours int   `json:"hours"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.Hours != 24 {
		t.Errorf("expected hours=24, got %d", out.Hours)
	}
	if out.Count < 1 {
		t.Errorf("expected at least the recently-seen user to be counted, got count=%d", out.Count)
	}
}

func TestActiveUsersCount_InvalidHoursFallsBackTo24(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/metrics/active-users?hours=not-a-number", nil, adminAuth(t))
	var out struct {
		Hours int `json:"hours"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.Hours != 24 {
		t.Errorf("expected fallback to 24 hours for invalid input, got %d", out.Hours)
	}
}

func TestOnlineUsersStats_Buckets(t *testing.T) {
	app := apptest.New(t)
	justNow := time.Now().Add(-1 * time.Minute)
	testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &justNow })

	resp := testutil.DoJSON(t, app, "GET", "/admin/metrics/online-stats", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		M5  int64 `json:"m5"`
		M30 int64 `json:"m30"`
		H24 int64 `json:"h24"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.M5 < 1 || out.M30 < 1 || out.H24 < 1 {
		t.Errorf("expected a user seen 1 minute ago to count in all three buckets, got %+v", out)
	}
}

func TestOnlineHistory_FiltersByRange(t *testing.T) {
	app := apptest.New(t)
	inRange := time.Now().Add(-2 * 24 * time.Hour)
	outOfRange := time.Now().Add(-40 * 24 * time.Hour)
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: inRange, Count: 3})
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: outOfRange, Count: 99})

	now := time.Now()
	path := fmt.Sprintf("/admin/metrics/online-history?from_y=%d&from_m=%d&from_d=%d&to_y=%d&to_m=%d&to_d=%d",
		now.Year(), int(now.Month()), 1, now.Year(), int(now.Month()), now.Day())
	resp := testutil.DoJSON(t, app, "GET", path, nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Points []struct {
			Count int64 `json:"count"`
		} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &out)
	for _, p := range out.Points {
		if p.Count == 99 {
			t.Errorf("expected the out-of-range snapshot (count=99) to be excluded, got points=%+v", out.Points)
		}
	}
}

func TestTrackerPage_RequiresAuth(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/tracker", nil, nil)
	// AuthRequired redirects to /login when no token is present.
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect to /login without auth, got %d", resp.StatusCode)
	}
}

func TestTrackerPage_ShowsOpenCounts(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, nil)
	now := time.Now()
	database.DB.Create(&models.AppOpenEvent{UserID: u.ID, CreatedAt: now})
	database.DB.Create(&models.AppOpenEvent{UserID: u.ID, CreatedAt: now})

	resp := testutil.DoJSON(t, app, "GET", "/admin/tracker", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), u.Username) {
		t.Errorf("expected the tracker page to list user %q", u.Username)
	}
}
