package handlers_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// parseDateRange is unexported, so its behavior is exercised end-to-end through
// /admin/metrics/online-history, which calls it directly.

func TestParseDateRange_DefaultsToLast30Days(t *testing.T) {
	app := apptest.New(t)
	tooOld := time.Now().AddDate(0, 0, -31)
	recent := time.Now().AddDate(0, 0, -5)
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: tooOld, Count: 111})
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: recent, Count: 222})

	resp := testutil.DoJSON(t, app, "GET", "/admin/metrics/online-history", nil, adminAuth(t))
	var out struct {
		Points []struct {
			Count int64 `json:"count"`
		} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &out)
	var sawRecent, sawTooOld bool
	for _, p := range out.Points {
		if p.Count == 222 {
			sawRecent = true
		}
		if p.Count == 111 {
			sawTooOld = true
		}
	}
	if !sawRecent {
		t.Errorf("expected the 5-days-ago snapshot to be within the default 30-day window")
	}
	if sawTooOld {
		t.Errorf("expected the 31-days-ago snapshot to fall outside the default 30-day window")
	}
}

func TestParseDateRange_ExplicitJalaliParams(t *testing.T) {
	app := apptest.New(t)

	// 1403-01-01 (Jalali) is 2024-03-20 (Gregorian); pick a snapshot squarely
	// inside that single day and others a full day before/after it (wide
	// margins so the server's local UTC offset — e.g. Asia/Tehran's +03:30 —
	// can't shift a boundary snapshot across the line and produce a flaky test).
	inside := time.Date(2024, 3, 20, 12, 0, 0, 0, time.UTC)
	before := time.Date(2024, 3, 18, 12, 0, 0, 0, time.UTC)
	after := time.Date(2024, 3, 22, 12, 0, 0, 0, time.UTC)
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: inside, Count: 1})
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: before, Count: 2})
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: after, Count: 3})

	path := "/admin/metrics/online-history?from_y=1403&from_m=1&from_d=1&to_y=1403&to_m=1&to_d=1"
	resp := testutil.DoJSON(t, app, "GET", path, nil, func(r *http.Request) {
		adminAuth(t)(r)
		r.AddCookie(&http.Cookie{Name: "calendar_system", Value: "jalali"})
	})
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Points []struct {
			Count int64 `json:"count"`
		} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &out)
	counts := map[int64]bool{}
	for _, p := range out.Points {
		counts[p.Count] = true
	}
	if !counts[1] {
		t.Errorf("expected the snapshot inside 1403-01-01 to be included")
	}
	if counts[2] || counts[3] {
		t.Errorf("expected snapshots outside 1403-01-01 to be excluded, got points=%+v", out.Points)
	}
}

func TestParseDateRange_InvertedRangeReturnsEmpty(t *testing.T) {
	app := apptest.New(t)
	now := time.Now()
	database.DB.Create(&models.OnlineSnapshot{CreatedAt: now, Count: 42})

	// "from" after "to" — an inverted/empty window.
	path := fmt.Sprintf("/admin/metrics/online-history?from_y=%d&from_m=%d&from_d=%d&to_y=%d&to_m=%d&to_d=%d",
		now.Year(), int(now.Month()), now.Day(), now.Year()-1, 1, 1)
	resp := testutil.DoJSON(t, app, "GET", path, nil, adminAuth(t))
	var out struct {
		Points []interface{} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if len(out.Points) != 0 {
		t.Errorf("expected an inverted range to return no points, got %d", len(out.Points))
	}
}
