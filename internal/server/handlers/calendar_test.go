package handlers_test

import (
	"net/http"
	"testing"

	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestSetCalendar_SetsCookieAndRedirectsToNext(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/set-calendar?system=jalali&next=/admin/stats", nil, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/admin/stats" {
		t.Errorf("expected redirect to /admin/stats, got %q", loc)
	}
	var found string
	for _, c := range resp.Cookies() {
		if c.Name == "calendar_system" {
			found = c.Value
		}
	}
	if found != "jalali" {
		t.Errorf("expected calendar_system cookie to be jalali, got %q", found)
	}
}

func TestSetCalendar_InvalidSystemDefaultsToGregorian(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/set-calendar?system=bogus", nil, adminAuth(t))
	var found string
	for _, c := range resp.Cookies() {
		if c.Name == "calendar_system" {
			found = c.Value
		}
	}
	if found != "gregorian" {
		t.Errorf("expected an invalid system value to fall back to gregorian, got %q", found)
	}
}

func TestSetCalendar_FallsBackToRefererThenAdmin(t *testing.T) {
	app := apptest.New(t)

	// no next, no Referer -> falls back to /admin
	resp := testutil.DoJSON(t, app, "GET", "/admin/set-calendar?system=hijri", nil, adminAuth(t))
	if loc := resp.Header.Get("Location"); loc != "/admin" {
		t.Errorf("expected fallback redirect to /admin, got %q", loc)
	}

	// Referer present, no next -> uses Referer
	resp2 := testutil.DoJSON(t, app, "GET", "/admin/set-calendar?system=hijri", nil, func(r *http.Request) {
		adminAuth(t)(r)
		r.Header.Set("Referer", "/admin/tracker")
	})
	if loc := resp2.Header.Get("Location"); loc != "/admin/tracker" {
		t.Errorf("expected redirect to the Referer, got %q", loc)
	}
}
