package handlers_test

import (
	"net/url"
	"testing"

	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestNotifyPage_Renders(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/notify", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestNotifySend_SucceedsWithNoDevices(t *testing.T) {
	// FCM_SERVER_KEY is empty in this test environment, so SendPushToTokens
	// short-circuits without making any real network call — safe to exercise
	// the full handler here.
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/notify", url.Values{
		"title": {"hello"}, "body": {"world"},
	}, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPushPage_Renders(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/push", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
