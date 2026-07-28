package handlers_test

import (
	"testing"

	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestHarnessSmoke(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/healthz", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from /healthz, got %d", resp.StatusCode)
	}
}
