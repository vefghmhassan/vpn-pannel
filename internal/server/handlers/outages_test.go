package handlers_test

import (
	"io"
	"strconv"
	"strings"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestOutagesList_ShowsReport(t *testing.T) {
	app := apptest.New(t)
	report := models.OutageReport{Title: testutil.UniqueName("outage-title"), Status: models.OutageOpen}
	database.DB.Create(&report)

	resp := testutil.DoJSON(t, app, "GET", "/admin/outages", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), report.Title) {
		t.Errorf("expected the outage report to be listed")
	}
}

func TestOutageSetStatus_Acknowledge(t *testing.T) {
	app := apptest.New(t)
	report := models.OutageReport{Title: "t", Status: models.OutageOpen}
	database.DB.Create(&report)

	resp := testutil.DoJSON(t, app, "GET", "/admin/outages/"+strconv.FormatUint(uint64(report.ID), 10)+"?s=ack", nil, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var reloaded models.OutageReport
	database.DB.First(&reloaded, report.ID)
	if reloaded.Status != models.OutageAcknowledged {
		t.Errorf("expected status ACK, got %q", reloaded.Status)
	}
}

func TestOutageSetStatus_Resolve(t *testing.T) {
	app := apptest.New(t)
	report := models.OutageReport{Title: "t", Status: models.OutageOpen}
	database.DB.Create(&report)

	resp := testutil.DoJSON(t, app, "GET", "/admin/outages/"+strconv.FormatUint(uint64(report.ID), 10)+"?s=resolve", nil, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var reloaded models.OutageReport
	database.DB.First(&reloaded, report.ID)
	if reloaded.Status != models.OutageResolved {
		t.Errorf("expected status RESOLVED, got %q", reloaded.Status)
	}
}
