package handlers_test

import (
	"net/url"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestSettingsPage_Renders(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/settings", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSettingsUpdate_ChecksboxFalseWhenAbsent(t *testing.T) {
	// Regression test for the gorm zero-value bug applied to the settings-update
	// checkbox pattern: unchecking a toggle (omitting the form field entirely)
	// must actually persist false, not silently keep true.
	app := apptest.New(t)
	var s models.AppSettings
	database.DB.First(&s, 1)
	s.WheelEnabled = true
	s.UpdateEnable = true
	database.DB.Save(&s)

	resp := testutil.DoForm(t, app, "POST", "/admin/settings", url.Values{
		"current_version": {"9.9.9"},
		// wheel_enabled / update_enable intentionally omitted == unchecked
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}

	var reloaded models.AppSettings
	database.DB.First(&reloaded, 1)
	if reloaded.WheelEnabled {
		t.Errorf("expected WheelEnabled to be false after submitting the form without the checkbox")
	}
	if reloaded.UpdateEnable {
		t.Errorf("expected UpdateEnable to be false after submitting the form without the checkbox")
	}
	if reloaded.CurrentVersion != "9.9.9" {
		t.Errorf("expected CurrentVersion to be updated, got %q", reloaded.CurrentVersion)
	}
}

func TestSettingsUpdate_RewardPercentClamped(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/settings", url.Values{
		"reward_display_percent": {"250"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var s models.AppSettings
	database.DB.First(&s, 1)
	if s.RewardDisplayPercent != 100 {
		t.Errorf("expected reward_display_percent to clamp to 100, got %d", s.RewardDisplayPercent)
	}
}

func TestSettingsUpdate_SplashConfCountMinimumTwo(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/settings", url.Values{
		"splash_conf_count": {"1"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var s models.AppSettings
	database.DB.First(&s, 1)
	if s.SplashConfCount != 2 {
		t.Errorf("expected splash_conf_count to clamp up to 2, got %d", s.SplashConfCount)
	}
}

func TestSettingsDelete_RemovesSingletonRow(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "POST", "/admin/settings/delete", nil, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).Count(&count)
	if count != 0 {
		t.Errorf("expected the settings row to be deleted")
	}
}
