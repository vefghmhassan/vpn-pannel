package handlers_test

import (
	"net/url"
	"strings"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestApiWheel_RespectsDisabledSetting(t *testing.T) {
	// Regression test for the gorm:"default:true" zero-value bug on
	// AppSettings.WheelEnabled: explicitly disabling the wheel must actually
	// persist and be reflected by the API.
	app := apptest.New(t)
	var settings models.AppSettings
	database.DB.First(&settings, 1)
	settings.WheelEnabled = false
	if err := database.DB.Save(&settings).Error; err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	var reloaded models.AppSettings
	database.DB.First(&reloaded, 1)
	if reloaded.WheelEnabled {
		t.Fatalf("expected WheelEnabled=false to persist in the DB")
	}

	resp := testutil.DoJSON(t, app, "GET", "/api/v1/wheel", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		Enabled bool `json:"enabled"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.Enabled {
		t.Errorf("expected the API to report the wheel as disabled")
	}
}

func TestApiWheel_OnlyActiveSegmentsAndWeightMath(t *testing.T) {
	app := apptest.New(t)
	database.DB.Create(&models.WheelSegment{Position: 0, DisplayType: "text", Label: "A", RewardType: "none", Weight: 30, IsActive: true})
	database.DB.Create(&models.WheelSegment{Position: 1, DisplayType: "text", Label: "B", RewardType: "none", Weight: 70, IsActive: true})
	inactive := models.WheelSegment{Position: 2, DisplayType: "text", Label: "C", RewardType: "none", Weight: 1000, IsActive: true}
	database.DB.Create(&inactive)
	inactive.IsActive = false
	database.DB.Save(&inactive)

	resp := testutil.DoJSON(t, app, "GET", "/api/v1/wheel", nil, nil)
	var out struct {
		Segments []struct {
			Label   string  `json:"label"`
			Percent float64 `json:"percent"`
		} `json:"segments"`
		TotalWeight int `json:"total_weight"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if out.TotalWeight != 100 {
		t.Fatalf("expected total_weight=100 (30+70, excluding the inactive segment), got %d", out.TotalWeight)
	}
	for _, s := range out.Segments {
		if s.Label == "C" {
			t.Errorf("expected the inactive segment to be excluded")
		}
		if s.Label == "A" && s.Percent != 30 {
			t.Errorf("expected segment A to be 30%%, got %v", s.Percent)
		}
	}
}

func TestWheelUpdate_ReplacesAllSegments(t *testing.T) {
	app := apptest.New(t)
	database.DB.Create(&models.WheelSegment{Position: 0, DisplayType: "text", Label: "old", RewardType: "none", Weight: 1, IsActive: true})

	payload := `[
		{"displayType":"text","label":"new-a","rewardType":"time","rewardValue":10,"weight":5,"isActive":true},
		{"displayType":"bogus","label":"new-b","rewardType":"bogus","rewardValue":-5,"weight":-3,"isActive":false}
	]`
	resp := testutil.DoForm(t, app, "POST", "/admin/wheel", url.Values{"segments_json": {payload}}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}

	var segments []models.WheelSegment
	database.DB.Order("position asc").Find(&segments)
	if len(segments) != 2 {
		t.Fatalf("expected exactly 2 segments after replace-all, got %d", len(segments))
	}
	if segments[0].Label != "new-a" || segments[1].Label != "new-b" {
		t.Fatalf("expected the old segment to be replaced, got %+v", segments)
	}
	// invalid displayType/rewardType normalize, negative values clamp to 0
	if segments[1].DisplayType != "text" {
		t.Errorf("expected an invalid displayType to normalize to 'text', got %q", segments[1].DisplayType)
	}
	if segments[1].RewardType != "none" {
		t.Errorf("expected an invalid rewardType to normalize to 'none', got %q", segments[1].RewardType)
	}
	if segments[1].RewardValue != 0 || segments[1].Weight != 0 {
		t.Errorf("expected negative rewardValue/weight to clamp to 0, got %+v", segments[1])
	}
	// IsActive=false must persist correctly (already fixed via the no-default-tag convention).
	if segments[1].IsActive {
		t.Errorf("expected the second segment's IsActive=false to persist")
	}
}

func TestWheelUpdate_TooManySegmentsRejected(t *testing.T) {
	app := apptest.New(t)
	segments := make([]string, 0, 51)
	for i := 0; i < 51; i++ {
		segments = append(segments, `{"displayType":"text","label":"x","rewardType":"none","weight":1,"isActive":true}`)
	}
	payload := "[" + strings.Join(segments, ",") + "]"

	resp := testutil.DoForm(t, app, "POST", "/admin/wheel", url.Values{"segments_json": {payload}}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for more than 50 segments, got %d", resp.StatusCode)
	}
}

func TestWheelUpdate_InvalidJSONRejected(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/wheel", url.Values{"segments_json": {"not json"}}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}
