package config

import (
	"testing"
	"time"
)

// Load must pin the process timezone. Without this the dev compose service
// (TZ=Asia/Tehran) and the distroless production image (no TZ, so UTC) report
// different UTC offsets for the same instant.
func TestLoad_AppliesTimezoneToTimeLocal(t *testing.T) {
	original := time.Local
	t.Cleanup(func() { time.Local = original })

	t.Setenv("TZ", "Asia/Tehran")
	if err := Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if Current.Timezone != "Asia/Tehran" {
		t.Errorf("expected Timezone=Asia/Tehran, got %q", Current.Timezone)
	}
	if Current.Location == nil || Current.Location.String() != "Asia/Tehran" {
		t.Fatalf("expected Location=Asia/Tehran, got %v", Current.Location)
	}
	if time.Local.String() != "Asia/Tehran" {
		t.Errorf("expected time.Local to be pinned to Asia/Tehran, got %q", time.Local.String())
	}
	// Tehran has been at a fixed +03:30 since it dropped DST in 2022.
	if _, offset := time.Now().Zone(); offset != 12600 {
		t.Errorf("expected a +03:30 (12600s) offset, got %ds", offset)
	}
}

// The zone database must be resolvable without a system zoneinfo directory —
// the production image is distroless and the build is CGO_ENABLED=0. This passes
// only because config.go blank-imports time/tzdata.
func TestLoad_ResolvesZonesWithoutSystemTzdata(t *testing.T) {
	original := time.Local
	t.Cleanup(func() { time.Local = original })

	for _, zone := range []string{"UTC", "Asia/Tehran", "America/New_York"} {
		t.Setenv("TZ", zone)
		if err := Load(); err != nil {
			t.Fatalf("Load(%s) failed: %v", zone, err)
		}
		if time.Local.String() != zone {
			t.Errorf("expected time.Local=%q, got %q", zone, time.Local.String())
		}
	}
}

func TestLoad_RejectsInvalidTimezone(t *testing.T) {
	original := time.Local
	t.Cleanup(func() { time.Local = original })

	t.Setenv("TZ", "Not/ARealZone")
	if err := Load(); err == nil {
		t.Fatalf("expected Load to fail on an unknown timezone")
	}
	if time.Local != original {
		t.Errorf("expected time.Local to be left alone when the timezone is invalid")
	}
}
