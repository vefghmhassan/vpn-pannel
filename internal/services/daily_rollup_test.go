// External test package: testutil imports internal/services (for token minting),
// so an in-package test here would close an import cycle.
package services_test

import (
	"testing"
	"time"

	"gorm.io/gorm/clause"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
	"vpnpannel/internal/testutil"
)

func seedOpen(t *testing.T, userID uint, at time.Time) {
	t.Helper()
	if err := database.DB.Create(&models.AppOpenEvent{UserID: userID, CreatedAt: at}).Error; err != nil {
		t.Fatalf("failed to seed app-open event: %v", err)
	}
}

func loadStat(t *testing.T, day time.Time) models.DailyStat {
	t.Helper()
	var stat models.DailyStat
	if err := database.DB.Where("day = ?", services.DayStart(day)).First(&stat).Error; err != nil {
		t.Fatalf("no rollup row for %s: %v", day.Format("2006-01-02"), err)
	}
	return stat
}

func TestRecomputeDayAggregates(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now())
	user := testutil.CreateUser(t, nil)
	seedOpen(t, user.ID, day.Add(2*time.Hour))
	seedOpen(t, user.ID, day.Add(5*time.Hour))

	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("RecomputeDay: %v", err)
	}

	stat := loadStat(t, day)
	if stat.ActiveUsers < 1 {
		t.Fatalf("ActiveUsers = %d, want at least 1", stat.ActiveUsers)
	}
	if stat.TotalOpens < 2 {
		t.Fatalf("TotalOpens = %d, want at least the 2 seeded events", stat.TotalOpens)
	}
}

// TestRecomputeDayIsIdempotent is the property the hourly ticker depends on: it
// re-runs the same days on every tick, so a second pass must overwrite rather
// than accumulate.
func TestRecomputeDayIsIdempotent(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now())
	user := testutil.CreateUser(t, nil)
	seedOpen(t, user.ID, day.Add(time.Hour))

	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("first RecomputeDay: %v", err)
	}
	first := loadStat(t, day)

	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("second RecomputeDay: %v", err)
	}
	second := loadStat(t, day)

	if first.TotalOpens != second.TotalOpens || first.ActiveUsers != second.ActiveUsers {
		t.Fatalf("recompute changed the result: %+v then %+v", first, second)
	}

	var count int64
	database.DB.Model(&models.DailyStat{}).Where("day = ?", day).Count(&count)
	if count != 1 {
		t.Fatalf("%d rows for one day, want exactly 1 (the upsert should replace, not insert)", count)
	}
}

// TestRecomputeDayPicksUpLateEvents: an event written after the day was first
// rolled up must be reflected on the next pass, which is why the ticker redoes
// yesterday rather than only today.
func TestRecomputeDayPicksUpLateEvents(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now())
	user := testutil.CreateUser(t, nil)
	seedOpen(t, user.ID, day.Add(time.Hour))

	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("RecomputeDay: %v", err)
	}
	before := loadStat(t, day).TotalOpens

	seedOpen(t, user.ID, day.Add(2*time.Hour))
	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("RecomputeDay after late event: %v", err)
	}

	if after := loadStat(t, day).TotalOpens; after != before+1 {
		t.Fatalf("TotalOpens = %d after a late event, want %d", after, before+1)
	}
}

// TestRecomputeDayRespectsDayBoundaries: events on either side of midnight must
// not leak into the day being computed.
func TestRecomputeDayRespectsDayBoundaries(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now()).AddDate(0, 0, -3)
	user := testutil.CreateUser(t, nil)

	// Measured as a delta rather than an absolute count: these tests run against
	// the real development database, which may already hold events on this day.
	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("baseline RecomputeDay: %v", err)
	}
	before := loadStat(t, day).TotalOpens

	seedOpen(t, user.ID, day)                                  // first instant of the day
	seedOpen(t, user.ID, day.Add(-time.Second))                // previous day
	seedOpen(t, user.ID, day.AddDate(0, 0, 1))                 // next day, exactly midnight
	seedOpen(t, user.ID, day.Add(23*time.Hour+59*time.Minute)) // last minute

	if err := services.RecomputeDay(day); err != nil {
		t.Fatalf("RecomputeDay: %v", err)
	}
	if got := loadStat(t, day).TotalOpens; got != before+2 {
		t.Fatalf("TotalOpens = %d, want %d (only the two events inside the day)", got, before+2)
	}
}

func TestBackfillIsSafeOnEmptyDatabase(t *testing.T) {
	testutil.SetupDB(t)

	// The seeded admin user exists in every database, so this exercises the
	// "users but no events" path rather than a truly empty one.
	if err := services.BackfillDailyStats(); err != nil {
		t.Fatalf("BackfillDailyStats: %v", err)
	}
}

// TestBackfillLeavesExistingRowsAlone: the backfill runs on every boot, so it
// must only fill gaps — recomputing settled days on each restart would be
// needless work on a large database.
func TestBackfillLeavesExistingRowsAlone(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now()).AddDate(0, 0, -2)
	// Upsert rather than insert: a running server will already have backfilled
	// this day, and the test is about the value surviving, not about the row
	// being new.
	sentinel := models.DailyStat{Day: day, TotalOpens: 999, ActiveUsers: 7, UpdatedAt: time.Now()}
	if err := database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "day"}},
		UpdateAll: true,
	}).Create(&sentinel).Error; err != nil {
		t.Fatalf("failed to seed sentinel row: %v", err)
	}

	if err := services.BackfillDailyStats(); err != nil {
		t.Fatalf("BackfillDailyStats: %v", err)
	}

	if got := loadStat(t, day); got.TotalOpens != 999 {
		t.Fatalf("backfill overwrote an existing row: TotalOpens = %d, want 999", got.TotalOpens)
	}
}

func TestDayStartTruncatesToMidnight(t *testing.T) {
	at := time.Date(2026, 9, 6, 17, 42, 13, 500, time.Local)
	got := services.DayStart(at)
	if got.Hour() != 0 || got.Minute() != 0 || got.Second() != 0 || got.Nanosecond() != 0 {
		t.Fatalf("services.DayStart(%s) = %s, want local midnight", at, got)
	}
	if got.Year() != 2026 || got.Month() != time.September || got.Day() != 6 {
		t.Fatalf("DayStart moved the date: %s", got)
	}
}
