package analytics

import (
	"testing"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
	"vpnpannel/internal/testutil"
)

// seedOpen inserts an app-open event at an explicit time. GORM would otherwise
// stamp CreatedAt itself, which is useless for testing anything about the past.
func seedOpen(t *testing.T, userID uint, at time.Time) {
	t.Helper()
	event := models.AppOpenEvent{UserID: userID, CreatedAt: at}
	if err := database.DB.Create(&event).Error; err != nil {
		t.Fatalf("failed to seed app-open event: %v", err)
	}
}

// seedUserAt creates a user whose registration timestamp is forced to `at`, so
// cohort and new-vs-returning logic has something other than "now" to work with.
func seedUserAt(t *testing.T, at time.Time) *models.User {
	t.Helper()
	u := testutil.CreateUser(t, nil)
	if err := database.DB.Model(u).UpdateColumn("created_at", at).Error; err != nil {
		t.Fatalf("failed to backdate user: %v", err)
	}
	u.CreatedAt = at
	return u
}

func TestDistinctActiveCountsUsersNotEvents(t *testing.T) {
	testutil.SetupDB(t)

	now := time.Now()
	from := services.DayStart(now)
	to := from.AddDate(0, 0, 1)

	// Measured as a delta: these tests run against the real development database,
	// which already has its own activity today. What matters is that four events
	// from two users move the count by two, not by four.
	before, err := DistinctActive(from, to)
	if err != nil {
		t.Fatalf("baseline DistinctActive: %v", err)
	}

	busy := seedUserAt(t, now)
	quiet := seedUserAt(t, now)
	seedOpen(t, busy.ID, from.Add(2*time.Hour))
	seedOpen(t, busy.ID, from.Add(5*time.Hour))
	seedOpen(t, busy.ID, from.Add(9*time.Hour))
	seedOpen(t, quiet.ID, from.Add(3*time.Hour))

	got, err := DistinctActive(from, to)
	if err != nil {
		t.Fatalf("DistinctActive: %v", err)
	}
	if got != before+2 {
		t.Fatalf("DistinctActive = %d, want %d (four events from two new users)", got, before+2)
	}
}

// TestDistinctActiveRangeIsHalfOpen pins the [from, to) convention every caller
// assumes. An inclusive upper bound would double-count the boundary day whenever
// two adjacent ranges are compared against each other.
func TestDistinctActiveRangeIsHalfOpen(t *testing.T) {
	testutil.SetupDB(t)

	start := services.DayStart(time.Now())
	end := start.AddDate(0, 0, 1)

	// Delta-measured, since the development database has its own activity today.
	before, err := DistinctActive(start, end)
	if err != nil {
		t.Fatalf("baseline DistinctActive: %v", err)
	}

	inside := seedUserAt(t, start)
	boundary := seedUserAt(t, start)
	seedOpen(t, inside.ID, start)                     // exactly `from` — included
	seedOpen(t, boundary.ID, end)                     // exactly `to`   — excluded
	seedOpen(t, boundary.ID, start.Add(-time.Second)) // just before — excluded

	got, err := DistinctActive(start, end)
	if err != nil {
		t.Fatalf("DistinctActive: %v", err)
	}
	if got != before+1 {
		t.Fatalf("DistinctActive = %d, want %d — only the event at exactly `from` counts, "+
			"the ones at `to` and just before it must not", got, before+1)
	}
}

// TestDailySeriesFillsEmptyDays: a day with no activity must appear as a zero
// rather than be missing, or the chart quietly closes the gap and shows a
// dead week as continuous usage.
func TestDailySeriesFillsEmptyDays(t *testing.T) {
	testutil.SetupDB(t)

	today := services.DayStart(time.Now())
	from := today.AddDate(0, 0, -4)
	to := today.AddDate(0, 0, 1)

	points, err := DailySeries(from, to)
	if err != nil {
		t.Fatalf("DailySeries: %v", err)
	}
	if len(points) != 5 {
		t.Fatalf("DailySeries returned %d points, want 5 (one per day of the range)", len(points))
	}
	for i, p := range points {
		want := from.AddDate(0, 0, i)
		if !services.DayStart(p.Day).Equal(want) {
			t.Fatalf("point %d is for %s, want %s", i, p.Day.Format("2006-01-02"), want.Format("2006-01-02"))
		}
	}
}

// TestDailySeriesTodayIsLive: today's bucket must reflect events written after
// the last rollup tick, since the rollup only runs hourly and an admin watching
// the dashboard expects today's number to move.
func TestDailySeriesTodayIsLive(t *testing.T) {
	testutil.SetupDB(t)

	today := services.DayStart(time.Now())
	user := seedUserAt(t, today)
	seedOpen(t, user.ID, time.Now())

	points, err := DailySeries(today, today.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("DailySeries: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("got %d points, want 1", len(points))
	}
	if points[0].ActiveUsers < 1 {
		t.Fatalf("today's ActiveUsers = %d, want at least 1 without waiting for a rollup tick",
			points[0].ActiveUsers)
	}
}

// TestNewVsReturningSplit: a user who registered today counts as new, one who
// registered earlier counts as returning, and the two must not overlap.
func TestNewVsReturningSplit(t *testing.T) {
	testutil.SetupDB(t)

	today := services.DayStart(time.Now())

	fresh := seedUserAt(t, today.Add(time.Hour))
	seedOpen(t, fresh.ID, today.Add(2*time.Hour))

	veteran := seedUserAt(t, today.AddDate(0, 0, -20))
	seedOpen(t, veteran.ID, today.Add(3*time.Hour))

	points, err := DailySeries(today, today.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("DailySeries: %v", err)
	}
	p := points[0]

	if p.NewUsers < 1 {
		t.Fatalf("NewUsers = %d, want at least 1", p.NewUsers)
	}
	if p.ReturningUsers < 1 {
		t.Fatalf("ReturningUsers = %d, want at least 1", p.ReturningUsers)
	}
	if p.ReturningUsers > p.ActiveUsers {
		t.Fatalf("ReturningUsers (%d) exceeds ActiveUsers (%d)", p.ReturningUsers, p.ActiveUsers)
	}
}

// TestReturningNeverNegative: a user can register without ever opening the app,
// so returning must be derived from active users rather than as
// active-minus-new, which would go negative on a day of pure signups.
func TestReturningNeverNegative(t *testing.T) {
	testutil.SetupDB(t)

	today := services.DayStart(time.Now())
	for i := 0; i < 3; i++ {
		seedUserAt(t, today.Add(time.Duration(i)*time.Hour))
	}

	points, err := DailySeries(today, today.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("DailySeries: %v", err)
	}
	if points[0].ReturningUsers < 0 {
		t.Fatalf("ReturningUsers = %d on a signup-only day, want >= 0", points[0].ReturningUsers)
	}
}

func TestSummaryStickiness(t *testing.T) {
	testutil.SetupDB(t)

	now := time.Now()
	user := seedUserAt(t, now.AddDate(0, 0, -40))
	seedOpen(t, user.ID, now.Add(-time.Hour))

	s, err := Summary(services.DayStart(now), services.DayStart(now).AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if s.DAU < 1 || s.MAU < 1 {
		t.Fatalf("DAU=%d MAU=%d, want both >= 1", s.DAU, s.MAU)
	}
	if s.Stickiness <= 0 || s.Stickiness > 100 {
		t.Fatalf("Stickiness = %f, want a percentage in (0, 100]", s.Stickiness)
	}
}

// TestSummaryAnchorsToRangeEnd: asking about a past window must report that
// window's DAU, not today's, or comparing a period against the one before it
// would compare two identical numbers.
func TestSummaryAnchorsToRangeEnd(t *testing.T) {
	testutil.SetupDB(t)

	today := services.DayStart(time.Now())
	past := today.AddDate(0, 0, -10)

	user := seedUserAt(t, past.AddDate(0, 0, -5))
	seedOpen(t, user.ID, past.Add(6*time.Hour))

	s, err := Summary(past, past.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if s.DAU < 1 {
		t.Fatalf("DAU for a past day = %d, want the activity from that day, not from today", s.DAU)
	}
}

func TestHourlyHeatmapBuckets(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now())
	user := seedUserAt(t, day)
	at := day.Add(14 * time.Hour)
	seedOpen(t, user.ID, at)
	seedOpen(t, user.ID, at)

	grid, err := HourlyHeatmap(day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("HourlyHeatmap: %v", err)
	}
	dow := int(at.Weekday())
	if grid.Cells[dow][14] < 2 {
		t.Fatalf("cell [%d][14] = %d, want at least the 2 seeded events", dow, grid.Cells[dow][14])
	}
	if grid.Max < grid.Cells[dow][14] {
		t.Fatalf("Max (%d) is below a cell it should bound (%d)", grid.Max, grid.Cells[dow][14])
	}
}

func TestCohortsRetentionShape(t *testing.T) {
	testutil.SetupDB(t)

	now := time.Now()
	user := seedUserAt(t, now.AddDate(0, 0, -14))
	seedOpen(t, user.ID, now.AddDate(0, 0, -14))
	seedOpen(t, user.ID, now.AddDate(0, 0, -6)) // a later week

	rows, err := Cohorts(8)
	if err != nil {
		t.Fatalf("Cohorts: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("Cohorts returned no rows despite seeded signups")
	}
	for _, row := range rows {
		if len(row.Percent) != len(CohortOffsets) {
			t.Fatalf("cohort %s has %d percentages, want %d",
				row.WeekStart.Format("2006-01-02"), len(row.Percent), len(CohortOffsets))
		}
		for i, pct := range row.Percent {
			if pct < 0 || pct > 100 {
				t.Fatalf("cohort %s offset %d retention = %f, want a percentage",
					row.WeekStart.Format("2006-01-02"), CohortOffsets[i], pct)
			}
		}
	}
}

// TestAtRiskExcludesNeverSeen: users with no last_seen_at at all are a signup
// problem, not churn, and would otherwise swamp the list.
func TestAtRiskExcludesNeverSeen(t *testing.T) {
	testutil.SetupDB(t)

	never := testutil.CreateUser(t, nil)

	longAgo := time.Now().AddDate(0, 0, -30)
	gone := testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &longAgo })

	users, err := AtRiskUsers(7, 100)
	if err != nil {
		t.Fatalf("AtRiskUsers: %v", err)
	}

	var sawGone bool
	for _, u := range users {
		if u.User.ID == never.ID {
			t.Fatal("a never-seen user was reported as at risk")
		}
		if u.User.ID == gone.ID {
			sawGone = true
			if u.InactiveDays < 28 {
				t.Fatalf("InactiveDays = %d, want ~30", u.InactiveDays)
			}
		}
	}
	if !sawGone {
		t.Fatal("a user last seen 30 days ago was not reported as at risk")
	}
}

// TestOnlineSeriesDownsamples is the whole point of the granularity parameter:
// a month of 5-minute snapshots must come back as a day per bucket, not as
// thousands of raw rows.
func TestOnlineSeriesDownsamples(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now()).AddDate(0, 0, -1)
	for i := 0; i < 24; i++ {
		snap := models.OnlineSnapshot{Count: int64(i), CreatedAt: day.Add(time.Duration(i) * time.Hour)}
		if err := database.DB.Create(&snap).Error; err != nil {
			t.Fatalf("failed to seed snapshot: %v", err)
		}
	}

	points, err := OnlineSeries(day, day.AddDate(0, 0, 1), "day")
	if err != nil {
		t.Fatalf("OnlineSeries: %v", err)
	}
	// The property under test is the collapse: many snapshots in, one bucket out.
	if len(points) != 1 {
		t.Fatalf("24 hourly snapshots bucketed by day gave %d points, want 1", len(points))
	}
	// Bounds rather than exact values: these tests run against the real
	// development database, which may already hold snapshots for this day, so the
	// bucket can legitimately peak above the highest count seeded here.
	if points[0].Max < 23 {
		t.Fatalf("bucket Max = %d, want at least the highest seeded count (23)", points[0].Max)
	}
	if points[0].Avg <= 0 || points[0].Avg > float64(points[0].Max) {
		t.Fatalf("bucket Avg = %f, want a positive mean no greater than the max (%d)",
			points[0].Avg, points[0].Max)
	}
}

// TestOnlineSeriesRejectsUnknownGranularity: the granularity string is spliced
// into SQL, so anything not in the allow-list must fall back rather than reach
// the database.
func TestOnlineSeriesRejectsUnknownGranularity(t *testing.T) {
	testutil.SetupDB(t)

	day := services.DayStart(time.Now())
	if _, err := OnlineSeries(day, day.AddDate(0, 0, 1), "day'); DROP TABLE users; --"); err != nil {
		t.Fatalf("unknown granularity should fall back to a safe default, got: %v", err)
	}
}
