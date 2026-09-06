package handlers_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// adminGet performs an authenticated admin GET, which every /admin/metrics
// endpoint requires — without the token the middleware redirects to /login and
// the handler never runs.
func adminGet(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	admin := testutil.CreateUser(t, func(u *models.User) { u.Role = models.RoleSuperAdmin })
	token := testutil.AdminToken(t, admin.ID, models.RoleSuperAdmin)
	return testutil.DoJSON(t, app, http.MethodGet, path, nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	})
}

func TestSummaryEndpointShape(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/metrics/summary?preset=30d")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body struct {
		Compare bool `json:"compare"`
		Current struct {
			DAU        int64   `json:"dau"`
			WAU        int64   `json:"wau"`
			MAU        int64   `json:"mau"`
			Stickiness float64 `json:"stickiness"`
			NewUsers   int64   `json:"new_users"`
			TotalOpens int64   `json:"total_opens"`
		} `json:"current"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if body.Compare {
		t.Fatal("compare should be off unless requested")
	}
	if body.Current.DAU < 0 || body.Current.MAU < 0 {
		t.Fatalf("negative counts in summary: %+v", body.Current)
	}
}

// TestSummaryCompareIncludesDeltas: with compare=1 the response must carry both
// the previous period and the percentage change, since that is what the KPI
// tiles render.
func TestSummaryCompareIncludesDeltas(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/metrics/summary?preset=7d&compare=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]interface{}
	testutil.DecodeJSON(t, resp, &body)

	if body["compare"] != true {
		t.Fatal("compare flag not echoed back")
	}
	if _, ok := body["previous"]; !ok {
		t.Fatal("compare=1 did not return the previous period")
	}
	if _, ok := body["delta"]; !ok {
		t.Fatal("compare=1 did not return deltas")
	}
}

// TestDailyEndpointHonoursPreset: "today" must produce exactly one bucket, which
// is the cheapest proof that presets are resolved server-side rather than
// ignored in favour of the default 30-day window.
func TestDailyEndpointHonoursPreset(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/metrics/daily?preset=today")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body struct {
		Granularity string `json:"granularity"`
		Points      []struct {
			Label     string `json:"label"`
			Active    int64  `json:"active"`
			New       int64  `json:"new"`
			Returning int64  `json:"returning"`
			Opens     int64  `json:"opens"`
		} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if len(body.Points) != 1 {
		t.Fatalf("preset=today gave %d points, want 1", len(body.Points))
	}
	if body.Points[0].Label == "" {
		t.Fatal("points must carry a server-rendered label for the chart axis")
	}
}

// TestDailyGranularityBuckets: a long range asked for weekly buckets must return
// far fewer points than it has days.
func TestDailyGranularityBuckets(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/metrics/daily?preset=30d&granularity=week")
	var body struct {
		Granularity string        `json:"granularity"`
		Points      []interface{} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if body.Granularity != "week" {
		t.Fatalf("granularity = %q, want week", body.Granularity)
	}
	if len(body.Points) > 6 {
		t.Fatalf("30 days in weekly buckets gave %d points, want at most 6", len(body.Points))
	}
}

// TestOnlineHistoryIsDownsampled is the fix for the original complaint: a month
// of 5-minute snapshots used to come back as thousands of points.
func TestOnlineHistoryIsDownsampled(t *testing.T) {
	app := apptest.New(t)

	// One snapshot every 5 minutes for a day, as the real snapshotter writes them.
	day := time.Now().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	for i := 0; i < 288; i++ {
		snap := models.OnlineSnapshot{Count: int64(i % 20), CreatedAt: day.Add(time.Duration(i*5) * time.Minute)}
		if err := database.DB.Create(&snap).Error; err != nil {
			t.Fatalf("failed to seed snapshot: %v", err)
		}
	}

	resp := adminGet(t, app, "/admin/metrics/online-history?preset=30d&granularity=day")
	var body struct {
		Granularity string `json:"granularity"`
		Points      []struct {
			Label string  `json:"label"`
			Max   int64   `json:"max"`
			Count int64   `json:"count"`
			Avg   float64 `json:"avg"`
		} `json:"points"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if len(body.Points) > 31 {
		t.Fatalf("30 days of 5-minute snapshots gave %d points, want at most 31", len(body.Points))
	}
	for _, p := range body.Points {
		// "count" is the backwards-compatible alias for the bucket peak.
		if p.Count != p.Max {
			t.Fatalf("count (%d) and max (%d) disagree", p.Count, p.Max)
		}
	}
}

func TestHeatmapEndpointShape(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/metrics/heatmap?preset=30d")
	var body struct {
		Cells           [][]int64 `json:"cells"`
		Weekdays        []string  `json:"weekdays"`
		WeekStartOffset int       `json:"week_start_offset"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if len(body.Cells) != 7 {
		t.Fatalf("heatmap has %d weekday rows, want 7", len(body.Cells))
	}
	for i, row := range body.Cells {
		if len(row) != 24 {
			t.Fatalf("weekday %d has %d hours, want 24", i, len(row))
		}
	}
	if len(body.Weekdays) != 7 {
		t.Fatalf("got %d weekday labels, want 7", len(body.Weekdays))
	}
}

func TestCohortsEndpointShape(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/metrics/cohorts?weeks=4")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body struct {
		Offsets []int `json:"offsets"`
		Rows    []struct {
			Week    string    `json:"week"`
			Size    int64     `json:"size"`
			Percent []float64 `json:"percent"`
		} `json:"rows"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if len(body.Offsets) == 0 {
		t.Fatal("cohorts response carries no week offsets")
	}
	for _, row := range body.Rows {
		if len(row.Percent) != len(body.Offsets) {
			t.Fatalf("cohort %s has %d percentages for %d offsets", row.Week, len(row.Percent), len(body.Offsets))
		}
	}
}

func TestAtRiskEndpoint(t *testing.T) {
	app := apptest.New(t)

	longAgo := time.Now().AddDate(0, 0, -20)
	testutil.CreateUser(t, func(u *models.User) { u.LastSeenAt = &longAgo })

	resp := adminGet(t, app, "/admin/metrics/at-risk?days=7&limit=50")
	var body struct {
		Days  int `json:"days"`
		Users []struct {
			ID           uint   `json:"id"`
			Username     string `json:"username"`
			LastSeen     string `json:"last_seen"`
			InactiveDays int    `json:"inactive_days"`
		} `json:"users"`
	}
	testutil.DecodeJSON(t, resp, &body)

	if body.Days != 7 {
		t.Fatalf("days = %d, want 7", body.Days)
	}
	for _, u := range body.Users {
		if u.InactiveDays < 7 {
			t.Fatalf("user %d is only %d days inactive but was listed for a 7-day threshold",
				u.ID, u.InactiveDays)
		}
		if u.LastSeen == "" {
			t.Fatalf("user %d has no formatted last-seen date", u.ID)
		}
	}
}

// TestCalendarMonthGrid covers the endpoint the date picker depends on for all
// its date arithmetic.
func TestCalendarMonthGrid(t *testing.T) {
	app := apptest.New(t)

	resp := adminGet(t, app, "/admin/calendar/month?system=jalali&y=1403&m=12")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var grid struct {
		System        string `json:"system"`
		Year          int    `json:"year"`
		Month         int    `json:"month"`
		Label         string `json:"label"`
		WeekdayOffset int    `json:"weekday_offset"`
		Days          []struct {
			D    int    `json:"d"`
			Greg string `json:"greg"`
		} `json:"days"`
		Prev struct{ Y, M int } `json:"prev"`
		Next struct{ Y, M int } `json:"next"`
	}
	testutil.DecodeJSON(t, resp, &grid)

	// Esfand 1403 is a leap month: 30 days, not 29.
	if len(grid.Days) != 30 {
		t.Fatalf("Esfand 1403 grid has %d days, want 30", len(grid.Days))
	}
	if grid.Label == "" {
		t.Fatal("grid has no month label")
	}
	if grid.Prev.M != 11 || grid.Next.Y != 1404 || grid.Next.M != 1 {
		t.Fatalf("month navigation wrong: prev=%+v next=%+v", grid.Prev, grid.Next)
	}
	for _, d := range grid.Days {
		if _, err := time.Parse("2006-01-02", d.Greg); err != nil {
			t.Fatalf("day %d has unparseable Gregorian equivalent %q", d.D, d.Greg)
		}
	}
}

// TestMetricsRequireAuth: these endpoints sit behind the admin group, and an
// unauthenticated request must not reach the data.
func TestMetricsRequireAuth(t *testing.T) {
	app := apptest.New(t)

	for _, path := range []string{
		"/admin/metrics/summary",
		"/admin/metrics/daily",
		"/admin/metrics/heatmap",
		"/admin/metrics/cohorts",
		"/admin/metrics/at-risk",
		"/admin/calendar/month",
	} {
		resp := testutil.DoJSON(t, app, http.MethodGet, path, nil, nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s served data without authentication", path)
		}
	}
}

// TestStatsAndTrackerPagesRender guards the templates: a bad field reference in
// a Go template fails at render time, not at build time.
func TestStatsAndTrackerPagesRender(t *testing.T) {
	app := apptest.New(t)

	for _, path := range []string{
		"/admin/stats?preset=7d&compare=1",
		"/admin/tracker?preset=30d&q=&page=1",
		"/admin",
	} {
		resp := adminGet(t, app, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s rendered with status %d, want 200", path, resp.StatusCode)
		}
	}
}
