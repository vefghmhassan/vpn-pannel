package analytics

import (
	"fmt"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// --- Time zone ------------------------------------------------------------

// localZoneOperand returns the SQL fragment and bind value for an AT TIME ZONE
// operand matching the Go process's local zone.
//
// Postgres evaluates date_trunc and EXTRACT on a timestamptz in the *session's*
// time zone, which defaults to UTC and has nothing to do with the zone the Go
// side used to compute day boundaries. Without converting first, a heatmap files
// Tehran's 9pm peak under 17:30, and a "day" bucket straddles two real days —
// which is exactly what the tests for both caught.
//
// A named zone is preferred because it follows DST. Go cannot always supply one
// (on Windows time.Local reports "Local"), so the current fixed offset is the
// fallback; it is correct except across a DST transition. Both forms are bound as
// parameters — the only thing chosen here is the placeholder's shape.
func localZoneOperand() (string, interface{}) {
	if name := time.Now().Location().String(); name != "" && name != "Local" {
		return "?", name
	}
	_, offset := time.Now().Zone()
	return "?::interval", fmt.Sprintf("%d seconds", offset)
}

// --- Hourly heatmap -------------------------------------------------------

// Heatmap holds app-open counts bucketed by weekday (0=Sunday, matching
// Postgres' EXTRACT(DOW)) and hour of day, for the "when is the app used" grid.
type Heatmap struct {
	// Cells is [weekday][hour]; the caller decides which weekday to render first
	// so the Persian week can start on Saturday without changing the data.
	Cells [7][24]int64 `json:"cells"`
	Max   int64        `json:"max"`
}

// HourlyHeatmap counts app opens per weekday/hour over [from, to).
//
// The extraction happens in Postgres rather than in Go so only 168 rows cross the
// wire instead of every event in the range.
func HourlyHeatmap(from, to time.Time) (Heatmap, error) {
	var out Heatmap

	var rows []struct {
		Dow  int
		Hour int
		N    int64
	}
	tzSQL, tz := localZoneOperand()
	selectSQL := fmt.Sprintf(
		"EXTRACT(DOW FROM created_at AT TIME ZONE %s)::int AS dow, "+
			"EXTRACT(HOUR FROM created_at AT TIME ZONE %s)::int AS hour, "+
			"COUNT(*) AS n", tzSQL, tzSQL)

	if err := database.DB.Model(&models.AppOpenEvent{}).
		Select(selectSQL, tz, tz).
		Where("created_at >= ? AND created_at < ?", from, to).
		Group("dow, hour").
		Scan(&rows).Error; err != nil {
		return out, err
	}

	for _, r := range rows {
		if r.Dow < 0 || r.Dow > 6 || r.Hour < 0 || r.Hour > 23 {
			continue
		}
		out.Cells[r.Dow][r.Hour] = r.N
		if r.N > out.Max {
			out.Max = r.N
		}
	}
	return out, nil
}

// --- Retention cohorts ----------------------------------------------------

// CohortRow is one signup week and how much of it came back later.
type CohortRow struct {
	WeekStart time.Time `json:"week_start"`
	Size      int64     `json:"size"`
	// Retained[i] is how many of Size were still opening the app during
	// CohortOffsets[i]'s window. Retained[0] is week 0 (the signup week itself).
	Retained []int64   `json:"retained"`
	Percent  []float64 `json:"percent"`
}

// CohortOffsets are the week offsets each cohort is measured at: the signup week,
// then the following four weeks.
var CohortOffsets = []int{0, 1, 2, 3, 4}

// Cohorts builds a weekly retention matrix for the last `weeks` signup cohorts.
//
// Weekly rather than daily cohorts: with daily buckets a panel this size produces
// rows of two or three users where a single person swings retention by 30
// percentage points, which reads as noise rather than a trend.
//
// The whole matrix is one query — grouping users by signup week and their events
// by the week offset from that signup — instead of a query per cohort per offset.
func Cohorts(weeks int) ([]CohortRow, error) {
	if weeks <= 0 {
		weeks = 8
	}

	var rows []struct {
		WeekStart time.Time
		Size      int64
		WeekIndex int
		Retained  int64
	}
	// cohorts: each user's signup week. activity: the distinct week offsets at
	// which that user came back. The LEFT JOIN keeps cohorts with zero retention
	// visible rather than dropping the row entirely.
	// Weeks are truncated in local time for the same reason as everywhere else in
	// this file — a UTC week boundary would move signups made late on a Friday
	// evening into the following cohort.
	//
	// The cutoff is computed in Go rather than as an interval built from a bound
	// parameter: Postgres resolves an unknown parameter's type before the cast is
	// applied, so the count arrives as text and fails to encode.
	cutoff := time.Now().AddDate(0, 0, -7*weeks)
	tzSQL, tz := localZoneOperand()
	query := fmt.Sprintf(`
		WITH cohorts AS (
			SELECT id AS user_id, date_trunc('week', created_at AT TIME ZONE %s) AS week_start
			FROM users
			WHERE created_at >= ?
		),
		sizes AS (
			SELECT week_start, COUNT(*) AS size FROM cohorts GROUP BY week_start
		),
		activity AS (
			SELECT DISTINCT c.week_start,
			       (EXTRACT(EPOCH FROM date_trunc('week', e.created_at AT TIME ZONE %s) - c.week_start) / 604800)::int AS week_index,
			       e.user_id
			FROM cohorts c
			JOIN app_open_events e ON e.user_id = c.user_id
		)
		SELECT s.week_start, s.size, a.week_index, COUNT(a.user_id) AS retained
		FROM sizes s
		LEFT JOIN activity a ON a.week_start = s.week_start AND a.week_index >= 0
		GROUP BY s.week_start, s.size, a.week_index
		ORDER BY s.week_start DESC
	`, tzSQL, tzSQL)
	// Argument order follows the placeholders' order of appearance in the SQL, not
	// their logical grouping: the second time zone sits in the `activity` CTE,
	// which is written after the cutoff's WHERE clause.
	if err := database.DB.Raw(query, tz, cutoff, tz).Scan(&rows).Error; err != nil {
		return nil, err
	}

	byWeek := map[time.Time]*CohortRow{}
	order := []time.Time{}
	for _, r := range rows {
		row, ok := byWeek[r.WeekStart]
		if !ok {
			row = &CohortRow{
				WeekStart: r.WeekStart,
				Size:      r.Size,
				Retained:  make([]int64, len(CohortOffsets)),
				Percent:   make([]float64, len(CohortOffsets)),
			}
			byWeek[r.WeekStart] = row
			order = append(order, r.WeekStart)
		}
		for i, off := range CohortOffsets {
			if r.WeekIndex == off {
				row.Retained[i] = r.Retained
				if row.Size > 0 {
					row.Percent[i] = float64(r.Retained) / float64(row.Size) * 100
				}
			}
		}
	}

	out := make([]CohortRow, 0, len(order))
	for _, w := range order {
		out = append(out, *byWeek[w])
	}
	return out, nil
}

// --- Churn risk -----------------------------------------------------------

// AtRiskUser is a user who has stopped opening the app, plus how long they have
// been gone — the actionable half of the retention picture.
type AtRiskUser struct {
	User         models.User
	InactiveDays int
}

// AtRiskUsers lists users whose last visit is older than inactiveDays, most
// recently seen first (the ones still worth a push notification rather than the
// long-gone tail).
//
// Users who have never been seen at all are excluded: they are a signup problem,
// not a churn problem, and would otherwise flood the list.
func AtRiskUsers(inactiveDays, limit int) ([]AtRiskUser, error) {
	if inactiveDays <= 0 {
		inactiveDays = 7
	}
	if limit <= 0 {
		limit = 20
	}
	cutoff := time.Now().AddDate(0, 0, -inactiveDays)

	var users []models.User
	if err := database.DB.
		Where("role = ? AND is_active = ? AND last_seen_at IS NOT NULL AND last_seen_at < ?",
			models.RoleUser, true, cutoff).
		Order("last_seen_at desc").
		Limit(limit).
		Find(&users).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	out := make([]AtRiskUser, 0, len(users))
	for _, u := range users {
		days := 0
		if u.LastSeenAt != nil {
			days = int(now.Sub(*u.LastSeenAt).Hours() / 24)
		}
		out = append(out, AtRiskUser{User: u, InactiveDays: days})
	}
	return out, nil
}

// --- Online history, downsampled -----------------------------------------

// OnlinePoint is one bucket of the online-users trend.
type OnlinePoint struct {
	Time time.Time `json:"t"`
	Max  int64     `json:"max"`
	Avg  float64   `json:"avg"`
}

// truncUnits maps a granularity name to the Postgres date_trunc unit.
var truncUnits = map[string]string{
	"hour":  "hour",
	"day":   "day",
	"week":  "week",
	"month": "month",
}

// OnlineSeries returns the online-user history over [from, to), aggregated into
// buckets of the given granularity.
//
// Snapshots are taken every 5 minutes, so a raw 30-day range is ~8,600 points —
// more than a chart can draw distinctly and far more than is useful to send.
// Bucketing in SQL turns that into ~30. Both the max and the mean are returned
// because they answer different questions: peak concurrency sizes the servers,
// the average describes the typical load.
func OnlineSeries(from, to time.Time, granularity string) ([]OnlinePoint, error) {
	unit, ok := truncUnits[granularity]
	if !ok {
		unit = "day"
	}

	var rows []struct {
		Bucket time.Time
		Max    int64
		Avg    float64
	}
	// unit comes from the truncUnits lookup above, never from the request, so this
	// Sprintf can only ever splice in one of those four literals; the time zone is
	// bound as a parameter.
	//
	// The double AT TIME ZONE is deliberate: the first converts the stored instant
	// to local wall time so the bucket boundaries land on local midnight, and the
	// second turns the truncated wall time back into an instant for the caller.
	tzSQL, tz := localZoneOperand()
	query := fmt.Sprintf(`
		SELECT date_trunc('%s', created_at AT TIME ZONE %s) AT TIME ZONE %s AS bucket,
		       MAX(count) AS max,
		       AVG(count) AS avg
		FROM online_snapshots
		WHERE created_at >= ? AND created_at < ?
		GROUP BY bucket
		ORDER BY bucket ASC
	`, unit, tzSQL, tzSQL)
	if err := database.DB.Raw(query, tz, tz, from, to).Scan(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]OnlinePoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, OnlinePoint{Time: r.Bucket, Max: r.Max, Avg: r.Avg})
	}
	return out, nil
}
