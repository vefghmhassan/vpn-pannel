package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/analytics"
	"vpnpannel/internal/calendar"
)

// This file serves the admin analytics dashboard's JSON. Each endpoint takes the
// same date-range parameters as the page itself (see parseDateRange), so the
// browser can forward location.search verbatim and stay in sync with the picker.

// bucketLabel renders a timestamp for a chart axis in the *request's* calendar
// system, with a level of detail matching the bucket size.
//
// Labels are built server-side on purpose. Doing it in JavaScript would mean
// either shipping a Jalali date library or calling toLocaleString('fa-IR'), and
// the latter renders Jalali for every viewer regardless of the calendar they
// actually selected — which is exactly what the old chart did wrong.
func bucketLabel(t time.Time, system calendar.System, granularity string) string {
	y, m, d := calendar.ToParts(t, system)
	switch granularity {
	case "hour":
		return pad2(m) + "/" + pad2(d) + " " + pad2(t.Hour()) + ":00"
	case "month":
		return calendar.MonthYearLabel(system, y, m)
	default:
		return pad2(m) + "/" + pad2(d)
	}
}

// AnalyticsSummary returns the dashboard's KPI row for the selected range, and —
// when compare=1 — the same figures for the preceding equally long window plus
// the percentage change between them.
func AnalyticsSummary(c *fiber.Ctx) error {
	r := parseDateRange(c)

	current, err := analytics.Summary(r.From, r.To)
	if err != nil {
		return fiber.ErrInternalServerError
	}

	payload := fiber.Map{"current": current, "compare": r.Compare}
	if r.Compare {
		previous, err := analytics.Summary(r.PrevFrom, r.PrevTo)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		payload["previous"] = previous
		payload["delta"] = fiber.Map{
			"dau":          percentChange(float64(previous.DAU), float64(current.DAU)),
			"wau":          percentChange(float64(previous.WAU), float64(current.WAU)),
			"mau":          percentChange(float64(previous.MAU), float64(current.MAU)),
			"stickiness":   percentChange(previous.Stickiness, current.Stickiness),
			"active_users": percentChange(float64(previous.ActiveUsers), float64(current.ActiveUsers)),
			"new_users":    percentChange(float64(previous.NewUsers), float64(current.NewUsers)),
			"total_opens":  percentChange(float64(previous.TotalOpens), float64(current.TotalOpens)),
			"peak_online":  percentChange(float64(previous.PeakOnline), float64(current.PeakOnline)),
		}
	}
	return c.JSON(payload)
}

// percentChange reports the change from previous to current as a percentage.
//
// Returns nil rather than 0 or an infinity when the previous period was empty:
// growth from zero has no meaningful percentage, and rendering it as "0%" or
// "+Inf%" would both be lies. The client shows a dash for a null.
func percentChange(previous, current float64) *float64 {
	if previous == 0 {
		return nil
	}
	v := (current - previous) / previous * 100
	return &v
}

// AnalyticsDaily returns the per-day series behind the dashboard's bar chart:
// active users, new vs returning, total opens and peak concurrency for each day
// in the selected range.
//
// Always daily regardless of the chart granularity — coarser buckets are summed
// on top of these, and "how did each day look" is the question the page exists to
// answer.
func AnalyticsDaily(c *fiber.Ctx) error {
	r := parseDateRange(c)
	system := calendar.System(r.Calendar)

	// A day is this series' finest resolution — distinct-user counts cannot be
	// split below the bucket they were counted in. An "hour" granularity (which
	// `auto` picks for a one- or two-day range) is therefore reported and labelled
	// as "day" rather than dressing a single daily figure up as an hourly one.
	granularity := r.ResolvedGranularity
	if granularity == "hour" {
		granularity = "day"
	}

	series, err := analytics.DailySeries(r.From, r.To)
	if err != nil {
		return fiber.ErrInternalServerError
	}

	buckets := bucketDaily(series, granularity)
	points := make([]fiber.Map, 0, len(buckets))
	for _, b := range buckets {
		points = append(points, fiber.Map{
			"t":      b.Day,
			"label":  bucketLabel(b.Day, system, granularity),
			"active": b.ActiveUsers,
			// "new" is registrations (the acquisition number); "new_active" is the
			// slice of "active" that registered in the bucket, which is what the
			// stacked chart adds to "returning".
			"new":        b.NewUsers,
			"new_active": b.ActiveNewUsers,
			"returning":  b.ReturningUsers,
			"opens":      b.TotalOpens,
			"peak":       b.PeakOnline,
		})
	}
	return c.JSON(fiber.Map{"granularity": granularity, "points": points})
}

// bucketDaily rolls a daily series up into week or month buckets.
//
// Counts (opens, new users) sum; peak concurrency takes the maximum, since the
// busiest moment of a week is the busiest moment of one of its days. Active users
// is summed too and so overstates a week's distinct users when someone is active
// on several days — the KPI row carries the true distinct WAU/MAU, which cannot
// be derived from per-day numbers at all.
func bucketDaily(series []analytics.DayPoint, granularity string) []analytics.DayPoint {
	if granularity != "week" && granularity != "month" {
		return series
	}

	out := make([]analytics.DayPoint, 0, len(series)/7+1)
	var currentKey time.Time
	for _, p := range series {
		key := bucketStart(p.Day, granularity)
		if len(out) == 0 || !key.Equal(currentKey) {
			currentKey = key
			out = append(out, analytics.DayPoint{Day: key})
		}
		agg := &out[len(out)-1]
		agg.ActiveUsers += p.ActiveUsers
		agg.NewUsers += p.NewUsers
		agg.ActiveNewUsers += p.ActiveNewUsers
		agg.ReturningUsers += p.ReturningUsers
		agg.TotalOpens += p.TotalOpens
		if p.PeakOnline > agg.PeakOnline {
			agg.PeakOnline = p.PeakOnline
		}
	}
	return out
}

// bucketStart snaps a day to the start of its week (Monday, matching Postgres'
// date_trunc so the two series line up) or month.
func bucketStart(day time.Time, granularity string) time.Time {
	if granularity == "month" {
		return time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, day.Location())
	}
	offset := (int(day.Weekday()) + 6) % 7 // days since Monday
	return day.AddDate(0, 0, -offset)
}

// AnalyticsHeatmap returns app-open counts per weekday and hour, for the "when is
// the app used" grid.
func AnalyticsHeatmap(c *fiber.Ctx) error {
	r := parseDateRange(c)
	grid, err := analytics.HourlyHeatmap(r.From, r.To)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{
		"cells":    grid.Cells,
		"max":      grid.Max,
		"weekdays": calendar.WeekdayNames(calendar.System(r.Calendar)),
		// The data is indexed 0=Sunday; a Persian week starts on Saturday, so the
		// client rotates the rows by this much rather than the server reshaping
		// (and thereby hiding) the underlying indexing.
		"week_start_offset": weekStartOffsetFor(calendar.System(r.Calendar)),
	})
}

// weekStartOffsetFor mirrors the calendar package's week-start rule for the
// heatmap's row ordering: Gregorian weeks open on Sunday, Jalali/Hijri on Saturday.
func weekStartOffsetFor(system calendar.System) int {
	if system == calendar.Gregorian {
		return 0
	}
	return 6
}

// AnalyticsCohorts returns the weekly signup-retention matrix.
//
// Not range-bound: cohort analysis is about the recent past regardless of which
// window the rest of the page is showing, and slicing it by an arbitrary range
// would silently truncate the follow-up weeks that give each cohort its meaning.
func AnalyticsCohorts(c *fiber.Ctx) error {
	weeks := queryInt(c, "weeks", 8)
	if weeks < 1 || weeks > 52 {
		weeks = 8
	}

	rows, err := analytics.Cohorts(weeks)
	if err != nil {
		return fiber.ErrInternalServerError
	}

	system := calendarFromRequest(c)
	out := make([]fiber.Map, 0, len(rows))
	for _, row := range rows {
		y, m, d := calendar.ToParts(row.WeekStart, system)
		out = append(out, fiber.Map{
			"week":     formatParts(y, m, d),
			"size":     row.Size,
			"retained": row.Retained,
			"percent":  row.Percent,
		})
	}
	return c.JSON(fiber.Map{"offsets": analytics.CohortOffsets, "rows": out})
}

// AnalyticsAtRisk lists users who have gone quiet, so the admin can act on churn
// rather than only observe it.
func AnalyticsAtRisk(c *fiber.Ctx) error {
	days := queryInt(c, "days", 7)
	limit := queryInt(c, "limit", 20)
	if limit > 200 {
		limit = 200
	}

	users, err := analytics.AtRiskUsers(days, limit)
	if err != nil {
		return fiber.ErrInternalServerError
	}

	system := calendarFromRequest(c)
	out := make([]fiber.Map, 0, len(users))
	for _, u := range users {
		out = append(out, fiber.Map{
			"id":            u.User.ID,
			"username":      u.User.Username,
			"email":         u.User.Email,
			"last_seen":     calendar.FormatDateTime(u.User.LastSeenAt, system),
			"inactive_days": u.InactiveDays,
		})
	}
	return c.JSON(fiber.Map{"days": days, "users": out})
}
