// Package analytics computes the admin dashboard's product metrics from the raw
// activity tables (app_open_events, users, online_snapshots) and the daily_stats
// rollup that services.RecomputeDay maintains.
//
// It is deliberately free of HTTP concerns so the metric definitions can be
// tested directly. Every range is half-open [from, to), matching the convention
// that handlers.parseDateRange already resolves query parameters into.
package analytics

import (
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

// DayPoint is one bucket of the daily series behind the dashboard's bar chart.
type DayPoint struct {
	Day         time.Time `json:"t"`
	ActiveUsers int64     `json:"active"`
	// NewUsers is registrations; ActiveNewUsers is the subset of ActiveUsers who
	// registered that day. Only the latter stacks cleanly with ReturningUsers.
	NewUsers       int64 `json:"new"`
	ActiveNewUsers int64 `json:"new_active"`
	ReturningUsers int64 `json:"returning"`
	TotalOpens     int64 `json:"opens"`
	PeakOnline     int64 `json:"peak"`
}

// DailySeries returns one point per day in [from, to), with days that have no
// data present as zeros so the chart shows a real gap rather than silently
// closing it.
//
// Days from today onward are computed live instead of read from the rollup: the
// rollup ticker only runs hourly, and an admin watching the dashboard expects
// today's numbers to move. Recomputing today on read costs one aggregation over
// a single indexed day.
func DailySeries(from, to time.Time) ([]DayPoint, error) {
	from = services.DayStart(from)
	today := services.DayStart(time.Now())

	var rows []models.DailyStat
	if err := database.DB.
		Where("day >= ? AND day < ?", from, to).
		Order("day asc").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	byDay := make(map[string]models.DailyStat, len(rows))
	for _, r := range rows {
		byDay[r.Day.Format("2006-01-02")] = r
	}

	points := make([]DayPoint, 0, 32)
	for day := from; day.Before(to); day = day.AddDate(0, 0, 1) {
		if !day.Before(today) {
			live, err := computeDay(day)
			if err != nil {
				return nil, err
			}
			points = append(points, live)
			continue
		}
		stat := byDay[day.Format("2006-01-02")]
		points = append(points, DayPoint{
			Day:            day,
			ActiveUsers:    stat.ActiveUsers,
			NewUsers:       stat.NewUsers,
			ActiveNewUsers: stat.ActiveNewUsers,
			ReturningUsers: stat.ReturningUsers,
			TotalOpens:     stat.TotalOpens,
			PeakOnline:     stat.PeakOnline,
		})
	}
	return points, nil
}

// computeDay derives a single day's numbers directly from the event tables,
// used for days the rollup has not settled yet (today and anything ahead of it).
func computeDay(day time.Time) (DayPoint, error) {
	start := services.DayStart(day)
	end := start.AddDate(0, 0, 1)
	point := DayPoint{Day: start}

	var agg struct {
		ActiveUsers int64
		TotalOpens  int64
	}
	if err := database.DB.Model(&models.AppOpenEvent{}).
		Select("COUNT(DISTINCT user_id) AS active_users, COUNT(*) AS total_opens").
		Where("created_at >= ? AND created_at < ?", start, end).
		Scan(&agg).Error; err != nil {
		return point, err
	}

	var newUsers int64
	if err := database.DB.Model(&models.User{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Count(&newUsers).Error; err != nil {
		return point, err
	}

	var activeNew int64
	if err := database.DB.Model(&models.AppOpenEvent{}).
		Joins("JOIN users ON users.id = app_open_events.user_id").
		Where("app_open_events.created_at >= ? AND app_open_events.created_at < ?", start, end).
		Where("users.created_at >= ? AND users.created_at < ?", start, end).
		Distinct("app_open_events.user_id").
		Count(&activeNew).Error; err != nil {
		return point, err
	}

	var peak struct{ PeakOnline int64 }
	if err := database.DB.Model(&models.OnlineSnapshot{}).
		Select("COALESCE(MAX(count), 0) AS peak_online").
		Where("created_at >= ? AND created_at < ?", start, end).
		Scan(&peak).Error; err != nil {
		return point, err
	}

	point.ActiveUsers = agg.ActiveUsers
	point.TotalOpens = agg.TotalOpens
	point.NewUsers = newUsers
	point.ActiveNewUsers = activeNew
	point.ReturningUsers = agg.ActiveUsers - activeNew
	point.PeakOnline = peak.PeakOnline
	return point, nil
}

// DistinctActive counts the distinct users who opened the app in [from, to).
//
// This cannot be read off daily_stats: distinct-user counts are not additive
// across days (one user active on three days is one WAU, not three), so the
// rolling windows must go back to the events. The (user_id, created_at) index on
// app_open_events is what keeps that affordable.
func DistinctActive(from, to time.Time) (int64, error) {
	var count int64
	err := database.DB.Model(&models.AppOpenEvent{}).
		Where("created_at >= ? AND created_at < ?", from, to).
		Distinct("user_id").
		Count(&count).Error
	return count, err
}

// SummaryStats is the dashboard's KPI row for one period.
type SummaryStats struct {
	DAU        int64   `json:"dau"`
	WAU        int64   `json:"wau"`
	MAU        int64   `json:"mau"`
	Stickiness float64 `json:"stickiness"` // DAU/MAU as a percentage

	ActiveUsers int64 `json:"active_users"` // distinct users over the whole period
	NewUsers    int64 `json:"new_users"`
	TotalOpens  int64 `json:"total_opens"`
	PeakOnline  int64 `json:"peak_online"`

	OpensPerUser float64 `json:"opens_per_user"`
}

// Summary computes the KPI row for [from, to).
//
// DAU/WAU/MAU are anchored to the *end* of the period rather than to now, so that
// comparing a period against the preceding one compares like with like: asking
// for last week's numbers should give last week's DAU, not today's.
func Summary(from, to time.Time) (SummaryStats, error) {
	var s SummaryStats

	anchor := to
	if now := time.Now(); anchor.After(now) {
		anchor = now
	}

	var err error
	if s.DAU, err = DistinctActive(anchor.AddDate(0, 0, -1), anchor); err != nil {
		return s, err
	}
	if s.WAU, err = DistinctActive(anchor.AddDate(0, 0, -7), anchor); err != nil {
		return s, err
	}
	if s.MAU, err = DistinctActive(anchor.AddDate(0, 0, -30), anchor); err != nil {
		return s, err
	}
	if s.MAU > 0 {
		s.Stickiness = float64(s.DAU) / float64(s.MAU) * 100
	}

	if s.ActiveUsers, err = DistinctActive(from, to); err != nil {
		return s, err
	}

	var agg struct{ TotalOpens int64 }
	if err := database.DB.Model(&models.AppOpenEvent{}).
		Select("COUNT(*) AS total_opens").
		Where("created_at >= ? AND created_at < ?", from, to).
		Scan(&agg).Error; err != nil {
		return s, err
	}
	s.TotalOpens = agg.TotalOpens
	if s.ActiveUsers > 0 {
		s.OpensPerUser = float64(s.TotalOpens) / float64(s.ActiveUsers)
	}

	if err := database.DB.Model(&models.User{}).
		Where("created_at >= ? AND created_at < ?", from, to).
		Count(&s.NewUsers).Error; err != nil {
		return s, err
	}

	var peak struct{ PeakOnline int64 }
	if err := database.DB.Model(&models.OnlineSnapshot{}).
		Select("COALESCE(MAX(count), 0) AS peak_online").
		Where("created_at >= ? AND created_at < ?", from, to).
		Scan(&peak).Error; err != nil {
		return s, err
	}
	s.PeakOnline = peak.PeakOnline

	return s, nil
}
