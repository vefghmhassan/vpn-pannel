package services

import (
	"context"
	"log"
	"time"

	"gorm.io/gorm/clause"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// rollupBackfillLimitDays caps how far back BackfillDailyStats will reach on a
// cold start. Without a bound, the first boot against a long-lived database would
// run one aggregation query per historical day before the server starts serving.
const rollupBackfillLimitDays = 400

// StartDailyRollup launches a background ticker that keeps the daily_stats rollup
// table current, mirroring StartOnlineSnapshotter.
//
// Each tick recomputes today *and* yesterday rather than only the current day:
// events land continuously, so a day is not final the moment it ends, and a
// process restart shortly after midnight would otherwise leave yesterday frozen
// at whatever partial numbers the last pre-midnight tick wrote. Recomputation is
// idempotent, so redoing a settled day costs one query and changes nothing.
func StartDailyRollup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		rollupRecent()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rollupRecent()
			}
		}
	}()
}

func rollupRecent() {
	now := time.Now()
	for _, day := range []time.Time{now.AddDate(0, 0, -1), now} {
		if err := RecomputeDay(day); err != nil {
			log.Printf("daily rollup for %s failed: %v", day.Format("2006-01-02"), err)
		}
	}
}

// DayStart truncates t to local midnight, the canonical key of a DailyStat row.
func DayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// RecomputeDay rebuilds the daily_stats row for the calendar day containing the
// given time, from the underlying event tables, and upserts it.
//
// Always a full recompute rather than an increment: the aggregates are cheap for
// one day's slice of the indexed tables, and rebuilding means a missed tick, a
// late-arriving event or a bad earlier write all self-heal on the next run
// instead of accumulating drift that nothing would ever notice.
func RecomputeDay(day time.Time) error {
	start := DayStart(day)
	end := start.AddDate(0, 0, 1)

	var agg struct {
		ActiveUsers int64
		TotalOpens  int64
	}
	if err := database.DB.Model(&models.AppOpenEvent{}).
		Select("COUNT(DISTINCT user_id) AS active_users, COUNT(*) AS total_opens").
		Where("created_at >= ? AND created_at < ?", start, end).
		Scan(&agg).Error; err != nil {
		return err
	}

	var newUsers int64
	if err := database.DB.Model(&models.User{}).
		Where("created_at >= ? AND created_at < ?", start, end).
		Count(&newUsers).Error; err != nil {
		return err
	}

	// Returning = active users who did not register today. Derived by counting the
	// active users who *did* register today rather than subtracting newUsers, since
	// a user can register without ever opening the app (and would otherwise push
	// the returning count negative).
	var activeNew int64
	if err := database.DB.Model(&models.AppOpenEvent{}).
		Joins("JOIN users ON users.id = app_open_events.user_id").
		Where("app_open_events.created_at >= ? AND app_open_events.created_at < ?", start, end).
		Where("users.created_at >= ? AND users.created_at < ?", start, end).
		Distinct("app_open_events.user_id").
		Count(&activeNew).Error; err != nil {
		return err
	}

	var peak struct{ PeakOnline int64 }
	if err := database.DB.Model(&models.OnlineSnapshot{}).
		Select("COALESCE(MAX(count), 0) AS peak_online").
		Where("created_at >= ? AND created_at < ?", start, end).
		Scan(&peak).Error; err != nil {
		return err
	}

	row := models.DailyStat{
		Day:            start,
		UpdatedAt:      time.Now(),
		ActiveUsers:    agg.ActiveUsers,
		NewUsers:       newUsers,
		ActiveNewUsers: activeNew,
		ReturningUsers: agg.ActiveUsers - activeNew,
		TotalOpens:     agg.TotalOpens,
		PeakOnline:     peak.PeakOnline,
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "day"}},
		UpdateAll: true,
	}).Create(&row).Error
}

// BackfillDailyStats fills in rollup rows for every day from the first recorded
// activity up to today that does not have one yet, so the dashboard has history
// on the very first deploy of this feature rather than starting empty.
//
// Only missing days are computed, which makes this safe (and near-free) to run on
// every boot. Days that already have a row are left alone — StartDailyRollup owns
// keeping the recent ones fresh.
func BackfillDailyStats() error {
	start, ok, err := earliestActivity()
	if err != nil || !ok {
		return err
	}

	today := DayStart(time.Now())
	if limit := today.AddDate(0, 0, -rollupBackfillLimitDays); start.Before(limit) {
		start = limit
	}

	existing, err := existingRollupDays(start)
	if err != nil {
		return err
	}

	for day := start; !day.After(today); day = day.AddDate(0, 0, 1) {
		if existing[day.Format("2006-01-02")] {
			continue
		}
		if err := RecomputeDay(day); err != nil {
			return err
		}
	}
	return nil
}

// earliestActivity finds the first day worth rolling up: the older of the first
// app-open event and the first user registration. Reports ok=false for an empty
// database, which is not an error — there is simply nothing to backfill.
func earliestActivity() (time.Time, bool, error) {
	var bounds struct {
		FirstEvent *time.Time
		FirstUser  *time.Time
	}
	if err := database.DB.Raw(`
		SELECT (SELECT MIN(created_at) FROM app_open_events) AS first_event,
		       (SELECT MIN(created_at) FROM users)           AS first_user
	`).Scan(&bounds).Error; err != nil {
		return time.Time{}, false, err
	}

	first := bounds.FirstEvent
	if first == nil || (bounds.FirstUser != nil && bounds.FirstUser.Before(*first)) {
		first = bounds.FirstUser
	}
	if first == nil {
		return time.Time{}, false, nil
	}
	return DayStart(first.Local()), true, nil
}

// existingRollupDays returns the set of already-computed days from `since`
// onward, keyed by YYYY-MM-DD, so the backfill can skip them with one query
// instead of one existence check per day.
func existingRollupDays(since time.Time) (map[string]bool, error) {
	var days []time.Time
	if err := database.DB.Model(&models.DailyStat{}).
		Where("day >= ?", since).
		Pluck("day", &days).Error; err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(days))
	for _, d := range days {
		set[d.Format("2006-01-02")] = true
	}
	return set, nil
}
