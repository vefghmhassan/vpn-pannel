package handlers

import (
	"sort"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

func Dashboard(c *fiber.Ctx) error {
	var users int64
	var nodes int64
	var outages int64
	var splashCount int64
	database.DB.Model(&models.User{}).Count(&users)
	database.DB.Model(&models.SplashProtocol{}).Count(&splashCount)
	database.DB.Model(&models.V2RayNode{}).Count(&nodes)
	database.DB.Model(&models.OutageReport{}).Where("status <> ?", models.OutageResolved).Count(&outages)
	return c.Render("dashboard", fiber.Map{
		"title":   "Dashboard",
		"users":   users,
		"nodes":   nodes,
		"outages": outages,
		"splash":  splashCount,
	})
}

// ActiveUsersCount returns count of users active within the last N hours (default 24)
func ActiveUsersCount(c *fiber.Ctx) error {
	hoursParam := c.Query("hours", "24")
	hours, err := strconv.Atoi(hoursParam)
	if err != nil || hours <= 0 {
		hours = 24
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	return c.JSON(fiber.Map{"count": countActiveUsersSince(since), "hours": hours})
}

// countActiveUsersSince counts active users last seen after the given time.
func countActiveUsersSince(since time.Time) int64 {
	var count int64
	database.DB.Model(&models.User{}).
		Where("is_active = ? AND last_seen_at IS NOT NULL AND last_seen_at > ?", true, since).
		Count(&count)
	return count
}

// StatsPage renders the online-users stats page (5 min / 30 min / 24 hour buckets,
// plus a date-range-able trend chart defaulting to the last 30 days).
func StatsPage(c *fiber.Ctx) error {
	r := parseDateRange(c)
	return c.Render("stats/index", fiber.Map{
		"title": "آمار کاربران آنلاین",
		"range": r,
	})
}

// OnlineUsersStats returns online-user counts bucketed like a realtime analytics widget:
// active in the last 5 minutes, last 30 minutes, and last 24 hours.
func OnlineUsersStats(c *fiber.Ctx) error {
	now := time.Now()
	return c.JSON(fiber.Map{
		"m5":  countActiveUsersSince(now.Add(-5 * time.Minute)),
		"m30": countActiveUsersSince(now.Add(-30 * time.Minute)),
		"h24": countActiveUsersSince(now.Add(-24 * time.Hour)),
	})
}

// OnlineHistory returns the online-user snapshot history (see services.StartOnlineSnapshotter)
// for the selected date range (see parseDateRange; defaults to the last 30 days), used
// to draw the stats trend chart.
func OnlineHistory(c *fiber.Ctx) error {
	r := parseDateRange(c)

	var snapshots []models.OnlineSnapshot
	database.DB.Where("created_at >= ? AND created_at < ?", r.From, r.To).Order("created_at asc").Find(&snapshots)

	points := make([]fiber.Map, 0, len(snapshots))
	for _, s := range snapshots {
		points = append(points, fiber.Map{"t": s.CreatedAt, "count": s.Count})
	}
	return c.JSON(fiber.Map{"points": points})
}

// userOpenStats is one row of the tracker table.
type userOpenStats struct {
	User       models.User
	OpensToday int64
	OpensMonth int64
	OpensRange int64
}

// opensByUserSince returns a map of user_id -> open count for events since the given time.
func opensByUserSince(since time.Time) map[uint]int64 {
	return opensByUserInRange(since, time.Now().AddDate(1, 0, 0))
}

// currentSessionWindow is how far back an app-open event still counts as "this
// session" rather than a previous visit.
const currentSessionWindow = 15 * time.Minute

// previousOpenAt returns when the user last opened the app *before* the current
// session, ignoring events from the last few minutes.
//
// The window matters: ApiLastConnection writes an AppOpenEvent (and LastSeenAt)
// on every launch, so measuring from the newest event would report a gap of zero
// whenever the client happens to check in before asking for messages. Skipping
// the current session makes the answer independent of that call order.
//
// Returns ok=false for a user with no earlier visit — a fresh install, which must
// not be treated as "inactive forever" just because LastSeenAt is null.
func previousOpenAt(userID uint, now time.Time) (t time.Time, ok bool) {
	var event models.AppOpenEvent
	err := database.DB.
		Where("user_id = ? AND created_at < ?", userID, now.Add(-currentSessionWindow)).
		Order("created_at desc").
		First(&event).Error
	if err == nil {
		return event.CreatedAt, true
	}

	// Fall back to LastSeenAt for users who predate AppOpenEvent, or who are
	// tracked through endpoints that touch LastSeenAt but log no open event.
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil || user.LastSeenAt == nil {
		return time.Time{}, false
	}
	if user.LastSeenAt.After(now.Add(-currentSessionWindow)) {
		return time.Time{}, false
	}
	return *user.LastSeenAt, true
}

// daysSincePreviousOpen reports how many whole days the user was away before the
// current session. Returns (0, false) when there is no earlier visit to measure from.
func daysSincePreviousOpen(userID uint, now time.Time) (days int, hasPrevious bool) {
	last, ok := previousOpenAt(userID, now)
	if !ok {
		return 0, false
	}
	gap := now.Sub(last)
	if gap < 0 {
		return 0, true
	}
	return int(gap.Hours() / 24), true
}

// opensByUserInRange returns a map of user_id -> open count for events within [from, to).
func opensByUserInRange(from, to time.Time) map[uint]int64 {
	var rows []struct {
		UserID uint
		Count  int64
	}
	database.DB.Model(&models.AppOpenEvent{}).
		Select("user_id, count(*) as count").
		Where("created_at >= ? AND created_at < ?", from, to).
		Group("user_id").
		Scan(&rows)

	out := make(map[uint]int64, len(rows))
	for _, r := range rows {
		out[r.UserID] = r.Count
	}
	return out
}

// TrackerPage renders the full app-open tracker: every user with how many times they
// opened the app today, this month, and within a custom selected date range.
func TrackerPage(c *fiber.Ctx) error {
	var users []models.User
	database.DB.Order("id desc").Find(&users)

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	todayCounts := opensByUserSince(todayStart)
	monthCounts := opensByUserSince(monthStart)

	r := parseDateRange(c)
	rangeCounts := opensByUserInRange(r.From, r.To)

	rows := make([]userOpenStats, 0, len(users))
	for _, u := range users {
		rows = append(rows, userOpenStats{
			User:       u,
			OpensToday: todayCounts[u.ID],
			OpensMonth: monthCounts[u.ID],
			OpensRange: rangeCounts[u.ID],
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].OpensToday != rows[j].OpensToday {
			return rows[i].OpensToday > rows[j].OpensToday
		}
		return rows[i].OpensMonth > rows[j].OpensMonth
	})

	return c.Render("tracker/index", fiber.Map{
		"title":    "ترکر کاربران",
		"rows":     rows,
		"range":    r,
		"calendar": string(calendarFromRequest(c)),
	})
}
