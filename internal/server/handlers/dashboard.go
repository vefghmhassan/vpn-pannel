package handlers

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"vpnpannel/internal/analytics"
	"vpnpannel/internal/calendar"
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

// kpiCard describes one tile of the analytics dashboard's KPI row. Key matches a
// field of analytics.SummaryStats' JSON, which is how the page's script knows
// which number and which delta belong in which tile.
type kpiCard struct {
	Key   string
	Label string
	Hint  string
}

// statsKPIs is the KPI row's definition. It lives here rather than in the
// template so the labels and the summary payload's field names stay together.
var statsKPIs = []kpiCard{
	{"dau", "کاربر فعال روزانه", "DAU — ۲۴ ساعت منتهی به پایان بازه"},
	{"wau", "کاربر فعال هفتگی", "WAU — ۷ روز"},
	{"mau", "کاربر فعال ماهانه", "MAU — ۳۰ روز"},
	{"stickiness", "چسبندگی", "DAU ÷ MAU — چند درصد کاربران ماهانه هر روز برمی‌گردند"},
	{"new_users", "کاربر جدید", "ثبت‌نام در بازه انتخابی"},
	{"total_opens", "باز کردن اپ", "مجموع در بازه انتخابی"},
}

// StatsPage renders the analytics dashboard shell. Every panel on it loads its
// own data from the /admin/metrics/* endpoints, so the page itself only has to
// carry the date picker's state and the KPI row's labels.
func StatsPage(c *fiber.Ctx) error {
	r := parseDateRange(c)
	return c.Render("stats/index", fiber.Map{
		"title":    "آمار و تحلیل",
		"range":    r,
		"calendar": r.Calendar,
		"kpis":     statsKPIs,
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
//
// The series is bucketed by the range's granularity rather than returned raw:
// snapshots land every 5 minutes, so an unaggregated month is ~8,600 points —
// unreadable as a line and wasteful to send. Each bucket carries both its peak
// and its mean, which answer different questions about load.
func OnlineHistory(c *fiber.Ctx) error {
	r := parseDateRange(c)
	system := calendar.System(r.Calendar)

	series, err := analytics.OnlineSeries(r.From, r.To, r.ResolvedGranularity)
	if err != nil {
		return fiber.ErrInternalServerError
	}

	points := make([]fiber.Map, 0, len(series))
	for _, p := range series {
		points = append(points, fiber.Map{
			"t":     p.Time,
			"label": bucketLabel(p.Time, system, r.ResolvedGranularity),
			// "count" is kept as an alias for the peak so any caller written
			// against the old raw-snapshot shape keeps working.
			"count": p.Max,
			"max":   p.Max,
			"avg":   p.Avg,
		})
	}
	return c.JSON(fiber.Map{"granularity": r.ResolvedGranularity, "points": points})
}

// userOpenStats is one row of the tracker table.
type userOpenStats struct {
	User       models.User
	OpensToday int64
	OpensMonth int64
	OpensRange int64
}

// opensByUserSince returns a map of user_id -> open count for events since the
// given time, restricted to userIDs (nil means every user).
func opensByUserSince(since time.Time, userIDs []uint) map[uint]int64 {
	return opensByUserInRange(since, time.Now().AddDate(1, 0, 0), userIDs)
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

// opensByUserInRange returns a map of user_id -> open count for events within
// [from, to), restricted to userIDs when that slice is non-nil.
func opensByUserInRange(from, to time.Time, userIDs []uint) map[uint]int64 {
	if userIDs != nil && len(userIDs) == 0 {
		return map[uint]int64{}
	}

	var rows []struct {
		UserID uint
		Count  int64
	}
	q := database.DB.Model(&models.AppOpenEvent{}).
		Select("user_id, count(*) as count").
		Where("created_at >= ? AND created_at < ?", from, to)
	if userIDs != nil {
		q = q.Where("user_id IN ?", userIDs)
	}
	q.Group("user_id").Scan(&rows)

	out := make(map[uint]int64, len(rows))
	for _, r := range rows {
		out[r.UserID] = r.Count
	}
	return out
}

// trackerPageSize is how many tracker rows are shown at once.
const trackerPageSize = 50

// TrackerPage renders the app-open tracker: users with how many times they opened
// the app today, this month, and within a custom selected date range.
//
// Paginated and searchable rather than listing everyone: the page used to load
// every user row and sort them in memory, which grows without bound and puts the
// interesting users (the most active ones) behind a scroll of thousands.
func TrackerPage(c *fiber.Ctx) error {
	page := queryInt(c, "page", 1)
	if page < 1 {
		page = 1
	}
	search := strings.TrimSpace(c.Query("q"))

	query := database.DB.Model(&models.User{})
	if search != "" {
		like := "%" + strings.ToLower(search) + "%"
		query = query.Where("LOWER(username) LIKE ? OR LOWER(email) LIKE ?", like, like)
	}

	var total int64
	query.Count(&total)

	var users []models.User
	query.Order("id desc").
		Limit(trackerPageSize).
		Offset((page - 1) * trackerPageSize).
		Find(&users)

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	// Aggregate only for the users actually on this page — without the filter the
	// group-by would scan every event in the range to build counts for rows that
	// are never rendered.
	ids := make([]uint, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}

	todayCounts := opensByUserSince(todayStart, ids)
	monthCounts := opensByUserSince(monthStart, ids)

	r := parseDateRange(c)
	rangeCounts := opensByUserInRange(r.From, r.To, ids)

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

	totalPages := int((total + trackerPageSize - 1) / trackerPageSize)
	if totalPages < 1 {
		totalPages = 1
	}

	return c.Render("tracker/index", fiber.Map{
		"title":      "ترکر کاربران",
		"rows":       rows,
		"range":      r,
		"calendar":   string(calendarFromRequest(c)),
		"search":     search,
		"page":       page,
		"totalPages": totalPages,
		"total":      total,
		"hasPrev":    page > 1,
		"hasNext":    page < totalPages,
		"prevPage":   page - 1,
		"nextPage":   page + 1,
	})
}
