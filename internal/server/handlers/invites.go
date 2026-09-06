package handlers

import (
	"sort"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// referrerRow is one row of the invites overview table.
type referrerRow struct {
	User          models.User
	ReferralCount int64
}

// referralCountsByUser returns a map of user_id -> how many users they referred.
func referralCountsByUser() map[uint]int64 {
	var rows []struct {
		ReferredByUserID uint
		Count            int64
	}
	database.DB.Model(&models.User{}).
		Select("referred_by_user_id, count(*) as count").
		Where("referred_by_user_id IS NOT NULL").
		Group("referred_by_user_id").
		Scan(&rows)

	out := make(map[uint]int64, len(rows))
	for _, r := range rows {
		out[r.ReferredByUserID] = r.Count
	}
	return out
}

// InvitesPage lists every user who has an invite code, with how many people they referred.
func InvitesPage(c *fiber.Ctx) error {
	var users []models.User
	database.DB.Where("invite_code IS NOT NULL").Order("id desc").Find(&users)

	counts := referralCountsByUser()

	rows := make([]referrerRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, referrerRow{User: u, ReferralCount: counts[u.ID]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ReferralCount > rows[j].ReferralCount })

	var settings models.AppSettings
	if err := database.DB.First(&settings, 1).Error; err != nil {
		settings = models.AppSettings{ID: 1}
		_ = database.DB.FirstOrCreate(&settings, models.AppSettings{ID: 1}).Error
	}

	inviterDays, inviterHours := splitMinutes(settings.ReferralInviterRewardMinutes)
	inviteeDays, inviteeHours := splitMinutes(settings.ReferralInviteeRewardMinutes)

	return c.Render("invites/index", fiber.Map{
		"title":        "دعوت‌ها",
		"rows":         rows,
		"settings":     settings,
		"inviterDays":  inviterDays,
		"inviterHours": inviterHours,
		"inviteeDays":  inviteeDays,
		"inviteeHours": inviteeHours,
		"calendar":     string(calendarFromRequest(c)),
	})
}

// minutesPerDay/minutesPerHour convert between the stored reward duration (minutes)
// and the day+hour pair the admin form edits.
const (
	minutesPerDay  = 24 * 60
	minutesPerHour = 60
)

// splitMinutes breaks a stored duration into whole days plus leftover hours, since
// Go templates have no integer division to do it at render time.
func splitMinutes(total int) (days, hours int) {
	if total <= 0 {
		return 0, 0
	}
	return total / minutesPerDay, (total % minutesPerDay) / minutesPerHour
}

// formDuration reads a "<prefix>_days"/"<prefix>_hours" input pair and combines them
// into minutes. ok is false when neither field was submitted, so the caller can leave
// the stored value alone rather than zeroing it.
func formDuration(c *fiber.Ctx, prefix string) (minutes int, ok bool) {
	dayVal, hourVal := c.FormValue(prefix+"_days"), c.FormValue(prefix+"_hours")
	if dayVal == "" && hourVal == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(dayVal); err == nil && n > 0 {
		minutes += n * minutesPerDay
	}
	if n, err := strconv.Atoi(hourVal); err == nil && n > 0 {
		minutes += n * minutesPerHour
	}
	return minutes, true
}

// ReferralTaskSettingsUpdate updates the admin-configurable referral settings: the
// master on/off switch, the per-side instant reward durations, the rewarded-invite
// cap, and the text shown to users. Follows the same singleton-row pattern as
// settings.go — an absent checkbox means false.
func ReferralTaskSettingsUpdate(c *fiber.Ctx) error {
	var settings models.AppSettings
	if err := database.DB.First(&settings, 1).Error; err != nil {
		settings = models.AppSettings{ID: 1}
		_ = database.DB.Create(&settings).Error
	}

	settings.ReferralEnabled = c.FormValue("referral_enabled") != ""

	if v := c.FormValue("referral_task_text"); v != "" {
		settings.ReferralTaskText = v
	}
	if v := c.FormValue("referral_share_text"); v != "" {
		settings.ReferralShareText = v
	}

	// 0 is meaningful for all of these (no reward for that side / unlimited cap),
	// so they accept it rather than treating it as "unset".
	settings.ReferralInstantRewardEnabled = c.FormValue("referral_instant_reward_enabled") != ""
	if m, ok := formDuration(c, "referral_inviter_reward"); ok {
		settings.ReferralInviterRewardMinutes = m
	}
	if m, ok := formDuration(c, "referral_invitee_reward"); ok {
		settings.ReferralInviteeRewardMinutes = m
	}
	if v := c.FormValue("referral_max_rewarded_invites"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			settings.ReferralMaxRewardedInvites = n
		}
	}

	if err := database.DB.Save(&settings).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Redirect("/admin/invites")
}

// InviteDetailPage shows one referrer's invite code and everyone they referred, with
// each referred user's open counts (today/this month) and last-seen time.
func InviteDetailPage(c *fiber.Ctx) error {
	id, _ := strconv.Atoi(c.Params("id"))
	var referrer models.User
	if err := database.DB.First(&referrer, id).Error; err != nil {
		return fiber.ErrNotFound
	}

	var referred []models.User
	database.DB.Where("referred_by_user_id = ?", referrer.ID).Order("id desc").Find(&referred)

	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	// Scoped to just this referrer's invitees, so the aggregation reads only the
	// events it will actually render.
	ids := make([]uint, 0, len(referred))
	for _, u := range referred {
		ids = append(ids, u.ID)
	}
	todayCounts := opensByUserSince(todayStart, ids)
	monthCounts := opensByUserSince(monthStart, ids)

	r := parseDateRange(c)
	rangeCounts := opensByUserInRange(r.From, r.To, ids)

	rows := make([]userOpenStats, 0, len(referred))
	for _, u := range referred {
		rows = append(rows, userOpenStats{
			User:       u,
			OpensToday: todayCounts[u.ID],
			OpensMonth: monthCounts[u.ID],
			OpensRange: rangeCounts[u.ID],
		})
	}

	return c.Render("invites/detail", fiber.Map{
		"title":    "زیرمجموعه‌های کاربر",
		"referrer": referrer,
		"rows":     rows,
		"range":    r,
		"calendar": string(calendarFromRequest(c)),
	})
}

// taskProgressRow is one row of the invite stats table.
type taskProgressRow struct {
	User          models.User
	InvitesCount  int64
	RewardActive  bool
	RewardExpires *time.Time
	RewardedCount int
}

// InviteTaskStatsPage shows, per referrer, how many people they invited, how many of
// those actually paid out, and whether their ad-free reward is currently running.
func InviteTaskStatsPage(c *fiber.Ctx) error {
	var settings models.AppSettings
	if err := database.DB.First(&settings, 1).Error; err != nil {
		settings = models.AppSettings{ID: 1}
		_ = database.DB.FirstOrCreate(&settings, models.AppSettings{ID: 1}).Error
	}

	var users []models.User
	database.DB.Where("invite_code IS NOT NULL").Order("id desc").Find(&users)
	counts := referralCountsByUser()

	now := time.Now()
	rows := make([]taskProgressRow, 0, len(users))
	activeCount := 0
	for _, u := range users {
		var active bool
		expires := u.RewardExpiresAt
		if expires != nil {
			active = now.Before(*expires)
		}
		if active {
			activeCount++
		}
		rows = append(rows, taskProgressRow{
			User:          u,
			InvitesCount:  counts[u.ID],
			RewardActive:  active,
			RewardExpires: expires,
			RewardedCount: u.RewardedReferralCount,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].InvitesCount > rows[j].InvitesCount })

	inviterDays, inviterHours := splitMinutes(settings.ReferralInviterRewardMinutes)
	inviteeDays, inviteeHours := splitMinutes(settings.ReferralInviteeRewardMinutes)

	return c.Render("invite_stats/index", fiber.Map{
		"title":          "آمار دعوت‌ها",
		"rows":           rows,
		"settings":       settings,
		"totalReferrers": len(users),
		"activeCount":    activeCount,
		"inviterDays":    inviterDays,
		"inviterHours":   inviterHours,
		"inviteeDays":    inviteeDays,
		"inviteeHours":   inviteeHours,
		"calendar":       string(calendarFromRequest(c)),
	})
}
