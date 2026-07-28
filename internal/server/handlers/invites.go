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

	return c.Render("invites/index", fiber.Map{
		"title":    "دعوت‌ها",
		"rows":     rows,
		"settings": settings,
		"calendar": string(calendarFromRequest(c)),
	})
}

// ReferralTaskSettingsUpdate updates the admin-configurable referral reward task:
// how many invites are required, how many ad-free days the reward grants, and the
// task/share text shown to users. Follows the same singleton-row pattern as settings.go.
func ReferralTaskSettingsUpdate(c *fiber.Ctx) error {
	var settings models.AppSettings
	if err := database.DB.First(&settings, 1).Error; err != nil {
		settings = models.AppSettings{ID: 1}
		_ = database.DB.Create(&settings).Error
	}

	if v := c.FormValue("referral_required_invites"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			settings.ReferralRequiredInvites = n
		}
	}
	if v := c.FormValue("referral_reward_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			settings.ReferralRewardDays = n
		}
	}
	if v := c.FormValue("referral_task_text"); v != "" {
		settings.ReferralTaskText = v
	}
	if v := c.FormValue("referral_share_text"); v != "" {
		settings.ReferralShareText = v
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
	todayCounts := opensByUserSince(todayStart)
	monthCounts := opensByUserSince(monthStart)

	r := parseDateRange(c)
	rangeCounts := opensByUserInRange(r.From, r.To)

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

// taskProgressRow is one row of the invite-task stats table.
type taskProgressRow struct {
	User          models.User
	InvitesCount  int64
	Reached       bool
	RewardActive  bool
	RewardExpires *time.Time
}

// InviteTaskStatsPage shows how many users have completed the referral reward task
// (invited enough friends) and how many currently have an active ad-free reward.
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
	reachedCount, activeCount := 0, 0
	for _, u := range users {
		cnt := counts[u.ID]
		reached := cnt >= int64(settings.ReferralRequiredInvites)
		var active bool
		var expires *time.Time
		if u.RewardActivatedAt != nil {
			exp := u.RewardActivatedAt.AddDate(0, 0, settings.ReferralRewardDays)
			expires = &exp
			active = now.Before(exp)
		}
		if reached {
			reachedCount++
		}
		if active {
			activeCount++
		}
		rows = append(rows, taskProgressRow{
			User:          u,
			InvitesCount:  cnt,
			Reached:       reached,
			RewardActive:  active,
			RewardExpires: expires,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].InvitesCount > rows[j].InvitesCount })

	return c.Render("invite_stats/index", fiber.Map{
		"title":          "آمار تسک دعوت",
		"rows":           rows,
		"settings":       settings,
		"totalReferrers": len(users),
		"reachedCount":   reachedCount,
		"activeCount":    activeCount,
		"calendar":       string(calendarFromRequest(c)),
	})
}
