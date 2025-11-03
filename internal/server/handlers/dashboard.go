package handlers

import (
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
	var count int64
	database.DB.Model(&models.User{}).
		Where("is_active = ? AND last_seen_at IS NOT NULL AND last_seen_at > ?", true, since).
		Count(&count)
	return c.JSON(fiber.Map{"count": count, "hours": hours})
}
