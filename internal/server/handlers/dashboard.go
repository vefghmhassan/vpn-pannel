package handlers

import (
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
