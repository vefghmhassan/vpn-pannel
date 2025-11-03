package handlers

import (
	"github.com/gofiber/fiber/v2"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

func SettingsPage(c *fiber.Ctx) error {
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		// ensure singleton exists
		s = models.AppSettings{ID: 1, CurrentVersion: "1.0.0"}
		_ = database.DB.FirstOrCreate(&s, models.AppSettings{ID: 1}).Error
	}
	return c.Render("settings/index", fiber.Map{
		"title": "تنظیمات برنامه",
		"s":     s,
	})
}

func SettingsUpdate(c *fiber.Ctx) error {
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		s = models.AppSettings{ID: 1}
		_ = database.DB.Create(&s).Error
	}

	// checkboxes: presence means true
	s.AdsEnabledInSplash = c.FormValue("ads_enabled_in_splash") != ""
	s.ShowAdsAfterSplash = c.FormValue("show_ads_after_splash") != ""
	s.ShowAdsOnMainPage = c.FormValue("show_ads_on_main_page") != ""
	if v := c.FormValue("current_version"); v != "" {
		s.CurrentVersion = v
	}

	if err := database.DB.Save(&s).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Redirect("/admin/settings")
}
