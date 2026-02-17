package handlers

import (
	"strconv"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"

	"github.com/gofiber/fiber/v2"
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
	s.UpdateEnable = c.FormValue("update_enable") != ""
	s.ShowAdsAfterSplash = c.FormValue("show_ads_after_splash") != ""
	s.ShowAdsOnMainPage = c.FormValue("show_ads_on_main_page") != ""
	s.AdsRewardEnabled = c.FormValue("ads_reward_enabled") != ""
	s.AdsAppOpenEnabled = c.FormValue("ads_app_open_enabled") != ""
	if v := c.FormValue("current_version"); v != "" {
		s.CurrentVersion = v
	}

	if v := c.FormValue("ad_unit_id"); v != "" {
		s.AdUnitID = v
	}
	if v := c.FormValue("ads_reward_unit"); v != "" {
		s.AdsRewardUnit = v
	}
	if v := c.FormValue("ads_unit_open"); v != "" {
		s.AdsUnitOpen = v
	}
	if v := c.FormValue("ads_application_id"); v != "" {
		s.AdsApplicationID = v
	}
	if v := c.FormValue("privacy_url"); v != "" {
		s.PrivacyURL = v
	}
	if v := c.FormValue("connected_timeout"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.ConnectedTimeoutSeconds = n
		}
	}

	if err := database.DB.Save(&s).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Redirect("/admin/settings")
}
