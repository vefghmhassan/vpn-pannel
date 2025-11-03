package handlers

import (
	"net/http"
	"strconv"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"

	"github.com/gofiber/fiber/v2"
)

func SplashList(c *fiber.Ctx) error {
	// pagination params
	const pageSize = 15
	pageStr := c.Query("page", "1")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	var total int64
	if err := database.DB.Model(&models.SplashProtocol{}).Count(&total).Error; err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to count")
	}

	var items []models.SplashProtocol
	if err := database.DB.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error; err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to load")
	}

	totalPages := int((total + pageSize - 1) / pageSize)
	if totalPages == 0 {
		totalPages = 1
	}

	return c.Render("splash/index", fiber.Map{
		"title":      "Splash Protocols",
		"items":      items,
		"page":       page,
		"totalPages": totalPages,
		"hasPrev":    page > 1,
		"hasNext":    page < totalPages,
		"prevPage":   page - 1,
		"nextPage":   page + 1,
	})
}

func SplashNewPage(c *fiber.Ctx) error {
	return c.Render("splash/new", fiber.Map{
		"title": "New Splash Protocol",
	})
}

func SplashCreate(c *fiber.Ctx) error {
	idStr := c.FormValue("id")
	name := c.FormValue("name")
	value := c.FormValue("value")
	priceStr := c.FormValue("price")
	usageStr := c.FormValue("usage")
	serverIDStr := c.FormValue("serverId")

	if idStr == "" || name == "" || value == "" {
		return c.Status(http.StatusBadRequest).SendString("missing required fields")
	}
	id64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return c.Status(http.StatusBadRequest).SendString("invalid id")
	}
	price, _ := strconv.Atoi(priceStr)
	usage, _ := strconv.Atoi(usageStr)
	serverID, _ := strconv.Atoi(serverIDStr)

	rec := models.SplashProtocol{
		ID:       id64,
		Name:     name,
		Value:    value,
		Price:    price,
		Usage:    usage,
		ServerID: serverID,
	}
	// Upsert-like: ignore if exists
	var existing models.SplashProtocol
	if err := database.DB.First(&existing, id64).Error; err == nil {
		// exists: update fields (except ID)
		existing.Name = rec.Name
		existing.Value = rec.Value
		existing.Price = rec.Price
		existing.Usage = rec.Usage
		existing.ServerID = rec.ServerID
		if err := database.DB.Save(&existing).Error; err != nil {
			return c.Status(http.StatusInternalServerError).SendString("update failed")
		}
	} else {
		if err := database.DB.Create(&rec).Error; err != nil {
			return c.Status(http.StatusInternalServerError).SendString("create failed")
		}
	}
	return c.Redirect("/admin/splash")
}
