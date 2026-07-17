package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/utils"

	"github.com/gofiber/fiber/v2"
)

func SplashList(c *fiber.Ctx) error {
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

type splashImportItem struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	ServerID int    `json:"serverId"`
	Price    int    `json:"price"`
	Usage    int    `json:"usage"`
}

type splashImportPayload struct {
	Splash []splashImportItem `json:"splash"`
}

func SplashCreate(c *fiber.Ctx) error {
	jsonData := strings.TrimSpace(c.FormValue("json_data"))

	// ── Bulk JSON import mode ──
	if jsonData != "" {
		return splashBulkImport(c, jsonData)
	}

	// ── Single entry mode ──
	idStr := c.FormValue("id")
	name := c.FormValue("name")
	value := c.FormValue("value")
	priceStr := c.FormValue("price")
	usageStr := c.FormValue("usage")
	serverIDStr := c.FormValue("serverId")

	if idStr == "" || name == "" || value == "" {
		return c.Status(http.StatusBadRequest).Render("splash/new", fiber.Map{
			"title": "New Splash Protocol",
			"error": "فیلدهای الزامی را پر کنید",
		})
	}
	id64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return c.Status(http.StatusBadRequest).Render("splash/new", fiber.Map{
			"title": "New Splash Protocol",
			"error": "شناسه نامعتبر است",
		})
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
	var existing models.SplashProtocol
	if err := database.DB.First(&existing, id64).Error; err == nil {
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

func splashBulkImport(c *fiber.Ctx, rawBody string) error {
	var payload splashImportPayload
	if err := json.Unmarshal([]byte(rawBody), &payload); err != nil {
		return c.Status(http.StatusBadRequest).Render("splash/new", fiber.Map{
			"title":   "New Splash Protocol",
			"error":   "JSON نامعتبر است: " + err.Error(),
			"jsonRaw": rawBody,
		})
	}

	if len(payload.Splash) == 0 {
		return c.Status(http.StatusBadRequest).Render("splash/new", fiber.Map{
			"title":   "New Splash Protocol",
			"error":   "هیچ آیتمی در JSON یافت نشد",
			"jsonRaw": rawBody,
		})
	}

	var imported, updated, skipped int
	var importErrors []string

	for _, item := range payload.Splash {
		if item.ID == 0 || item.Name == "" || item.Value == "" {
			skipped++
			continue
		}

		// Try decrypt; if fails, use as plaintext
		storedValue := item.Value
		if decrypted, err := utils.DecryptValue(item.Value, int(item.ID)); err == nil && strings.TrimSpace(decrypted) != "" {
			storedValue = decrypted
		}

		var existing models.SplashProtocol
		if err := database.DB.First(&existing, item.ID).Error; err == nil {
			existing.Name = item.Name
			existing.Value = storedValue
			existing.Price = item.Price
			existing.Usage = item.Usage
			existing.ServerID = item.ServerID
			if err := database.DB.Save(&existing).Error; err != nil {
				importErrors = append(importErrors, "خطا در بروزرسانی id="+strconv.FormatUint(item.ID, 10))
			} else {
				updated++
			}
		} else {
			rec := models.SplashProtocol{
				ID:       item.ID,
				Name:     item.Name,
				Value:    storedValue,
				Price:    item.Price,
				Usage:    item.Usage,
				ServerID: item.ServerID,
			}
			if err := database.DB.Create(&rec).Error; err != nil {
				importErrors = append(importErrors, "خطا در ایجاد id="+strconv.FormatUint(item.ID, 10))
			} else {
				imported++
			}
		}
	}

	msg := "وارد کردن تمام شد: " + strconv.Itoa(imported) + " جدید، " + strconv.Itoa(updated) + " بروزرسانی، " + strconv.Itoa(skipped) + " رد شد"
	if len(importErrors) > 0 {
		msg += " (" + strconv.Itoa(len(importErrors)) + " خطا)"
	}

	return c.Render("splash/new", fiber.Map{
		"title":       "New Splash Protocol",
		"success":     msg,
		"errors":      importErrors,
		"imported":    imported,
		"updated":     updated,
		"skipped":     skipped,
		"importCount": len(payload.Splash),
	})
}
