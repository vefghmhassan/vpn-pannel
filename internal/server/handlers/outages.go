package handlers

import (
    "strconv"

    "github.com/gofiber/fiber/v2"

    "vpnpannel/internal/database"
    "vpnpannel/internal/models"
)

func OutagesList(c *fiber.Ctx) error {
    var reports []models.OutageReport
    database.DB.Order("id desc").Find(&reports)
    return c.Render("outages/index", fiber.Map{"title": "گزارش خرابی", "reports": reports})
}

func OutageSetStatus(c *fiber.Ctx) error {
    id, _ := strconv.Atoi(c.Params("id"))
    action := c.Query("s")
    status := models.OutageAcknowledged
    if action == "resolve" { status = models.OutageResolved }
    database.DB.Model(&models.OutageReport{}).Where("id = ?", id).Update("status", status)
    return c.Redirect("/admin/outages")
}




