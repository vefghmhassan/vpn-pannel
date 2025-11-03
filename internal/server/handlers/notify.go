package handlers

import (
    "context"

    "github.com/gofiber/fiber/v2"

    "vpnpannel/internal/database"
    "vpnpannel/internal/models"
    "vpnpannel/internal/services"
)

func NotifyPage(c *fiber.Ctx) error {
    return c.Render("notify/index", fiber.Map{"title": "ارسال نوتیفیکیشن"})
}

func NotifySend(c *fiber.Ctx) error {
    var in struct {
        Title string `form:"title"`
        Body  string `form:"body"`
    }
    if err := c.BodyParser(&in); err != nil {
        return fiber.ErrBadRequest
    }
    type tokenRow struct{ FCMToken string }
    var rows []tokenRow
    database.DB.Model(&models.MobileDevice{}).Where("fcm_token <> ''").Find(&rows)
    tokens := make([]string, 0, len(rows))
    for _, r := range rows { tokens = append(tokens, r.FCMToken) }
    _ = services.SendPushToTokens(context.Background(), tokens, services.PushMessage{Title: in.Title, Body: in.Body})
    return c.Render("notify/index", fiber.Map{"title": "ارسال نوتیفیکیشن", "ok": true})
}


