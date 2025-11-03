package handlers

import (
	"github.com/gofiber/fiber/v2"
)

// PushPage renders a UI-only page to send push notifications via an external API.
func PushPage(c *fiber.Ctx) error {
	return c.Render("push/index", fiber.Map{
		"title": "ارسال پوش نوتیفیکیشن (UI)",
	})
}
