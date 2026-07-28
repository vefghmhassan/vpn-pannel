package handlers

import (
	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/calendar"
)

const calendarCookieName = "calendar_system"

// SetCalendar switches the admin's preferred calendar system (stored per-browser
// in a cookie, not a global setting) and redirects back to where the request came from.
func SetCalendar(c *fiber.Ctx) error {
	system := calendar.ParseSystem(c.Query("system"))
	c.Cookie(&fiber.Cookie{
		Name:   calendarCookieName,
		Value:  string(system),
		MaxAge: 365 * 24 * 60 * 60,
		// Not HTTPOnly: the navbar reads this client-side to show which system is active.
		// Holds only a display preference, never sensitive data.
		HTTPOnly: false,
		Path:     "/",
	})

	next := c.Query("next")
	if next == "" {
		next = c.Get("Referer")
	}
	if next == "" {
		next = "/admin"
	}
	return c.Redirect(next)
}

// calendarFromRequest reads the admin's preferred calendar system from the cookie,
// defaulting to Gregorian.
func calendarFromRequest(c *fiber.Ctx) calendar.System {
	return calendar.ParseSystem(c.Cookies(calendarCookieName))
}
