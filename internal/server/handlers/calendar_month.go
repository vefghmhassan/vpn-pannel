package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/calendar"
)

// CalendarMonth serves one month grid for the admin date picker.
//
// The picker has no date library of its own: it asks for a month and renders
// whatever comes back, including the Gregorian equivalent of every cell. That
// keeps Jalali and Hijri arithmetic in internal/calendar — one tested
// implementation — instead of a second copy in JavaScript that would drift on
// leap years and go unnoticed until an admin picked the wrong Esfand.
//
// Defaults to the current month in the request's active calendar system, so an
// initial fetch needs no parameters at all.
func CalendarMonth(c *fiber.Ctx) error {
	system := calendarFromRequest(c)
	if q := c.Query("system"); q != "" {
		system = calendar.ParseSystem(q)
	}

	now := time.Now()
	defY, defM, _ := calendar.ToParts(now, system)

	y := queryInt(c, "y", defY)
	m := queryInt(c, "m", defM)
	if m < 1 || m > 12 {
		m = defM
	}

	return c.JSON(calendar.BuildMonthGrid(system, y, m, now))
}
