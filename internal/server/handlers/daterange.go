package handlers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/calendar"
)

// monthOption is one <option> in the picker's month dropdown.
type monthOption struct {
	Value int
	Label string
}

// dateRange is a resolved [From, To) Gregorian window plus everything the shared
// partials/daterange.html picker needs to render itself in the active calendar system.
type dateRange struct {
	From, To time.Time
	Calendar string

	FromY, FromM, FromD int
	ToY, ToM, ToD       int

	Years    []int
	Months   []monthOption
	FromDays []int
	ToDays   []int
}

// parseDateRange reads from_y/from_m/from_d/to_y/to_m/to_d query params (interpreted
// in the caller's active calendar system) into a resolved Gregorian [From, To) window,
// defaulting to the last 30 days when absent.
func parseDateRange(c *fiber.Ctx) dateRange {
	system := calendarFromRequest(c)
	loc := time.Now().Location()
	now := time.Now()

	defY, defM, defD := calendar.ToParts(now, system)
	defFromY, defFromM, defFromD := calendar.ToParts(now.AddDate(0, 0, -29), system)

	fromY := queryInt(c, "from_y", defFromY)
	fromM := queryInt(c, "from_m", defFromM)
	fromD := queryInt(c, "from_d", defFromD)
	toY := queryInt(c, "to_y", defY)
	toM := queryInt(c, "to_m", defM)
	toD := queryInt(c, "to_d", defD)

	from := calendar.FromParts(system, fromY, fromM, fromD, 0, 0, 0, loc)
	// "to" is inclusive of the whole selected day, so bump to the start of the next day.
	toExclusive := calendar.FromParts(system, toY, toM, toD, 0, 0, 0, loc).AddDate(0, 0, 1)

	years := make([]int, 0, 6)
	for y := defY - 5; y <= defY+1; y++ {
		years = append(years, y)
	}
	months := make([]monthOption, 12)
	for m := 1; m <= 12; m++ {
		months[m-1] = monthOption{Value: m, Label: calendar.MonthLabel(system, m)}
	}

	return dateRange{
		From: from, To: toExclusive,
		Calendar: string(system),
		FromY:    fromY, FromM: fromM, FromD: fromD,
		ToY: toY, ToM: toM, ToD: toD,
		Years:    years,
		Months:   months,
		FromDays: daysList(calendar.DaysInMonth(system, fromY, fromM)),
		ToDays:   daysList(calendar.DaysInMonth(system, toY, toM)),
	}
}

func queryInt(c *fiber.Ctx, key string, def int) int {
	v := c.Query(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func daysList(n int) []int {
	days := make([]int, n)
	for i := range days {
		days[i] = i + 1
	}
	return days
}
