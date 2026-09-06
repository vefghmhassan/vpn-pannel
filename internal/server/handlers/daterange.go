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

// presetOption is one quick-range button in the picker.
type presetOption struct {
	Value string
	Label string
}

// rangePresets are the quick ranges offered above the picker, in display order.
// They exist because the overwhelmingly common question is "how did the last week
// look", and answering it should not require six dropdowns.
var rangePresets = []presetOption{
	{"today", "امروز"},
	{"yesterday", "دیروز"},
	{"7d", "۷ روز اخیر"},
	{"30d", "۳۰ روز اخیر"},
	{"this_month", "این ماه"},
	{"last_month", "ماه قبل"},
	{"this_year", "امسال"},
}

// granularityOptions are the bucket sizes the charts can be drawn at. "auto"
// picks one from the range length (see resolveGranularity).
var granularityOptions = []presetOption{
	{"auto", "خودکار"},
	{"hour", "ساعتی"},
	{"day", "روزانه"},
	{"week", "هفتگی"},
	{"month", "ماهانه"},
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

	// Preset is the active quick range, or "custom" when the dates were picked
	// by hand. Presets are resolved in the *active calendar*, so "this month"
	// means the current Jalali month for an admin viewing in Jalali.
	Preset   string
	Presets  []presetOption
	FromText string
	ToText   string

	// Granularity is the requested bucket size ("auto" until resolved) and
	// Resolved is what "auto" actually became for this range.
	Granularity         string
	ResolvedGranularity string
	Granularities       []presetOption

	// Compare turns on the previous-period comparison; PrevFrom/PrevTo are the
	// equally long window ending exactly where this one starts.
	Compare  bool
	PrevFrom time.Time
	PrevTo   time.Time
}

// parseDateRange reads from_y/from_m/from_d/to_y/to_m/to_d query params (interpreted
// in the caller's active calendar system) into a resolved Gregorian [From, To) window,
// defaulting to the last 30 days when absent.
//
// A `preset` parameter overrides those six: it is the picker's normal mode, with
// the explicit parts kept both for hand-picked ranges and for the pages that were
// already linking to this picker with y/m/d parameters.
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

	preset := c.Query("preset")
	if p, ok := applyPreset(preset, system, now); ok {
		fromY, fromM, fromD = p.fromY, p.fromM, p.fromD
		toY, toM, toD = p.toY, p.toM, p.toD
	} else {
		preset = "custom"
	}

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

	granularity := c.Query("granularity", "auto")
	if !isKnownGranularity(granularity) {
		granularity = "auto"
	}

	r := dateRange{
		From: from, To: toExclusive,
		Calendar: string(system),
		FromY:    fromY, FromM: fromM, FromD: fromD,
		ToY: toY, ToM: toM, ToD: toD,
		Years:    years,
		Months:   months,
		FromDays: daysList(calendar.DaysInMonth(system, fromY, fromM)),
		ToDays:   daysList(calendar.DaysInMonth(system, toY, toM)),

		Preset:   preset,
		Presets:  rangePresets,
		FromText: formatParts(fromY, fromM, fromD),
		ToText:   formatParts(toY, toM, toD),

		Granularity:         granularity,
		ResolvedGranularity: resolveGranularity(granularity, from, toExclusive),
		Granularities:       granularityOptions,

		Compare: c.Query("compare") == "1",
	}

	// The comparison window is the same length immediately before From, so a
	// 7-day range is compared against the 7 days before it rather than against a
	// fixed "last week" that would not line up for other range lengths.
	span := r.To.Sub(r.From)
	r.PrevFrom = r.From.Add(-span)
	r.PrevTo = r.From

	return r
}

// presetParts is one preset resolved into calendar parts.
type presetParts struct {
	fromY, fromM, fromD int
	toY, toM, toD       int
}

// applyPreset resolves a named quick range into from/to parts in the active
// calendar. Reports ok=false for an empty or unknown name so the caller falls
// back to the explicit parameters.
func applyPreset(name string, system calendar.System, now time.Time) (presetParts, bool) {
	todayY, todayM, todayD := calendar.ToParts(now, system)

	partsOf := func(t time.Time) (int, int, int) { return calendar.ToParts(t, system) }

	switch name {
	case "today":
		return presetParts{todayY, todayM, todayD, todayY, todayM, todayD}, true
	case "yesterday":
		y, m, d := partsOf(now.AddDate(0, 0, -1))
		return presetParts{y, m, d, y, m, d}, true
	case "7d":
		y, m, d := partsOf(now.AddDate(0, 0, -6))
		return presetParts{y, m, d, todayY, todayM, todayD}, true
	case "30d":
		y, m, d := partsOf(now.AddDate(0, 0, -29))
		return presetParts{y, m, d, todayY, todayM, todayD}, true
	case "this_month":
		return presetParts{todayY, todayM, 1, todayY, todayM, todayD}, true
	case "last_month":
		// Walk back through the calendar's own month lengths rather than
		// subtracting 30 days, which would land in the wrong month for a
		// 31-day Jalali month or a 29-day Hijri one.
		py, pm := calendar.PrevMonth(todayY, todayM)
		return presetParts{py, pm, 1, py, pm, calendar.DaysInMonth(system, py, pm)}, true
	case "this_year":
		return presetParts{todayY, 1, 1, todayY, todayM, todayD}, true
	default:
		return presetParts{}, false
	}
}

// resolveGranularity turns "auto" into a concrete bucket size based on how long
// the range is, aiming for a readable number of bars rather than a wall of them.
func resolveGranularity(requested string, from, to time.Time) string {
	if requested != "auto" && requested != "" {
		return requested
	}
	days := to.Sub(from).Hours() / 24
	switch {
	case days <= 2:
		return "hour"
	case days <= 92:
		return "day"
	case days <= 400:
		return "week"
	default:
		return "month"
	}
}

func isKnownGranularity(g string) bool {
	for _, opt := range granularityOptions {
		if opt.Value == g {
			return true
		}
	}
	return false
}

// formatParts renders y/m/d as the "YYYY/MM/DD" text shown in the picker's input.
func formatParts(y, m, d int) string {
	return pad4(y) + "/" + pad2(m) + "/" + pad2(d)
}

func pad2(n int) string {
	if n < 10 && n >= 0 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func pad4(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
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
