package calendar

import (
	"fmt"
	"time"
)

// This file builds the month grids the admin date picker renders. The picker is
// a plain JavaScript widget with no date library of its own: it asks the server
// for a month and draws whatever comes back. That keeps a single implementation
// of Jalali/Hijri arithmetic (the one in this package, which is tested) instead
// of a second, silently diverging copy in the browser.

// Day is one cell of a month grid.
type Day struct {
	// D is the day number in the grid's own calendar system.
	D int `json:"d"`
	// Greg is the same day as "YYYY-MM-DD" in the Gregorian calendar, which is
	// what every stored timestamp uses. The picker echoes it back so the client
	// never has to convert anything itself.
	Greg string `json:"greg"`
	// Today marks the current day so the grid can highlight it.
	Today bool `json:"today"`
}

// YearMonth addresses a month in some calendar system.
type YearMonth struct {
	Y int `json:"y"`
	M int `json:"m"`
}

// MonthGrid is everything needed to draw one month of the picker.
type MonthGrid struct {
	System string `json:"system"`
	Year   int    `json:"year"`
	Month  int    `json:"month"`
	Label  string `json:"label"`
	// WeekdayOffset is how many blank cells precede the 1st, given that the week
	// starts on WeekdayNames[0] for this system.
	WeekdayOffset int       `json:"weekday_offset"`
	WeekdayNames  []string  `json:"weekday_names"`
	Days          []Day     `json:"days"`
	Prev          YearMonth `json:"prev"`
	Next          YearMonth `json:"next"`
}

// gregorianWeekdayNames start on Sunday, matching Go's time.Weekday numbering.
var gregorianWeekdayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// persianWeekdayNames start on Saturday: the Iranian week begins with شنبه, so a
// Jalali or Hijri grid that opened on Sunday would put the weekend in the middle.
var persianWeekdayNames = []string{"ش", "ی", "د", "س", "چ", "پ", "ج"}

// WeekdayNames returns the column headers for the given system, in the order the
// grid lays them out.
func WeekdayNames(system System) []string {
	if system == Gregorian {
		return gregorianWeekdayNames
	}
	return persianWeekdayNames
}

// weekStartOffset is how far the system's first weekday sits from Sunday, which
// is where JDN-derived weekday numbers start.
func weekStartOffset(system System) int {
	if system == Gregorian {
		return 0 // Sunday
	}
	return 6 // Saturday
}

// Weekday returns the column index (0-based, in the system's own week order) of
// the given date. Derived from the Julian Day Number rather than from
// time.Weekday so that it works identically for all three calendars.
func Weekday(system System, y, m, d int) int {
	jdn := toJDN(system, y, m, d)
	// JDN 0 was a Monday, so (jdn+1) mod 7 gives 0=Sunday.
	sundayBased := (jdn + 1) % 7
	return (sundayBased - weekStartOffset(system) + 7) % 7
}

// toJDN converts a date in the given system to a Julian Day Number.
func toJDN(system System, y, m, d int) int {
	switch system {
	case Jalali:
		return jalaliToJDN(y, m, d)
	case Hijri:
		return hijriToJDN(y, m, d)
	default:
		return gregorianToJDN(y, m, d)
	}
}

// PrevMonth returns the month before (y, m) in the same system, rolling the year.
func PrevMonth(y, m int) (int, int) {
	if m <= 1 {
		return y - 1, 12
	}
	return y, m - 1
}

// NextMonth returns the month after (y, m) in the same system, rolling the year.
func NextMonth(y, m int) (int, int) {
	if m >= 12 {
		return y + 1, 1
	}
	return y, m + 1
}

// BuildMonthGrid assembles the grid for month (y, m) of the given system,
// marking `now`'s date as today.
func BuildMonthGrid(system System, y, m int, now time.Time) MonthGrid {
	if m < 1 {
		m = 1
	}
	if m > 12 {
		m = 12
	}

	todayY, todayM, todayD := ToParts(now, system)
	count := DaysInMonth(system, y, m)

	days := make([]Day, 0, count)
	for d := 1; d <= count; d++ {
		gy, gm, gd := jdnToGregorian(toJDN(system, y, m, d))
		days = append(days, Day{
			D:     d,
			Greg:  fmt.Sprintf("%04d-%02d-%02d", gy, gm, gd),
			Today: y == todayY && m == todayM && d == todayD,
		})
	}

	prevY, prevM := PrevMonth(y, m)
	nextY, nextM := NextMonth(y, m)

	return MonthGrid{
		System:        string(system),
		Year:          y,
		Month:         m,
		Label:         MonthYearLabel(system, y, m),
		WeekdayOffset: Weekday(system, y, m, 1),
		WeekdayNames:  WeekdayNames(system),
		Days:          days,
		Prev:          YearMonth{Y: prevY, M: prevM},
		Next:          YearMonth{Y: nextY, M: nextM},
	}
}

// MonthYearLabel renders a month heading such as "شهریور 1405" or "September 2026".
func MonthYearLabel(system System, y, m int) string {
	names := MonthNames(system)
	if names == nil {
		if m >= 1 && m <= 12 {
			return fmt.Sprintf("%s %d", time.Month(m).String(), y)
		}
		return fmt.Sprintf("%d", y)
	}
	if m < 1 || m > 12 {
		return fmt.Sprintf("%d", y)
	}
	return fmt.Sprintf("%s %d", names[m-1], y)
}
