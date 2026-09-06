package calendar

import (
	"testing"
	"time"
)

// TestWeekdayAgainstGo pins the JDN-derived weekday to Go's own, which is the
// only independent check available for the Jalali and Hijri grids: they share
// the same JDN path, so if it is right for Gregorian dates it is right for them.
func TestWeekdayAgainstGo(t *testing.T) {
	for i := 0; i < 400; i++ {
		day := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, i)
		got := Weekday(Gregorian, day.Year(), int(day.Month()), day.Day())
		want := int(day.Weekday()) // 0 = Sunday, matching the Gregorian week start
		if got != want {
			t.Fatalf("Weekday(%s) = %d, want %d", day.Format("2006-01-02"), got, want)
		}
	}
}

// TestJalaliWeekStartsOnSaturday guards the grid's column ordering: a Persian
// month laid out from Sunday would put the weekend mid-row.
func TestJalaliWeekStartsOnSaturday(t *testing.T) {
	// 2026-09-05 is a Saturday.
	saturday := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	jy, jm, jd := GregorianToJalali(saturday)
	if got := Weekday(Jalali, jy, jm, jd); got != 0 {
		t.Fatalf("Jalali weekday of a Saturday = %d, want 0", got)
	}
}

// TestBuildMonthGridDayCounts checks that each grid holds exactly the month's
// days and that consecutive cells are consecutive Gregorian days — the property
// the picker relies on when it compares two selections by their `greg` field.
func TestBuildMonthGridDayCounts(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	for _, system := range []System{Gregorian, Jalali, Hijri} {
		y, m, _ := ToParts(now, system)
		grid := BuildMonthGrid(system, y, m, now)

		if len(grid.Days) != DaysInMonth(system, y, m) {
			t.Fatalf("%s: grid has %d days, want %d", system, len(grid.Days), DaysInMonth(system, y, m))
		}
		if grid.WeekdayOffset < 0 || grid.WeekdayOffset > 6 {
			t.Fatalf("%s: weekday offset %d out of range", system, grid.WeekdayOffset)
		}

		var previous time.Time
		for i, day := range grid.Days {
			parsed, err := time.Parse("2006-01-02", day.Greg)
			if err != nil {
				t.Fatalf("%s: day %d has unparseable greg %q: %v", system, day.D, i, err)
			}
			if i > 0 && !parsed.Equal(previous.AddDate(0, 0, 1)) {
				t.Fatalf("%s: day %d (%s) does not follow %s", system, day.D, day.Greg, previous.Format("2006-01-02"))
			}
			previous = parsed
		}
	}
}

// TestBuildMonthGridMarksToday makes sure exactly one cell of the current month
// is flagged, since the picker highlights it.
func TestBuildMonthGridMarksToday(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, system := range []System{Gregorian, Jalali, Hijri} {
		y, m, _ := ToParts(now, system)
		grid := BuildMonthGrid(system, y, m, now)

		count := 0
		for _, day := range grid.Days {
			if day.Today {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s: %d cells marked today, want exactly 1", system, count)
		}
	}
}

// TestLeapEsfandGrid covers the Jalali leap year, where Esfand has 30 days
// instead of 29 — the case a hand-rolled JavaScript implementation would most
// likely get wrong, and the reason the grid is built server-side at all.
func TestLeapEsfandGrid(t *testing.T) {
	// 1403 is a Jalali leap year; 1404 is not.
	if got := DaysInMonth(Jalali, 1403, 12); got != 30 {
		t.Fatalf("Esfand 1403 has %d days, want 30", got)
	}
	if got := DaysInMonth(Jalali, 1404, 12); got != 29 {
		t.Fatalf("Esfand 1404 has %d days, want 29", got)
	}

	now := time.Now()
	if got := len(BuildMonthGrid(Jalali, 1403, 12, now).Days); got != 30 {
		t.Fatalf("leap Esfand grid has %d cells, want 30", got)
	}
}

func TestPrevNextMonthRollsYear(t *testing.T) {
	if y, m := PrevMonth(1405, 1); y != 1404 || m != 12 {
		t.Fatalf("PrevMonth(1405,1) = %d,%d want 1404,12", y, m)
	}
	if y, m := NextMonth(1405, 12); y != 1406 || m != 1 {
		t.Fatalf("NextMonth(1405,12) = %d,%d want 1406,1", y, m)
	}
}
