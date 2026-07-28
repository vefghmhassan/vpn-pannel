// Package calendar converts between the Gregorian calendar (used internally for
// all stored timestamps) and the Jalali (Persian/Shamsi) and Hijri (Islamic/Qamari,
// tabular/arithmetic variant) calendars, purely for admin-panel display and
// date-range selection. No external service or dependency is used.
package calendar

import (
	"fmt"
	"math"
	"time"
)

// System identifies which calendar a date should be interpreted/rendered in.
type System string

const (
	Gregorian System = "gregorian"
	Jalali    System = "jalali"
	Hijri     System = "hijri"
)

// ParseSystem normalizes a query/cookie value to a known System, defaulting to Gregorian.
func ParseSystem(s string) System {
	switch System(s) {
	case Jalali:
		return Jalali
	case Hijri:
		return Hijri
	default:
		return Gregorian
	}
}

var jalaliMonthNames = [12]string{
	"فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
	"مهر", "آبان", "آذر", "دی", "بهمن", "اسفند",
}

var hijriMonthNames = [12]string{
	"محرم", "صفر", "ربیع‌الاول", "ربیع‌الثانی", "جمادی‌الاول", "جمادی‌الثانی",
	"رجب", "شعبان", "رمضان", "شوال", "ذی‌القعده", "ذی‌الحجه",
}

// MonthNames returns the 12 month names for the given system (nil for Gregorian,
// callers should fall back to numeric months).
func MonthNames(system System) []string {
	switch system {
	case Jalali:
		return jalaliMonthNames[:]
	case Hijri:
		return hijriMonthNames[:]
	default:
		return nil
	}
}

// --- Gregorian <-> Julian Day Number (Fliegel & Van Flandern algorithm) ---

func gregorianToJDN(y, m, d int) int {
	a := (14 - m) / 12
	y2 := y + 4800 - a
	m2 := m + 12*a - 3
	return d + (153*m2+2)/5 + 365*y2 + y2/4 - y2/100 + y2/400 - 32045
}

func jdnToGregorian(jdn int) (y, m, d int) {
	a := jdn + 32044
	b := (4*a + 3) / 146097
	c := a - (146097*b)/4
	dd := (4*c + 3) / 1461
	e := c - (1461*dd)/4
	m2 := (5*e + 2) / 153
	d = e - (153*m2+2)/5 + 1
	m = m2 + 3 - 12*(m2/10)
	y = 100*b + dd - 4800 + m2/10
	return y, m, d
}

func timeToJDN(t time.Time) int {
	return gregorianToJDN(t.Year(), int(t.Month()), t.Day())
}

func jdnToDate(jdn int, hour, min, sec int, loc *time.Location) time.Time {
	y, m, d := jdnToGregorian(jdn)
	return time.Date(y, time.Month(m), d, hour, min, sec, 0, loc)
}

// floorDiv and floorMod implement floored (not truncated) integer division, which
// is what the cyclical Jalali arithmetic below assumes. Go's native "/" and "%"
// truncate toward zero, which silently gives wrong results once the intermediate
// year offset goes negative (dates before ~1600 CE) — see calendar_test.go's
// TestVeryEarlyDateRoundTrip, which caught this.
func floorDiv(a, b int) int {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func floorMod(a, b int) int {
	m := a % b
	if m != 0 && (a < 0) != (b < 0) {
		m += b
	}
	return m
}

// --- Jalali (Persian/Shamsi) <-> Julian Day Number (33-year cycle algorithm) ---

// jalaliToJDN converts a Jalali (Shamsi) date to a Julian Day Number.
func jalaliToJDN(jy, jm, jd int) int {
	jy1 := jy - 979
	jm1 := jm - 1
	jd1 := jd - 1

	jDayNo := 365*jy1 + floorDiv(jy1, 33)*8 + floorDiv(floorMod(jy1, 33)+3, 4)
	for i := 0; i < jm1; i++ {
		if i < 6 {
			jDayNo += 31
		} else {
			jDayNo += 30
		}
	}
	jDayNo += jd1

	// Epoch JDN for 1 Farvardin 979, calibrated against known anchors (see calendar_test.go).
	return jDayNo + 2305527
}

// jdnToJalali converts a Julian Day Number to a Jalali (Shamsi) date.
func jdnToJalali(jdn int) (jy, jm, jd int) {
	jDayNo := jdn - 2305527
	jy1 := 979 + 33*floorDiv(jDayNo, 12053)
	jDayNo = floorMod(jDayNo, 12053)

	jy1 += 4 * floorDiv(jDayNo, 1461)
	jDayNo = floorMod(jDayNo, 1461)

	if jDayNo >= 366 {
		jy1 += floorDiv(jDayNo-1, 365)
		jDayNo = floorMod(jDayNo-1, 365)
	}

	var monthLen int
	i := 0
	for ; i < 11; i++ {
		if i < 6 {
			monthLen = 31
		} else {
			monthLen = 30
		}
		if jDayNo < monthLen {
			break
		}
		jDayNo -= monthLen
	}
	jm = i + 1
	jd = jDayNo + 1
	jy = jy1
	return
}

// GregorianToJalali converts a Gregorian time.Time to a Jalali (Shamsi) y/m/d.
func GregorianToJalali(t time.Time) (int, int, int) {
	return jdnToJalali(timeToJDN(t))
}

// JalaliToGregorian converts a Jalali (Shamsi) y/m/d (plus a time-of-day) to a Gregorian time.Time.
func JalaliToGregorian(jy, jm, jd, hour, min, sec int, loc *time.Location) time.Time {
	return jdnToDate(jalaliToJDN(jy, jm, jd), hour, min, sec, loc)
}

// JalaliDaysInMonth returns how many days the given Jalali month has.
func JalaliDaysInMonth(jy, jm int) int {
	if jm <= 6 {
		return 31
	}
	if jm <= 11 {
		return 30
	}
	// 12th month (اسفند): 30 in a leap year, else 29. Determine leap-ness by
	// comparing day-count between this Esfand 1 and next year's Farvardin 1.
	thisEsfand1 := jalaliToJDN(jy, 12, 1)
	nextFarvardin1 := jalaliToJDN(jy+1, 1, 1)
	if nextFarvardin1-thisEsfand1 == 30 {
		return 30
	}
	return 29
}

// --- Hijri (Islamic/Qamari, tabular/civil variant) <-> Julian Day Number ---
// Standard algorithm from Reingold & Dershowitz, "Calendrical Calculations".

const hijriEpoch = 1948440 // JDN of 1 Muharram, 1 AH

func hijriToJDN(y, m, d int) int {
	return d + int(math.Ceil(29.5*float64(m-1))) + (y-1)*354 + (3+11*y)/30 + hijriEpoch - 1
}

func jdnToHijri(jdn int) (y, m, d int) {
	jd := float64(jdn) + 0.5
	y = int(math.Floor((30*(jd-float64(hijriEpoch)) + 10646) / 10631))
	m = int(math.Min(12, math.Ceil((jd-float64(29+hijriToJDN(y, 1, 1)))/29.5)+1))
	d = jdn - hijriToJDN(y, m, 1) + 1
	return
}

// GregorianToHijri converts a Gregorian time.Time to a Hijri (Qamari) y/m/d.
func GregorianToHijri(t time.Time) (int, int, int) {
	return jdnToHijri(timeToJDN(t))
}

// HijriToGregorian converts a Hijri (Qamari) y/m/d (plus a time-of-day) to a Gregorian time.Time.
func HijriToGregorian(hy, hm, hd, hour, min, sec int, loc *time.Location) time.Time {
	return jdnToDate(hijriToJDN(hy, hm, hd), hour, min, sec, loc)
}

// HijriDaysInMonth returns how many days the given Hijri month has (odd months
// have 30 days, even months 29, except the 12th month in a leap year has 30).
func HijriDaysInMonth(hy, hm int) int {
	nextY, nextM := hy, hm+1
	if nextM > 12 {
		nextY, nextM = hy+1, 1
	}
	return hijriToJDN(nextY, nextM, 1) - hijriToJDN(hy, hm, 1)
}

// --- Generic helpers used by handlers/templates ---

// ToParts converts a Gregorian time.Time to y/m/d in the given system.
func ToParts(t time.Time, system System) (y, m, d int) {
	switch system {
	case Jalali:
		return GregorianToJalali(t)
	case Hijri:
		return GregorianToHijri(t)
	default:
		return t.Year(), int(t.Month()), t.Day()
	}
}

// FromParts converts y/m/d in the given system (plus a time-of-day) to a Gregorian time.Time.
func FromParts(system System, y, m, d, hour, min, sec int, loc *time.Location) time.Time {
	switch system {
	case Jalali:
		return JalaliToGregorian(y, m, d, hour, min, sec, loc)
	case Hijri:
		return HijriToGregorian(y, m, d, hour, min, sec, loc)
	default:
		return time.Date(y, time.Month(m), d, hour, min, sec, 0, loc)
	}
}

// DaysInMonth returns the number of days in the given system's month.
func DaysInMonth(system System, y, m int) int {
	switch system {
	case Jalali:
		return JalaliDaysInMonth(y, m)
	case Hijri:
		return HijriDaysInMonth(y, m)
	default:
		return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
	}
}

// FormatDateTime renders a nullable timestamp as "YYYY/MM/DD HH:MM" in the given
// system, or "—" if t is nil.
func FormatDateTime(t *time.Time, system System) string {
	if t == nil || t.IsZero() {
		return "—"
	}
	y, m, d := ToParts(*t, system)
	return fmt.Sprintf("%04d/%02d/%02d %02d:%02d", y, m, d, t.Hour(), t.Minute())
}

// MonthLabel returns "3 (خرداد)" style labels for pickers, or just "3" for Gregorian.
func MonthLabel(system System, month int) string {
	names := MonthNames(system)
	if names == nil || month < 1 || month > 12 {
		return fmt.Sprintf("%d", month)
	}
	return fmt.Sprintf("%d - %s", month, names[month-1])
}
