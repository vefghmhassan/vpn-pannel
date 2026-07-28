package calendar

import (
	"testing"
	"time"
)

func TestGregorianJalaliRoundTrip(t *testing.T) {
	cases := []time.Time{
		time.Date(2024, 3, 20, 0, 0, 0, 0, time.UTC),
		time.Date(1979, 2, 11, 0, 0, 0, 0, time.UTC),
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
	}
	for _, g := range cases {
		jy, jm, jd := GregorianToJalali(g)
		back := JalaliToGregorian(jy, jm, jd, 0, 0, 0, time.UTC)
		if !back.Equal(g) {
			t.Errorf("round trip failed for %v: jalali=%d-%02d-%02d back=%v", g, jy, jm, jd, back)
		}
	}
}

func TestJalaliKnownAnchors(t *testing.T) {
	// Nowruz 1403 was 2024-03-20.
	jy, jm, jd := GregorianToJalali(time.Date(2024, 3, 20, 0, 0, 0, 0, time.UTC))
	if jy != 1403 || jm != 1 || jd != 1 {
		t.Errorf("expected 1403-01-01, got %d-%02d-%02d", jy, jm, jd)
	}

	// Iranian revolution day: 1979-02-11 = 22 Bahman 1357.
	jy, jm, jd = GregorianToJalali(time.Date(1979, 2, 11, 0, 0, 0, 0, time.UTC))
	if jy != 1357 || jm != 11 || jd != 22 {
		t.Errorf("expected 1357-11-22, got %d-%02d-%02d", jy, jm, jd)
	}
}

func TestGregorianHijriRoundTrip(t *testing.T) {
	cases := []time.Time{
		time.Date(2024, 7, 7, 0, 0, 0, 0, time.UTC),
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		time.Date(622, 7, 19, 0, 0, 0, 0, time.UTC),
	}
	for _, g := range cases {
		hy, hm, hd := GregorianToHijri(g)
		back := HijriToGregorian(hy, hm, hd, 0, 0, 0, time.UTC)
		if !back.Equal(g) {
			t.Errorf("round trip failed for %v: hijri=%d-%02d-%02d back=%v", g, hy, hm, hd, back)
		}
	}
}

func TestHijriEpoch(t *testing.T) {
	// 1 Muharram, 1 AH is the well-known tabular-calendar epoch (622-07-19 Gregorian, proleptic).
	hy, hm, hd := GregorianToHijri(time.Date(622, 7, 19, 0, 0, 0, 0, time.UTC))
	if hy != 1 || hm != 1 || hd != 1 {
		t.Errorf("expected 1-01-01, got %d-%02d-%02d", hy, hm, hd)
	}
}

func TestDaysInMonth(t *testing.T) {
	if DaysInMonth(Jalali, 1403, 1) != 31 {
		t.Errorf("expected Farvardin to have 31 days")
	}
	if DaysInMonth(Jalali, 1403, 7) != 30 {
		t.Errorf("expected Mehr to have 30 days")
	}
	if DaysInMonth(Gregorian, 2024, 2) != 29 {
		t.Errorf("expected Feb 2024 (leap) to have 29 days")
	}
	if DaysInMonth(Gregorian, 2023, 2) != 28 {
		t.Errorf("expected Feb 2023 to have 28 days")
	}
	hijriDays := DaysInMonth(Hijri, 1446, 1)
	if hijriDays != 29 && hijriDays != 30 {
		t.Errorf("expected Hijri month to have 29 or 30 days, got %d", hijriDays)
	}
}

func TestHijriMonth12LeapLength(t *testing.T) {
	// Tabular Hijri leap years fall at positions {2,5,7,10,13,16,18,21,24,26,29}
	// of each 30-year cycle; month 12 (Dhu al-Hijjah) has 30 days in a leap year,
	// 29 otherwise. Year 2 is a leap year, year 1 is not.
	if got := HijriDaysInMonth(2, 12); got != 30 {
		t.Errorf("expected Hijri year 2 (leap) month 12 to have 30 days, got %d", got)
	}
	if got := HijriDaysInMonth(1, 12); got != 29 {
		t.Errorf("expected Hijri year 1 (non-leap) month 12 to have 29 days, got %d", got)
	}
	// Sum of all 12 month lengths in a year must equal 354 (or 355 if leap).
	total := 0
	for m := 1; m <= 12; m++ {
		total += HijriDaysInMonth(2, m)
	}
	if total != 355 {
		t.Errorf("expected leap Hijri year to total 355 days, got %d", total)
	}
}

func TestJalaliYearRollover(t *testing.T) {
	// Last day of Jalali 1402 (a non-leap year: 1402 % ... let's just derive it
	// from DaysInMonth) must roll into 1403-01-01 the next day.
	lastEsfandDay := DaysInMonth(Jalali, 1402, 12)
	g := JalaliToGregorian(1402, 12, lastEsfandDay, 0, 0, 0, time.UTC)
	nextDay := g.AddDate(0, 0, 1)
	jy, jm, jd := GregorianToJalali(nextDay)
	if jy != 1403 || jm != 1 || jd != 1 {
		t.Errorf("expected rollover to 1403-01-01, got %d-%02d-%02d", jy, jm, jd)
	}
}

func TestHijriYearRollover(t *testing.T) {
	lastDhulHijjahDay := DaysInMonth(Hijri, 1445, 12)
	g := HijriToGregorian(1445, 12, lastDhulHijjahDay, 0, 0, 0, time.UTC)
	nextDay := g.AddDate(0, 0, 1)
	hy, hm, hd := GregorianToHijri(nextDay)
	if hy != 1446 || hm != 1 || hd != 1 {
		t.Errorf("expected rollover to 1446-01-01, got %d-%02d-%02d", hy, hm, hd)
	}
}

func TestVeryEarlyDateRoundTrip(t *testing.T) {
	// Well before the Hijri epoch and Jalali year 1 — exercises the algorithms
	// far from their "normal" operating range.
	g := time.Date(100, 1, 1, 0, 0, 0, 0, time.UTC)

	jy, jm, jd := GregorianToJalali(g)
	backJ := JalaliToGregorian(jy, jm, jd, 0, 0, 0, time.UTC)
	if !backJ.Equal(g) {
		t.Errorf("jalali round trip failed for %v: got back %v", g, backJ)
	}

	hy, hm, hd := GregorianToHijri(g)
	backH := HijriToGregorian(hy, hm, hd, 0, 0, 0, time.UTC)
	if !backH.Equal(g) {
		t.Errorf("hijri round trip failed for %v: got back %v", g, backH)
	}
}

func TestParseSystem(t *testing.T) {
	cases := map[string]System{
		"jalali":    Jalali,
		"hijri":     Hijri,
		"gregorian": Gregorian,
		"":          Gregorian,
		"nonsense":  Gregorian,
		"JALALI":    Gregorian, // case-sensitive by design; unknown values fall back
	}
	for in, want := range cases {
		if got := ParseSystem(in); got != want {
			t.Errorf("ParseSystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatDateTime(t *testing.T) {
	if FormatDateTime(nil, Gregorian) != "—" {
		t.Errorf("expected em dash for nil time")
	}
	tm := time.Date(2024, 3, 20, 14, 5, 0, 0, time.UTC)
	got := FormatDateTime(&tm, Jalali)
	want := "1403/01/01 14:05"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
