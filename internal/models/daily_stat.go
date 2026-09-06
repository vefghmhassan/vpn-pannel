package models

import "time"

// DailyStat is one pre-aggregated row per local calendar day — the rollup behind
// the admin analytics dashboard.
//
// It exists because app_open_events grows by one row per app launch, so charting
// a few months of history straight off it means scanning millions of rows on
// every page load. Everything here is derivable from app_open_events, users and
// online_snapshots; the table is a cache, never a source of truth, and
// services.RecomputeDay rebuilds any day from scratch.
//
// Day is stored as a DATE at local midnight. Note that day-level rollups are NOT
// enough on their own: DAU/WAU/MAU are distinct-user counts, and distinct counts
// do not sum across days, so the rolling windows are still computed live against
// app_open_events (see internal/analytics).
type DailyStat struct {
	Day       time.Time `gorm:"primaryKey;type:date"`
	UpdatedAt time.Time

	// ActiveUsers is the day's DAU: users with at least one app-open event.
	ActiveUsers int64
	// NewUsers counts users whose account was created that day, whether or not
	// they went on to open the app — the acquisition number.
	NewUsers int64
	// ActiveNewUsers counts the subset of ActiveUsers who registered that same
	// day. It exists separately from NewUsers because the two answer different
	// questions and only this one composes: ActiveNewUsers + ReturningUsers is
	// exactly ActiveUsers, so the dashboard can stack them without the bar
	// overshooting the day's real active total.
	ActiveNewUsers int64
	// ReturningUsers is ActiveUsers minus ActiveNewUsers — how many came back
	// rather than arrived.
	ReturningUsers int64
	// TotalOpens is the raw app_open_events count (opens per user = this / ActiveUsers).
	TotalOpens int64
	// PeakOnline is the highest online_snapshots count recorded that day.
	PeakOnline int64
}
