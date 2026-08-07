package models

import "time"

// AppMessage is an admin-authored reminder shown inside the mobile app — for
// example "you haven't opened the app in a week". The app both displays these
// in-app and schedules them as its own *local* notifications; nothing is pushed
// from the server, so no FCM token is involved.
//
// How often a message has already been shown to a given user is tracked by the
// app, not here. That makes the row ID part of the contract: the admin form
// updates rows in place rather than replacing the table, so an edit never
// resets a user's count. See MessagesUpdate in handlers/messages.go.
type AppMessage struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	// Display order, assigned from the admin table's row order.
	Position int    `gorm:"not null;default:0" json:"position"`
	Title    string `gorm:"size:120;not null" json:"title"`
	Body     string `gorm:"size:1000;not null" json:"body"`

	// Show to users who haven't opened the app for at least this many days.
	// 0 targets everyone.
	//
	// No `default:` tag on either of the next two fields: 0 is a legitimate admin
	// choice, and a non-zero default would make GORM skip the zero value on save
	// so the DB silently substituted the default instead — the same bug class
	// documented on User.IsActive and AppSettings.WheelEnabled. The admin form
	// pre-fills 7 for new rows instead.
	InactiveDays int `gorm:"not null" json:"inactiveDays"`
	// Re-show cadence in days. 1 means every day (several days in a row).
	RepeatEveryDays int `gorm:"not null" json:"repeatEveryDays"`
	// Stop after this many shows. 0 means unlimited. Enforced by the app.
	MaxShows int `gorm:"not null;default:0" json:"maxShows"`

	// Delivery channels; both may be on at once.
	// `default:false` rather than no tag so AutoMigrate can add the columns to
	// existing rows without NULLs. Safe in a way `default:true` would not be:
	// when GORM skips the zero value the DB substitutes false, which is the
	// value the admin asked for anyway.
	ShowInApp         bool `gorm:"not null;default:false" json:"showInApp"`
	LocalNotification bool `gorm:"not null;default:false" json:"localNotification"`

	IsActive bool `gorm:"not null;default:false" json:"isActive"`
}
