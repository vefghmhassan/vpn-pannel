package handlers

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// maxAppMessages caps how many reminders an admin can define, mirroring the
// wheel's guard against an oversized payload.
const maxAppMessages = 50

// appMessageDTO is the shape served to the mobile app. Snake_case, matching the
// other /api/v1 responses (the model's own tags are camelCase and are used by the
// admin form instead).
type appMessageDTO struct {
	ID                uint   `json:"id"`
	Position          int    `json:"position"`
	Title             string `json:"title"`
	Body              string `json:"body"`
	InactiveDays      int    `json:"inactive_days"`
	RepeatEveryDays   int    `json:"repeat_every_days"`
	MaxShows          int    `json:"max_shows"`
	ShowInApp         bool   `json:"show_in_app"`
	LocalNotification bool   `json:"local_notification"`
}

// ApiMessages serves the active reminders plus how long this caller has been away,
// so the app can decide what to display now and what to schedule as a local
// notification later.
//
// Read-only on purpose: it must not touch LastSeenAt, or it would erase the very
// gap it is reporting.
func ApiMessages(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}

	user, err := findOrCreateUserByToken(token)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if !user.IsActive {
		return fiber.ErrUnauthorized
	}

	var rows []models.AppMessage
	database.DB.Where("is_active = ?", true).
		Order("position asc, id asc").
		Find(&rows)

	// One clock reading for the whole response, so the gap and the server time it
	// is measured against describe the same instant.
	now := time.Now()
	daysAway, hasPrevious := daysSincePreviousOpen(user.ID, now)

	messages := make([]appMessageDTO, 0, len(rows))
	dueIDs := make([]uint, 0, len(rows))
	for _, m := range rows {
		messages = append(messages, appMessageDTO{
			ID:                m.ID,
			Position:          m.Position,
			Title:             m.Title,
			Body:              m.Body,
			InactiveDays:      m.InactiveDays,
			RepeatEveryDays:   m.RepeatEveryDays,
			MaxShows:          m.MaxShows,
			ShowInApp:         m.ShowInApp,
			LocalNotification: m.LocalNotification,
		})
		// A brand-new install has no gap to measure, so nothing is due yet —
		// otherwise a null LastSeenAt would read as "inactive forever".
		if hasPrevious && daysAway >= m.InactiveDays {
			dueIDs = append(dueIDs, m.ID)
		}
	}

	resp := fiber.Map{
		"messages":             messages,
		"days_since_last_seen": daysAway,
		// The server's view of what to show right now. The app still evaluates
		// the rules itself for local notifications, since it is not running then.
		"due_message_ids": dueIDs,
	}
	if prev, ok := previousOpenAt(user.ID, now); ok {
		resp["previous_open_at_unix"] = prev.Unix()
	} else {
		resp["previous_open_at_unix"] = nil
	}
	mergeInto(resp, serverClockFields(now))
	return c.JSON(resp)
}

// --- Admin ---

// MessagesPage renders the reminder editor.
func MessagesPage(c *fiber.Ctx) error {
	var messages []models.AppMessage
	database.DB.Order("position asc, id asc").Find(&messages)

	return c.Render("messages/index", fiber.Map{
		"title":       "پیام‌های یادآور",
		"messages":    messages,
		"maxMessages": maxAppMessages,
		"calendar":    string(calendarFromRequest(c)),
	})
}

// appMessageInput is one row of the admin table's JSON payload. ID is 0 for a row
// the admin just added.
type appMessageInput struct {
	ID                uint   `json:"id"`
	Title             string `json:"title"`
	Body              string `json:"body"`
	InactiveDays      int    `json:"inactiveDays"`
	RepeatEveryDays   int    `json:"repeatEveryDays"`
	MaxShows          int    `json:"maxShows"`
	ShowInApp         bool   `json:"showInApp"`
	LocalNotification bool   `json:"localNotification"`
	IsActive          bool   `json:"isActive"`
}

// MessagesUpdate saves the whole reminder table in one shot.
//
// Unlike the wheel, this cannot delete-and-recreate: the app counts how many times
// it has shown message #N, keyed by that ID, so recreating rows would silently
// reset every user's count. Existing rows are therefore updated in place and only
// rows the admin actually removed are deleted.
func MessagesUpdate(c *fiber.Ctx) error {
	raw := strings.TrimSpace(c.FormValue("messages_json"))
	if raw == "" {
		raw = "[]"
	}

	var in []appMessageInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid messages payload")
	}
	if len(in) > maxAppMessages {
		return fiber.NewError(fiber.StatusBadRequest, "too many messages")
	}

	position := 0
	keep := make([]uint, 0, len(in))
	updates := make([]models.AppMessage, 0, len(in))
	creates := make([]models.AppMessage, 0, len(in))

	for _, row := range in {
		title := strings.TrimSpace(row.Title)
		if title == "" {
			// A reminder with no title has nothing to show; drop it silently the
			// same way the wheel drops malformed values.
			continue
		}

		m := models.AppMessage{
			ID:                row.ID,
			Position:          position,
			Title:             title,
			Body:              strings.TrimSpace(row.Body),
			InactiveDays:      clampNonNegative(row.InactiveDays),
			RepeatEveryDays:   clampNonNegative(row.RepeatEveryDays),
			MaxShows:          clampNonNegative(row.MaxShows),
			ShowInApp:         row.ShowInApp,
			LocalNotification: row.LocalNotification,
			IsActive:          row.IsActive,
		}
		position++

		if row.ID == 0 {
			creates = append(creates, m)
		} else {
			updates = append(updates, m)
			keep = append(keep, row.ID)
		}
	}

	err := database.DB.Transaction(func(tx *gorm.DB) error {
		// Drop whatever the admin removed from the table. GORM refuses a global
		// delete without a where clause, hence the "1 = 1" when nothing is kept.
		del := tx.Session(&gorm.Session{})
		if len(keep) > 0 {
			del = del.Where("id NOT IN ?", keep)
		} else {
			del = del.Where("1 = 1")
		}
		if err := del.Delete(&models.AppMessage{}).Error; err != nil {
			return err
		}

		for i := range updates {
			m := updates[i]
			// Select every column explicitly so unchecked boxes persist as false;
			// a plain Updates() would skip those zero values.
			if err := tx.Model(&models.AppMessage{ID: m.ID}).
				Select("position", "title", "body", "inactive_days", "repeat_every_days",
					"max_shows", "show_in_app", "local_notification", "is_active").
				Updates(m).Error; err != nil {
				return err
			}
		}
		if len(creates) > 0 {
			if err := tx.Create(&creates).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Redirect("/admin/messages")
}

func clampNonNegative(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
