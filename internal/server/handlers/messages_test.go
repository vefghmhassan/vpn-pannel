package handlers_test

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// messagesResponse mirrors POST /api/v1/messages.
type messagesResponse struct {
	Messages []struct {
		ID                uint   `json:"id"`
		Position          int    `json:"position"`
		Title             string `json:"title"`
		Body              string `json:"body"`
		InactiveDays      int    `json:"inactive_days"`
		RepeatEveryDays   int    `json:"repeat_every_days"`
		MaxShows          int    `json:"max_shows"`
		ShowInApp         bool   `json:"show_in_app"`
		LocalNotification bool   `json:"local_notification"`
	} `json:"messages"`
	DaysSinceLastSeen  int    `json:"days_since_last_seen"`
	PreviousOpenAtUnix *int64 `json:"previous_open_at_unix"`
	DueMessageIDs      []uint `json:"due_message_ids"`
	ServerTimeUnix     int64  `json:"server_time_unix"`
	ServerTimezone     string `json:"server_timezone"`
}

// clearMessages empties the table inside the test's transaction, so assertions on
// the full message list hold regardless of what a shared dev database already
// contains. The transaction rolls back, so real data is untouched.
func clearMessages(t *testing.T) {
	t.Helper()
	if err := database.DB.Where("1 = 1").Delete(&models.AppMessage{}).Error; err != nil {
		t.Fatalf("failed to clear messages: %v", err)
	}
}

func createMessage(t *testing.T, mutate func(*models.AppMessage)) *models.AppMessage {
	t.Helper()
	m := &models.AppMessage{
		Title:           testutil.UniqueName("msg"),
		Body:            "body",
		InactiveDays:    7,
		RepeatEveryDays: 7,
		ShowInApp:       true,
		IsActive:        true,
	}
	if mutate != nil {
		mutate(m)
	}
	if err := database.DB.Create(m).Error; err != nil {
		t.Fatalf("failed to create test message: %v", err)
	}
	return m
}

// seedOpen backdates an app-open event so the user looks like they were away.
func seedOpen(t *testing.T, userID uint, ago time.Duration) {
	t.Helper()
	if err := database.DB.Create(&models.AppOpenEvent{
		UserID: userID, CreatedAt: time.Now().Add(-ago),
	}).Error; err != nil {
		t.Fatalf("failed to seed an app-open event: %v", err)
	}
}

func TestApiMessages_ReturnsOnlyActiveInPositionOrder(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)

	second := createMessage(t, func(m *models.AppMessage) { m.Position = 2; m.Title = "second" })
	first := createMessage(t, func(m *models.AppMessage) { m.Position = 1; m.Title = "first" })
	hidden := createMessage(t, func(m *models.AppMessage) { m.Position = 0; m.Title = "hidden"; m.IsActive = false })

	token := testutil.UniqueName("msg-token")
	resp := testutil.DoJSON(t, app, "POST", "/api/v1/messages", map[string]string{"token": token}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out messagesResponse
	testutil.DecodeJSON(t, resp, &out)

	if len(out.Messages) != 2 {
		t.Fatalf("expected only the 2 active messages, got %d", len(out.Messages))
	}
	if out.Messages[0].ID != first.ID || out.Messages[1].ID != second.ID {
		t.Errorf("expected position order (%d then %d), got %d then %d",
			first.ID, second.ID, out.Messages[0].ID, out.Messages[1].ID)
	}
	for _, m := range out.Messages {
		if m.ID == hidden.ID {
			t.Errorf("inactive message %d must not be served", hidden.ID)
		}
	}
	if out.ServerTimezone == "" || out.ServerTimeUnix == 0 {
		t.Errorf("expected the server clock block, got %+v", out)
	}
}

func TestApiMessages_ComputesDayGapAndDueList(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)

	weekly := createMessage(t, func(m *models.AppMessage) { m.InactiveDays = 7 })
	monthly := createMessage(t, func(m *models.AppMessage) { m.InactiveDays = 30 })

	token := testutil.UniqueName("gap-token")
	user := testutil.CreateUser(t, func(u *models.User) { u.ClientToken = &token })
	seedOpen(t, user.ID, 9*24*time.Hour)

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/messages", map[string]string{"token": token}, nil)
	var out messagesResponse
	testutil.DecodeJSON(t, resp, &out)

	if out.DaysSinceLastSeen != 9 {
		t.Errorf("expected days_since_last_seen=9, got %d", out.DaysSinceLastSeen)
	}
	if out.PreviousOpenAtUnix == nil {
		t.Errorf("expected previous_open_at_unix to be reported")
	}
	if len(out.DueMessageIDs) != 1 || out.DueMessageIDs[0] != weekly.ID {
		t.Errorf("expected only the 7-day message (%d) to be due, got %v", weekly.ID, out.DueMessageIDs)
	}
	for _, id := range out.DueMessageIDs {
		if id == monthly.ID {
			t.Errorf("the 30-day message must not be due after only 9 days")
		}
	}
}

// The regression that would silently break the whole feature: ApiLastConnection
// stamps LastSeenAt and logs an open event on every launch, so measuring from the
// newest event would report a gap of zero whenever the app checks in first.
func TestApiMessages_DayGapSurvivesLastConnectionFirst(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	createMessage(t, func(m *models.AppMessage) { m.InactiveDays = 7 })

	token := testutil.UniqueName("order-token")
	user := testutil.CreateUser(t, func(u *models.User) { u.ClientToken = &token })
	seedOpen(t, user.ID, 9*24*time.Hour)

	// The app checks in before asking for messages.
	if resp := testutil.DoJSON(t, app, "POST", "/api/v1/last-connection",
		map[string]string{"token": token}, nil); resp.StatusCode != 200 {
		t.Fatalf("expected the check-in to succeed, got %d", resp.StatusCode)
	}

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/messages", map[string]string{"token": token}, nil)
	var out messagesResponse
	testutil.DecodeJSON(t, resp, &out)

	if out.DaysSinceLastSeen != 9 {
		t.Fatalf("expected the gap to stay 9 after a check-in, got %d — the current session is leaking into the measurement", out.DaysSinceLastSeen)
	}
	if len(out.DueMessageIDs) != 1 {
		t.Errorf("expected the message to still be due, got %v", out.DueMessageIDs)
	}
}

// A fresh install has no gap to measure and must not be treated as "away forever".
func TestApiMessages_FreshInstallHasNoDueMessages(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	createMessage(t, func(m *models.AppMessage) { m.InactiveDays = 7 })

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/messages",
		map[string]string{"token": testutil.UniqueName("new-token")}, nil)
	var out messagesResponse
	testutil.DecodeJSON(t, resp, &out)

	if out.DaysSinceLastSeen != 0 {
		t.Errorf("expected days_since_last_seen=0 for a brand-new user, got %d", out.DaysSinceLastSeen)
	}
	if out.PreviousOpenAtUnix != nil {
		t.Errorf("expected previous_open_at_unix to be null, got %v", *out.PreviousOpenAtUnix)
	}
	if len(out.DueMessageIDs) != 0 {
		t.Errorf("a brand-new user must have nothing due, got %v", out.DueMessageIDs)
	}
}

// An inactive_days of 0 targets everyone — but still only once there is a gap to
// measure, so a first-launch user does not get spammed.
func TestApiMessages_ZeroInactiveDaysTargetsReturningUsers(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	everyone := createMessage(t, func(m *models.AppMessage) { m.InactiveDays = 0 })

	token := testutil.UniqueName("zero-token")
	user := testutil.CreateUser(t, func(u *models.User) { u.ClientToken = &token })
	seedOpen(t, user.ID, 2*time.Hour) // same day, but a real previous visit

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/messages", map[string]string{"token": token}, nil)
	var out messagesResponse
	testutil.DecodeJSON(t, resp, &out)

	if out.DaysSinceLastSeen != 0 {
		t.Errorf("expected a same-day gap of 0, got %d", out.DaysSinceLastSeen)
	}
	if len(out.DueMessageIDs) != 1 || out.DueMessageIDs[0] != everyone.ID {
		t.Errorf("expected the inactive_days=0 message to be due, got %v", out.DueMessageIDs)
	}
}

// --- Admin editor ---

func postMessages(t *testing.T, app *fiber.App, payload interface{}) int {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to encode payload: %v", err)
	}
	resp := testutil.DoForm(t, app, "POST", "/admin/messages", url.Values{
		"messages_json": {string(raw)},
	}, adminAuth(t))
	return resp.StatusCode
}

// The app keys its own "shown N times" counter on the message id, so an admin edit
// must never renumber existing rows. This is why the handler upserts instead of
// copying the wheel's delete-and-recreate.
func TestMessagesUpdate_KeepsExistingIDsStable(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	existing := createMessage(t, func(m *models.AppMessage) { m.Title = "before"; m.Body = "old body" })

	status := postMessages(t, app, []map[string]interface{}{{
		"id": existing.ID, "title": "after", "body": "new body",
		"inactiveDays": 3, "repeatEveryDays": 1, "maxShows": 5,
		"showInApp": true, "localNotification": true, "isActive": true,
	}})
	if status != 302 && status != 303 {
		t.Fatalf("expected a redirect, got %d", status)
	}

	var all []models.AppMessage
	database.DB.Find(&all)
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 message, got %d", len(all))
	}
	if all[0].ID != existing.ID {
		t.Errorf("expected id %d to survive the edit, got %d — client-side show counts would reset", existing.ID, all[0].ID)
	}
	if all[0].Title != "after" || all[0].Body != "new body" {
		t.Errorf("expected the edit to be applied, got %q / %q", all[0].Title, all[0].Body)
	}
	if all[0].InactiveDays != 3 || all[0].RepeatEveryDays != 1 || all[0].MaxShows != 5 {
		t.Errorf("expected the numeric fields to be saved, got %+v", all[0])
	}
}

func TestMessagesUpdate_CreatesNewAndDeletesRemoved(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	keep := createMessage(t, func(m *models.AppMessage) { m.Title = "keep" })
	drop := createMessage(t, func(m *models.AppMessage) { m.Title = "drop" })

	// Submit only `keep`, plus a brand-new row (id 0).
	status := postMessages(t, app, []map[string]interface{}{
		{"id": keep.ID, "title": "keep", "body": "b", "inactiveDays": 7, "repeatEveryDays": 7, "isActive": true},
		{"id": 0, "title": "fresh", "body": "b", "inactiveDays": 14, "repeatEveryDays": 7, "isActive": true},
	})
	if status != 302 && status != 303 {
		t.Fatalf("expected a redirect, got %d", status)
	}

	var all []models.AppMessage
	database.DB.Order("position asc").Find(&all)
	if len(all) != 2 {
		t.Fatalf("expected 2 messages after the save, got %d", len(all))
	}
	if all[0].ID != keep.ID {
		t.Errorf("expected the kept row to retain id %d, got %d", keep.ID, all[0].ID)
	}
	if all[1].Title != "fresh" || all[1].ID == 0 {
		t.Errorf("expected the new row to be created with a real id, got %+v", all[1])
	}
	var gone int64
	database.DB.Model(&models.AppMessage{}).Where("id = ?", drop.ID).Count(&gone)
	if gone != 0 {
		t.Errorf("expected the removed row to be deleted")
	}
}

// The project's recurring GORM trap: an unchecked box must persist as false.
func TestMessagesUpdate_UncheckedBoxesPersistAsFalse(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	existing := createMessage(t, func(m *models.AppMessage) {
		m.ShowInApp = true
		m.LocalNotification = true
		m.IsActive = true
	})

	postMessages(t, app, []map[string]interface{}{{
		"id": existing.ID, "title": "t", "body": "b",
		"inactiveDays": 7, "repeatEveryDays": 7,
		"showInApp": false, "localNotification": false, "isActive": false,
	}})

	var after models.AppMessage
	database.DB.First(&after, existing.ID)
	if after.ShowInApp || after.LocalNotification || after.IsActive {
		t.Errorf("expected all three flags to persist as false, got %+v", after)
	}
}

func TestMessagesUpdate_RejectsInvalidPayload(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/messages", url.Values{
		"messages_json": {"{not json"},
	}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for a malformed payload, got %d", resp.StatusCode)
	}
}

func TestMessagesUpdate_SkipsRowsWithoutATitle(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	postMessages(t, app, []map[string]interface{}{
		{"id": 0, "title": "   ", "body": "no title", "isActive": true},
		{"id": 0, "title": "real", "body": "b", "isActive": true},
	})

	var all []models.AppMessage
	database.DB.Find(&all)
	if len(all) != 1 || all[0].Title != "real" {
		t.Errorf("expected only the titled row to be saved, got %+v", all)
	}
}

func TestMessagesPage_RendersExistingRows(t *testing.T) {
	app := apptest.New(t)
	clearMessages(t)
	m := createMessage(t, func(x *models.AppMessage) { x.Title = testutil.UniqueName("shown-title") })

	resp := testutil.DoJSON(t, app, "GET", "/admin/messages", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), m.Title) {
		t.Errorf("expected the message title to appear on the admin page")
	}
}
