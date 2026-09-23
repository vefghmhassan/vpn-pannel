package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// These tests run the real handlers against a real GORM database, seeded to
// match what the live panel actually holds: every config is a separate node row
// with a unique name, and one server backs hundreds of them. That shape is the
// whole risk — the naming rule and the link rewriting both run per row.

// fleet mirrors the live panel's name bases and per-address row counts, measured
// by sampling its splash endpoint.
var fleet = []struct {
	address string
	port    int
	country string
	base    string
	count   int
}{
	{"5.161.158.200", 443, "US", "ash-one-C-A", 198},
	{"5.161.158.200", 8443, "US", "AshOne-C-AA", 189},
	{"2.29.60.163", 443, "FI", "fi  7", 592},
	{"174.138.13.95", 443, "NL", "Am", 98},
	{"65.109.216.204", 8443, "FI", "Helk2--new", 89},
}

func seedFleet(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_pragma=foreign_keys(1)"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.V2RayNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A shared in-memory database outlives a single connection, so start clean.
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.V2RayNode{})

	var rows []models.V2RayNode
	for _, f := range fleet {
		for i := 1; i <= f.count; i++ {
			name := fmt.Sprintf("%s-%d", f.base, i)
			rows = append(rows, models.V2RayNode{
				Name:        name,
				Address:     f.address,
				Port:        f.port,
				Protocol:    "vless",
				CountryCode: f.country,
				CountryFlag: "/country/" + f.country + ".png",
				IsActive:    true,
				Tags:        "seeded",
				// The live links carry the label in the fragment and a query
				// string the panel never regenerates, so both must survive.
				RawLink: fmt.Sprintf(
					"vless://11111111-2222-3333-4444-555555555555@%s:%d"+
						"?type=tcp&encryption=none&path=%%2F&host=store.steampowered.com"+
						"&headerType=http&security=none#%s",
					f.address, f.port, url.PathEscape(f.base)),
			})
		}
	}
	if err := db.CreateInBatches(rows, 200).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// database.DB is process-global and the Postgres-backed tests in this
	// package share it, so it goes back exactly as it was found.
	previous := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previous })
	return db
}

func panelApp() *fiber.App {
	app := fiber.New()
	app.Post("/admin/v2ray/bulk-active", V2RayBulkActive)
	app.Post("/admin/v2ray/replace-address", V2RayReplaceAddress)
	app.Post("/admin/v2ray/:id/active", V2RaySetActive)
	return app
}

// postForm sends exactly what the botchecker client sends: a urlencoded body
// with a JSON Accept header. Testing the shape the real caller uses is the
// point — a handler that only answers the browser form would pass otherwise.
func postForm(t *testing.T, app *fiber.App, path string, body map[string]any, out any) int {
	t.Helper()
	form := url.Values{}
	for k, v := range body {
		form.Set(k, fmt.Sprint(v))
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := app.Test(req, 60_000)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return resp.StatusCode
}

func TestBulkActiveHidesEveryConfigOnOneServer(t *testing.T) {
	db := seedFleet(t)
	app := panelApp()

	var out struct {
		Updated int `json:"updated"`
	}
	if code := postForm(t, app, "/admin/v2ray/bulk-active",
		map[string]any{"address": "5.161.158.200", "active": "false"}, &out); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	// Both ports on that machine, and nothing else.
	if want := 198 + 189; out.Updated != want {
		t.Fatalf("updated %d, want %d", out.Updated, want)
	}
	var stillActive int64
	db.Model(&models.V2RayNode{}).Where("address = ? AND is_active = ?", "5.161.158.200", true).Count(&stillActive)
	if stillActive != 0 {
		t.Fatalf("%d configs still reach the app", stillActive)
	}
	var others int64
	db.Model(&models.V2RayNode{}).Where("address <> ? AND is_active = ?", "5.161.158.200", true).Count(&others)
	if want := int64(592 + 98 + 89); others != want {
		t.Fatalf("collateral damage: %d other configs active, want %d", others, want)
	}
}

func TestReplaceMovesEveryConfigAndItsLink(t *testing.T) {
	db := seedFleet(t)
	app := panelApp()

	var out replaceResult
	if code := postForm(t, app, "/admin/v2ray/replace-address", map[string]any{
		"old_address": "5.161.158.200",
		"new_address": "49.12.100.7",
		"new_port":    2087,
		"country":     "DE",
		"activate":    "true",
	}, &out); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if want := 198 + 189; out.Updated != want || out.Skipped != 0 {
		t.Fatalf("updated=%d skipped=%d, want %d/0 (%v)", out.Updated, out.Skipped, want, out.Errors)
	}

	var left int64
	db.Model(&models.V2RayNode{}).Where("address = ?", "5.161.158.200").Count(&left)
	if left != 0 {
		t.Fatalf("%d configs still point at the dead address", left)
	}

	var moved []models.V2RayNode
	db.Where("address = ?", "49.12.100.7").Find(&moved)
	if len(moved) != out.Updated {
		t.Fatalf("found %d moved, handler reported %d", len(moved), out.Updated)
	}

	for _, n := range moved {
		if n.Port != 2087 {
			t.Fatalf("%s kept port %d", n.Name, n.Port)
		}
		if n.CountryCode != "DE" || n.CountryFlag != "/country/DE.png" {
			t.Fatalf("%s kept country %q %q", n.Name, n.CountryCode, n.CountryFlag)
		}
		if !n.IsActive {
			t.Fatalf("%s came back hidden", n.Name)
		}
		// The client dials the link, so the link is what has to have moved.
		if !strings.Contains(n.RawLink, "@49.12.100.7:2087") {
			t.Fatalf("%s link still points elsewhere: %s", n.Name, n.RawLink)
		}
		if strings.Contains(n.RawLink, "5.161.158.200") {
			t.Fatalf("%s link still mentions the old address: %s", n.Name, n.RawLink)
		}
		// Everything that identifies the config has to survive untouched.
		if !strings.Contains(n.RawLink, "11111111-2222-3333-4444-555555555555") {
			t.Fatalf("%s lost its uuid: %s", n.Name, n.RawLink)
		}
		if !strings.Contains(n.RawLink, "host=store.steampowered.com") {
			t.Fatalf("%s lost its query: %s", n.Name, n.RawLink)
		}
		if !strings.Contains(n.Tags, "was:") {
			t.Fatalf("%s lost its original name: %q", n.Name, n.Tags)
		}
	}
}

func TestMovedConfigsAnnounceTheNewCountryToTheClient(t *testing.T) {
	seedFleet(t)
	app := panelApp()

	if code := postForm(t, app, "/admin/v2ray/replace-address", map[string]any{
		"old_address": "174.138.13.95", "new_address": "49.12.100.7",
		"country": "DE", "activate": "true",
	}, &struct{}{}); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	var moved []models.V2RayNode
	database.DB.Where("address = ?", "49.12.100.7").Find(&moved)
	if len(moved) != 98 {
		t.Fatalf("moved %d", len(moved))
	}
	for _, n := range moved {
		// The label is what a client puts on screen. "Am" was Amsterdam; a
		// config now in Germany that still says Am is the bug this guards.
		u, err := url.Parse(n.RawLink)
		if err != nil {
			t.Fatalf("parse %s: %v", n.RawLink, err)
		}
		if u.Fragment != "de" {
			t.Fatalf("%s shows label %q to the user, want %q", n.Name, u.Fragment, "de")
		}
	}
}

func TestRenamingKeepsNumbersAndStaysUnique(t *testing.T) {
	seedFleet(t)
	app := panelApp()

	if code := postForm(t, app, "/admin/v2ray/replace-address", map[string]any{
		"old_address": "5.161.158.200", "new_address": "49.12.100.7",
		"country": "DE", "activate": "true",
	}, &struct{}{}); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	var moved []models.V2RayNode
	database.DB.Where("address = ?", "49.12.100.7").Order("id").Find(&moved)

	seen := map[string]string{}
	for _, n := range moved {
		if prev, dup := seen[n.Name]; dup {
			t.Fatalf("duplicate name %q (also %s)", n.Name, prev)
		}
		seen[n.Name] = n.Tags
		if !strings.HasPrefix(n.Name, "de") {
			t.Fatalf("%q does not say Germany", n.Name)
		}
	}
	// "ash-one-C-A-142" -> "de-one-C-A-142": the location token goes, the
	// operator's own numbering stays.
	if _, ok := seen["de-one-C-A-142"]; !ok {
		t.Fatalf("expected de-one-C-A-142 among %d renamed configs", len(moved))
	}
	// The whole table still has to satisfy the unique index.
	var total, distinct int64
	database.DB.Model(&models.V2RayNode{}).Count(&total)
	database.DB.Model(&models.V2RayNode{}).Distinct("name").Count(&distinct)
	if total != distinct {
		t.Fatalf("%d rows but only %d distinct names", total, distinct)
	}
}

func TestReplaceOntoAnAddressThatAlreadyHasConfigs(t *testing.T) {
	seedFleet(t)
	app := panelApp()

	// Move one server onto another that is already live and already named "de":
	// names can now genuinely collide, which is what the unique index punishes.
	if code := postForm(t, app, "/admin/v2ray/replace-address", map[string]any{
		"old_address": "65.109.216.204", "new_address": "1.1.1.1", "country": "DE",
	}, &struct{}{}); code != http.StatusOK {
		t.Fatalf("first move: status %d", code)
	}
	if code := postForm(t, app, "/admin/v2ray/replace-address", map[string]any{
		"old_address": "174.138.13.95", "new_address": "1.1.1.1", "country": "DE",
	}, &struct{}{}); code != http.StatusOK {
		t.Fatalf("second move: status %d", code)
	}

	var total, distinct int64
	database.DB.Model(&models.V2RayNode{}).Count(&total)
	database.DB.Model(&models.V2RayNode{}).Distinct("name").Count(&distinct)
	if total != distinct {
		t.Fatalf("%d rows but only %d distinct names — the unique index would reject this", total, distinct)
	}
	var on int64
	database.DB.Model(&models.V2RayNode{}).Where("address = ?", "1.1.1.1").Count(&on)
	if want := int64(89 + 98); on != want {
		t.Fatalf("%d configs on the new address, want %d", on, want)
	}
}

func TestUnknownAddressChangesNothing(t *testing.T) {
	db := seedFleet(t)
	app := panelApp()

	var before int64
	db.Model(&models.V2RayNode{}).Count(&before)
	code := postForm(t, app, "/admin/v2ray/replace-address", map[string]any{
		"old_address": "203.0.113.9", "new_address": "49.12.100.7", "country": "DE",
	}, nil)
	if code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", code)
	}
	var after int64
	db.Model(&models.V2RayNode{}).Where("address = ?", "49.12.100.7").Count(&after)
	if after != 0 {
		t.Fatalf("%d rows moved on a no-op replace", after)
	}
}

func TestSingleNodeToggleIsScopedToThatNode(t *testing.T) {
	db := seedFleet(t)
	app := panelApp()

	var one models.V2RayNode
	db.Where("address = ?", "174.138.13.95").First(&one)

	var out struct {
		IsActive bool `json:"is_active"`
	}
	if code := postForm(t, app, fmt.Sprintf("/admin/v2ray/%d/active", one.ID),
		map[string]any{"active": "false"}, &out); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if out.IsActive {
		t.Fatal("node reported still active")
	}
	var hidden int64
	db.Model(&models.V2RayNode{}).Where("is_active = ?", false).Count(&hidden)
	if hidden != 1 {
		t.Fatalf("%d configs hidden, want exactly 1", hidden)
	}
}
