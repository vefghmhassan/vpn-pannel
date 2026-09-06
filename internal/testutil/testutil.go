// Package testutil provides shared test infrastructure for exercising the real
// application (routes, templates, GORM models) against the project's real Postgres
// database. Every test gets a fresh, fully-isolated view of the data: a transaction
// is opened before the test runs and rolled back afterward, so nothing written
// during a test is ever actually persisted.
//
// This package intentionally does NOT import "vpnpannel/internal/server" (or
// anything else that imports back into internal/server/handlers or
// internal/server/middleware) so that it stays importable from internal
// (white-box, "package handlers") test files without creating an import cycle.
// The HTTP-level app builder that does need "server" lives in the sibling
// package internal/testutil/apptest, used only from external ("_test") test files.
package testutil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/config"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

var (
	initOnce sync.Once
	initErr  error
	realDB   *gorm.DB
)

// bootstrap connects to the real project database exactly once per test binary
// run (config.Load + database.Connect + AutoMigrateAndSeed, mirroring
// cmd/server/main.go) and remembers the resulting connection as realDB.
func bootstrap(t *testing.T) {
	initOnce.Do(func() {
		if err := config.Load(); err != nil {
			initErr = err
			return
		}
		if err := database.Connect(config.Current.DatabaseURL); err != nil {
			initErr = err
			return
		}
		if err := database.AutoMigrateAndSeed(); err != nil {
			initErr = err
			return
		}
		realDB = database.DB
	})
	if initErr != nil {
		t.Fatalf("testutil bootstrap failed: %v (tests need a reachable Postgres — see .env / docker-compose 'db' service; run via `docker compose exec golang go test ./...`)", initErr)
	}
}

// SetupDB gives the calling test its own transaction over the real database:
// database.DB is pointed at it for the duration of the test and every write the
// test (or the handler code it calls) makes is rolled back on cleanup, so the
// real dev data is never actually touched.
func SetupDB(t *testing.T) *gorm.DB {
	t.Helper()
	bootstrap(t)

	tx := realDB.Begin()
	if tx.Error != nil {
		t.Fatalf("failed to begin test transaction: %v", tx.Error)
	}
	database.DB = tx
	t.Cleanup(func() {
		tx.Rollback()
		database.DB = realDB
	})
	return tx
}

// SetupSharedDB points database.DB at the shared connection pool instead of a
// per-test transaction, for tests that drive the handlers from many goroutines
// at once. A gorm transaction is bound to a single database connection, so
// hundreds of parallel handler goroutines issuing queries through the one
// *gorm.DB that SetupDB installs would contend on that connection rather than
// exercising the real pool.
//
// The trade-off is that nothing is rolled back: writes made through this land in
// the real database. Callers must clean up whatever they create and must never
// bulk-mutate rows they did not create themselves — in a dev environment those
// rows are the operator's live data.
func SetupSharedDB(t *testing.T) *gorm.DB {
	t.Helper()
	bootstrap(t)

	previous := database.DB
	database.DB = realDB
	t.Cleanup(func() { database.DB = previous })
	return realDB
}

// AdminToken mints a valid admin-panel JWT (as accepted by
// middleware.AuthRequired via the Authorization header) for the given user/role.
func AdminToken(t *testing.T, userID uint, role string) string {
	t.Helper()
	token, err := services.GenerateUserToken(userID, role, "", 12*time.Hour)
	if err != nil {
		t.Fatalf("failed to mint admin token: %v", err)
	}
	return token
}

// MobileToken mints a valid mobile-API JWT (as accepted by handlers.ApiAuth).
func MobileToken(t *testing.T, userID uint, deviceID string) string {
	t.Helper()
	token, err := services.GenerateUserToken(userID, models.RoleUser, deviceID, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to mint mobile token: %v", err)
	}
	return token
}

// CreateUser inserts a minimal valid user row, letting the caller override
// whichever fields the test cares about.
func CreateUser(t *testing.T, mutate func(*models.User)) *models.User {
	t.Helper()
	u := &models.User{
		Username: uniqueName("user"),
		Email:    uniqueName("user") + "@example.com",
		Role:     models.RoleUser,
		IsActive: true,
	}
	if mutate != nil {
		mutate(u)
	}
	if err := database.DB.Create(u).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return u
}

var seq atomic.Int64

// UniqueName returns a short collision-free string for building unique
// usernames/emails/tokens/etc. across tests sharing the same DB.
func UniqueName(prefix string) string {
	return uniqueName(prefix)
}

func uniqueName(prefix string) string {
	n := seq.Add(1)
	return prefix + "-" + strconv.FormatInt(n, 10) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// DoJSON marshals body (if non-nil) as JSON, performs the request against app,
// and returns the raw *http.Response for the caller to assert on.
func DoJSON(t *testing.T, app *fiber.App, method, path string, body interface{}, mutateReq func(*http.Request)) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if mutateReq != nil {
		mutateReq(req)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// DoForm submits values as an application/x-www-form-urlencoded body — for the
// many admin POST handlers that read c.FormValue(...) rather than a JSON body.
func DoForm(t *testing.T, app *fiber.App, method, path string, values url.Values, mutateReq func(*http.Request)) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if mutateReq != nil {
		mutateReq(req)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

// DecodeJSON reads and JSON-decodes resp.Body into v.
func DecodeJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
}
