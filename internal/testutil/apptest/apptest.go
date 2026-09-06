// Package apptest builds a real, fully-routed *fiber.App for HTTP-level testing.
// It is deliberately kept separate from internal/testutil (which every internal
// white-box test can import) because it imports "vpnpannel/internal/server",
// which itself imports internal/server/handlers and internal/server/middleware —
// importing this package from an internal test file in either of those packages
// would be a compile-time import cycle. Use it only from external ("_test")
// test files, e.g. `package handlers_test`.
package apptest

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	"vpnpannel/internal/calendar"
	"vpnpannel/internal/server"
	"vpnpannel/internal/testutil"
)

// New builds a real *fiber.App wired exactly like cmd/server/main.go (same
// template engine, same fmtDate func, same route table) on top of an isolated
// per-test transaction from testutil.SetupDB.
//
// The template directory is resolved relative to `go test`'s working directory,
// which is always the calling test package's own directory — "../../../../web/templates"
// is correct for callers living at internal/server/handlers or internal/server/middleware
// (both three levels below the repo root, one more to get out of testutil/apptest's
// own import path doesn't matter — only the *caller's* directory matters at runtime).
func New(t *testing.T) *fiber.App {
	t.Helper()
	testutil.SetupDB(t)
	return build(t)
}

// NewShared builds the same app over the shared connection pool
// (testutil.SetupSharedDB) rather than a per-test transaction, for concurrency
// tests that need many handler goroutines running real queries in parallel.
// Writes are not rolled back — see SetupSharedDB.
func NewShared(t *testing.T) *fiber.App {
	t.Helper()
	testutil.SetupSharedDB(t)
	return build(t)
}

func build(t *testing.T) *fiber.App {
	t.Helper()

	engine := html.New("../../../web/templates", ".html")
	engine.AddFunc("fmtDate", func(tm *time.Time, system string) string {
		return calendar.FormatDateTime(tm, calendar.System(system))
	})
	engine.AddFunc("fmtTime", func(tm time.Time, system string) string {
		return calendar.FormatDateTime(&tm, calendar.System(system))
	})

	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layout",
	})
	server.RegisterRoutes(app)
	return app
}
