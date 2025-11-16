package server

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/server/handlers"
	"vpnpannel/internal/server/middleware"
)

func RegisterRoutes(app *fiber.App) {
	// Serve uploaded files
	app.Static("/uploads", "./uploads")
	// Auth
	app.Get("/login", handlers.LoginPage)
	app.Post("/login", handlers.LoginSubmit)
	app.Get("/logout", handlers.Logout)

	// Dashboard
	app.Get("/admin", middleware.AuthRequired("SUPER_ADMIN", "ADMIN", "SUPPORT"), handlers.Dashboard)

	// Admin area
	admin := app.Group("/admin", middleware.AuthRequired("SUPER_ADMIN", "ADMIN", "SUPPORT"))
	// Admin metrics
	admin.Get("/metrics/active-users", handlers.ActiveUsersCount)
	// App versions
	admin.Get("/app", handlers.AppList)
	admin.Get("/app/new", handlers.AppNewPage)
	admin.Post("/app/new", handlers.AppCreate)
	// Settings
	admin.Get("/settings", handlers.SettingsPage)
	app.Get("/", handlers.HomePage)
	admin.Post("/settings", handlers.SettingsUpdate)
	// Users
	admin.Get("/users", handlers.UsersList)
	admin.Get("/users/active", handlers.UsersActive)
	admin.Get("/users/:id", handlers.UserDetail)

	// V2Ray nodes
	admin.Get("/v2ray", handlers.V2RayList)
	admin.Get("/v2ray/new", handlers.V2RayNewPage)
	admin.Post("/v2ray/new", handlers.V2RayCreate)
	admin.Post("/v2ray/:id/delete", handlers.V2RayDelete)
	// Outages
	admin.Get("/outages", handlers.OutagesList)
	admin.Get("/outages/:id", handlers.OutageSetStatus)

	// Notifications
	admin.Get("/notify", handlers.NotifyPage)
	admin.Post("/notify", handlers.NotifySend)

	// Push UI-only page (posts to external API via JS)
	admin.Get("/push", handlers.PushPage)

	// Splash protocols
	admin.Get("/splash", handlers.SplashList)
	admin.Get("/splash/new", handlers.SplashNewPage)
	admin.Post("/splash/new", handlers.SplashCreate)

	// Admin misc APIs
	admin.Post("/users/:id/fcm", handlers.UpdateUserFCM)

	// API v1 (mobile)
	api := app.Group("/api/v1")
	api.Post("/auth/login", handlers.ApiLogin)
	api.Post("/auth/no-login", handlers.ApiNoLogin)
	api.Get("/profile", handlers.ApiAuth, handlers.ApiProfile)
	api.Get("/nodes", handlers.ApiAuth, handlers.ApiNodes)
	api.Post("/heartbeat", handlers.ApiHeartbeat)
	api.Post("/outages", handlers.ApiAuth, handlers.ApiCreateOutage)
	api.Post("/splash", handlers.ApiSPlash)
	api.Post("/last-connection", handlers.ApiAuth, handlers.ApiLastConnection)
	api.Get("/settings", handlers.ApiSettings)
	api.Post("/app/check-update", handlers.ApiCheckUpdate)

	// Health
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "time": time.Now()})
	})

	// Swagger UI removed per request
}
