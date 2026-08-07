package server

import (
	"time"

	"github.com/gofiber/fiber/v2"
	swagger "github.com/gofiber/swagger"

	"vpnpannel/internal/server/handlers"
	"vpnpannel/internal/server/middleware"
	_ "vpnpannel/internal/swagger"
)

func RegisterRoutes(app *fiber.App) {
	// Serve uploaded files
	app.Static("/uploads", "./uploads")
	app.Static("/country", "./country")
	// Auth
	app.Get("/login", handlers.LoginPage)
	app.Post("/login", handlers.LoginSubmit)
	app.Get("/logout", handlers.Logout)

	// Dashboard
	app.Get("/admin", middleware.AuthRequired("SUPER_ADMIN", "ADMIN", "SUPPORT"), handlers.Dashboard)

	// Admin area
	admin := app.Group("/admin", middleware.AuthRequired("SUPER_ADMIN", "ADMIN", "SUPPORT"))
	// Calendar system switcher (per-browser cookie)
	admin.Get("/set-calendar", handlers.SetCalendar)
	// Admin metrics
	admin.Get("/metrics/active-users", handlers.ActiveUsersCount)
	admin.Get("/metrics/online-stats", handlers.OnlineUsersStats)
	admin.Get("/metrics/online-history", handlers.OnlineHistory)
	// Online users stats page (5m / 30m / 24h, like Firebase Analytics)
	admin.Get("/stats", handlers.StatsPage)
	// App-open tracker (per-user opens today / this month)
	admin.Get("/tracker", handlers.TrackerPage)
	// Referral / invite-code program
	admin.Get("/invites", handlers.InvitesPage)
	admin.Post("/invites/task-settings", handlers.ReferralTaskSettingsUpdate)
	admin.Get("/invites/:id", handlers.InviteDetailPage)
	admin.Get("/invite-task-stats", handlers.InviteTaskStatsPage)
	// App versions
	admin.Get("/app", handlers.AppList)
	admin.Get("/app/new", handlers.AppNewPage)
	admin.Post("/app/new", handlers.AppCreate)
	// Settings
	admin.Get("/settings", handlers.SettingsPage)
	app.Get("/", handlers.HomePage)
	admin.Post("/settings", handlers.SettingsUpdate)
	admin.Post("/settings/delete", handlers.SettingsDelete)
	admin.Get("/settings/export", handlers.SettingsExport)
	admin.Post("/settings/import", handlers.SettingsImport)
	// Lucky wheel (گردونه شانس)
	admin.Get("/wheel", handlers.WheelPage)
	admin.Post("/wheel", handlers.WheelUpdate)
	// In-app reminder messages (پیام‌های یادآور)
	admin.Get("/messages", handlers.MessagesPage)
	admin.Post("/messages", handlers.MessagesUpdate)
	// Users
	admin.Get("/users", handlers.UsersList)
	admin.Get("/users/active", handlers.UsersActive)
	admin.Get("/users/:id", handlers.UserDetail)

	// V2Ray nodes
	admin.Get("/v2ray", handlers.V2RayList)
	admin.Get("/v2ray/new", handlers.V2RayNewPage)
	admin.Post("/v2ray/new", handlers.V2RayCreate)
	admin.Get("/v2ray/:id/edit", handlers.V2RayEditPage)
	admin.Post("/v2ray/:id/edit", handlers.V2RayUpdate)
	admin.Post("/v2ray/batch-delete", handlers.V2RayBatchDelete)
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
	//api.Post("/splash", handlers.ApiSPlash)
	api.Post("/splash", handlers.ApiSplashRefresh)
	api.Post("/splash/conf", handlers.ApiSplashConf)
	api.Post("/last-connection", handlers.ApiLastConnection)
	api.Post("/invite/code", handlers.ApiInviteCode)
	api.Post("/invite/redeem", handlers.ApiInviteRedeem)
	api.Post("/invite/reward-status", handlers.ApiInviteRewardStatus)
	api.Post("/messages", handlers.ApiMessages)
	api.Get("/settings", handlers.ApiSettings)
	api.Get("/wheel", handlers.ApiWheel)
	api.Post("/app/check-update", handlers.ApiCheckUpdate)

	// Health
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "time": time.Now()})
	})

	// Swagger UI
	app.Get("/swagger/*", swagger.HandlerDefault)
}
