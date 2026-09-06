package main

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"log"
	"os"
	"time"
	"vpnpannel/internal/calendar"
	"vpnpannel/internal/config"
	"vpnpannel/internal/database"
	"vpnpannel/internal/server"
	"vpnpannel/internal/services"
)

func main() {
	// Load environment variables
	if err := config.Load(); err != nil {
		log.Printf("env load: %v", err)
	}

	// Init DB
	if err := database.Connect(config.Current.DatabaseURL); err != nil {
		log.Fatalf("database connect failed: %v", err)
	}

	// Auto-migrate models and seed admin
	if err := database.AutoMigrateAndSeed(); err != nil {
		log.Fatalf("migration/seed failed: %v", err)
	}

	// Template engine
	engine := html.New("web/templates", ".html")
	engine.AddFunc("fmtDate", func(t *time.Time, system string) string {
		return calendar.FormatDateTime(t, calendar.System(system))
	})
	// fmtTime is fmtDate for non-nullable timestamps such as gorm's CreatedAt,
	// which templates cannot pass to fmtDate's *time.Time parameter.
	engine.AddFunc("fmtTime", func(t time.Time, system string) string {
		return calendar.FormatDateTime(&t, calendar.System(system))
	})

	app := fiber.New(fiber.Config{
		Views:        engine,
		ViewsLayout:  "layout",
		ServerHeader: "VpnPannel",
		AppName:      "VpnPannel Admin",
		BodyLimit:    200 * 1024 * 1024, // allow up to 200MB uploads
	})

	// Static assets (optional, for logos etc.)
	app.Static("/static", "public")

	// Setup routes
	server.RegisterRoutes(app)

	// start background jobs
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	services.StartOnlineSnapshotter(ctx, 5*time.Minute)
	// Fill in rollup rows for history that predates this feature, then keep the
	// recent days fresh. Backfill failures are logged rather than fatal: the
	// dashboard degrading to fewer days of history is not a reason to refuse to
	// serve the panel.
	if err := services.BackfillDailyStats(); err != nil {
		log.Printf("daily stats backfill: %v", err)
	}
	services.StartDailyRollup(ctx, time.Hour)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server listening on :%s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
