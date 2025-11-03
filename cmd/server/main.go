package main

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"log"
	"os"
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
	services.StartSplashFetcher(ctx)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server listening on :%s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
