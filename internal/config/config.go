package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	// Embeds the IANA timezone database in the binary. The production image is
	// distroless and the build is CGO_ENABLED=0, so LoadLocation must not depend
	// on a system zoneinfo directory being present.
	_ "time/tzdata"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL    string
	JWTSecret      string
	AdminEmail     string
	AdminPassword  string
	FCMServerKey   string
	SplashURL      string
	SplashHeaders  map[string]string
	SplashInterval time.Duration

	// Timezone the whole app runs in (IANA name, e.g. "Asia/Tehran"). Load applies
	// it to time.Local, so every entry point — the server and the test harness —
	// agrees. Without this the dev compose service (TZ=Asia/Tehran) and the
	// distroless production image (no TZ, so UTC) emit different UTC offsets for
	// the same instant.
	Timezone string
	Location *time.Location
}

var Current Config

func Load() error {
	_ = godotenv.Load()

	Current = Config{
		DatabaseURL:   getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5444/vpnpannel?sslmode=disable"),
		JWTSecret:     getenv("JWT_SECRET", "dev-secret-change"),
		AdminEmail:    getenv("ADMIN_EMAIL", "admin@example.com"),
		AdminPassword: getenv("ADMIN_PASSWORD", "admin1234"),
		FCMServerKey:  getenv("FCM_SERVER_KEY", ""),
		SplashURL:     getenv("SPLASH_URL", "https://wooddentools.com/api/protocols/splash"),
	}

	// Map headers from env with SPLASH_HEADER_ prefix
	Current.SplashHeaders = map[string]string{
		"giat":            getenv("SPLASH_HEADER_giat", ""),
		"giat;":           getenv("SPLASH_HEADER_giat_semicolon", ""),
		"build":           getenv("SPLASH_HEADER_build", "false"),
		"seen":            getenv("SPLASH_HEADER_seen", "1"),
		"sign":            getenv("SPLASH_HEADER_sign", ""),
		"token":           getenv("SPLASH_HEADER_token", ""),
		"firebase_token":  getenv("SPLASH_HEADER_firebase_token", ""),
		"sha_hexadecimal": getenv("SPLASH_HEADER_sha_hexadecimal", ""),
		"version_code":    getenv("SPLASH_HEADER_version_code", ""),
		"app_name":        getenv("SPLASH_HEADER_app_name", "co.vpn.plus"),
		"User-Agent":      getenv("SPLASH_HEADER_User_Agent", "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N976N Build/QP1A.190711.020)"),
		// keep Content-Type configurable, although request enforces it to application/json
		"Content-Type": getenv("SPLASH_HEADER_Content_Type", "application/json"),
	}

	// interval in minutes
	if v := os.Getenv("SPLASH_INTERVAL_MINUTES"); v != "" {
		if d, err := time.ParseDuration(v + "m"); err == nil {
			Current.SplashInterval = d
		}
	} else {
		Current.SplashInterval = 1 * time.Minute
	}

	// Pin the process timezone before anything reads the clock. Done here rather
	// than in main.go so the test harness (which also calls Load) matches the
	// server exactly.
	Current.Timezone = getenv("TZ", "Asia/Tehran")
	loc, err := time.LoadLocation(Current.Timezone)
	if err != nil {
		return fmt.Errorf("invalid TZ %q: %w", Current.Timezone, err)
	}
	Current.Location = loc
	time.Local = loc

	if Current.JWTSecret == "" {
		return errors.New("JWT_SECRET is required")
	}
	if Current.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
