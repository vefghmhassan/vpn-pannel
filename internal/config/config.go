package config

import (
	"errors"
	"os"
	"time"

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
}

var Current Config

func Load() error {
	_ = godotenv.Load()

	Current = Config{
		DatabaseURL:   getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/vpnpannel?sslmode=disable"),
		JWTSecret:     getenv("JWT_SECRET", "dev-secret-change"),
		AdminEmail:    getenv("ADMIN_EMAIL", "admin@example.com"),
		AdminPassword: getenv("ADMIN_PASSWORD", "admin1234"),
		FCMServerKey:  getenv("FCM_SERVER_KEY", ""),
		SplashURL:     getenv("SPLASH_URL", "https://amur.wooddentools.net/api/protocols/splash"),
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
