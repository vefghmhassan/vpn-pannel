package services

import (
	"context"
	"time"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// StartOnlineSnapshotter launches a background ticker that periodically records how
// many users are currently online, building the history behind the admin stats trend chart.
func StartOnlineSnapshotter(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		takeOnlineSnapshot()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				takeOnlineSnapshot()
			}
		}
	}()
}

func takeOnlineSnapshot() {
	since := time.Now().Add(-5 * time.Minute)
	var count int64
	database.DB.Model(&models.User{}).
		Where("is_active = ? AND last_seen_at IS NOT NULL AND last_seen_at > ?", true, since).
		Count(&count)
	database.DB.Create(&models.OnlineSnapshot{Count: count})
}
