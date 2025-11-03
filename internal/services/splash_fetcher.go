package services

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"vpnpannel/internal/config"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

type splashItem struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Price    int    `json:"price"`
	Usage    int    `json:"usage"`
	ServerID int    `json:"serverId"`
}

// StartSplashFetcher launches a background ticker that periodically fetches splash protocols
// and inserts new ones into the database while skipping duplicates by primary key.
func StartSplashFetcher(ctx context.Context) {
	interval := config.Current.SplashInterval
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// immediate run
		fetchAndStoreSplash()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchAndStoreSplash()
			}
		}
	}()
}

func fetchAndStoreSplash() {
	client := &http.Client{Timeout: 20 * time.Second}
	url := config.Current.SplashURL
	if url == "" {
		url = "https://wooddentools.com/api/protocols/splash"
	}

	log.Printf("start fetch ")
	req, err := http.NewRequest(http.MethodGet, url, strings.NewReader("{}"))
	if err != nil {
		log.Printf("splash: new request: %v", err)
		return
	}

	// ensure JSON content-type as curl had
	req.Header.Add("giat", "")
	req.Header.Add("build", "false")
	req.Header.Add("seen", "1")
	req.Header.Add("sign", "w8z946T8GvQ0OYHgSASIgg==")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("token", "bf8009ecdd7c41a3")
	req.Header.Add("firebase_token", "cmmd8qHrTseaQMjZksQn_C:APA91bGwOlYixYil3Wi8k44T2IftbrtEPCTTmQUcZCvNt1r2U-Hl6GnWKHDYWhVNlB4CAWYfAgoOuCi_VTwchDV2eiOejjT2AIG6tav24lrrONY4Nq5JvwA")
	req.Header.Add("sha_hexadecimal", "6a28befce23991c20d92f4a64b7faf9922308c8e10c5f687ef811ad885d03ee0")
	req.Header.Add("version_code", "1005697")
	req.Header.Add("app_name", "co.vpn.plus")
	req.Header.Add("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N976N Build/QP1A.190711.020)")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("splash: request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("splash: non-2xx status: %s", resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("splash: read body failed: %v", err)
		return
	}
	if len(body) == 0 {
		log.Printf("splash: empty body")
		return
	}

	var items []splashItem
	if err := json.Unmarshal(body, &items); err != nil {
		// try {"data": [...]}
		var wrap struct {
			Data []splashItem `json:"data"`
		}
		if err2 := json.Unmarshal(body, &wrap); err2 == nil && len(wrap.Data) > 0 {
			items = wrap.Data
		} else {
			// try single object
			var single splashItem
			if err3 := json.Unmarshal(body, &single); err3 == nil && single.ID != 0 {
				items = []splashItem{single}
			} else {
				log.Printf("splash: decode failed: %v, body: %s", err, string(body))
				return
			}
		}
	}
	if len(items) == 0 {
		return
	}

	// insert ignoring duplicates by primary key, batch with upsert-do-nothing
	var batch []models.SplashProtocol
	for _, it := range items {
		batch = append(batch, models.SplashProtocol{
			ID:       it.ID,
			Name:     it.Name,
			Value:    it.Value,
			Price:    it.Price,
			Usage:    it.Usage,
			ServerID: it.ServerID,
		})
	}
	if len(batch) == 0 {
		return
	}
	// Use GORM upsert DO NOTHING on conflict with primary key id
	type conflictColumn struct{ Name string }
	// inline minimal clause to avoid extra imports: build SQL explicitly via Create and ignore errors containing duplicate
	// Fallback: insert one by one if batch fails
	if err := database.DB.Create(&batch).Error; err != nil {
		// fallback to per-row with duplicate tolerance
		inserted := 0
		for _, rec := range batch {
			if err2 := database.DB.Create(&rec).Error; err2 != nil {
				lower := strings.ToLower(err2.Error())
				if strings.Contains(lower, "duplicate") || strings.Contains(lower, "unique") || strings.Contains(lower, "constraint") {
					continue
				}
				log.Printf("splash: insert %d failed: %v", rec.ID, err2)
				continue
			}
			inserted++
		}
		log.Printf("splash: inserted %d/%d (fallback)", inserted, len(batch))
		return
	}
	// When Create succeeds as batch, rows affected equals len(batch) typically; if duplicates exist, DB driver may still report success.
	log.Printf("splash: processed %d records (batch create attempted)", len(batch))
}

// createIfNotExists removed in favor of batch logic above
