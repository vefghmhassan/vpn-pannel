package handlers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func doMultipartUpload(t *testing.T, app *fiber.App, path, fieldName, filename string, content []byte, mutateReq func(*http.Request)) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("failed to write form file content: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if mutateReq != nil {
		mutateReq(req)
	}
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func TestSettingsExport_ReturnsBackupJSON(t *testing.T) {
	app := apptest.New(t)
	database.DB.Create(&models.V2RayNode{Name: testutil.UniqueName("export-node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true})

	resp := testutil.DoJSON(t, app, "GET", "/admin/settings/export", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	var generic map[string]interface{}
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatalf("expected valid JSON backup payload: %v", err)
	}
	if _, ok := generic["version"]; !ok {
		t.Errorf("expected a version field in the backup payload")
	}
	if _, ok := generic["v2ray_nodes"]; !ok {
		t.Errorf("expected a v2ray_nodes field in the backup payload")
	}
}

func TestSettingsImport_RoundTrip(t *testing.T) {
	app := apptest.New(t)

	// Export the current state first to get a valid, well-formed payload shape.
	exportResp := testutil.DoJSON(t, app, "GET", "/admin/settings/export", nil, adminAuth(t))
	body, _ := io.ReadAll(exportResp.Body)

	var payload map[string]interface{}
	json.Unmarshal(body, &payload)
	appSettings := payload["app_settings"].(map[string]interface{})
	appSettings["wheel_enabled"] = false
	appSettings["current_version"] = "5.5.5"
	modified, _ := json.Marshal(payload)

	resp := doMultipartUpload(t, app, "/admin/settings/import", "backup_file", "backup.json", modified, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after import, got %d", resp.StatusCode)
	}

	var s models.AppSettings
	database.DB.First(&s, 1)
	if s.CurrentVersion != "5.5.5" {
		t.Errorf("expected CurrentVersion to be updated by import, got %q", s.CurrentVersion)
	}
	if s.WheelEnabled {
		t.Errorf("expected WheelEnabled=false to round-trip through export/import correctly")
	}
}

func TestSettingsImport_OmittedSplashDiverseServersKeepsValue(t *testing.T) {
	// splash_diverse_servers defaults to on, so a backup taken before the setting
	// existed must leave it alone rather than reset it to the Go zero value.
	app := apptest.New(t)
	var s models.AppSettings
	database.DB.First(&s, 1)
	s.SplashDiverseServers = true
	database.DB.Save(&s)

	exportResp := testutil.DoJSON(t, app, "GET", "/admin/settings/export", nil, adminAuth(t))
	body, _ := io.ReadAll(exportResp.Body)
	var payload map[string]interface{}
	json.Unmarshal(body, &payload)
	appSettings := payload["app_settings"].(map[string]interface{})
	delete(appSettings, "splash_diverse_servers")
	appSettings["current_version"] = "7.7.7"
	modified, _ := json.Marshal(payload)

	resp := doMultipartUpload(t, app, "/admin/settings/import", "backup_file", "backup.json", modified, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after import, got %d", resp.StatusCode)
	}

	var reloaded models.AppSettings
	database.DB.First(&reloaded, 1)
	if reloaded.CurrentVersion != "7.7.7" {
		t.Fatalf("expected the import to apply, got CurrentVersion %q", reloaded.CurrentVersion)
	}
	if !reloaded.SplashDiverseServers {
		t.Errorf("expected SplashDiverseServers to survive an import that omits the key")
	}
}

func TestSettingsImport_RejectsWrongVersion(t *testing.T) {
	app := apptest.New(t)
	bad := []byte(`{"version": 999, "app_settings": {}}`)
	resp := doMultipartUpload(t, app, "/admin/settings/import", "backup_file", "backup.json", bad, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for an unsupported backup version, got %d", resp.StatusCode)
	}
}

func TestSettingsImport_RejectsInvalidJSON(t *testing.T) {
	app := apptest.New(t)
	resp := doMultipartUpload(t, app, "/admin/settings/import", "backup_file", "backup.json", []byte("not json"), adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestSettingsImport_RejectsMissingFile(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "POST", "/admin/settings/import", nil, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 without a backup_file, got %d", resp.StatusCode)
	}
}
