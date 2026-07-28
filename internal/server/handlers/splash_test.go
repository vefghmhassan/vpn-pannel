package handlers_test

import (
	"net/url"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestSplashList_Paginates(t *testing.T) {
	app := apptest.New(t)
	for i := 0; i < 20; i++ {
		database.DB.Create(&models.SplashProtocol{Name: testutil.UniqueName("splash")})
	}
	resp := testutil.DoJSON(t, app, "GET", "/admin/splash?page=2", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSplashCreate_SingleEntry(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/splash/new", url.Values{
		"id": {"123456"}, "name": {"n"}, "value": {"v"}, "price": {"10"}, "usage": {"5"}, "serverId": {"1"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var rec models.SplashProtocol
	if err := database.DB.First(&rec, 123456).Error; err != nil {
		t.Fatalf("expected the splash protocol to be created: %v", err)
	}
}

func TestSplashCreate_MissingRequiredFields(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/splash/new", url.Values{
		"id": {""}, "name": {""}, "value": {""},
	}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for missing required fields, got %d", resp.StatusCode)
	}
}

func TestSplashCreate_BulkJSONImport(t *testing.T) {
	app := apptest.New(t)
	payload := `{"splash":[{"id":555001,"name":"a","value":"va","serverId":1},{"id":555002,"name":"b","value":"vb","serverId":2}]}`
	resp := testutil.DoForm(t, app, "POST", "/admin/splash/new", url.Values{
		"json_data": {payload},
	}, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.SplashProtocol{}).Where("id IN ?", []uint64{555001, 555002}).Count(&count)
	if count != 2 {
		t.Errorf("expected both bulk-imported items to be created, got %d", count)
	}
}

func TestSplashCreate_BulkJSONImportSkipsInvalidEntries(t *testing.T) {
	app := apptest.New(t)
	payload := `{"splash":[{"id":0,"name":"","value":""},{"id":555003,"name":"ok","value":"v"}]}`
	resp := testutil.DoForm(t, app, "POST", "/admin/splash/new", url.Values{
		"json_data": {payload},
	}, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.SplashProtocol{}).Where("id = ?", 555003).Count(&count)
	if count != 1 {
		t.Errorf("expected the valid entry to be imported despite the invalid one being skipped")
	}
}
