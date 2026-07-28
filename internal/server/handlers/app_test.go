package handlers_test

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestAppList_Renders(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/admin/app", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAppCreate_RequiresPackageName(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/app/new", url.Values{
		"version_code": {"5"},
	}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 without package_name, got %d", resp.StatusCode)
	}
}

func TestAppCreate_RequiresValidVersionCode(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/app/new", url.Values{
		"package_name": {testutil.UniqueName("pkg")}, "version_code": {"0"},
	}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for a non-positive version_code, got %d", resp.StatusCode)
	}
}

func TestAppCreate_CreatesVersion(t *testing.T) {
	app := apptest.New(t)
	pkg := testutil.UniqueName("pkg")
	// AppCreate creates an uploads/apk/<pkg>/<version> directory as a side
	// effect even without any files attached; clean it up afterward so tests
	// don't leave debris on disk.
	t.Cleanup(func() {
		safe := ""
		for _, r := range pkg {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' {
				safe += string(r)
			} else {
				safe += "-"
			}
		}
		os.RemoveAll(filepath.Join("uploads", "apk", safe))
	})

	resp := testutil.DoForm(t, app, "POST", "/admin/app/new", url.Values{
		"package_name": {pkg}, "version_code": {"7"}, "version_name": {"1.2.3"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}

	var v models.AppVersion
	if err := database.DB.Where("package_name = ? AND version_code = ?", pkg, 7).First(&v).Error; err != nil {
		t.Fatalf("expected the app version to be created: %v", err)
	}
	if v.VersionName != "1.2.3" {
		t.Errorf("expected version_name to be saved, got %q", v.VersionName)
	}
}
