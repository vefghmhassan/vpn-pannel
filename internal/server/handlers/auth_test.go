package handlers_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestLoginSubmit_Success(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, func(u *models.User) {
		u.SetPassword("pass1234")
		u.Role = models.RoleSuperAdmin
	})

	resp := testutil.DoForm(t, app, "POST", "/login", url.Values{
		"email": {u.Email}, "password": {"pass1234"},
	}, nil)
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect on successful login, got %d", resp.StatusCode)
	}
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "admin_token" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an admin_token cookie to be set")
	}
}

func TestLoginSubmit_BadCredentials(t *testing.T) {
	app := apptest.New(t)
	u := testutil.CreateUser(t, func(u *models.User) {
		u.SetPassword("correct")
		u.Role = models.RoleSuperAdmin
	})

	resp := testutil.DoForm(t, app, "POST", "/login", url.Values{
		"email": {u.Email}, "password": {"wrong"},
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad credentials, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "اشتباه") {
		t.Errorf("expected the re-rendered login form to show an error message")
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoJSON(t, app, "GET", "/logout", nil, nil)
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after logout, got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "admin_token" && c.Value != "" {
			t.Errorf("expected the admin_token cookie to be cleared, got value %q", c.Value)
		}
	}
}
