package middleware

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
	"vpnpannel/internal/testutil"
)

// newProtectedApp builds a minimal app with a single route gated by AuthRequired,
// without needing the full template-rendered application (AuthRequired itself
// doesn't render anything).
func newProtectedApp(roles ...string) *fiber.App {
	app := fiber.New()
	app.Get("/protected", AuthRequired(roles...), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})
	return app
}

func TestAuthRequired_NoToken_RedirectsToLogin(t *testing.T) {
	testutil.SetupDB(t)
	app := newProtectedApp("SUPER_ADMIN")

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("expected a redirect (302) without a token, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

func TestAuthRequired_InvalidToken_RedirectsToLogin(t *testing.T) {
	testutil.SetupDB(t)
	app := newProtectedApp("SUPER_ADMIN")

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("expected a redirect (302) for an invalid token, got %d", resp.StatusCode)
	}
}

func TestAuthRequired_ExpiredToken_RedirectsToLogin(t *testing.T) {
	testutil.SetupDB(t)
	app := newProtectedApp("SUPER_ADMIN")

	token, err := services.GenerateUserToken(1, models.RoleSuperAdmin, "", -1*time.Hour)
	if err != nil {
		t.Fatalf("failed to mint an expired token: %v", err)
	}
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("expected a redirect (302) for an expired token, got %d", resp.StatusCode)
	}
}

func TestAuthRequired_WrongRole_Forbidden(t *testing.T) {
	testutil.SetupDB(t)
	app := newProtectedApp("SUPER_ADMIN")

	u := testutil.CreateUser(t, func(u *models.User) { u.Role = models.RoleSupport })
	token := testutil.AdminToken(t, u.ID, models.RoleSupport)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected 403 for a role not in the allowed list, got %d", resp.StatusCode)
	}
}

func TestAuthRequired_ValidToken_Passes(t *testing.T) {
	testutil.SetupDB(t)
	app := newProtectedApp("SUPER_ADMIN", "ADMIN")

	u := testutil.CreateUser(t, func(u *models.User) { u.Role = models.RoleAdmin })
	token := testutil.AdminToken(t, u.ID, models.RoleAdmin)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 for a valid token with an allowed role, got %d", resp.StatusCode)
	}
}

func TestAuthRequired_NoRoleRestriction_AllowsAny(t *testing.T) {
	testutil.SetupDB(t)
	app := newProtectedApp() // no roles passed => any authenticated role is allowed

	u := testutil.CreateUser(t, func(u *models.User) { u.Role = models.RoleUser })
	token := testutil.AdminToken(t, u.ID, models.RoleUser)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 when AuthRequired has no role restriction, got %d", resp.StatusCode)
	}
}
