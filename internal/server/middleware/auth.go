package middleware

import (
    "strings"

    "github.com/gofiber/fiber/v2"

    "vpnpannel/internal/database"
    "vpnpannel/internal/models"
    "vpnpannel/internal/services"
)

func hasRole(userRole string, allowed []string) bool {
    if len(allowed) == 0 {
        return true
    }
    for _, r := range allowed {
        if r == userRole {
            return true
        }
    }
    return false
}

// AuthRequired checks JWT from Cookie("admin_token") or Authorization: Bearer
func AuthRequired(roles ...string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        token := c.Cookies("admin_token")
        if token == "" {
            authz := c.Get("Authorization")
            if strings.HasPrefix(authz, "Bearer ") {
                token = strings.TrimPrefix(authz, "Bearer ")
            }
        }
        if token == "" {
            return c.Redirect("/login")
        }
        claims, err := services.ParseToken(token)
        if err != nil {
            return c.Redirect("/login")
        }
        if !hasRole(claims.Role, roles) {
            return fiber.ErrForbidden
        }
        // Load user (for templates)
        var user models.User
        if err := database.DB.First(&user, claims.UserID).Error; err == nil {
            c.Locals("user", &user)
        }
        c.Locals("claims", claims)
        return c.Next()
    }
}


