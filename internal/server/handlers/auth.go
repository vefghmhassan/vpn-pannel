package handlers

import (
    "time"

    "github.com/gofiber/fiber/v2"

    "vpnpannel/internal/database"
    "vpnpannel/internal/models"
    "vpnpannel/internal/services"
)

func LoginPage(c *fiber.Ctx) error {
    return c.Render("login", fiber.Map{"title": "Login"})
}

func LoginSubmit(c *fiber.Ctx) error {
    type form struct {
        Email    string `form:"email"`
        Password string `form:"password"`
    }
    var f form
    if err := c.BodyParser(&f); err != nil {
        return c.Status(fiber.StatusBadRequest).SendString("invalid form")
    }
    var user models.User
    if err := database.DB.Where("email = ?", f.Email).First(&user).Error; err != nil {
        return c.Status(fiber.StatusUnauthorized).Render("login", fiber.Map{"error": "نام کاربری یا رمز عبور اشتباه است"})
    }
    if !user.CheckPassword(f.Password) || !user.IsActive {
        return c.Status(fiber.StatusUnauthorized).Render("login", fiber.Map{"error": "نام کاربری یا رمز عبور اشتباه است"})
    }
    token, err := services.GenerateUserToken(user.ID, user.Role, "", 12*time.Hour)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).SendString("token error")
    }
    c.Cookie(&fiber.Cookie{
        Name:     "admin_token",
        Value:    token,
        Expires:  time.Now().Add(12 * time.Hour),
        HTTPOnly: true,
        Secure:   false,
        SameSite: "Lax",
        Path:     "/",
    })
    return c.Redirect("/")
}

func Logout(c *fiber.Ctx) error {
    c.Cookie(&fiber.Cookie{Name: "admin_token", Value: "", Expires: time.Now().Add(-1 * time.Hour), HTTPOnly: true, Path: "/"})
    return c.Redirect("/login")
}


