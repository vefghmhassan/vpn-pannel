package handlers

import (
    "strconv"
    "time"

    "github.com/gofiber/fiber/v2"

    "vpnpannel/internal/database"
    "vpnpannel/internal/models"
)

func UsersList(c *fiber.Ctx) error {
    var users []models.User
    database.DB.Order("id desc").Find(&users)
    return c.Render("users/index", fiber.Map{
        "title": "Users",
        "users": users,
    })
}

func UserDetail(c *fiber.Ctx) error {
    id, _ := strconv.Atoi(c.Params("id"))
    var user models.User
    if err := database.DB.First(&user, id).Error; err != nil {
        return fiber.ErrNotFound
    }
    var devices []models.MobileDevice
    database.DB.Where("user_id = ?", user.ID).Order("id desc").Find(&devices)
    return c.Render("users/detail", fiber.Map{
        "title":   "User Detail",
        "user":    user,
        "devices": devices,
    })
}

// API helpers to update FCM token and last seen from admin if needed
func UpdateUserFCM(c *fiber.Ctx) error {
    id, _ := strconv.Atoi(c.Params("id"))
    type req struct{ Token string `json:"token"` }
    var r req
    if err := c.BodyParser(&r); err != nil {
        return fiber.ErrBadRequest
    }
    var device models.MobileDevice
    if err := database.DB.Where("user_id = ?", id).Order("id desc").First(&device).Error; err != nil {
        return fiber.ErrNotFound
    }
    device.FCMToken = r.Token
    now := time.Now()
    device.LastSeenAt = &now
    if err := database.DB.Save(&device).Error; err != nil {
        return fiber.ErrInternalServerError
    }
    return c.JSON(fiber.Map{"ok": true})
}

func UsersActive(c *fiber.Ctx) error {
    since := time.Now().Add(-24 * time.Hour)
    var users []models.User
    database.DB.Where("last_seen_at IS NOT NULL AND last_seen_at > ?", since).Order("last_seen_at desc").Find(&users)
    return c.Render("users/index", fiber.Map{ "title": "کاربران فعال", "users": users })
}


