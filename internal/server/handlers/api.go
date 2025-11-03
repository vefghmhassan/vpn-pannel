package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"vpnpannel/internal/utils"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

// ApiAuth middleware for mobile API
func ApiAuth(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	if token == "" {
		return fiber.ErrUnauthorized
	}
	claims, err := services.ParseToken(token)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	var user models.User
	if err := database.DB.First(&user, claims.UserID).Error; err != nil || !user.IsActive {
		return fiber.ErrUnauthorized
	}
	// update last seen
	now := time.Now()
	user.LastSeenAt = &now
	_ = database.DB.Save(&user).Error
	c.Locals("user", &user)
	c.Locals("claims", claims)
	return c.Next()
}

// ApiLogin with deviceID to receive JWT
func ApiLogin(c *fiber.Ctx) error {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		DeviceID string `json:"device_id"`
		FCMToken string `json:"fcm_token"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	var user models.User
	if err := database.DB.Where("email = ?", in.Email).First(&user).Error; err != nil {
		return fiber.ErrUnauthorized
	}
	if !user.CheckPassword(in.Password) || !user.IsActive {
		return fiber.ErrUnauthorized
	}
	now := time.Now()
	user.LastSeenAt = &now
	_ = database.DB.Save(&user).Error
	// upsert mobile device
	var device models.MobileDevice
	if err := database.DB.Where("user_id = ? AND device_id = ?", user.ID, in.DeviceID).First(&device).Error; err != nil {
		device = models.MobileDevice{UserID: user.ID, DeviceID: in.DeviceID, FCMToken: in.FCMToken}
		_ = database.DB.Create(&device).Error
	} else {
		device.FCMToken = in.FCMToken
		now := time.Now()
		device.LastSeenAt = &now
		_ = database.DB.Save(&device).Error
	}
	token, err := services.GenerateUserToken(user.ID, user.Role, in.DeviceID, 30*24*time.Hour)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"token": token})
}

// ApiNoLogin accepts only device_id and fcm_token and returns a guest JWT
func ApiNoLogin(c *fiber.Ctx) error {
	var in struct {
		DeviceID string `json:"device_id"`
		FCMToken string `json:"fcm_token"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	if in.DeviceID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "device_id required")
	}

	email := in.DeviceID + "@vpnpannel.local"

	// Ensure a guest user exists (created on demand)
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		user = models.User{
			Email:    email,
			Username: usernameFromDeviceID(in.DeviceID),
			Role:     models.RoleUser,
			IsActive: true,
		}
		// no password needed for guest programmatic login
		if err := database.DB.Create(&user).Error; err != nil {
			return fiber.ErrInternalServerError
		}
	}

	// Upsert guest device
	var device models.MobileDevice
	if err := database.DB.Where("user_id = ? AND device_id = ?", user.ID, in.DeviceID).First(&device).Error; err != nil {
		device = models.MobileDevice{UserID: user.ID, DeviceID: in.DeviceID, FCMToken: in.FCMToken}
		_ = database.DB.Create(&device).Error
	} else {
		device.FCMToken = in.FCMToken
		now := time.Now()
		device.LastSeenAt = &now
		_ = database.DB.Save(&device).Error
	}

	token, err := services.GenerateUserToken(user.ID, user.Role, in.DeviceID, 30*24*time.Hour)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"token": token})
}
func usernameFromDeviceID(deviceID string) string {
	deviceID = strings.ToLower(deviceID)
	sum := sha1.Sum([]byte(deviceID))
	return fmt.Sprintf("guest_%s_%s", deviceID, hex.EncodeToString(sum[:])[:6]) // guest_abc..._a1b2c3
}

// ApiLastConnection updates which node the user last used
func ApiLastConnection(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)
	var in struct {
		NodeID uint `json:"node_id"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	user.LastConnectedNode = &in.NodeID
	now := time.Now()
	user.LastSeenAt = &now
	if err := database.DB.Save(user).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"ok": true})
}

func ApiProfile(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)
	var devices []models.MobileDevice
	database.DB.Where("user_id = ?", user.ID).Find(&devices)
	return c.JSON(fiber.Map{"user": user, "devices": devices})
}

func ApiNodes(c *fiber.Ctx) error {
	var nodes []models.V2RayNode
	database.DB.Where("is_active = ?", true).Order("id desc").Find(&nodes)
	return c.JSON(fiber.Map{"nodes": nodes})
}

func ApiCreateOutage(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)
	var in struct {
		NodeID      *uint  `json:"node_id"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	report := models.OutageReport{UserID: &user.ID, NodeID: in.NodeID, Title: in.Title, Description: in.Description, Status: models.OutageOpen}
	if err := database.DB.Create(&report).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"ok": true, "id": report.ID})
}

// ApiHeartbeat: update user's last seen (and device last seen) using JWT sent in body
func ApiHeartbeat(c *fiber.Ctx) error {
    var in struct {
        Token string `json:"token"`
        JWT   string `json:"jwt"`
    }
    if err := c.BodyParser(&in); err != nil {
        return fiber.ErrBadRequest
    }
    tokenStr := in.Token
    if tokenStr == "" {
        tokenStr = in.JWT
    }
    if tokenStr == "" {
        return fiber.NewError(fiber.StatusBadRequest, "token required")
    }

    claims, err := services.ParseToken(tokenStr)
    if err != nil {
        return fiber.ErrUnauthorized
    }

    var user models.User
    if err := database.DB.First(&user, claims.UserID).Error; err != nil || !user.IsActive {
        return fiber.ErrUnauthorized
    }

    now := time.Now()
    user.LastSeenAt = &now
    _ = database.DB.Save(&user).Error

    if claims.DeviceID != "" {
        var device models.MobileDevice
        if err := database.DB.Where("user_id = ? AND device_id = ?", user.ID, claims.DeviceID).First(&device).Error; err != nil {
            device = models.MobileDevice{UserID: user.ID, DeviceID: claims.DeviceID, LastSeenAt: &now}
            _ = database.DB.Create(&device).Error
        } else {
            device.LastSeenAt = &now
            _ = database.DB.Save(&device).Error
        }
    }
    return c.JSON(fiber.Map{"ok": true, "ts": now})
}

type SplashItemDTO struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	ServerID  int    `json:"serverId"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func ApiSPlash(c *fiber.Ctx) error {
	var splash []models.SplashProtocol
	if err := database.DB.Order("RANDOM()").Limit(10).Find(&splash).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	resp := make([]SplashItemDTO, 0, len(splash))

	for _, r := range splash {
		vitem, _ := utils.DecryptValue(r.Value, int(r.ID))
		resp = append(resp, SplashItemDTO{ID: uint(r.ID), Name: r.Name, Value: vitem, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return c.JSON(fiber.Map{"splash": resp})
}

// ApiSettings returns public application settings for the mobile app
func ApiSettings(c *fiber.Ctx) error {
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		// ensure a default response even if not seeded yet
        s = models.AppSettings{AdsEnabledInSplash: false, ShowAdsAfterSplash: false, ShowAdsOnMainPage: false, CurrentVersion: "1.0.0", ConnectedTimeoutSeconds: 15}
	}
	return c.JSON(fiber.Map{
		"ads_enabled_in_splash": s.AdsEnabledInSplash,
		"show_ads_after_splash": s.ShowAdsAfterSplash,
		"show_ads_on_main_page": s.ShowAdsOnMainPage,
		"current_version":       s.CurrentVersion,
        "ad_unit_id":            s.AdUnitID,
        "privacy_url":           s.PrivacyURL,
        "connected_timeout":     s.ConnectedTimeoutSeconds,
	})
}

// ApiCheckUpdate: client sends version_code and abi, server responds with download URL if newer
func ApiCheckUpdate(c *fiber.Ctx) error {
    var in struct {
        PackageName string `json:"package_name"`
        Package     string `json:"package"`
        VersionCode int    `json:"version_code"`
        ABI         string `json:"abi"`
    }
    if err := c.BodyParser(&in); err != nil {
        return fiber.ErrBadRequest
    }
    pkg := strings.TrimSpace(in.PackageName)
    if pkg == "" { pkg = strings.TrimSpace(in.Package) }
    if pkg == "" {
        return fiber.NewError(fiber.StatusBadRequest, "package_name required")
    }
    if in.VersionCode <= 0 {
        return fiber.NewError(fiber.StatusBadRequest, "version_code required")
    }
    // find latest version with higher version_code
    var latest models.AppVersion
    if err := database.DB.Where("package_name = ? AND version_code > ?", pkg, in.VersionCode).Order("version_code desc").First(&latest).Error; err != nil {
        return c.JSON(fiber.Map{"update": false})
    }
    // find matching build by ABI, fallback to universal
    var build models.AppBuild
    if in.ABI != "" {
        if err := database.DB.Where("app_version_id = ? AND abi = ?", latest.ID, in.ABI).First(&build).Error; err != nil {
            _ = database.DB.Where("app_version_id = ? AND abi = ?", latest.ID, "universal").First(&build).Error
        }
    } else {
        _ = database.DB.Where("app_version_id = ? AND abi = ?", latest.ID, "universal").First(&build).Error
    }
    if build.ID == 0 {
        // no suitable build available
        return c.JSON(fiber.Map{"update": true, "version_code": latest.VersionCode, "version_name": latest.VersionName, "mandatory": latest.IsMandatory, "changelog": latest.Changelog, "url": nil})
    }
    return c.JSON(fiber.Map{
        "update":       true,
        "version_code": latest.VersionCode,
        "version_name": latest.VersionName,
        "mandatory":    latest.IsMandatory,
        "changelog":    latest.Changelog,
        "abi":          build.ABI,
        "url":          build.FilePath,
        "size":         build.FileSize,
        "sha256":       build.Sha256,
    })
}
