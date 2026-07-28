package handlers

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
	"vpnpannel/internal/utils"
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

// findOrCreateUserByToken resolves the user identified by a client-generated token
// (e.g. a stable install id), creating a lightweight account on first sight. Shared by
// every token-only endpoint (check-in, invite code, invite redeem).
func findOrCreateUserByToken(token string) (*models.User, error) {
	var user models.User
	err := database.DB.Where("client_token = ?", token).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}
	sum := sha1.Sum([]byte(token))
	hashed := hex.EncodeToString(sum[:])
	user = models.User{
		Email:       hashed + "@client.vpnpannel.local",
		Username:    "client_" + hashed[:12],
		Role:        models.RoleUser,
		IsActive:    true,
		ClientToken: &token,
	}
	if err := database.DB.Create(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// parseClientToken extracts and validates the "token" field shared by every
// token-only mobile endpoint.
func parseClientToken(c *fiber.Ctx) (string, error) {
	var in struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&in); err != nil {
		return "", fiber.ErrBadRequest
	}
	token := strings.TrimSpace(in.Token)
	if token == "" {
		return "", fiber.NewError(fiber.StatusBadRequest, "token required")
	}
	if len(token) > 36 {
		return "", fiber.NewError(fiber.StatusBadRequest, "token too long")
	}
	return token, nil
}

// ApiLastConnection checks a client in as online using a client-generated token
// (e.g. a stable install id), finding or creating the underlying user by that token.
func ApiLastConnection(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}

	user, err := findOrCreateUserByToken(token)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if !user.IsActive {
		return fiber.ErrUnauthorized
	}

	now := time.Now()
	user.LastSeenAt = &now
	if err := database.DB.Save(user).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	database.DB.Create(&models.AppOpenEvent{UserID: user.ID})
	return c.JSON(fiber.Map{"ok": true})
}

// inviteCodeChars excludes ambiguous characters (0/O, 1/I) to keep shared codes readable.
const inviteCodeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
const inviteCodeLength = 6

func generateUniqueInviteCode() (string, error) {
	for i := 0; i < 10; i++ {
		b := make([]byte, inviteCodeLength)
		for j := range b {
			b[j] = inviteCodeChars[rand.Intn(len(inviteCodeChars))]
		}
		code := string(b)
		var count int64
		database.DB.Model(&models.User{}).Where("invite_code = ?", code).Count(&count)
		if count == 0 {
			return code, nil
		}
	}
	return "", errors.New("could not generate unique invite code")
}

// referralCount returns how many users this user has referred (lifetime total).
func referralCount(userID uint) int64 {
	var count int64
	database.DB.Model(&models.User{}).Where("referred_by_user_id = ?", userID).Count(&count)
	return count
}

// currentSettings loads the singleton AppSettings row (row 1), returning a zero
// value (safe defaults) if it hasn't been seeded yet.
func currentSettings() models.AppSettings {
	var s models.AppSettings
	database.DB.First(&s, 1)
	return s
}

// ApiInviteCode returns the caller's own shareable invite code, generating one on
// first request (idempotent — repeat calls return the same code) — along with the
// admin-configured task text and a ready-to-share message with the code filled in.
func ApiInviteCode(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}

	user, err := findOrCreateUserByToken(token)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if !user.IsActive {
		return fiber.ErrUnauthorized
	}

	if user.InviteCode == nil {
		code, err := generateUniqueInviteCode()
		if err != nil {
			return fiber.ErrInternalServerError
		}
		user.InviteCode = &code
		if err := database.DB.Save(user).Error; err != nil {
			return fiber.ErrInternalServerError
		}
	}

	settings := currentSettings()
	shareText := strings.ReplaceAll(settings.ReferralShareText, "{code}", *user.InviteCode)

	return c.JSON(fiber.Map{
		"invite_code":      *user.InviteCode,
		"invites_count":    referralCount(user.ID),
		"invites_required": settings.ReferralRequiredInvites,
		"task_text":        settings.ReferralTaskText,
		"share_text":       shareText,
	})
}

// ApiInviteRedeem links the caller to whoever owns the given invite code. Each user
// may redeem exactly one code, ever, and cannot redeem their own.
func ApiInviteRedeem(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}
	var in struct {
		InviteCode string `json:"invite_code"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	code := strings.ToUpper(strings.TrimSpace(in.InviteCode))
	if code == "" {
		return fiber.NewError(fiber.StatusBadRequest, "invite_code required")
	}

	user, err := findOrCreateUserByToken(token)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if !user.IsActive {
		return fiber.ErrUnauthorized
	}
	if user.ReferredByUserID != nil {
		return fiber.NewError(fiber.StatusConflict, "already redeemed an invite code")
	}

	var referrer models.User
	if err := database.DB.Where("invite_code = ?", code).First(&referrer).Error; err != nil {
		return fiber.NewError(fiber.StatusNotFound, "invalid invite code")
	}
	if referrer.ID == user.ID {
		return fiber.NewError(fiber.StatusBadRequest, "cannot redeem your own invite code")
	}

	user.ReferredByUserID = &referrer.ID
	if err := database.DB.Save(user).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"ok": true})
}

// ApiInviteRewardStatus reports whether the caller has reached the admin-configured
// referral threshold and, if so, whether their reward window is still active. The
// reward timer starts the first time this endpoint sees them past the threshold.
func ApiInviteRewardStatus(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}

	user, err := findOrCreateUserByToken(token)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if !user.IsActive {
		return fiber.ErrUnauthorized
	}

	settings := currentSettings()
	count := referralCount(user.ID)
	eligible := count >= int64(settings.ReferralRequiredInvites)

	if eligible && user.RewardActivatedAt == nil {
		now := time.Now()
		user.RewardActivatedAt = &now
		if err := database.DB.Save(user).Error; err != nil {
			return fiber.ErrInternalServerError
		}
	}

	resp := fiber.Map{
		"eligible":         eligible,
		"invites_count":    count,
		"invites_required": settings.ReferralRequiredInvites,
		"reward_active":    false,
	}
	if user.RewardActivatedAt != nil {
		expiresAt := user.RewardActivatedAt.AddDate(0, 0, settings.ReferralRewardDays)
		active := time.Now().Before(expiresAt)
		resp["reward_active"] = active
		resp["reward_expires_at"] = expiresAt
		daysLeft := 0
		if active {
			daysLeft = int(time.Until(expiresAt).Hours()/24) + 1
		}
		resp["days_left"] = daysLeft
	}
	return c.JSON(resp)
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

type ConfRequest struct {
	ClientKey string `json:"client_key"`
	DeviceID  string `json:"device_id"`
}

type ConfResponse struct {
	NoAds     models.V2RayNode   `json:"no_ads"`
	Ads       models.V2RayNode   `json:"ads"`
	NoAdsList []models.V2RayNode `json:"no_ads_list"`
	AdsList   []models.V2RayNode `json:"ads_list"`
}

// ApiSplashConf returns nodes per request: lists for ads=false and ads=true.
// It leases each node to the requester for 30 minutes when possible.
func ApiSplashConf(c *fiber.Ctx) error {
	var in ConfRequest
	_ = c.BodyParser(&in)
	reqKey := requestKey(c, in.ClientKey, in.DeviceID)
	now := time.Now()

	count := 4
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err == nil && s.SplashConfCount > 0 {
		count = s.SplashConfCount
	}
	if count < 2 {
		count = 2
	}

	noAdsCount := count - 1
	noAdsList, err := findOrAssignNodes(reqKey, false, noAdsCount, now)
	if err != nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "no non-ads nodes available")
	}
	adsList, err := findOrAssignNodes(reqKey, true, 1, now)
	if err != nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "no ads nodes available")
	}
	resp := ConfResponse{NoAdsList: noAdsList, AdsList: adsList}
	if len(noAdsList) > 0 {
		resp.NoAds = noAdsList[0]
	}
	if len(adsList) > 0 {
		resp.Ads = adsList[0]
	}
	return c.JSON(resp)
}

func requestKey(c *fiber.Ctx, clientKey string, deviceID string) string {
	base := strings.TrimSpace(clientKey)
	if base == "" {
		base = strings.TrimSpace(c.IP()) + "|" + strings.TrimSpace(c.Get("User-Agent")) + "|" + strings.TrimSpace(deviceID)
	}
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

func findOrAssignNodes(reqKey string, ads bool, count int, now time.Time) ([]models.V2RayNode, error) {
	if count <= 0 {
		return []models.V2RayNode{}, nil
	}
	var nodes []models.V2RayNode
	if err := database.DB.Where("is_active = ? AND ads = ?", true, ads).
		Order("RANDOM()").Limit(count).Find(&nodes).Error; err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return nodes, nil
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
	// Try to fetch records created within the last 5 minutes, randomly ordered
	threshold := time.Now().Add(-5 * time.Minute)
	if err := database.DB.Where("created_at >= ?", threshold).Order("RANDOM()").Limit(5).Find(&splash).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	// Fallback: if nothing recent exists, return any random set
	if len(splash) == 0 {
		if err := database.DB.Order("RANDOM()").Limit(5).Find(&splash).Error; err != nil {
			return fiber.ErrInternalServerError
		}
	}
	resp := make([]SplashItemDTO, 0, len(splash))

	for _, r := range splash {
		vitem, err := utils.DecryptValue(r.Value, int(r.ID))
		if err != nil || strings.TrimSpace(vitem) == "" {
			// Decryption failed or produced empty result — use raw value as plaintext
			vitem = r.Value
		}
		resp = append(resp, SplashItemDTO{
			ID:        uint(r.ID),
			Name:      r.Name,
			Value:     vitem,
			ServerID:  r.ServerID,
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		})
	}
	return c.JSON(fiber.Map{"splash": resp})
}

// ApiSplashRefresh performs a live fetch via services and returns converted items like ApiSPlash
func ApiSplashRefresh(c *fiber.Ctx) error {
	items, err := services.FetchSplashAndReturn()
	if err != nil {
		return fiber.ErrInternalServerError
	}
	resp := make([]SplashItemDTO, 0, len(items))
	for _, r := range items {
		vitem, err := utils.DecryptValue(r.Value, int(r.ID))
		if err != nil || strings.TrimSpace(vitem) == "" {
			vitem = r.Value
		}
		resp = append(resp, SplashItemDTO{
			ID:        uint(r.ID),
			Name:      r.Name,
			Value:     vitem,
			ServerID:  r.ServerID,
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		})
	}
	return c.JSON(fiber.Map{"splash": resp})
}

// ApiSettings returns public application settings for the mobile app
func ApiSettings(c *fiber.Ctx) error {
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		// ensure a default response even if not seeded yet
		s = models.AppSettings{
			AdsEnabledInSplash:      false,
			ShowAdsAfterSplash:      false,
			ShowAdsOnMainPage:       false,
			AdsRewardEnabled:        false,
			AdsAppOpenEnabled:       false,
			CurrentVersion:          "1.0.0",
			ConnectedTimeoutSeconds: 15,
			SplashConfCount:         4,
			ConnectionTimer:         1000,
			CurrentVersionCode:      4000011,
			WheelEnabled:            true,
		}
	}
	return c.JSON(fiber.Map{
		"ads_enabled_in_splash":  s.AdsEnabledInSplash,
		"show_ads_after_splash":  s.ShowAdsAfterSplash,
		"show_ads_on_main_page":  s.ShowAdsOnMainPage,
		"ads_reward_enabled":     s.AdsRewardEnabled,
		"ads_app_open_enabled":   s.AdsAppOpenEnabled,
		"reward_display_percent": s.RewardDisplayPercent,
		"current_version":        s.CurrentVersion,
		"ad_unit_id":             s.AdUnitID,
		"ads_reward_unit":        s.AdsRewardUnit,
		"ads_unit_open":          s.AdsUnitOpen,
		"ads_application_id":     s.AdsApplicationID,
		"updated_app":            s.UpdateEnable,
		"privacy_url":            s.PrivacyURL,
		"connected_timeout":      s.ConnectedTimeoutSeconds,
		"splash_conf_count":      s.SplashConfCount,
		"link_app":               s.LinkApp,
		"release_notes":          s.ReleaseNotes,
		"connection_timer":       s.ConnectionTimer,
		"current_version_code":   s.CurrentVersionCode,
		"wheel_enabled":          s.WheelEnabled,
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
	if pkg == "" {
		pkg = strings.TrimSpace(in.Package)
	}
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
