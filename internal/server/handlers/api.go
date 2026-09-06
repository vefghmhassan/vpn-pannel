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
	"gorm.io/gorm/clause"

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

// grantAdFreeReward extends the user's ad-free window by d. If a previous reward is
// still running it stacks on top of the remaining time (so a second referral adds to
// the first rather than replacing it); otherwise the window starts now.
//
// This only mutates the in-memory user — the caller is responsible for persisting it.
func grantAdFreeReward(u *models.User, d time.Duration) {
	base := time.Now()
	if u.RewardExpiresAt != nil && u.RewardExpiresAt.After(base) {
		base = *u.RewardExpiresAt
	}
	exp := base.Add(d)
	u.RewardExpiresAt = &exp
}

// serverClockFields returns the clock metadata that every invite response carries,
// so the client never has to trust its own device clock or guess the server's UTC
// offset when it renders a countdown.
func serverClockFields(now time.Time) fiber.Map {
	_, offsetSeconds := now.Zone()
	return fiber.Map{
		"server_time":               now, // RFC3339 with the server's offset
		"server_time_unix":          now.Unix(),
		"server_timezone":           now.Location().String(),
		"server_utc_offset_seconds": offsetSeconds,
	}
}

// rewardStatusFields describes the caller's remaining ad-free window. Both sides of
// a referral get this identical shape from every invite endpoint.
//
// Every key is always present (zeroed when there is no reward) so clients can read
// them unconditionally; only the two timestamps go null. remaining_days/hours/minutes
// are a non-overlapping breakdown meant to be displayed together, unlike the legacy
// days_left/hours_left/minutes_left, which are each a total of the whole remainder
// and are kept only so already-published apps keep working.
func rewardStatusFields(u *models.User, now time.Time) fiber.Map {
	m := fiber.Map{
		"reward_active":          false,
		"reward_expires_at":      nil,
		"reward_expires_at_unix": nil,
		"remaining_seconds":      int64(0),
		"remaining_days":         0,
		"remaining_hours":        0,
		"remaining_minutes":      0,
		"days_left":              0,
		"hours_left":             0,
		"minutes_left":           0,
	}
	if u.RewardExpiresAt == nil {
		return m
	}

	expiresAt := *u.RewardExpiresAt
	m["reward_expires_at"] = expiresAt
	m["reward_expires_at_unix"] = expiresAt.Unix()
	if !now.Before(expiresAt) {
		return m
	}

	remaining := expiresAt.Sub(now)
	secs := int64(remaining.Seconds())
	m["reward_active"] = true
	m["remaining_seconds"] = secs
	m["remaining_days"] = int(secs / 86400)
	m["remaining_hours"] = int((secs % 86400) / 3600)
	m["remaining_minutes"] = int((secs % 3600) / 60)
	m["days_left"] = int(remaining.Hours()/24) + 1
	m["hours_left"] = int(remaining.Hours())
	m["minutes_left"] = int(remaining.Minutes())
	return m
}

// mergeInto copies src into dst. Used to fold the shared clock/reward blocks into
// each endpoint's own response map.
func mergeInto(dst, src fiber.Map) fiber.Map {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// currentSettings loads the singleton AppSettings row (row 1), returning a zero
// value (safe defaults) if it hasn't been seeded yet.
func currentSettings() models.AppSettings {
	var s models.AppSettings
	database.DB.First(&s, 1)
	return s
}

// referralDisabledResponse is what every /invite endpoint returns while the feature
// is switched off: a plain 200 carrying referral_enabled=false, so the app can hide
// the invite screen without having to special-case an error status.
func referralDisabledResponse(c *fiber.Ctx) error {
	resp := fiber.Map{
		"referral_enabled": false,
		"ok":               false,
	}
	mergeInto(resp, serverClockFields(time.Now()))
	return c.JSON(resp)
}

// ApiInviteCode returns the caller's own shareable invite code, generating one on
// first request (idempotent — repeat calls return the same code) — along with the
// admin-configured task text and a ready-to-share message with the code filled in.
func ApiInviteCode(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}

	settings := currentSettings()
	// Checked before findOrCreateUserByToken so a disabled feature never mints an
	// invite code (or any other state) as a side effect.
	if !settings.ReferralEnabled {
		return referralDisabledResponse(c)
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

	shareText := strings.ReplaceAll(settings.ReferralShareText, "{code}", *user.InviteCode)

	// One clock reading for the whole response, so the countdown and the server
	// time it is relative to describe the same instant.
	now := time.Now()
	resp := fiber.Map{
		"referral_enabled": true,
		"invite_code":      *user.InviteCode,
		"invites_count":    referralCount(user.ID),
		"task_text":        settings.ReferralTaskText,
		"share_text":       shareText,
		// So the invite screen can advertise what each side gets before redeeming.
		"instant_reward_enabled": settings.ReferralInstantRewardEnabled,
		"inviter_reward_minutes": settings.ReferralInviterRewardMinutes,
		"invitee_reward_minutes": settings.ReferralInviteeRewardMinutes,
	}
	// Carried here too so the invite screen can show the caller's own remaining
	// reward without a second round trip.
	mergeInto(resp, rewardStatusFields(user, now))
	mergeInto(resp, serverClockFields(now))
	return c.JSON(resp)
}

// ApiInviteRedeem links the caller to whoever owns the given invite code and, when
// the instant reward is enabled, pays *both* sides ad-free time right away: the
// redeemer once, and the code's owner for every friend they bring in (up to
// ReferralMaxRewardedInvites). Each user may redeem exactly one code, ever, cannot
// redeem their own, and cannot redeem the code of somebody they already referred.
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

	settings := currentSettings()
	// Checked before any lookup or write, so a disabled feature records nothing.
	if !settings.ReferralEnabled {
		return referralDisabledResponse(c)
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
	// A ↔ B: if the code's owner was themselves referred by this caller, refuse.
	// Otherwise two people simply swap codes and each collects both sides' rewards.
	if referrer.ReferredByUserID != nil && *referrer.ReferredByUserID == user.ID {
		return fiber.NewError(fiber.StatusConflict, "cannot redeem the code of someone you already referred")
	}

	var grantedMinutes int

	// One transaction, with the referrer row locked: RewardedReferralCount gates a
	// payout, so two friends redeeming at the same moment must not both read the
	// same count and slip past the cap.
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		var locked models.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&locked, referrer.ID).Error; err != nil {
			return err
		}

		user.ReferredByUserID = &locked.ID

		if settings.ReferralInstantRewardEnabled {
			if settings.ReferralInviteeRewardMinutes > 0 {
				grantedMinutes = settings.ReferralInviteeRewardMinutes
				grantAdFreeReward(user, time.Duration(grantedMinutes)*time.Minute)
			}

			underCap := settings.ReferralMaxRewardedInvites == 0 ||
				locked.RewardedReferralCount < settings.ReferralMaxRewardedInvites
			if settings.ReferralInviterRewardMinutes > 0 && underCap {
				grantAdFreeReward(&locked, time.Duration(settings.ReferralInviterRewardMinutes)*time.Minute)
				locked.RewardedReferralCount++
				if err := tx.Save(&locked).Error; err != nil {
					return err
				}
			}
		}

		return tx.Save(user).Error
	})
	if err != nil {
		return fiber.ErrInternalServerError
	}

	now := time.Now()
	resp := fiber.Map{
		"referral_enabled": true,
		"ok":               true,
		// What this redemption just added, alongside the total window below.
		"reward_granted_minutes": grantedMinutes,
		"reward_granted_seconds": grantedMinutes * 60,
	}
	mergeInto(resp, rewardStatusFields(user, now))
	mergeInto(resp, serverClockFields(now))
	return c.JSON(resp)
}

// ApiInviteRewardStatus reports how much ad-free time the caller has left. Purely a
// read: rewards are granted at redemption time, so polling this never changes state.
func ApiInviteRewardStatus(c *fiber.Ctx) error {
	token, err := parseClientToken(c)
	if err != nil {
		return err
	}

	settings := currentSettings()
	if !settings.ReferralEnabled {
		return referralDisabledResponse(c)
	}

	user, err := findOrCreateUserByToken(token)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if !user.IsActive {
		return fiber.ErrUnauthorized
	}

	now := time.Now()
	resp := fiber.Map{
		"referral_enabled":        true,
		"invites_count":           referralCount(user.ID),
		"rewarded_referral_count": user.RewardedReferralCount,
	}
	mergeInto(resp, rewardStatusFields(user, now))
	mergeInto(resp, serverClockFields(now))
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

// ApiSplashConf returns AppSettings.SplashConfCount nodes per request: one ads
// node plus the rest non-ads, as separate lists. When
// AppSettings.SplashDiverseServers is on, the non-ads picks are spread across
// distinct node addresses rather than drawn uniformly at random.
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
	var noAdsList []models.V2RayNode
	var err error
	if s.SplashDiverseServers {
		noAdsList, err = findDiverseNoAdsNodes(noAdsCount)
	} else {
		noAdsList, err = findOrAssignNodes(reqKey, false, noAdsCount, now)
	}
	if err != nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "no non-ads nodes available")
	}
	// Multi-config ads is a ceiling, not a quota: findDiverseAdsNodes returns at
	// most one node per address, so with fewer ads servers than asked for the
	// response simply carries fewer configs rather than repeating a server.
	adsCount := 1
	if s.AdsMultiConfigEnabled && s.AdsConfigCount > 1 {
		adsCount = s.AdsConfigCount
	}
	var adsList []models.V2RayNode
	if adsCount > 1 {
		adsList, err = findDiverseAdsNodes(adsCount)
	} else {
		adsList, err = findOrAssignNodes(reqKey, true, 1, now)
	}
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

// diverseNoAdsSQL picks non-ads nodes round-robin across distinct addresses.
// ROW_NUMBER numbers each address's nodes in random order, so the outer ORDER BY
// emits round 1 first (one random node per address, in random address order),
// then round 2, and so on. With at least `count` distinct addresses every row
// returned comes from a different server; with fewer it degrades gracefully and
// still returns `count` nodes, balanced across whatever addresses exist.
//
// The columns are listed explicitly because the inner SELECT * also exposes rn.
const diverseNoAdsSQL = `
SELECT id, created_at, updated_at, name, address, port, protocol, tags, ads,
       country_code, country_flag, is_active, capacity, raw_link
FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY address ORDER BY random()) AS rn
    FROM v2_ray_nodes
    WHERE is_active = true AND ads = false
) ranked
ORDER BY rn, random()
LIMIT ?`

// findDiverseNoAdsNodes is the AppSettings.SplashDiverseServers variant of
// findOrAssignNodes for the ads = false case: same contract, but it spreads the
// picks over distinct node addresses instead of drawing rows uniformly at
// random. Ads nodes deliberately keep using findOrAssignNodes.
func findDiverseNoAdsNodes(count int) ([]models.V2RayNode, error) {
	if count <= 0 {
		return []models.V2RayNode{}, nil
	}
	var nodes []models.V2RayNode
	if err := database.DB.Raw(diverseNoAdsSQL, count).Scan(&nodes).Error; err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return nodes, nil
}

// diverseAdsSQL picks at most one ads node per distinct address. ROW_NUMBER
// numbers each address's nodes in random order and the outer WHERE keeps only
// the first, so the candidate set is exactly "one random node from every ads
// server"; ORDER BY random() then chooses which of those servers make the cut.
//
// Unlike diverseNoAdsSQL this deliberately never starts a second round: asking
// for more configs than there are ads servers yields fewer rows rather than two
// configs from the same server.
//
// The columns are listed explicitly because the inner SELECT * also exposes rn.
const diverseAdsSQL = `
SELECT id, created_at, updated_at, name, address, port, protocol, tags, ads,
       country_code, country_flag, is_active, capacity, raw_link
FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY address ORDER BY random()) AS rn
    FROM v2_ray_nodes
    WHERE is_active = true AND ads = true
) ranked
WHERE rn = 1
ORDER BY random()
LIMIT ?`

// findDiverseAdsNodes is the AppSettings.AdsMultiConfigEnabled variant of
// findOrAssignNodes for the ads = true case: same contract, but it returns up to
// count nodes drawn from distinct addresses instead of a single random one.
func findDiverseAdsNodes(count int) ([]models.V2RayNode, error) {
	if count <= 0 {
		return []models.V2RayNode{}, nil
	}
	var nodes []models.V2RayNode
	if err := database.DB.Raw(diverseAdsSQL, count).Scan(&nodes).Error; err != nil {
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
			AdsMultiConfigEnabled:   false,
			AdsConfigCount:          1,
			ReferralEnabled:         false,
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
		// So the app knows to expect more than one entry in ads_list.
		"ads_multi_config_enabled": s.AdsMultiConfigEnabled,
		"ads_config_count":         s.AdsConfigCount,
		// So the app can hide the invite menu without calling an /invite endpoint.
		"referral_enabled": s.ReferralEnabled,
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
