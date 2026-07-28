package handlers

import (
	"encoding/json"
	"math/rand"
	"strings"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

// maxWheelSegments caps how many slices the admin can design.
const maxWheelSegments = 50

// wheelDisplayTypes and wheelRewardTypes are the allowed enum values.
var wheelDisplayTypes = map[string]bool{"text": true, "icon": true}
var wheelRewardTypes = map[string]bool{"time": true, "premium": true, "none": true}

// wheelPalette is used to assign a random color to segments left blank.
var wheelPalette = []string{
	"#ef4444", "#f97316", "#f59e0b", "#eab308", "#84cc16",
	"#22c55e", "#10b981", "#14b8a6", "#06b6d4", "#3b82f6",
	"#6366f1", "#8b5cf6", "#a855f7", "#d946ef", "#ec4899",
}

func randomHexColor() string {
	return wheelPalette[rand.Intn(len(wheelPalette))]
}

// WheelPage renders the admin management page for the lucky wheel.
func WheelPage(c *fiber.Ctx) error {
	var segments []models.WheelSegment
	database.DB.Order("position asc, id asc").Find(&segments)

	totalWeight := 0
	for _, s := range segments {
		if s.IsActive && s.Weight > 0 {
			totalWeight += s.Weight
		}
	}

	return c.Render("wheel/index", fiber.Map{
		"title":       "گردونه شانس",
		"segments":    segments,
		"totalWeight": totalWeight,
		"maxSegments": maxWheelSegments,
	})
}

// wheelSegmentInput is one row posted from the admin form (as JSON).
type wheelSegmentInput struct {
	DisplayType string `json:"displayType"`
	Label       string `json:"label"`
	Icon        string `json:"icon"`
	RewardType  string `json:"rewardType"`
	RewardValue int    `json:"rewardValue"`
	Color       string `json:"color"`
	Weight      int    `json:"weight"`
	IsActive    bool   `json:"isActive"`
}

// WheelUpdate replaces all wheel segments with the submitted set.
func WheelUpdate(c *fiber.Ctx) error {
	raw := strings.TrimSpace(c.FormValue("segments_json"))
	if raw == "" {
		raw = "[]"
	}

	var in []wheelSegmentInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid segments payload")
	}
	if len(in) > maxWheelSegments {
		return fiber.NewError(fiber.StatusBadRequest, "too many segments")
	}

	segments := make([]models.WheelSegment, 0, len(in))
	for i, row := range in {
		displayType := strings.ToLower(strings.TrimSpace(row.DisplayType))
		if !wheelDisplayTypes[displayType] {
			displayType = "text"
		}
		rewardType := strings.ToLower(strings.TrimSpace(row.RewardType))
		if !wheelRewardTypes[rewardType] {
			rewardType = "none"
		}
		rewardValue := row.RewardValue
		if rewardValue < 0 {
			rewardValue = 0
		}
		weight := row.Weight
		if weight < 0 {
			weight = 0
		}
		color := normalizeHexColor(row.Color)

		segments = append(segments, models.WheelSegment{
			Position:    i,
			DisplayType: displayType,
			Label:       strings.TrimSpace(row.Label),
			Icon:        strings.TrimSpace(row.Icon),
			RewardType:  rewardType,
			RewardValue: rewardValue,
			Color:       color,
			Weight:      weight,
			IsActive:    row.IsActive,
		})
	}

	// Replace-all in a single transaction.
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&models.WheelSegment{}).Error; err != nil {
			return err
		}
		if len(segments) > 0 {
			if err := tx.Create(&segments).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fiber.ErrInternalServerError
	}

	return c.Redirect("/admin/wheel")
}

// normalizeHexColor returns a cleaned #rrggbb value, or "" if not a valid hex
// (empty means "assign a random color" when served to the client).
func normalizeHexColor(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "#") {
		v = "#" + v
	}
	if len(v) != 7 {
		return ""
	}
	for _, ch := range v[1:] {
		isHex := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
		if !isHex {
			return ""
		}
	}
	return strings.ToLower(v)
}

// wheelSegmentDTO is the client-facing shape of a segment.
type wheelSegmentDTO struct {
	ID            uint    `json:"id"`
	Position      int     `json:"position"`
	DisplayType   string  `json:"display_type"`
	Label         string  `json:"label"`
	Icon          string  `json:"icon"`
	RewardType    string  `json:"reward_type"`
	RewardValue   int     `json:"reward_value"`
	Color         string  `json:"color"`
	ColorIsRandom bool    `json:"color_is_random"`
	Weight        int     `json:"weight"`
	Percent       float64 `json:"percent"`
}

// ApiWheel returns the active wheel configuration for the mobile app.
// The client performs the weighted draw and handles the reward.
func ApiWheel(c *fiber.Ctx) error {
	// Global on/off flag from app settings (defaults to enabled if missing).
	enabled := true
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err == nil {
		enabled = s.WheelEnabled
	}

	var segments []models.WheelSegment
	database.DB.Where("is_active = ?", true).Order("position asc, id asc").Find(&segments)

	totalWeight := 0
	for _, s := range segments {
		if s.Weight > 0 {
			totalWeight += s.Weight
		}
	}

	out := make([]wheelSegmentDTO, 0, len(segments))
	for _, s := range segments {
		percent := 0.0
		if totalWeight > 0 && s.Weight > 0 {
			percent = float64(s.Weight) / float64(totalWeight) * 100
		}
		color := s.Color
		colorIsRandom := false
		if color == "" {
			color = randomHexColor()
			colorIsRandom = true
		}
		out = append(out, wheelSegmentDTO{
			ID:            s.ID,
			Position:      s.Position,
			DisplayType:   s.DisplayType,
			Label:         s.Label,
			Icon:          s.Icon,
			RewardType:    s.RewardType,
			RewardValue:   s.RewardValue,
			Color:         color,
			ColorIsRandom: colorIsRandom,
			Weight:        s.Weight,
			Percent:       percent,
		})
	}

	return c.JSON(fiber.Map{
		"enabled":      enabled,
		"segments":     out,
		"total_weight": totalWeight,
	})
}
