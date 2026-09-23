package handlers

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

// V2RaySetActive toggles one node's visibility to the app.
//
// The panel could previously only create, edit and delete nodes, so is_active —
// which the splash query already honours — could never be turned off. Taking a
// broken server out of rotation meant deleting it.
func V2RaySetActive(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.ErrBadRequest
	}

	var node models.V2RayNode
	if err := database.DB.First(&node, id).Error; err != nil {
		return fiber.ErrNotFound
	}

	active := parseActive(c.FormValue("active"), !node.IsActive)
	if err := database.DB.Model(&models.V2RayNode{}).
		Where("id = ?", id).Update("is_active", active).Error; err != nil {
		return fiber.ErrInternalServerError
	}

	if wantsJSON(c) {
		return c.JSON(fiber.Map{"id": id, "is_active": active})
	}
	return c.Redirect(v2rayReturnTo(c))
}

// V2RayBulkActive flips every node that serves one address, which is the unit a
// server is replaced in: one machine backs many configs.
func V2RayBulkActive(c *fiber.Ctx) error {
	// BodyParser rather than FormValue: the browser form posts urlencoded and a
	// service may post JSON, and a silent 400 on the second is a nasty surprise.
	var in struct {
		Address string `form:"address" json:"address"`
		Active  string `form:"active" json:"active"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	address := strings.TrimSpace(in.Address)
	if address == "" {
		return fiber.NewError(fiber.StatusBadRequest, "address required")
	}
	active := parseActive(in.Active, false)

	res := database.DB.Model(&models.V2RayNode{}).
		Where("address = ?", address).Update("is_active", active)
	if res.Error != nil {
		return fiber.ErrInternalServerError
	}

	if wantsJSON(c) {
		return c.JSON(fiber.Map{"address": address, "is_active": active, "updated": res.RowsAffected})
	}
	return c.Redirect(v2rayReturnTo(c))
}

// replaceResult reports what a replacement did, per node.
type replaceResult struct {
	Updated int      `json:"updated"`
	Skipped int      `json:"skipped"`
	IDs     []uint   `json:"ids"`
	Errors  []string `json:"errors,omitempty"`
}

// V2RayReplaceAddress moves every config off one address and onto another.
//
// This is the whole point of the endpoint: the client dials RawLink, not
// Address, so both have to move together. Rewriting only the column would leave
// every config still pointing at the dead IP while the panel looked correct.
func V2RayReplaceAddress(c *fiber.Ctx) error {
	var in struct {
		OldAddress string `form:"old_address" json:"old_address"`
		NewAddress string `form:"new_address" json:"new_address"`
		NewPort    int    `form:"new_port" json:"new_port"`
		Country    string `form:"country" json:"country"`
		Activate   string `form:"activate" json:"activate"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}

	oldAddress := strings.TrimSpace(in.OldAddress)
	newAddress := strings.TrimSpace(in.NewAddress)
	if oldAddress == "" || newAddress == "" {
		return fiber.NewError(fiber.StatusBadRequest, "old_address and new_address are required")
	}

	country := strings.ToUpper(strings.TrimSpace(in.Country))
	countryFlag := ""
	if country != "" {
		countryFlag = "/country/" + country + ".png"
	}
	activate := parseActive(in.Activate, true)

	var nodes []models.V2RayNode
	if err := database.DB.Where("address = ?", oldAddress).Order("id").Find(&nodes).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	if len(nodes) == 0 {
		return fiber.NewError(fiber.StatusNotFound, "no nodes use that address")
	}

	// One index for the whole run. newNameAllocator queries per base, and every
	// node has a distinct base because its number is part of it — on a server
	// backing hundreds of configs that was hundreds of LIKE scans per request.
	index, err := newNameIndex()
	if err != nil {
		return fiber.ErrInternalServerError
	}

	out := replaceResult{}
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		for _, node := range nodes {
			rewritten := node.RawLink
			if strings.TrimSpace(node.RawLink) != "" {
				link, err := services.RewriteAddress(node.RawLink, newAddress, in.NewPort)
				if err != nil {
					// A config whose link cannot be rewritten is left completely
					// alone: a half-moved node is worse than an untouched one.
					out.Skipped++
					out.Errors = append(out.Errors,
						fmt.Sprintf("node %d (%s): %v", node.ID, node.Name, err))
					continue
				}
				rewritten = link
			}

			base := renameForCountry(node.Name, country)
			name := index.take(base, node.Name)

			// Clients show the link's own label, not this column, so a config
			// that moved would keep announcing its old country without this.
			if label := services.LinkLabel(rewritten); label != "" {
				relabelled, err := services.RewriteLabel(rewritten, renameForCountry(label, country))
				if err == nil {
					rewritten = relabelled
				}
			}

			updates := map[string]any{
				"address":   newAddress,
				"raw_link":  rewritten,
				"name":      name,
				"is_active": activate,
				// The original name is kept so nothing the operator chose is lost
				// to the renaming rule.
				"tags": mergeTags(node.Tags, "was:"+node.Name),
			}
			if in.NewPort > 0 {
				updates["port"] = in.NewPort
			}
			if country != "" {
				updates["country_code"] = country
				updates["country_flag"] = countryFlag
			}

			if err := tx.Model(&models.V2RayNode{}).Where("id = ?", node.ID).
				Updates(updates).Error; err != nil {
				return err
			}
			out.Updated++
			out.IDs = append(out.IDs, node.ID)
		}
		return nil
	})
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	if wantsJSON(c) {
		return c.JSON(out)
	}
	return c.Redirect(v2rayReturnTo(c))
}

// knownLocationTokens are the leading name fragments that describe where a node
// lives, so they can be swapped when it moves. Two-letter country codes are
// matched separately.
var knownLocationTokens = map[string]bool{
	"ash": true, "hil": true, "hel": true, "hel1": true, "fsn": true, "fsn1": true,
	"nbg": true, "nbg1": true, "sin": true, "nur": true, "fal": true,
}

// nameTokenSplit finds the first separator in a name: "ash-one-C-A-142" or
// "fi 9-166" both start with a location token.
var nameTokenSplit = regexp.MustCompile(`^([A-Za-z]{2,4}\d?)[-_ ]+(.+)$`)

// renameForCountry gives a node a name that says where it now lives.
//
// A leading token is replaced when it looks like a place — a two-letter country
// code or a known datacenter code — and otherwise the country is prefixed. The
// rule is a heuristic because the existing names are not uniform; the original
// is preserved in Tags so nothing is lost when it guesses wrong.
func renameForCountry(name, country string) string {
	name = strings.TrimSpace(name)
	if country == "" || name == "" {
		return name
	}
	prefix := strings.ToLower(country)

	// A name that is nothing but a place ("Am", "ash") becomes the country
	// alone. This mostly matters for link labels, which are often just the base.
	if lower := strings.ToLower(name); knownLocationTokens[lower] || len(lower) == 2 {
		return prefix
	}

	if m := nameTokenSplit.FindStringSubmatch(name); m != nil {
		token := strings.ToLower(m[1])
		if knownLocationTokens[token] || len(token) == 2 {
			if token == prefix {
				return name // already named for this country
			}
			return prefix + "-" + m[2]
		}
	}
	return prefix + "-" + name
}

// mergeTags appends a tag without duplicating it.
func mergeTags(tags, add string) string {
	tags = strings.TrimSpace(tags)
	if add == "" {
		return tags
	}
	for _, t := range strings.Split(tags, ",") {
		if strings.TrimSpace(t) == add {
			return tags
		}
	}
	if tags == "" {
		return add
	}
	return tags + "," + add
}

// parseActive reads a boolean form value, falling back when it is absent.
func parseActive(v string, def bool) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// wantsJSON reports whether the caller is a service rather than the admin UI.
// The browser forms rely on the redirect, so the JSON shape is opt-in.
func wantsJSON(c *fiber.Ctx) bool {
	return strings.Contains(c.Get("Accept"), "application/json") ||
		strings.Contains(c.Get("Content-Type"), "application/json")
}

// nameIndex hands out unique node names, reading the existing ones once.
//
// Names are unique in the database, so a rename that collides has to fall back
// to a numbered variant the way the panel's own importer does.
type nameIndex struct{ taken map[string]bool }

func newNameIndex() (*nameIndex, error) {
	var names []string
	if err := database.DB.Model(&models.V2RayNode{}).Pluck("name", &names).Error; err != nil {
		return nil, err
	}
	taken := make(map[string]bool, len(names))
	for _, n := range names {
		taken[n] = true
	}
	return &nameIndex{taken: taken}, nil
}

// take reserves base, or the next free "base-N". The name being replaced is
// released first: a node keeping its own name must not collide with itself.
func (x *nameIndex) take(base, releasing string) string {
	delete(x.taken, releasing)
	if !x.taken[base] {
		x.taken[base] = true
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s%s%d", base, nameNumberSeparator, n)
		if !x.taken[candidate] {
			x.taken[candidate] = true
			return candidate
		}
	}
}
