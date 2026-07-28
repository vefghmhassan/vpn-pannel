package handlers

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

var v2rayAllowedPageSizes = map[int]bool{25: true, 50: true, 100: true, 200: true}

const v2rayDefaultPageSize = 50

func v2rayFilteredQuery(address, protocol, adsFilter, activeFilter string) *gorm.DB {
	q := database.DB.Model(&models.V2RayNode{})
	if address != "" {
		q = q.Where("address = ?", address)
	}
	if protocol != "" {
		q = q.Where("protocol = ?", protocol)
	}
	if adsFilter == "true" {
		q = q.Where("ads = ?", true)
	} else if adsFilter == "false" {
		q = q.Where("ads = ?", false)
	}
	if activeFilter == "true" {
		q = q.Where("is_active = ?", true)
	} else if activeFilter == "false" {
		q = q.Where("is_active = ?", false)
	}
	return q
}

func V2RayList(c *fiber.Ctx) error {
	address := strings.TrimSpace(c.Query("address"))
	protocol := strings.TrimSpace(c.Query("protocol"))
	adsFilter := strings.TrimSpace(c.Query("ads"))
	activeFilter := strings.TrimSpace(c.Query("active"))

	pageSize := v2rayDefaultPageSize
	if v, err := strconv.Atoi(c.Query("page_size")); err == nil && v2rayAllowedPageSizes[v] {
		pageSize = v
	}
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}

	var total int64
	v2rayFilteredQuery(address, protocol, adsFilter, activeFilter).Count(&total)
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	var nodes []models.V2RayNode
	v2rayFilteredQuery(address, protocol, adsFilter, activeFilter).
		Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&nodes)

	var addresses []string
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("address").Pluck("address", &addresses).Error
	var protocols []string
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("protocol").Pluck("protocol", &protocols).Error

	qs := url.Values{}
	if address != "" {
		qs.Set("address", address)
	}
	if protocol != "" {
		qs.Set("protocol", protocol)
	}
	if adsFilter != "" {
		qs.Set("ads", adsFilter)
	}
	if activeFilter != "" {
		qs.Set("active", activeFilter)
	}
	qs.Set("page_size", strconv.Itoa(pageSize))

	return c.Render("v2ray/index", fiber.Map{
		"title":      "V2Ray Nodes",
		"nodes":      nodes,
		"addresses":  addresses,
		"protocols":  protocols,
		"page":       page,
		"totalPages": totalPages,
		"total":      total,
		"pageSize":   pageSize,
		"hasPrev":    page > 1,
		"hasNext":    page < totalPages,
		"prevPage":   page - 1,
		"nextPage":   page + 1,
		"pageQuery":  qs.Encode(),
		"filters": fiber.Map{
			"address":  address,
			"protocol": protocol,
			"ads":      adsFilter,
			"active":   activeFilter,
		},
	})
}

func V2RayNewPage(c *fiber.Ctx) error {
	countries := listCountryCodes()
	return c.Render("v2ray/new", fiber.Map{
		"title":         "Add V2Ray Node",
		"countryPicker": countryPickerVM{Countries: countries},
	})
}

func V2RayEditPage(c *fiber.Ctx) error {
	id, _ := strconv.Atoi(c.Params("id"))
	var node models.V2RayNode
	if err := database.DB.First(&node, id).Error; err != nil {
		return fiber.ErrNotFound
	}
	countries := listCountryCodes()
	return c.Render("v2ray/edit", fiber.Map{
		"title":         "Edit V2Ray Node",
		"node":          node,
		"countryPicker": countryPickerVM{Countries: countries, Selected: node.CountryCode},
	})
}

func V2RayCreate(c *fiber.Ctx) error {
	var in struct {
		Name     string `form:"name"`
		Address  string `form:"address"`
		Port     int    `form:"port"`
		Protocol string `form:"protocol"`
		Tags     string `form:"tags"`
		Link     string `form:"link"`
		Links    string `form:"links"`
		Mode     string `form:"mode"` // link or manual
		Ads      string `form:"ads"`
		Country  string `form:"country"`
		BaseName string `form:"base_name"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	adsEnabled := in.Ads != ""
	country := strings.ToUpper(strings.TrimSpace(in.Country))
	countryFlag := ""
	if country != "" {
		countryFlag = "/country/" + country + ".png"
	}

	var node models.V2RayNode
	if in.Mode == "link" && strings.TrimSpace(in.Links) != "" {
		baseName := strings.TrimSpace(in.BaseName)
		if len(baseName) > 80 {
			baseName = baseName[:80]
		}
		var batchAllocator *nameAllocator
		if baseName != "" {
			batchAllocator = newNameAllocator(baseName)
		}
		perLineAllocators := map[string]*nameAllocator{}

		added := 0
		failed := 0
		scanner := bufio.NewScanner(strings.NewReader(in.Links))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			p, err := services.ParseV2Link(line)
			if err != nil {
				failed++
				continue
			}

			var name string
			if batchAllocator != nil {
				name = batchAllocator.allocate(true)
			} else {
				remark := strings.TrimSpace(p.Name)
				if remark == "" {
					remark = fmt.Sprintf("%s:%d", p.Address, p.Port)
				}
				alloc, ok := perLineAllocators[remark]
				if !ok {
					alloc = newNameAllocator(remark)
					perLineAllocators[remark] = alloc
				}
				name = alloc.allocate(false)
			}
			rawLink := line
			if p.RawConfig != "" {
				rawLink = p.RawConfig
			}
			node = models.V2RayNode{
				Name:        name,
				Address:     p.Address,
				Port:        p.Port,
				Protocol:    p.Protocol,
				Tags:        p.Tags,
				Ads:         adsEnabled,
				CountryCode: country,
				CountryFlag: countryFlag,
				IsActive:    true,
				RawLink:     rawLink,
			}
			if err := database.DB.Create(&node).Error; err != nil {
				failed++
				continue
			}
			added++
		}
		if added == 0 {
			return c.Status(fiber.StatusBadRequest).SendString("no valid links")
		}
		return c.Redirect("/admin/v2ray")
	}

	if in.Mode == "link" && strings.TrimSpace(in.Link) != "" {
		p, err := services.ParseV2Link(in.Link)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("invalid link")
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = fmt.Sprintf("%s:%d", p.Address, p.Port)
		}
		if v2rayNameExists(name) {
			return c.Status(fiber.StatusBadRequest).SendString("duplicate name")
		}
		rawLink := in.Link
		if p.RawConfig != "" {
			rawLink = p.RawConfig
		}
		node = models.V2RayNode{Name: name, Address: p.Address, Port: p.Port, Protocol: p.Protocol, Tags: p.Tags, Ads: adsEnabled, CountryCode: country, CountryFlag: countryFlag, IsActive: true, RawLink: rawLink}
	} else {
		if in.Name != "" && v2rayNameExists(in.Name) {
			return c.Status(fiber.StatusBadRequest).SendString("duplicate name")
		}
		node = models.V2RayNode{Name: in.Name, Address: in.Address, Port: in.Port, Protocol: in.Protocol, Tags: in.Tags, Ads: adsEnabled, CountryCode: country, CountryFlag: countryFlag, IsActive: true}
	}
	if err := database.DB.Create(&node).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Redirect("/admin/v2ray")
}

func V2RayUpdate(c *fiber.Ctx) error {
	id, _ := strconv.Atoi(c.Params("id"))
	var node models.V2RayNode
	if err := database.DB.First(&node, id).Error; err != nil {
		return fiber.ErrNotFound
	}

	var in struct {
		Name     string `form:"name"`
		Address  string `form:"address"`
		Port     int    `form:"port"`
		Protocol string `form:"protocol"`
		Tags     string `form:"tags"`
		Link     string `form:"link"`
		Mode     string `form:"mode"` // link or manual
		Ads      string `form:"ads"`
		Country  string `form:"country"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}

	adsEnabled := in.Ads != ""
	country := strings.ToUpper(strings.TrimSpace(in.Country))
	countryFlag := ""
	if country != "" {
		countryFlag = "/country/" + country + ".png"
	}

	if in.Mode == "link" {
		link := strings.TrimSpace(in.Link)
		if link == "" {
			return fiber.NewError(fiber.StatusBadRequest, "link required")
		}
		p, err := services.ParseV2Link(link)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid link")
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = fmt.Sprintf("%s:%d", p.Address, p.Port)
		}
		if v2rayNameExistsExcept(name, node.ID) {
			return fiber.NewError(fiber.StatusBadRequest, "duplicate name")
		}

		rawLink := link
		if p.RawConfig != "" {
			rawLink = p.RawConfig
		}

		node.Name = name
		node.Address = p.Address
		node.Port = p.Port
		node.Protocol = p.Protocol
		node.Tags = p.Tags
		node.Ads = adsEnabled
		node.CountryCode = country
		node.CountryFlag = countryFlag
		node.RawLink = rawLink
	} else {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			return fiber.NewError(fiber.StatusBadRequest, "name required")
		}
		if v2rayNameExistsExcept(name, node.ID) {
			return fiber.NewError(fiber.StatusBadRequest, "duplicate name")
		}
		address := strings.TrimSpace(in.Address)
		if address == "" {
			return fiber.NewError(fiber.StatusBadRequest, "address required")
		}
		if in.Port <= 0 {
			return fiber.NewError(fiber.StatusBadRequest, "invalid port")
		}
		protocol := strings.TrimSpace(in.Protocol)
		if protocol == "" {
			return fiber.NewError(fiber.StatusBadRequest, "protocol required")
		}

		node.Name = name
		node.Address = address
		node.Port = in.Port
		node.Protocol = protocol
		node.Tags = strings.TrimSpace(in.Tags)
		node.Ads = adsEnabled
		node.CountryCode = country
		node.CountryFlag = countryFlag
	}

	if err := database.DB.Save(&node).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return c.Redirect("/admin/v2ray")
}

type countryPickerVM struct {
	Countries []string
	Selected  string
}

func listCountryCodes() []string {
	entries, err := os.ReadDir("country")
	if err != nil {
		return []string{}
	}
	codes := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(strings.ToLower(name), ".png") {
			code := strings.TrimSuffix(name, filepath.Ext(name))
			if code != "" {
				codes = append(codes, strings.ToUpper(code))
			}
		}
	}
	sort.Strings(codes)
	return codes
}

func v2rayNameExists(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	var count int64
	database.DB.Model(&models.V2RayNode{}).Where("name = ?", name).Count(&count)
	return count > 0
}

func v2rayNameExistsExcept(name string, id uint) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	var count int64
	database.DB.Model(&models.V2RayNode{}).Where("name = ? AND id <> ?", name, id).Count(&count)
	return count > 0
}

const nameNumberSeparator = "-"

// nameAllocator hands out unique names based on a base string, numbering
// collisions as "base-2", "base-3", etc. It loads existing matches from the
// DB once (rather than per-row) so bulk imports of ~1000 links stay fast.
type nameAllocator struct {
	base  string
	taken map[string]bool
	next  int
}

func newNameAllocator(base string) *nameAllocator {
	taken := map[string]bool{}
	var names []string
	database.DB.Model(&models.V2RayNode{}).
		Where("name = ? OR name LIKE ?", base, base+nameNumberSeparator+"%").
		Pluck("name", &names)

	maxN := 0
	re := regexp.MustCompile("^" + regexp.QuoteMeta(base+nameNumberSeparator) + `(\d+)$`)
	for _, n := range names {
		taken[n] = true
		if m := re.FindStringSubmatch(n); m != nil {
			if v, err := strconv.Atoi(m[1]); err == nil && v > maxN {
				maxN = v
			}
		}
	}
	return &nameAllocator{base: base, taken: taken, next: maxN + 1}
}

// allocate returns a free name derived from the allocator's base. When
// forceNumber is false, the bare base name is returned once (if unused)
// before numbering kicks in; when true, every call returns a numbered form
// starting at 1 (or continuing after any pre-existing "base-N" names).
func (a *nameAllocator) allocate(forceNumber bool) string {
	if !forceNumber && !a.taken[a.base] {
		a.taken[a.base] = true
		return a.base
	}
	for {
		candidate := fmt.Sprintf("%s%s%d", a.base, nameNumberSeparator, a.next)
		a.next++
		if !a.taken[candidate] {
			a.taken[candidate] = true
			return candidate
		}
	}
}

func V2RayDelete(c *fiber.Ctx) error {
	id, _ := strconv.Atoi(c.Params("id"))
	database.DB.Delete(&models.V2RayNode{}, id)
	return c.Redirect("/admin/v2ray")
}

func V2RayBatchDelete(c *fiber.Ctx) error {
	var in struct {
		IDs []uint `form:"ids"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	if len(in.IDs) == 0 {
		return c.Redirect("/admin/v2ray")
	}
	database.DB.Where("id IN ?", in.IDs).Delete(&models.V2RayNode{})
	return c.Redirect("/admin/v2ray")
}
