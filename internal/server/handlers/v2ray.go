package handlers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

func V2RayList(c *fiber.Ctx) error {
	address := strings.TrimSpace(c.Query("address"))
	protocol := strings.TrimSpace(c.Query("protocol"))
	adsFilter := strings.TrimSpace(c.Query("ads"))
	activeFilter := strings.TrimSpace(c.Query("active"))

	var nodes []models.V2RayNode
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
	q.Order("id desc").Find(&nodes)

	var addresses []string
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("address").Pluck("address", &addresses).Error
	var protocols []string
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("protocol").Pluck("protocol", &protocols).Error
	return c.Render("v2ray/index", fiber.Map{
		"title":     "V2Ray Nodes",
		"nodes":     nodes,
		"addresses": addresses,
		"protocols": protocols,
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
		"title":     "Add V2Ray Node",
		"countries": countries,
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
		"title":     "Edit V2Ray Node",
		"node":      node,
		"countries": countries,
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
			name := strings.TrimSpace(p.Name)
			if name == "" {
				name = fmt.Sprintf("%s:%d", p.Address, p.Port)
			}
			if v2rayNameExists(name) {
				failed++
				continue
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
