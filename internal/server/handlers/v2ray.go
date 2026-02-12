package handlers

import (
    "bufio"
    "fmt"
    "strconv"
    "strings"

    "github.com/gofiber/fiber/v2"

    "vpnpannel/internal/database"
    "vpnpannel/internal/models"
    "vpnpannel/internal/services"
)

func V2RayList(c *fiber.Ctx) error {
    var nodes []models.V2RayNode
    database.DB.Order("id desc").Find(&nodes)
    return c.Render("v2ray/index", fiber.Map{
        "title": "V2Ray Nodes",
        "nodes": nodes,
    })
}

func V2RayNewPage(c *fiber.Ctx) error {
    return c.Render("v2ray/new", fiber.Map{"title": "Add V2Ray Node"})
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
    }
    if err := c.BodyParser(&in); err != nil {
        return fiber.ErrBadRequest
    }
    adsEnabled := in.Ads != ""

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
            node = models.V2RayNode{
                Name:     name,
                Address:  p.Address,
                Port:     p.Port,
                Protocol: p.Protocol,
                Tags:     p.Tags,
                Ads:      adsEnabled,
                IsActive: true,
                RawLink:  line,
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
        if err != nil { return c.Status(fiber.StatusBadRequest).SendString("invalid link") }
        name := strings.TrimSpace(p.Name)
        if name == "" {
            name = fmt.Sprintf("%s:%d", p.Address, p.Port)
        }
        node = models.V2RayNode{Name: name, Address: p.Address, Port: p.Port, Protocol: p.Protocol, Tags: p.Tags, Ads: adsEnabled, IsActive: true, RawLink: in.Link}
    } else {
        node = models.V2RayNode{Name: in.Name, Address: in.Address, Port: in.Port, Protocol: in.Protocol, Tags: in.Tags, Ads: adsEnabled, IsActive: true}
    }
    if err := database.DB.Create(&node).Error; err != nil {
        return fiber.ErrInternalServerError
    }
    return c.Redirect("/admin/v2ray")
}

func V2RayDelete(c *fiber.Ctx) error {
    id, _ := strconv.Atoi(c.Params("id"))
    database.DB.Delete(&models.V2RayNode{}, id)
    return c.Redirect("/admin/v2ray")
}

