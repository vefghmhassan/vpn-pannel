package handlers

import (
    "strconv"

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
        Mode     string `form:"mode"` // link or manual
    }
    if err := c.BodyParser(&in); err != nil {
        return fiber.ErrBadRequest
    }
    var node models.V2RayNode
    if in.Mode == "link" && in.Link != "" {
        p, err := services.ParseV2Link(in.Link)
        if err != nil { return c.Status(fiber.StatusBadRequest).SendString("invalid link") }
        node = models.V2RayNode{Name: p.Name, Address: p.Address, Port: p.Port, Protocol: p.Protocol, Tags: p.Tags, IsActive: true, RawLink: in.Link}
    } else {
        node = models.V2RayNode{Name: in.Name, Address: in.Address, Port: in.Port, Protocol: in.Protocol, Tags: in.Tags, IsActive: true}
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


