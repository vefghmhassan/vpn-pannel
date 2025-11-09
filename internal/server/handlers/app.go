package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
)

func AppList(c *fiber.Ctx) error {
	var versions []models.AppVersion
	database.DB.Preload("Builds").Order("version_code desc").Find(&versions)
	return c.Render("app/index", fiber.Map{
		"title":    "App Versions",
		"versions": versions,
	})
}

func AppNewPage(c *fiber.Ctx) error {
	return c.Render("app/new", fiber.Map{
		"title": "New App Version",
	})
}

func AppCreate(c *fiber.Ctx) error {
	packageName := strings.TrimSpace(c.FormValue("package_name"))
	versionCode, _ := strconv.Atoi(c.FormValue("version_code"))
	versionName := c.FormValue("version_name")
	changelog := c.FormValue("changelog")
	isMandatory := c.FormValue("mandatory") == "on"
	if packageName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "package_name required")
	}
	if versionCode <= 0 {
		return fiber.NewError(fiber.StatusBadRequest, "invalid version_code")
	}

	// create or upsert version
	v := models.AppVersion{PackageName: packageName, VersionCode: versionCode}
	if err := database.DB.Where("package_name = ? AND version_code = ?", packageName, versionCode).First(&v).Error; err != nil {
		v.PackageName = packageName
		v.VersionName = versionName
		v.Changelog = changelog
		v.IsMandatory = isMandatory
		if err := database.DB.Create(&v).Error; err != nil {
			return fiber.ErrInternalServerError
		}
	} else {
		v.VersionName = versionName
		v.Changelog = changelog
		v.IsMandatory = isMandatory
		_ = database.DB.Save(&v).Error
	}

	// ensure folder exists
	safePkg := func(s string) string {
		s = strings.ToLower(s)
		b := make([]rune, 0, len(s))
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' {
				b = append(b, r)
			} else {
				b = append(b, '-')
			}
		}
		return string(b)
	}
	baseDir := filepath.Join("uploads", "apk", safePkg(packageName), fmt.Sprintf("%d", versionCode))
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return fiber.ErrInternalServerError
	}

	abiFields := []string{"arm64-v8a", "armeabi-v7a", "x86", "x86_64", "universal"}
	for _, abi := range abiFields {
		field := "file_" + abi
		f, err := c.FormFile(field)
		if err != nil || f == nil {
			continue
		}
		src, err := f.Open()
		if err != nil {
			continue
		}
		defer src.Close()

		dstPath := filepath.Join(baseDir, abi+".apk")
		dst, err := os.Create(dstPath)
		if err != nil {
			continue
		}
		hasher := sha256.New()
		n, _ := io.Copy(io.MultiWriter(dst, hasher), src)
		dst.Close()
		sha := hex.EncodeToString(hasher.Sum(nil))

		publicPath := "/uploads/" + filepath.ToSlash(filepath.Join("apk", safePkg(packageName), fmt.Sprintf("%d", versionCode), abi+".apk"))

		// upsert build by abi
		var b models.AppBuild
		if err := database.DB.Where("app_version_id = ? AND abi = ?", v.ID, abi).First(&b).Error; err != nil {
			b = models.AppBuild{AppVersionID: v.ID, ABI: abi, FilePath: publicPath, FileSize: n, Sha256: sha}
			_ = database.DB.Create(&b).Error
		} else {
			b.FilePath = publicPath
			b.FileSize = n
			b.Sha256 = sha
			_ = database.DB.Save(&b).Error
		}
	}

	return c.Redirect("/admin/app")
}
