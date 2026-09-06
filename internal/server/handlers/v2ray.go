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
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/services"
)

// v2rayPageSizes is the single source of truth for the page-size selector: the
// handler validates against it and the template renders its options from it.
// The default stays low because the browser, not Postgres, is the bottleneck —
// 2000 rows is roughly 22k DOM nodes.
var v2rayPageSizes = []int{25, 50, 100, 200, 500, 1000, 2000}

const v2rayDefaultPageSize = 50

func v2rayValidPageSize(n int) bool {
	for _, s := range v2rayPageSizes {
		if s == n {
			return true
		}
	}
	return false
}

// v2raySortOrders maps a sort key to a fixed ORDER BY clause. The query value is
// only ever used to look up this map — gorm's Order takes raw SQL, so user input
// must never reach it directly.
//
// "newest"/"oldest" order by id rather than created_at: id is the primary key
// (so it's indexed) and, being auto-increment, yields the same ordering.
var v2raySortOrders = map[string]string{
	"newest":    "id desc",
	"oldest":    "id asc",
	"name_asc":  "name asc",
	"name_desc": "name desc",
	"address":   "address asc, id desc",
	"port":      "port asc, id desc",
	"country":   "country_code asc, id desc",
}

const v2rayDefaultSort = "newest"

// v2raySortOptions drives the sort dropdown, in display order (map iteration
// isn't stable, so the labels can't come from v2raySortOrders).
var v2raySortOptions = []struct{ Value, Label string }{
	{"newest", "جدیدترین"},
	{"oldest", "قدیمی‌ترین"},
	{"name_asc", "نام (الف تا ی)"},
	{"name_desc", "نام (ی تا الف)"},
	{"address", "آدرس"},
	{"port", "پورت"},
	{"country", "کشور"},
}

// v2rayNoCountry is the sentinel the country dropdown uses for "no country set",
// which an empty value can't express (empty already means "all").
const v2rayNoCountry = "none"

// v2rayFilters is the parsed filter state of the list page. It is carried as one
// value because the filter set outgrew a positional argument list.
type v2rayFilters struct {
	// Q is a free-text substring search across several columns. Every other
	// field here is an exact match.
	Q        string
	Address  string
	Protocol string
	Ads      string // "", "true", "false"
	Active   string // "", "true", "false"
	Port     string // "" or a decimal port number
	Country  string // "", a country code, or v2rayNoCountry
	Sort     string

	// DateOn gates the created-at window. parseDateRange always resolves a range
	// (defaulting to the last 30 days), so without an explicit opt-in the list
	// would silently hide every older node the first time the page is opened.
	DateOn bool
	From   time.Time
	To     time.Time
}

func v2rayFilteredQuery(f v2rayFilters) *gorm.DB {
	q := database.DB.Model(&models.V2RayNode{})
	if f.Q != "" {
		like := "%" + strings.ToLower(f.Q) + "%"
		// Passing a *gorm.DB to Where parenthesises the ORs, so they cannot
		// escape the other filters' ANDs. port is an int column, hence the
		// cast, which also lets "44" match 443.
		q = q.Where(database.DB.
			Where("LOWER(name) LIKE ?", like).
			Or("LOWER(address) LIKE ?", like).
			Or("LOWER(tags) LIKE ?", like).
			Or("LOWER(protocol) LIKE ?", like).
			Or("LOWER(country_code) LIKE ?", like).
			Or("CAST(port AS TEXT) LIKE ?", like))
	}
	if f.Address != "" {
		q = q.Where("address = ?", f.Address)
	}
	if f.Protocol != "" {
		q = q.Where("protocol = ?", f.Protocol)
	}
	if f.Ads == "true" {
		q = q.Where("ads = ?", true)
	} else if f.Ads == "false" {
		q = q.Where("ads = ?", false)
	}
	if f.Active == "true" {
		q = q.Where("is_active = ?", true)
	} else if f.Active == "false" {
		q = q.Where("is_active = ?", false)
	}
	if n, err := strconv.Atoi(f.Port); err == nil {
		q = q.Where("port = ?", n)
	}
	if f.Country == v2rayNoCountry {
		q = q.Where("country_code = '' OR country_code IS NULL")
	} else if f.Country != "" {
		q = q.Where("country_code = ?", f.Country)
	}
	if f.DateOn {
		q = q.Where("created_at >= ? AND created_at < ?", f.From, f.To)
	}
	return q
}

// v2rayQuery renders the filter state back into a query string. Every parameter
// has to be here or the pagination links would drop it.
func (f v2rayFilters) v2rayQuery() url.Values {
	qs := url.Values{}
	if f.Q != "" {
		qs.Set("q", f.Q)
	}
	if f.Address != "" {
		qs.Set("address", f.Address)
	}
	if f.Protocol != "" {
		qs.Set("protocol", f.Protocol)
	}
	if f.Ads != "" {
		qs.Set("ads", f.Ads)
	}
	if f.Active != "" {
		qs.Set("active", f.Active)
	}
	if f.Port != "" {
		qs.Set("port", f.Port)
	}
	if f.Country != "" {
		qs.Set("country", f.Country)
	}
	if f.Sort != "" && f.Sort != v2rayDefaultSort {
		qs.Set("sort", f.Sort)
	}
	return qs
}

// v2rayChip is one removable "active filter" badge. ClearURL is the current
// listing with just that one parameter dropped.
type v2rayChip struct {
	Label    string
	ClearURL string
}

// v2rayReturnTo resolves where an action should send the admin back to, so the
// active filter, sort and page survive the redirect.
//
// The supplied value is only honoured when it points back at this listing:
// c.Redirect would otherwise happily follow an absolute or protocol-relative URL
// planted in the form, turning every action into an open redirect.
func v2rayReturnTo(c *fiber.Ctx) string {
	next := strings.TrimSpace(c.FormValue("next"))
	if next == "" {
		next = strings.TrimSpace(c.Query("next"))
	}
	if next == "/admin/v2ray" || strings.HasPrefix(next, "/admin/v2ray?") {
		return next
	}
	return "/admin/v2ray"
}

func V2RayList(c *fiber.Ctx) error {
	// The date picker is always resolved so the panel can render it, but the
	// window is only applied when date_filter is explicitly checked.
	dr := parseDateRange(c)
	f := v2rayFilters{
		Q:        strings.TrimSpace(c.Query("q")),
		Address:  strings.TrimSpace(c.Query("address")),
		Protocol: strings.TrimSpace(c.Query("protocol")),
		Ads:      strings.TrimSpace(c.Query("ads")),
		Active:   strings.TrimSpace(c.Query("active")),
		Port:     strings.TrimSpace(c.Query("port")),
		Country:  strings.TrimSpace(c.Query("country")),
		Sort:     strings.TrimSpace(c.Query("sort")),
		DateOn:   c.Query("date_filter") != "",
		From:     dr.From,
		To:       dr.To,
	}
	if _, ok := v2raySortOrders[f.Sort]; !ok {
		f.Sort = v2rayDefaultSort
	}

	pageSize := v2rayDefaultPageSize
	if v, err := strconv.Atoi(c.Query("page_size")); err == nil && v2rayValidPageSize(v) {
		pageSize = v
	}
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}

	var total int64
	v2rayFilteredQuery(f).Count(&total)
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	var nodes []models.V2RayNode
	v2rayFilteredQuery(f).
		Order(v2raySortOrders[f.Sort]).Offset((page - 1) * pageSize).Limit(pageSize).Find(&nodes)

	var addresses []string
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("address").Pluck("address", &addresses).Error
	var protocols []string
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("protocol").Pluck("protocol", &protocols).Error
	var ports []int
	_ = database.DB.Model(&models.V2RayNode{}).Distinct().Order("port").Pluck("port", &ports).Error
	var countries []string
	_ = database.DB.Model(&models.V2RayNode{}).Where("country_code <> ''").
		Distinct().Order("country_code").Pluck("country_code", &countries).Error

	qs := f.v2rayQuery()
	if f.DateOn {
		qs.Set("date_filter", "1")
		qs.Set("from_y", strconv.Itoa(dr.FromY))
		qs.Set("from_m", strconv.Itoa(dr.FromM))
		qs.Set("from_d", strconv.Itoa(dr.FromD))
		qs.Set("to_y", strconv.Itoa(dr.ToY))
		qs.Set("to_m", strconv.Itoa(dr.ToM))
		qs.Set("to_d", strconv.Itoa(dr.ToD))
	}
	qs.Set("page_size", strconv.Itoa(pageSize))

	// The pagination links are built whole here. html/template percent-escapes
	// the "&" and "=" of a query string interpolated into the middle of an
	// href, which collapses every active filter into one meaningless parameter
	// name; interpolating a complete URL as the whole attribute, the way the
	// chips do, is what keeps them intact.
	pageURL := func(p int) string {
		link := make(url.Values, len(qs)+1)
		for k, v := range qs {
			link[k] = v
		}
		link.Set("page", strconv.Itoa(p))
		return "/admin/v2ray?" + link.Encode()
	}

	return c.Render("v2ray/index", fiber.Map{
		"title":       "V2Ray Nodes",
		"nodes":       nodes,
		"addresses":   addresses,
		"protocols":   protocols,
		"ports":       ports,
		"countries":   countries,
		"page":        page,
		"totalPages":  totalPages,
		"total":       total,
		"pageSize":    pageSize,
		"pageSizes":   v2rayPageSizes,
		"hasPrev":     page > 1,
		"hasNext":     page < totalPages,
		"prevPage":    page - 1,
		"nextPage":    page + 1,
		"prevURL":     pageURL(page - 1),
		"nextURL":     pageURL(page + 1),
		"f":           f,
		"sortOptions": v2raySortOptions,
		"chips":       v2rayBuildChips(f, dr, pageSize),
		"noCountry":   v2rayNoCountry,
		"range":       dr,
		"calendar":    string(calendarFromRequest(c)),
		"currentURL":  c.OriginalURL(),
	})
}

// v2rayBuildChips renders the active filters as removable badges. Each chip's
// ClearURL is the current listing with only that filter dropped, so removing one
// never disturbs the others.
func v2rayBuildChips(f v2rayFilters, dr dateRange, pageSize int) []v2rayChip {
	var chips []v2rayChip

	// without returns the current listing URL with one filter cleared.
	without := func(mutate func(*v2rayFilters)) string {
		cleared := f
		mutate(&cleared)
		qs := cleared.v2rayQuery()
		if cleared.DateOn {
			qs.Set("date_filter", "1")
			qs.Set("from_y", strconv.Itoa(dr.FromY))
			qs.Set("from_m", strconv.Itoa(dr.FromM))
			qs.Set("from_d", strconv.Itoa(dr.FromD))
			qs.Set("to_y", strconv.Itoa(dr.ToY))
			qs.Set("to_m", strconv.Itoa(dr.ToM))
			qs.Set("to_d", strconv.Itoa(dr.ToD))
		}
		if pageSize != v2rayDefaultPageSize {
			qs.Set("page_size", strconv.Itoa(pageSize))
		}
		if len(qs) == 0 {
			return "/admin/v2ray"
		}
		return "/admin/v2ray?" + qs.Encode()
	}

	add := func(label string, mutate func(*v2rayFilters)) {
		chips = append(chips, v2rayChip{Label: label, ClearURL: without(mutate)})
	}

	if f.Q != "" {
		add("جستجو: "+f.Q, func(x *v2rayFilters) { x.Q = "" })
	}
	if f.Address != "" {
		add("آدرس: "+f.Address, func(x *v2rayFilters) { x.Address = "" })
	}
	if f.Protocol != "" {
		add("پروتکل: "+f.Protocol, func(x *v2rayFilters) { x.Protocol = "" })
	}
	if f.Port != "" {
		add("پورت: "+f.Port, func(x *v2rayFilters) { x.Port = "" })
	}
	switch f.Country {
	case "":
	case v2rayNoCountry:
		add("بدون کشور", func(x *v2rayFilters) { x.Country = "" })
	default:
		add("کشور: "+f.Country, func(x *v2rayFilters) { x.Country = "" })
	}
	if f.Ads == "true" {
		add("فقط Ads", func(x *v2rayFilters) { x.Ads = "" })
	} else if f.Ads == "false" {
		add("بدون Ads", func(x *v2rayFilters) { x.Ads = "" })
	}
	if f.Active == "true" {
		add("فقط فعال", func(x *v2rayFilters) { x.Active = "" })
	} else if f.Active == "false" {
		add("فقط غیرفعال", func(x *v2rayFilters) { x.Active = "" })
	}
	if f.DateOn {
		label := fmt.Sprintf("تاریخ: %d/%02d/%02d تا %d/%02d/%02d",
			dr.FromY, dr.FromM, dr.FromD, dr.ToY, dr.ToM, dr.ToD)
		add(label, func(x *v2rayFilters) { x.DateOn = false })
	}
	return chips
}

func V2RayNewPage(c *fiber.Ctx) error {
	countries := listCountryCodes()
	return c.Render("v2ray/new", fiber.Map{
		"title":         "Add V2Ray Node",
		"countryPicker": countryPickerVM{Countries: countries},
		// Carried through the form so saving returns to the filtered listing.
		"next": v2rayReturnTo(c),
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
		// Carried through the form so saving returns to the filtered listing.
		"next": v2rayReturnTo(c),
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
		return c.Redirect(v2rayReturnTo(c))
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
	return c.Redirect(v2rayReturnTo(c))
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
	return c.Redirect(v2rayReturnTo(c))
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
	return c.Redirect(v2rayReturnTo(c))
}

func V2RayBatchDelete(c *fiber.Ctx) error {
	var in struct {
		IDs []uint `form:"ids"`
	}
	if err := c.BodyParser(&in); err != nil {
		return fiber.ErrBadRequest
	}
	if len(in.IDs) == 0 {
		return c.Redirect(v2rayReturnTo(c))
	}
	database.DB.Where("id IN ?", in.IDs).Delete(&models.V2RayNode{})
	return c.Redirect(v2rayReturnTo(c))
}
