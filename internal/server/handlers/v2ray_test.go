package handlers_test

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestV2RayCreate_ManualMode(t *testing.T) {
	app := apptest.New(t)
	name := testutil.UniqueName("node")

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"name": {name}, "address": {"1.2.3.4"}, "port": {"443"}, "protocol": {"vless"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after creating a node, got %d", resp.StatusCode)
	}

	var node models.V2RayNode
	if err := database.DB.Where("name = ?", name).First(&node).Error; err != nil {
		t.Fatalf("expected the node to be created: %v", err)
	}
	if !node.IsActive {
		t.Errorf("expected a newly-created node to be active by default")
	}
}

func TestV2RayCreate_DuplicateNameRejected(t *testing.T) {
	app := apptest.New(t)
	name := testutil.UniqueName("dup-node")
	database.DB.Create(&models.V2RayNode{Name: name, Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true})

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"name": {name}, "address": {"2.2.2.2"}, "port": {"443"}, "protocol": {"vless"},
	}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for a duplicate node name, got %d", resp.StatusCode)
	}
}

func TestV2RayUpdate_ValidationErrors(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	cases := []struct {
		name   string
		values url.Values
	}{
		{"missing name", url.Values{"name": {""}, "address": {"1.1.1.1"}, "port": {"443"}, "protocol": {"vless"}}},
		{"missing address", url.Values{"name": {node.Name}, "address": {""}, "port": {"443"}, "protocol": {"vless"}}},
		{"invalid port", url.Values{"name": {node.Name}, "address": {"1.1.1.1"}, "port": {"0"}, "protocol": {"vless"}}},
		{"missing protocol", url.Values{"name": {node.Name}, "address": {"1.1.1.1"}, "port": {"443"}, "protocol": {""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/edit", tc.values, adminAuth(t))
			if resp.StatusCode != 400 {
				t.Errorf("expected 400 for %s, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}

func TestV2RayUpdate_CanDeactivateNode(t *testing.T) {
	// Regression test for the gorm:"default:true" zero-value bug: explicitly
	// saving IsActive=false must actually persist as false, not silently
	// revert to true.
	testutil.SetupDB(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	node.IsActive = false
	if err := database.DB.Save(&node).Error; err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	var reloaded models.V2RayNode
	database.DB.First(&reloaded, node.ID)
	if reloaded.IsActive {
		t.Errorf("expected IsActive=false to persist, but the node came back active")
	}
}

func TestV2RayUpdate_DuplicateNameExceptSelfAllowed(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	// Saving the node with its own unchanged name must succeed (not treated as a duplicate).
	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/edit", url.Values{
		"name": {node.Name}, "address": {"9.9.9.9"}, "port": {"8443"}, "protocol": {"vmess"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect when a node keeps its own name, got %d", resp.StatusCode)
	}
}

func TestV2RayList_FiltersByActive(t *testing.T) {
	app := apptest.New(t)
	activeName := testutil.UniqueName("active-node")
	database.DB.Create(&models.V2RayNode{Name: activeName, Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true})
	inactiveName := testutil.UniqueName("inactive-node")
	inactiveNode := models.V2RayNode{Name: inactiveName, Address: "2.2.2.2", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&inactiveNode)
	inactiveNode.IsActive = false
	database.DB.Save(&inactiveNode)

	resp := testutil.DoJSON(t, app, "GET", "/admin/v2ray?active=false", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if !strings.Contains(text, inactiveName) {
		t.Errorf("expected the inactive-only filter to include %q", inactiveName)
	}
	if strings.Contains(text, activeName) {
		t.Errorf("expected the inactive-only filter to exclude %q", activeName)
	}
}

// v2rayListBody fetches the listing and returns its HTML. The harness runs over
// the real dev database, so these tests assert on the presence of their own
// uniquely-named nodes rather than on row counts.
func v2rayListBody(t *testing.T, app *fiber.App, query string) string {
	t.Helper()
	resp := testutil.DoJSON(t, app, "GET", "/admin/v2ray"+query, nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for %q, got %d", query, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestV2RayList_FiltersByPortAndCountry(t *testing.T) {
	app := apptest.New(t)
	match := testutil.UniqueName("p443fr")
	otherPort := testutil.UniqueName("p8443fr")
	otherCountry := testutil.UniqueName("p443de")
	database.DB.Create(&models.V2RayNode{Name: match, Address: "1.1.1.1", Port: 443, Protocol: "vless", CountryCode: "FR", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: otherPort, Address: "1.1.1.1", Port: 8443, Protocol: "vless", CountryCode: "FR", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: otherCountry, Address: "1.1.1.1", Port: 443, Protocol: "vless", CountryCode: "DE", IsActive: true})

	text := v2rayListBody(t, app, "?port=443&country=FR&page_size=2000")
	if !strings.Contains(text, match) {
		t.Errorf("expected port+country filter to include %q", match)
	}
	if strings.Contains(text, otherPort) {
		t.Errorf("expected the port filter to exclude %q", otherPort)
	}
	if strings.Contains(text, otherCountry) {
		t.Errorf("expected the country filter to exclude %q", otherCountry)
	}
}

func TestV2RayList_FiltersByNoCountry(t *testing.T) {
	app := apptest.New(t)
	blank := testutil.UniqueName("nocountry")
	withCountry := testutil.UniqueName("hascountry")
	database.DB.Create(&models.V2RayNode{Name: blank, Address: "9.9.9.9", Port: 443, Protocol: "vless", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: withCountry, Address: "9.9.9.9", Port: 443, Protocol: "vless", CountryCode: "IT", IsActive: true})

	text := v2rayListBody(t, app, "?address=9.9.9.9&country=none&page_size=2000")
	if !strings.Contains(text, blank) {
		t.Errorf("expected the no-country filter to include %q", blank)
	}
	if strings.Contains(text, withCountry) {
		t.Errorf("expected the no-country filter to exclude %q", withCountry)
	}
}

func TestV2RayList_SortNewestAndOldest(t *testing.T) {
	app := apptest.New(t)
	addr := testutil.UniqueName("sort") + ".example.com"
	older := testutil.UniqueName("older")
	newer := testutil.UniqueName("newer")
	database.DB.Create(&models.V2RayNode{Name: older, Address: addr, Port: 443, Protocol: "vless", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: newer, Address: addr, Port: 443, Protocol: "vless", IsActive: true})

	newestFirst := v2rayListBody(t, app, "?address="+addr+"&sort=newest&page_size=2000")
	if strings.Index(newestFirst, newer) > strings.Index(newestFirst, older) {
		t.Errorf("expected sort=newest to put %q before %q", newer, older)
	}
	oldestFirst := v2rayListBody(t, app, "?address="+addr+"&sort=oldest&page_size=2000")
	if strings.Index(oldestFirst, older) > strings.Index(oldestFirst, newer) {
		t.Errorf("expected sort=oldest to put %q before %q", older, newer)
	}
}

func TestV2RayList_RejectsUnknownSort(t *testing.T) {
	// The sort value is looked up in a whitelist because gorm's Order takes raw
	// SQL; anything unrecognised must fall back to the default, not reach the DB.
	app := apptest.New(t)
	name := testutil.UniqueName("sortguard")
	database.DB.Create(&models.V2RayNode{Name: name, Address: "4.4.4.4", Port: 443, Protocol: "vless", IsActive: true})

	text := v2rayListBody(t, app, "?address=4.4.4.4&sort=id%3BDROP+TABLE+v2_ray_nodes&page_size=2000")
	if !strings.Contains(text, name) {
		t.Errorf("expected an unknown sort to fall back to the default listing")
	}
}

func TestV2RayList_PageSizeAllowlist(t *testing.T) {
	app := apptest.New(t)

	if text := v2rayListBody(t, app, "?page_size=2000"); !strings.Contains(text, `value="2000" selected`) {
		t.Errorf("expected page_size=2000 to be accepted and marked selected")
	}
	if text := v2rayListBody(t, app, "?page_size=3000"); !strings.Contains(text, `value="50" selected`) {
		t.Errorf("expected an out-of-allowlist page_size to fall back to the default of 50")
	}
}

func TestV2RayList_DateFilterOffByDefault(t *testing.T) {
	// parseDateRange defaults to the last 30 days. Without an explicit
	// date_filter opt-in the listing must still show older nodes.
	app := apptest.New(t)
	name := testutil.UniqueName("ancient")
	node := models.V2RayNode{Name: name, Address: "5.5.5.5", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)
	database.DB.Model(&node).UpdateColumn("created_at", time.Now().AddDate(-1, 0, 0))

	if text := v2rayListBody(t, app, "?address=5.5.5.5&page_size=2000"); !strings.Contains(text, name) {
		t.Fatalf("expected a year-old node to remain visible without date_filter")
	}
	if text := v2rayListBody(t, app, "?address=5.5.5.5&date_filter=1&page_size=2000"); strings.Contains(text, name) {
		t.Errorf("expected date_filter=1 to apply the 30-day window and hide %q", name)
	}
}

func TestV2RayBatchDelete_PreservesFilterViaNext(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("keepfilter"), Address: "6.6.6.6", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	want := "/admin/v2ray?port=443&sort=oldest"
	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/batch-delete", url.Values{
		"ids":  {strconv.FormatUint(uint64(node.ID), 10)},
		"next": {want},
	}, adminAuth(t))
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("expected the action to return to %q, got %q", want, got)
	}
}

func TestV2RayDelete_RejectsExternalNext(t *testing.T) {
	// next is attacker-controllable, so anything not pointing back at this
	// listing must be discarded rather than followed.
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("openredir"), Address: "7.7.7.7", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	for _, bad := range []string{"https://evil.example.com", "//evil.example.com", "/admin/users"} {
		n := models.V2RayNode{Name: testutil.UniqueName("openredir"), Address: "7.7.7.7", Port: 443, Protocol: "vless", IsActive: true}
		database.DB.Create(&n)
		resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(n.ID), 10)+"/delete", url.Values{
			"next": {bad},
		}, adminAuth(t))
		if got := resp.Header.Get("Location"); got != "/admin/v2ray" {
			t.Errorf("expected next=%q to be rejected, redirected to %q", bad, got)
		}
	}
}

func TestV2RayDelete(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	resp := testutil.DoJSON(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/delete", nil, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.V2RayNode{}).Where("id = ?", node.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected the node to be deleted")
	}
}

func TestV2RayBatchDelete(t *testing.T) {
	app := apptest.New(t)
	n1 := models.V2RayNode{Name: testutil.UniqueName("n1"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	n2 := models.V2RayNode{Name: testutil.UniqueName("n2"), Address: "2.2.2.2", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&n1)
	database.DB.Create(&n2)

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/batch-delete", url.Values{
		"ids": {strconv.FormatUint(uint64(n1.ID), 10), strconv.FormatUint(uint64(n2.ID), 10)},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.V2RayNode{}).Where("id IN ?", []uint{n1.ID, n2.ID}).Count(&count)
	if count != 0 {
		t.Errorf("expected both nodes to be deleted, %d remain", count)
	}
}

// The search box is one free-text parameter over several columns, so these
// tests pin down each column it must reach and, above all, that its ORs stay
// grouped: unparenthesised they would swallow the other filters' ANDs.

func TestV2RayList_SearchMatchesAddressPartially(t *testing.T) {
	app := apptest.New(t)
	// A unique label in front of the octets keeps these rows out of every other
	// test's way while still exercising a partial address match.
	base := testutil.UniqueName("addr")
	near1 := testutil.UniqueName("near1")
	near2 := testutil.UniqueName("near2")
	far := testutil.UniqueName("far")
	database.DB.Create(&models.V2RayNode{Name: near1, Address: base + ".10.10.1", Port: 443, Protocol: "vless", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: near2, Address: base + ".10.10.2", Port: 443, Protocol: "vless", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: far, Address: base + ".99.99.9", Port: 443, Protocol: "vless", IsActive: true})

	text := v2rayListBody(t, app, "?q="+base+".10.10&page_size=2000")
	if !strings.Contains(text, near1) || !strings.Contains(text, near2) {
		t.Errorf("expected the partial address search to include %q and %q", near1, near2)
	}
	if strings.Contains(text, far) {
		t.Errorf("expected the partial address search to exclude %q", far)
	}
}

func TestV2RayList_SearchMatchesNameAndPort(t *testing.T) {
	app := apptest.New(t)
	addr := testutil.UniqueName("np") + ".example.com"
	oddPort := testutil.UniqueName("oddport")
	stdPort := testutil.UniqueName("stdport")
	database.DB.Create(&models.V2RayNode{Name: oddPort, Address: addr, Port: 51793, Protocol: "vless", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: stdPort, Address: addr, Port: 443, Protocol: "vless", IsActive: true})

	byName := v2rayListBody(t, app, "?q="+oddPort+"&page_size=2000")
	if !strings.Contains(byName, oddPort) {
		t.Errorf("expected the name search to include %q", oddPort)
	}
	if strings.Contains(byName, stdPort) {
		t.Errorf("expected the name search to exclude %q", stdPort)
	}

	// port is an int column: this only matches if the handler casts it to text.
	byPort := v2rayListBody(t, app, "?q=51793&page_size=2000")
	if !strings.Contains(byPort, oddPort) {
		t.Errorf("expected the port search to include %q", oddPort)
	}
	if strings.Contains(byPort, stdPort) {
		t.Errorf("expected the port search to exclude %q", stdPort)
	}
}

func TestV2RayList_SearchMatchesTagsProtocolAndCountry(t *testing.T) {
	app := apptest.New(t)
	addr := testutil.UniqueName("tpc") + ".example.com"
	tag := testutil.UniqueName("tag")
	tagged := testutil.UniqueName("tagged")
	trojan := testutil.UniqueName("trojan")
	plain := testutil.UniqueName("plain")
	database.DB.Create(&models.V2RayNode{Name: tagged, Address: addr, Port: 443, Protocol: "vless", Tags: "premium," + tag, IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: trojan, Address: addr, Port: 443, Protocol: "trojan", CountryCode: "SE", IsActive: true})
	database.DB.Create(&models.V2RayNode{Name: plain, Address: addr, Port: 443, Protocol: "vless", IsActive: true})

	byTag := v2rayListBody(t, app, "?q="+tag+"&page_size=2000")
	if !strings.Contains(byTag, tagged) {
		t.Errorf("expected the tag search to include %q", tagged)
	}
	if strings.Contains(byTag, plain) {
		t.Errorf("expected the tag search to exclude %q", plain)
	}

	byProtocol := v2rayListBody(t, app, "?q=trojan&address="+addr+"&page_size=2000")
	if !strings.Contains(byProtocol, trojan) {
		t.Errorf("expected the protocol search to include %q", trojan)
	}
	if strings.Contains(byProtocol, plain) {
		t.Errorf("expected the protocol search to exclude %q", plain)
	}

	byCountry := v2rayListBody(t, app, "?q=se&address="+addr+"&page_size=2000")
	if !strings.Contains(byCountry, trojan) {
		t.Errorf("expected the country-code search to include %q", trojan)
	}
}

func TestV2RayList_SearchCombinesWithOtherFilters(t *testing.T) {
	app := apptest.New(t)
	addr := testutil.UniqueName("combo") + ".example.com"
	activeName := testutil.UniqueName("comboactive")
	inactiveName := testutil.UniqueName("comboinactive")
	database.DB.Create(&models.V2RayNode{Name: activeName, Address: addr, Port: 443, Protocol: "vless", IsActive: true})
	inactive := models.V2RayNode{Name: inactiveName, Address: addr, Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&inactive)
	inactive.IsActive = false
	database.DB.Save(&inactive)

	// If the search ORs were not parenthesised they would bind looser than this
	// AND and the inactive node would come back too.
	text := v2rayListBody(t, app, "?q="+addr+"&active=true&page_size=2000")
	if !strings.Contains(text, activeName) {
		t.Errorf("expected search+active to include %q", activeName)
	}
	if strings.Contains(text, inactiveName) {
		t.Errorf("expected search+active to exclude %q", inactiveName)
	}
}

func TestV2RayList_SearchSurvivesPaginationLinks(t *testing.T) {
	app := apptest.New(t)
	addr := testutil.UniqueName("paged") + ".example.com"
	// One more than the smallest allowed page size, so a "next" link exists.
	nodes := make([]models.V2RayNode, 0, 26)
	for i := 0; i < 26; i++ {
		nodes = append(nodes, models.V2RayNode{
			Name: testutil.UniqueName("pagednode"), Address: addr,
			Port: 443, Protocol: "vless", IsActive: true,
		})
	}
	database.DB.Create(&nodes)

	// The whole link is asserted, not just "q=": built inside the href as
	// "?{{ .pageQuery }}&page=N", html/template percent-escaped the separators
	// and page 2 silently dropped every filter.
	text := v2rayListBody(t, app, "?q="+addr+"&page_size=25")
	want := "/admin/v2ray?page=2&amp;page_size=25&amp;q=" + addr
	if !strings.Contains(text, want) {
		t.Errorf("expected the next-page link %q in the listing", want)
	}
}
