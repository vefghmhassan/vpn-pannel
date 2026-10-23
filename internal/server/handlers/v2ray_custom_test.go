package handlers_test

import (
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// customConfig builds a pretty-printed xray config for a unique remark.
func customConfig(remark, address string, port int) string {
	return `{
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "tag": "socks"}],
  "outbounds": [
    {"protocol": "vless", "tag": "proxy",
     "settings": {"vnext": [{"address": "` + address + `", "port": ` + strconv.Itoa(port) + `,
       "users": [{"id": "647c784c-82d9-42f8-8d40-456029822eac", "encryption": "none"}]}]}},
    {"protocol": "freedom", "settings": {}, "tag": "direct"}
  ],
  "remarks": "` + remark + `"
}`
}

func isRedirect(code int) bool { return code == 302 || code == 303 }

func TestV2RayCreate_SingleCustomJSON(t *testing.T) {
	app := apptest.New(t)
	remark := testutil.UniqueName("custom")

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"mode": {"link"}, "link": {customConfig(remark, "5.223.59.39", 2008)},
	}, adminAuth(t))
	if !isRedirect(resp.StatusCode) {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected a redirect, got %d: %s", resp.StatusCode, body)
	}

	var node models.V2RayNode
	if err := database.DB.Where("name = ?", remark).First(&node).Error; err != nil {
		t.Fatalf("expected the node to be created: %v", err)
	}
	if node.Address != "5.223.59.39" || node.Port != 2008 || node.Protocol != "vless" {
		t.Errorf("unexpected node: %+v", node)
	}
	if strings.Contains(node.RawLink, "\n") || !json.Valid([]byte(node.RawLink)) {
		t.Errorf("RawLink should be a compact JSON string, got %q", node.RawLink)
	}
}

func TestV2RayCreate_SingleCustomJSONErrorIsExplained(t *testing.T) {
	app := apptest.New(t)
	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"mode": {"link"}, "link": {`{"outbounds":[{"protocol":"freedom"}]}`},
	}, adminAuth(t))
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 400 || !strings.Contains(string(body), "no proxy outbound") {
		t.Errorf("expected a 400 naming the reason, got %d %q", resp.StatusCode, body)
	}
}

func TestV2RayCreate_BulkMixesMultilineJSONAndLinks(t *testing.T) {
	app := apptest.New(t)
	a, b := testutil.UniqueName("custom-a"), testutil.UniqueName("custom-b")
	links := customConfig(a, "10.0.0.1", 443) + "\n\nvless://abc@10.0.0.2:443#" + testutil.UniqueName("plain") + "\n" +
		customConfig(b, "10.0.0.3", 8443) + "\n"

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"mode": {"link"}, "links": {links},
	}, adminAuth(t))
	if !isRedirect(resp.StatusCode) {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	for name, addr := range map[string]string{a: "10.0.0.1", b: "10.0.0.3"} {
		var node models.V2RayNode
		if err := database.DB.Where("name = ?", name).First(&node).Error; err != nil {
			t.Fatalf("expected %s to be created: %v", name, err)
		}
		if node.Address != addr || !models.IsCustomRawLink(node.RawLink) {
			t.Errorf("%s: unexpected node %+v", name, node)
		}
	}
}

func TestV2RayUpdate_LinkModeAcceptsCustomJSON(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)
	remark := testutil.UniqueName("custom")

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/edit", url.Values{
		"mode": {"link"}, "link": {customConfig(remark, "5.5.5.5", 2008)},
	}, adminAuth(t))
	if !isRedirect(resp.StatusCode) {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var got models.V2RayNode
	database.DB.First(&got, node.ID)
	if got.Name != remark || got.Address != "5.5.5.5" || !models.IsCustomRawLink(got.RawLink) {
		t.Errorf("node was not replaced by the JSON config: %+v", got)
	}
}

func TestV2RayUpdate_ManualEditRewritesRawLink(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{
		Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true,
		RawLink: `{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"1.1.1.1","port":443}]}}]}`,
	}
	database.DB.Create(&node)

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/edit", url.Values{
		"mode": {"manual"}, "name": {node.Name}, "address": {"2.2.2.2"}, "port": {"8443"}, "protocol": {"vless"},
	}, adminAuth(t))
	if !isRedirect(resp.StatusCode) {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var got models.V2RayNode
	database.DB.First(&got, node.ID)
	if !strings.Contains(got.RawLink, `"address":"2.2.2.2"`) || !strings.Contains(got.RawLink, `"port":8443`) {
		t.Errorf("RawLink still points at the old host: %s", got.RawLink)
	}
}

func TestApiSplashConf_FlagsCustomNodesAndServesJSONAsString(t *testing.T) {
	app := apptest.New(t)
	isolateSplashConfNodes(t)
	raw := `{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"1.1.1.1","port":443}]}}],"remarks":"c"}`
	database.DB.Create(&models.V2RayNode{Name: testutil.UniqueName("custom"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true, RawLink: raw})
	database.DB.Create(&models.V2RayNode{Name: testutil.UniqueName("ads"), Address: "2.2.2.2", Port: 443, Protocol: "vless", IsActive: true, Ads: true, RawLink: "vless://x@2.2.2.2:443#a"})

	resp := testutil.DoJSON(t, app, "POST", "/api/v1/splash/conf", map[string]string{"client_key": testutil.UniqueName("ck")}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out struct {
		NoAds struct {
			RawLink  string
			IsCustom bool
		} `json:"no_ads"`
		Ads struct {
			RawLink  string
			IsCustom bool
		} `json:"ads"`
	}
	testutil.DecodeJSON(t, resp, &out)
	if !out.NoAds.IsCustom || out.NoAds.RawLink != raw {
		t.Errorf("custom node should be flagged and carry the JSON string, got %+v", out.NoAds)
	}
	if out.Ads.IsCustom || !strings.HasPrefix(out.Ads.RawLink, "vless://") {
		t.Errorf("plain node must stay a URI and unflagged, got %+v", out.Ads)
	}
}
