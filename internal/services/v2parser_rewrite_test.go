package services

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// A vless link is what the real database holds, and the client dials it
// verbatim — so everything except the host has to survive untouched.
func TestRewriteAddressKeepsEverythingButTheHost(t *testing.T) {
	const link = "vless://0c0e8d8d-c9ce-42e0-928b-726b99b74f5b@5.161.158.200:443" +
		"?type=tcp&encryption=none&path=%2F&host=store.steampowered.com&headerType=http&security=none" +
		"#ash-one-C-A"

	got, err := RewriteAddress(link, "88.99.1.2", 0)
	if err != nil {
		t.Fatalf("RewriteAddress: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}
	if u.Hostname() != "88.99.1.2" {
		t.Errorf("host = %q, want the new address", u.Hostname())
	}
	if u.Port() != "443" {
		t.Errorf("port = %q, want 443 kept", u.Port())
	}
	if u.User.String() != "0c0e8d8d-c9ce-42e0-928b-726b99b74f5b" {
		t.Errorf("uuid = %q, want it preserved", u.User.String())
	}
	if u.Fragment != "ash-one-C-A" {
		t.Errorf("fragment = %q, want it preserved", u.Fragment)
	}

	q := u.Query()
	for key, want := range map[string]string{
		"type": "tcp", "encryption": "none", "path": "/",
		"host": "store.steampowered.com", "headerType": "http", "security": "none",
	} {
		if q.Get(key) != want {
			t.Errorf("query %s = %q, want %q", key, q.Get(key), want)
		}
	}
	if strings.Contains(got, "5.161.158.200") {
		t.Error("the old address survives somewhere in the link")
	}
}

func TestRewriteAddressCanChangeThePort(t *testing.T) {
	got, err := RewriteAddress("vless://uuid@1.2.3.4:443?type=tcp#n", "5.6.7.8", 8443)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if u.Hostname() != "5.6.7.8" || u.Port() != "8443" {
		t.Fatalf("host:port = %s, want 5.6.7.8:8443", u.Host)
	}
}

func TestRewriteAddressTrojan(t *testing.T) {
	got, err := RewriteAddress("trojan://secret@1.2.3.4:443?sni=example.com#tr", "9.9.9.9", 0)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if u.Hostname() != "9.9.9.9" {
		t.Errorf("host = %q", u.Hostname())
	}
	if u.Query().Get("sni") != "example.com" {
		t.Error("sni was lost")
	}
}

func TestRewriteAddressVmessKeepsUnknownFields(t *testing.T) {
	original := map[string]any{
		"v": "2", "ps": "node-1", "add": "1.2.3.4", "port": "443",
		"id": "uuid-here", "aid": "0", "net": "ws", "path": "/ws",
		"host": "example.com", "tls": "tls", "somethingNew": "keep me",
	}
	raw, _ := json.Marshal(original)
	link := "vmess://" + base64.StdEncoding.EncodeToString(raw)

	got, err := RewriteAddress(link, "5.6.7.8", 8443)
	if err != nil {
		t.Fatalf("RewriteAddress: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "vmess://"))
	if err != nil {
		t.Fatalf("result is not standard base64: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(decoded, &out); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}

	if out["add"] != "5.6.7.8" {
		t.Errorf("add = %v, want the new address", out["add"])
	}
	// The port was a string, so it must come back as one.
	if out["port"] != "8443" {
		t.Errorf("port = %v (%T), want the string 8443", out["port"], out["port"])
	}
	// A field the panel knows nothing about must not be dropped.
	if out["somethingNew"] != "keep me" {
		t.Error("an unknown field was lost in the round trip")
	}
	if out["id"] != "uuid-here" || out["path"] != "/ws" {
		t.Error("the credentials or transport settings changed")
	}
}

func TestRewriteAddressVmessRawBase64(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"add": "1.2.3.4", "port": "443"})
	link := "vmess://" + base64.RawStdEncoding.EncodeToString(raw)

	got, err := RewriteAddress(link, "5.6.7.8", 0)
	if err != nil {
		t.Fatalf("RewriteAddress: %v", err)
	}
	// The unpadded form has to be decodable the same way it arrived.
	if _, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(got, "vmess://")); err != nil {
		t.Fatalf("raw base64 input produced padded output: %v", err)
	}
}

func TestRewriteAddressXrayJSON(t *testing.T) {
	const cfg = `{"remarks":"n","outbounds":[
		{"protocol":"freedom","tag":"direct"},
		{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"1.2.3.4","port":443,
		 "users":[{"id":"uuid"}]}]}}]}`

	got, err := RewriteAddress(cfg, "5.6.7.8", 8443)
	if err != nil {
		t.Fatalf("RewriteAddress: %v", err)
	}

	parsed, err := ParseV2Link(got)
	if err != nil {
		t.Fatalf("the rewritten config no longer parses: %v", err)
	}
	if parsed.Address != "5.6.7.8" || parsed.Port != 8443 {
		t.Errorf("parsed back as %s:%d, want 5.6.7.8:8443", parsed.Address, parsed.Port)
	}
	// The direct outbound must not have been given an address.
	if strings.Contains(got, `"protocol":"freedom","tag":"direct","settings"`) {
		t.Error("the freedom outbound was modified")
	}
	if !strings.Contains(got, "uuid") {
		t.Error("the user credentials were lost")
	}
}

func TestRewriteAddressRejectsBadInput(t *testing.T) {
	cases := []struct{ link, addr string }{
		{"", "1.2.3.4"},
		{"not-a-link", "1.2.3.4"},
		{"ss://something", "1.2.3.4"},
		{"vless://uuid@1.2.3.4:443", ""},
		{"{\"outbounds\":[]}", "1.2.3.4"},
		{"{\"outbounds\":[{\"protocol\":\"freedom\"}]}", "1.2.3.4"},
	}
	for _, tc := range cases {
		if _, err := RewriteAddress(tc.link, tc.addr, 0); err == nil {
			t.Errorf("RewriteAddress(%q, %q) succeeded, want an error", tc.link, tc.addr)
		}
	}
}

// The rewritten link must still parse into the same node the panel would store.
func TestRewrittenLinkRoundTripsThroughParse(t *testing.T) {
	const link = "vless://uuid@5.161.158.200:443?type=tcp&security=none#my-node"

	got, err := RewriteAddress(link, "88.99.1.2", 0)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseV2Link(got)
	if err != nil {
		t.Fatalf("ParseV2Link on the rewritten link: %v", err)
	}
	if p.Address != "88.99.1.2" || p.Port != 443 || p.Protocol != "vless" || p.Name != "my-node" {
		t.Errorf("parsed %+v, want the new address with everything else intact", p)
	}
}

func TestLinkLabelReadsWhatTheClientShows(t *testing.T) {
	cases := []struct{ link, want string }{
		{"vless://u@1.2.3.4:443?type=tcp#fi%209c", "fi 9c"},
		{"vless://u@1.2.3.4:443?type=tcp", ""},
		{"trojan://p@1.2.3.4:443#Am", "Am"},
		{"{\"outbounds\":[]}", ""},
	}
	for _, c := range cases {
		if got := LinkLabel(c.link); got != c.want {
			t.Errorf("LinkLabel(%q) = %q, want %q", c.link, got, c.want)
		}
	}
}

func TestRewriteLabelLeavesTheRestOfTheLinkAlone(t *testing.T) {
	const in = "vless://11111111-2222-3333-4444-555555555555@5.161.158.200:443" +
		"?type=tcp&encryption=none&path=%2F&host=store.steampowered.com#ash-one-C-A"

	out, err := RewriteLabel(in, "de-one-C-A")
	if err != nil {
		t.Fatalf("RewriteLabel: %v", err)
	}
	if got := LinkLabel(out); got != "de-one-C-A" {
		t.Fatalf("label = %q", got)
	}
	for _, keep := range []string{
		"11111111-2222-3333-4444-555555555555",
		"5.161.158.200:443",
		"host=store.steampowered.com",
		"path=%2F",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("RewriteLabel dropped %q: %s", keep, out)
		}
	}
}

func TestRewriteLabelEscapesSpacesTheWayThePanelDoes(t *testing.T) {
	out, err := RewriteLabel("vless://u@1.2.3.4:443?type=tcp#old", "fi 9c")
	if err != nil {
		t.Fatalf("RewriteLabel: %v", err)
	}
	if !strings.HasSuffix(out, "#fi%209c") {
		t.Fatalf("got %q, want a percent-escaped label", out)
	}
}

func TestRewriteLabelVmessUsesPs(t *testing.T) {
	const raw = `{"v":"2","ps":"old","add":"1.2.3.4","port":"443","id":"u","net":"tcp","custom":"keep"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(raw))

	out, err := RewriteLabel(link, "de-1")
	if err != nil {
		t.Fatalf("RewriteLabel: %v", err)
	}
	if got := LinkLabel(out); got != "de-1" {
		t.Fatalf("label = %q", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(out, "vmess://"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(string(decoded), `"custom":"keep"`) {
		t.Fatalf("unknown field lost: %s", decoded)
	}
}

func TestRewriteLabelLeavesXrayConfigUntouched(t *testing.T) {
	const cfg = `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4"}]}}]}`
	out, err := RewriteLabel(cfg, "de-1")
	if err != nil {
		t.Fatalf("RewriteLabel: %v", err)
	}
	if out != cfg {
		t.Fatalf("xray config changed:\n got %s\nwant %s", out, cfg)
	}
}
