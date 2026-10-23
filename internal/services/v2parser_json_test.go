package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// A pretty-printed xray config as exported by v2rayNG-style clients: the proxy
// outbound is first here, with direct and block after it.
const customXrayConfig = `{
  "dns": {"hosts": {"domain:googleapis.cn": "googleapis.com"}, "servers": ["1.1.1.1"]},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "tag": "socks"}],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "5.223.59.39", "port": 2008,
        "users": [{"encryption": "none", "id": "647c784c-82d9-42f8-8d40-456029822eac", "level": 8}]}]},
      "streamSettings": {"network": "tcp", "security": ""},
      "tag": "proxy"
    },
    {"protocol": "freedom", "settings": {}, "tag": "direct"},
    {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
  ],
  "remarks": "ddd-r7xgr5v19d",
  "stats": {}
}`

func TestParseV2LinkCustomXrayConfig(t *testing.T) {
	p, err := ParseV2Link(customXrayConfig)
	if err != nil {
		t.Fatalf("ParseV2Link: %v", err)
	}
	if p.Name != "ddd-r7xgr5v19d" || p.Protocol != "vless" || p.Address != "5.223.59.39" || p.Port != 2008 {
		t.Fatalf("unexpected parse result: %+v", p)
	}
	if strings.ContainsAny(p.RawConfig, "\n\t") || strings.Contains(p.RawConfig, "  ") {
		t.Errorf("RawConfig should be compact, got %q", p.RawConfig)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(p.RawConfig), &back); err != nil {
		t.Fatalf("RawConfig is not valid JSON: %v", err)
	}
	if !IsCustomConfig(p.RawConfig) {
		t.Errorf("IsCustomConfig should be true for the stored config")
	}
}

func TestParseV2LinkCustomConfigPrefersProxyTag(t *testing.T) {
	const cfg = `{"outbounds":[
		{"protocol":"vless","tag":"other","settings":{"vnext":[{"address":"1.1.1.1","port":1}]}},
		{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"2.2.2.2","port":2}]}}]}`
	p, err := ParseV2Link(cfg)
	if err != nil {
		t.Fatalf("ParseV2Link: %v", err)
	}
	if p.Address != "2.2.2.2" || p.Port != 2 {
		t.Errorf("expected the proxy-tagged outbound, got %s:%d", p.Address, p.Port)
	}
}

func TestParseV2LinkCustomConfigFlatSettingsAndStringPort(t *testing.T) {
	const cfg = "\xef\xbb\xbf" + `{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"address":"3.3.3.3","port":"8443"}}]}`
	p, err := ParseV2Link(cfg)
	if err != nil {
		t.Fatalf("ParseV2Link: %v", err)
	}
	if p.Address != "3.3.3.3" || p.Port != 8443 {
		t.Errorf("got %s:%d", p.Address, p.Port)
	}
	if p.Name != "proxy" {
		t.Errorf("without remarks the outbound tag is the name, got %q", p.Name)
	}
}

func TestParseV2LinkCustomConfigErrors(t *testing.T) {
	cases := map[string]string{
		"not json":     `{"outbounds": [`,
		"no outbounds": `{"remarks":"x"}`,
		"only direct":  `{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`,
		"no address":   `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"port":1}]}}]}`,
		"no port":      `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.1.1.1"}]}}]}`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseV2Link(cfg); err == nil {
				t.Errorf("expected an error")
			}
		})
	}
}

func TestSplitConfigEntries(t *testing.T) {
	text := "vless://a@1.1.1.1:443#one\n\n" + customXrayConfig + "\r\n  trojan://p@2.2.2.2:443#two  \n" +
		`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"4.4.4.4","port":4}]}}]}` + "\n"
	got := SplitConfigEntries(text)
	if len(got) != 4 {
		t.Fatalf("expected 4 entries, got %d: %q", len(got), got)
	}
	if got[0] != "vless://a@1.1.1.1:443#one" || got[2] != "trojan://p@2.2.2.2:443#two" {
		t.Errorf("URI entries wrong: %q", got)
	}
	for _, i := range []int{1, 3} {
		if _, err := ParseV2Link(got[i]); err != nil {
			t.Errorf("entry %d should parse: %v", i, err)
		}
	}
}

func TestSplitConfigEntriesMalformedJSONKeptForErrorReporting(t *testing.T) {
	got := SplitConfigEntries("vless://a@1.1.1.1:443#one\n{\"outbounds\": [")
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %q", got)
	}
	if _, err := ParseV2Link(got[1]); err == nil {
		t.Errorf("malformed JSON entry should fail to parse")
	}
}

func TestRewriteAddressOnCustomConfigKeepsRestAndStaysCompact(t *testing.T) {
	p, _ := ParseV2Link(customXrayConfig)
	out, err := RewriteAddress(p.RawConfig, "9.9.9.9", 1234)
	if err != nil {
		t.Fatalf("RewriteAddress: %v", err)
	}
	re, err := ParseV2Link(out)
	if err != nil || re.Address != "9.9.9.9" || re.Port != 1234 || re.Name != "ddd-r7xgr5v19d" {
		t.Errorf("rewrite result wrong: %+v err=%v", re, err)
	}
}
