package services

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCleanAndFixDecoded_PassesThroughExistingScheme(t *testing.T) {
	in := "vless://uuid@host:443?type=tcp"
	if got := cleanAndFixDecoded(in); got != in {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestCleanAndFixDecoded_StripsLeadingGarbageAndDetectsVless(t *testing.T) {
	// The hex groups must actually look like a UUID (8-4-4-4-12 hex digits) for
	// the vless-detection regex to match.
	in := "\x01\x02aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@example.com:443"
	got := cleanAndFixDecoded(in)
	if got[:8] != "vless://" {
		t.Errorf("expected a vless:// prefix to be added, got %q", got)
	}
}

func TestCleanAndFixDecoded_DetectsTrojanShape(t *testing.T) {
	in := "somepassword@example.com:443"
	got := cleanAndFixDecoded(in)
	want := "trojan://somepassword@example.com:443"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestCleanAndFixDecoded_VmessSubstringBranchIsUnreachable(t *testing.T) {
	// NOTE: this documents existing (pre-session) behavior, not a fix. The
	// function's vmess://-extraction branch (`if m := ...vmess://...; m != ""`)
	// can never run: it's only reached when the earlier `strings.Contains(fixed,
	// "://")` check is false, but any string containing "vmess://" necessarily
	// contains "://" too, so that earlier check always wins first and returns
	// the raw string unchanged, junk and all. Flagged for a human decision
	// rather than silently "fixed" here, since this feeds a live external
	// splash-protocol pipeline this test suite doesn't otherwise exercise.
	in := "junk-prefix vmess://aGVsbG8= junk-suffix"
	got := cleanAndFixDecoded(in)
	if got != in {
		t.Errorf("expected the current (buggy) passthrough behavior to return input unchanged, got %q", got)
	}
}

func TestExtractLinks_FindsAllProtocolsAndDedupes(t *testing.T) {
	text := `here is one vless://a@b:443?x=1 and vless://a@b:443?x=1 again, plus trojan://p@h:443`
	links := extractLinks(text)
	if len(links) != 2 {
		t.Fatalf("expected 2 deduped links, got %d: %v", len(links), links)
	}
}

func TestExtractLinks_DoesNotMatchProtocolSubstringInsideAnotherLink(t *testing.T) {
	// "ss://" is a substring of "vle[ss://]", so a naive scan would spuriously
	// extract a phantom shadowsocks link out of every vless link. Regression
	// test for that fix.
	text := "vless://a@b:443?x=1"
	links := extractLinks(text)
	if len(links) != 1 {
		t.Fatalf("expected exactly 1 link (no phantom ss:// match), got %d: %v", len(links), links)
	}
	for _, l := range links {
		if strings.HasPrefix(l, "ss://") {
			t.Errorf("expected no spurious ss:// match embedded in a vless link, got %v", links)
		}
	}
}

func TestExtractLinks_WholeTextIsALink(t *testing.T) {
	text := "  ss://abc123  "
	links := extractLinks(text)
	if len(links) != 1 || links[0] != "ss://abc123" {
		t.Fatalf("expected the whole trimmed text to be treated as a single link, got %v", links)
	}
}

func TestExtractLinks_NoMatchesReturnsEmpty(t *testing.T) {
	links := extractLinks("nothing interesting here")
	if len(links) != 0 {
		t.Fatalf("expected no links, got %v", links)
	}
}

func TestBuildConfigFromLink_Vless(t *testing.T) {
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=none"
	cfg, err := buildConfigFromLink(link, 10808)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	outbounds := cfg["outbounds"].([]interface{})
	ob := outbounds[0].(map[string]interface{})
	if ob["protocol"] != "vless" {
		t.Errorf("expected protocol vless, got %v", ob["protocol"])
	}
}

func TestBuildConfigFromLink_VlessMissingHostRejected(t *testing.T) {
	_, err := buildConfigFromLink("vless://not-a-valid-link", 10808)
	if err == nil {
		t.Errorf("expected an error for a malformed vless link")
	}
}

func TestBuildConfigFromLink_Vmess_ProperlyPaddedBase64(t *testing.T) {
	// Regression test: the old code blindly appended "==" to the base64
	// payload, which corrupted input that Go's StdEncoding already pads
	// correctly (as opposed to some link generators that omit padding).
	payload := `{"add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"tcp","tls":"none"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	cfg, err := buildConfigFromLink("vmess://"+encoded, 10808)
	if err != nil {
		t.Fatalf("unexpected error decoding a properly-padded vmess payload: %v", err)
	}
	outbounds := cfg["outbounds"].([]interface{})
	ob := outbounds[0].(map[string]interface{})
	if ob["protocol"] != "vmess" {
		t.Errorf("expected protocol vmess, got %v", ob["protocol"])
	}
}

func TestBuildConfigFromLink_Vmess_UnpaddedBase64(t *testing.T) {
	// Some vmess link generators omit padding entirely; this must also work.
	payload := `{"add":"example.com","port":"443","id":"2","aid":"0","net":"tcp","tls":"none"}`
	encoded := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(payload)), "=")
	cfg, err := buildConfigFromLink("vmess://"+encoded, 10808)
	if err != nil {
		t.Fatalf("unexpected error decoding an unpadded vmess payload: %v", err)
	}
	outbounds := cfg["outbounds"].([]interface{})
	ob := outbounds[0].(map[string]interface{})
	if ob["protocol"] != "vmess" {
		t.Errorf("expected protocol vmess, got %v", ob["protocol"])
	}
}

func TestBuildConfigFromLink_Trojan(t *testing.T) {
	link := "trojan://my-password@example.com:443?type=tcp&security=tls"
	cfg, err := buildConfigFromLink(link, 10808)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	outbounds := cfg["outbounds"].([]interface{})
	ob := outbounds[0].(map[string]interface{})
	if ob["protocol"] != "trojan" {
		t.Errorf("expected protocol trojan, got %v", ob["protocol"])
	}
}

func TestBuildConfigFromLink_UnsupportedScheme(t *testing.T) {
	_, err := buildConfigFromLink("http://not-a-proxy-link", 10808)
	if err == nil {
		t.Errorf("expected an error for an unsupported scheme")
	}
}
