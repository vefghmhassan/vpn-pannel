package services

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type ParsedV2 struct {
	Name      string
	Protocol  string
	Address   string
	Port      int
	Tags      string
	RawConfig string // full raw config for JSON-type entries
}

// ParseV2Link supports vmess://, vless://, trojan:// URIs and raw xray JSON configs.
func ParseV2Link(link string) (ParsedV2, error) {
	link = strings.TrimSpace(link)
	if strings.HasPrefix(link, "vmess://") {
		raw := strings.TrimPrefix(link, "vmess://")
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(raw)
			if err != nil {
				return ParsedV2{}, err
			}
		}
		var v struct {
			Ps   string `json:"ps"`
			Add  string `json:"add"`
			Port string `json:"port"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return ParsedV2{}, err
		}
		p, _ := strconv.Atoi(v.Port)
		return ParsedV2{Name: v.Ps, Protocol: "vmess", Address: v.Add, Port: p}, nil
	}
	if strings.HasPrefix(link, "vless://") || strings.HasPrefix(link, "trojan://") {
		u, err := url.Parse(link)
		if err != nil {
			return ParsedV2{}, err
		}
		name := u.Fragment
		protocol := strings.SplitN(link, "://", 2)[0]
		port, _ := strconv.Atoi(u.Port())
		return ParsedV2{Name: name, Protocol: protocol, Address: u.Hostname(), Port: port}, nil
	}
	// Try parsing as raw xray JSON config
	if IsCustomConfig(link) {
		return parseXrayJSON(link)
	}
	return ParsedV2{}, errors.New("unsupported link")
}

// flexInt reads a JSON port written either as a number or as a quoted number.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

// xrayOutbound represents the relevant parts of an xray outbound config.
type xrayOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
	Settings struct {
		// Flat form used by newer xray outbounds (vless/trojan/shadowsocks...).
		Address string  `json:"address"`
		Port    flexInt `json:"port"`
		VNext   []struct {
			Address string  `json:"address"`
			Port    flexInt `json:"port"`
		} `json:"vnext"`
		Servers []struct {
			Address string  `json:"address"`
			Port    flexInt `json:"port"`
		} `json:"servers"`
	} `json:"settings"`
}

type xrayConfig struct {
	Remarks   string         `json:"remarks"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

// IsCustomConfig reports whether raw is a full xray JSON config rather than a
// vmess/vless/trojan URI. The panel flags such nodes as "custom".
func IsCustomConfig(raw string) bool {
	return strings.HasPrefix(trimConfig(raw), "{")
}

// trimConfig removes surrounding whitespace and a leading UTF-8 BOM, which
// editors and "copy as" menus like to add to pasted JSON.
func trimConfig(raw string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "\ufeff"))
}

func isProxyOutbound(o xrayOutbound) bool {
	switch o.Protocol {
	case "freedom", "blackhole", "dns", "":
		return false
	}
	return true
}

func parseXrayJSON(raw string) (ParsedV2, error) {
	raw = trimConfig(raw)
	var cfg xrayConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return ParsedV2{}, fmt.Errorf("invalid xray JSON config: %w", err)
	}
	if len(cfg.Outbounds) == 0 {
		return ParsedV2{}, errors.New("no outbounds in xray config")
	}
	// The outbound tagged "proxy" is what clients treat as the main one; fall
	// back to the first outbound that is not direct/blackhole/dns.
	var ob xrayOutbound
	found := false
	for _, o := range cfg.Outbounds {
		if o.Tag == "proxy" && isProxyOutbound(o) {
			ob, found = o, true
			break
		}
	}
	if !found {
		for _, o := range cfg.Outbounds {
			if isProxyOutbound(o) {
				ob, found = o, true
				break
			}
		}
	}
	if !found {
		return ParsedV2{}, errors.New("no proxy outbound found in xray config")
	}
	name := cfg.Remarks
	address := ob.Settings.Address
	port := int(ob.Settings.Port)
	if len(ob.Settings.VNext) > 0 {
		address = ob.Settings.VNext[0].Address
		port = int(ob.Settings.VNext[0].Port)
	} else if len(ob.Settings.Servers) > 0 {
		address = ob.Settings.Servers[0].Address
		port = int(ob.Settings.Servers[0].Port)
	}
	if address == "" {
		return ParsedV2{}, errors.New("no address found in xray config outbound")
	}
	if port <= 0 {
		return ParsedV2{}, errors.New("no port found in xray config outbound")
	}
	if name == "" {
		name = ob.Tag
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(raw)); err != nil {
		return ParsedV2{}, fmt.Errorf("invalid xray JSON config: %w", err)
	}
	return ParsedV2{
		Name:      name,
		Protocol:  ob.Protocol,
		Address:   address,
		Port:      port,
		RawConfig: compact.String(),
	}, nil
}

// SplitConfigEntries splits pasted text into individual configs. A URI takes one
// line; a JSON config starts at "{" and runs to its matching "}", so it may be
// pretty-printed over many lines. Blank lines are skipped.
func SplitConfigEntries(text string) []string {
	var entries []string
	text = strings.TrimPrefix(text, "\ufeff")
	for {
		text = strings.TrimLeft(text, " \t\r\n")
		if text == "" {
			return entries
		}
		if text[0] == '{' {
			dec := json.NewDecoder(strings.NewReader(text))
			var msg json.RawMessage
			if err := dec.Decode(&msg); err == nil {
				entries = append(entries, string(msg))
				text = text[dec.InputOffset():]
				continue
			}
			// Malformed JSON: hand the rest over as one entry so the parser can
			// report the real error.
			entries = append(entries, strings.TrimSpace(text))
			return entries
		}
		line := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		if line = strings.TrimSpace(line); line != "" {
			entries = append(entries, line)
		}
	}
}

// RewriteAddress returns link with its host replaced, and its port replaced too
// when newPort is positive. Everything else is preserved: the uuid, every query
// parameter, the fragment, and the original encoding.
//
// This exists because a node's RawLink is what the mobile app actually dials —
// the splash response hands it straight to the client. Changing V2RayNode.Address
// without rewriting RawLink leaves the database looking correct while every
// client keeps connecting to the old, blocked IP.
func RewriteAddress(link, newAddress string, newPort int) (string, error) {
	link = strings.TrimSpace(link)
	newAddress = strings.TrimSpace(newAddress)
	if newAddress == "" {
		return "", errors.New("new address is required")
	}

	switch {
	case strings.HasPrefix(link, "vmess://"):
		return rewriteVmess(link, newAddress, newPort)
	case strings.HasPrefix(link, "vless://"), strings.HasPrefix(link, "trojan://"):
		return rewriteURI(link, newAddress, newPort)
	case IsCustomConfig(link):
		return rewriteXrayJSON(link, newAddress, newPort)
	default:
		return "", errors.New("unsupported link")
	}
}

// rewriteURI handles the vless:// and trojan:// forms, which are ordinary URLs.
func rewriteURI(link, newAddress string, newPort int) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", err
	}

	port := u.Port()
	if newPort > 0 {
		port = strconv.Itoa(newPort)
	}
	if port == "" {
		u.Host = newAddress
	} else {
		u.Host = net.JoinHostPort(newAddress, port)
	}
	return u.String(), nil
}

// rewriteVmess handles the base64-encoded JSON form. The original encoding
// (standard or raw) is kept so the result stays byte-comparable with what the
// panel produced before.
func rewriteVmess(link, newAddress string, newPort int) (string, error) {
	// Decoding into a map keeps every field the panel does not know about.
	obj, encode, err := decodeVmess(link)
	if err != nil {
		return "", err
	}
	obj["add"] = newAddress
	if newPort > 0 {
		// vmess links carry the port as a string in the wild, so it is written
		// back the way it was found.
		if _, wasNumber := obj["port"].(float64); wasNumber {
			obj["port"] = newPort
		} else {
			obj["port"] = strconv.Itoa(newPort)
		}
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return "vmess://" + encode(out), nil
}

// rewriteXrayJSON handles a full xray config stored as the raw link.
func rewriteXrayJSON(raw, newAddress string, newPort int) (string, error) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return "", errors.New("invalid xray JSON config")
	}

	outbounds, ok := cfg["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return "", errors.New("no outbounds in xray config")
	}

	rewritten := false
	for _, o := range outbounds {
		ob, ok := o.(map[string]any)
		if !ok {
			continue
		}
		switch ob["protocol"] {
		case "freedom", "blackhole", "dns":
			continue
		}
		settings, ok := ob["settings"].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"vnext", "servers"} {
			list, ok := settings[key].([]any)
			if !ok || len(list) == 0 {
				continue
			}
			for _, e := range list {
				entry, ok := e.(map[string]any)
				if !ok {
					continue
				}
				entry["address"] = newAddress
				if newPort > 0 {
					entry["port"] = newPort
				}
				rewritten = true
			}
		}
	}
	if !rewritten {
		return "", errors.New("no proxy outbound found in xray config")
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// LinkLabel returns the human-readable remark a client shows for a config.
//
// Clients display this label, not the panel's Name column, so a config that
// moves to another country keeps announcing the old one until the label moves
// too. Returns "" when the link form carries no label.
func LinkLabel(link string) string {
	link = strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(link, "vmess://"):
		obj, _, err := decodeVmess(link)
		if err != nil {
			return ""
		}
		s, _ := obj["ps"].(string)
		return s
	case strings.HasPrefix(link, "vless://"), strings.HasPrefix(link, "trojan://"):
		u, err := url.Parse(link)
		if err != nil {
			return ""
		}
		return u.Fragment
	default:
		return ""
	}
}

// RewriteLabel returns link with its display label replaced.
//
// Address and label are separate rewrites because they answer to different
// rules: the address is dictated by the new server, the label by the naming
// rule. A raw xray config has nowhere to put a label and is returned unchanged.
func RewriteLabel(link, label string) (string, error) {
	link = strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(link, "vmess://"):
		obj, encode, err := decodeVmess(link)
		if err != nil {
			return "", err
		}
		obj["ps"] = label
		out, err := json.Marshal(obj)
		if err != nil {
			return "", err
		}
		return "vmess://" + encode(out), nil
	case strings.HasPrefix(link, "vless://"), strings.HasPrefix(link, "trojan://"):
		u, err := url.Parse(link)
		if err != nil {
			return "", err
		}
		// Fragment, not RawFragment: url.String escapes it on the way out, so
		// "fi 9c" becomes "fi%209c" exactly as the panel already writes it.
		u.Fragment = label
		return u.String(), nil
	case IsCustomConfig(link):
		return link, nil
	default:
		return "", errors.New("unsupported link")
	}
}

// decodeVmess unpacks a vmess link into its JSON object and the encoder that
// reproduces the original base64 variant.
func decodeVmess(link string) (map[string]any, func([]byte) string, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	encode := base64.StdEncoding.EncodeToString
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return nil, nil, err
		}
		encode = base64.RawStdEncoding.EncodeToString
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, nil, err
	}
	return obj, encode, nil
}
