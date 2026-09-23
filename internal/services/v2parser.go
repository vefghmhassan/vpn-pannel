package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
	if strings.HasPrefix(link, "{") {
		return parseXrayJSON(link)
	}
	return ParsedV2{}, errors.New("unsupported link")
}

// xrayOutbound represents the relevant parts of an xray outbound config.
type xrayOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
	Settings struct {
		VNext []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
			Users   []struct {
				ID string `json:"id"`
			} `json:"users"`
		} `json:"vnext"`
		Servers []struct {
			Address string `json:"address"`
			Port    int    `json:"port"`
		} `json:"servers"`
	} `json:"settings"`
}

type xrayConfig struct {
	Remarks   string         `json:"remarks"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

func parseXrayJSON(raw string) (ParsedV2, error) {
	var cfg xrayConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return ParsedV2{}, errors.New("invalid xray JSON config")
	}
	if len(cfg.Outbounds) == 0 {
		return ParsedV2{}, errors.New("no outbounds in xray config")
	}
	// Find the first non-direct/blackhole outbound (the proxy)
	var ob xrayOutbound
	found := false
	for _, o := range cfg.Outbounds {
		if o.Protocol != "freedom" && o.Protocol != "blackhole" && o.Protocol != "dns" {
			ob = o
			found = true
			break
		}
	}
	if !found {
		return ParsedV2{}, errors.New("no proxy outbound found in xray config")
	}
	name := cfg.Remarks
	address := ""
	port := 0
	if len(ob.Settings.VNext) > 0 {
		address = ob.Settings.VNext[0].Address
		port = ob.Settings.VNext[0].Port
	} else if len(ob.Settings.Servers) > 0 {
		address = ob.Settings.Servers[0].Address
		port = ob.Settings.Servers[0].Port
	}
	if address == "" {
		return ParsedV2{}, errors.New("no address found in xray config outbound")
	}
	if name == "" {
		name = ob.Tag
	}
	return ParsedV2{
		Name:      name,
		Protocol:  ob.Protocol,
		Address:   address,
		Port:      port,
		RawConfig: raw,
	}, nil
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
	case strings.HasPrefix(link, "{"):
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
	case strings.HasPrefix(link, "{"):
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
