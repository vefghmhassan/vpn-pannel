package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
