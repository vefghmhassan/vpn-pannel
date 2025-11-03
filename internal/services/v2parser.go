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
    Name     string
    Protocol string
    Address  string
    Port     int
    Tags     string
}

// ParseV2Link supports common vmess:// (base64 json), vless://, trojan:// formats.
func ParseV2Link(link string) (ParsedV2, error) {
    link = strings.TrimSpace(link)
    if strings.HasPrefix(link, "vmess://") {
        raw := strings.TrimPrefix(link, "vmess://")
        data, err := base64.StdEncoding.DecodeString(raw)
        if err != nil {
            // try rawurl base64
            data, err = base64.RawStdEncoding.DecodeString(raw)
            if err != nil { return ParsedV2{}, err }
        }
        var v struct{
            Ps string `json:"ps"`
            Add string `json:"add"`
            Port string `json:"port"`
        }
        if err := json.Unmarshal(data, &v); err != nil { return ParsedV2{}, err }
        p, _ := strconv.Atoi(v.Port)
        return ParsedV2{Name: v.Ps, Protocol: "vmess", Address: v.Add, Port: p}, nil
    }
    if strings.HasPrefix(link, "vless://") || strings.HasPrefix(link, "trojan://") {
        u, err := url.Parse(link)
        if err != nil { return ParsedV2{}, err }
        name := u.Fragment
        protocol := strings.SplitN(link, "://", 2)[0]
        port, _ := strconv.Atoi(u.Port())
        return ParsedV2{Name: name, Protocol: protocol, Address: u.Hostname(), Port: port}, nil
    }
    return ParsedV2{}, errors.New("unsupported link")
}




