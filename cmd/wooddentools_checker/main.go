package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vpnpannel/internal/utils"
)

// Config (mirrors Python defaults)
const (
	apiURL   = "https://wooddentools.com/api/protocols/splash"
	checkURL = "http://www.google.com/generate_204"
	timeoutS = 10

	outDecoded = "/root/decoded.json"
	outWorking = "/root/working.json"
	outFailed  = "/root/failed.json"
	outLogs    = "/root/logs.json"
	seenFile   = "/root/seen_ids.json"
)

var apiHeaders = map[string]string{
	"giat":            "",
	"build":           "false",
	"seen":            "1",
	"sign":            "w8z946T8GvQ0OYHgSASIgg==",
	"Content-Type":    "application/json",
	"token":           "bf8009ecdd7c41a3",
	"firebase_token":  "cmmd8qHrTseaQMjZksQn_C:APA91bGwOlYixYil3Wi8k44T2IftbrtEPCTTmQUcZCvNt1r2U-Hl6GnWKHDYWhVNlB4CAWYfAgoOuCi_VTwchDV2eiOejjT2AIG6tav24lrrONY4Nq5JvwA",
	"sha_hexadecimal": "6a28befce23991c20d92f4a64b7faf9922308c8e10c5f687ef811ad885d03ee0",
	"version_code":    "1005697",
	"app_name":        "co.vpn.plus",
	"User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N976N Build/QP1A.190711.020)",
}

// XRAY and CURL discovery
func findXrayBinary() (string, error) {
	paths := []string{"/usr/local/bin/xray", "/usr/bin/xray"}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if err := os.Chmod(p, 0o755); err == nil {
				return p, nil
			}
			return p, nil
		}
	}
	return "", errors.New("xray binary not found; install xray-core")
}

func findCurlBinary() string {
	if p, err := exec.LookPath("curl"); err == nil {
		return p
	}
	return "/usr/bin/curl"
}

// Seen IDs helpers
func loadSeen(path string) map[int]struct{} {
	seen := map[int]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		return seen
	}
	defer f.Close()
	var arr []int
	if err := json.NewDecoder(f).Decode(&arr); err != nil {
		return seen
	}
	for _, v := range arr {
		seen[v] = struct{}{}
	}
	return seen
}

func saveSeen(path string, seen map[int]struct{}) {
	arr := make([]int, 0, len(seen))
	for k := range seen {
		arr = append(arr, k)
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		fmt.Println("warning: cannot save seen ids:", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(arr)
}

// Decrypt and cleanup utilities
func cleanAndFixDecoded(plain string) string {
	// Trim leading non-printables
	reLeading := regexp.MustCompile(`^[^\x20-\x7E]+`)
	fixed := strings.TrimSpace(reLeading.ReplaceAllString(plain, ""))
	if strings.Contains(fixed, "://") {
		return fixed
	}
	// Heuristics for vless trojan
	if regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@`).FindStringIndex(fixed) != nil {
		return "vless://" + fixed
	}
	if regexp.MustCompile(`^[^:\s@]{1,60}@[\w\.-]+:\d+`).MatchString(fixed) {
		return "trojan://" + fixed
	}
	// Try vmess link extraction
	if m := regexp.MustCompile(`vmess://[A-Za-z0-9+/=]+`).FindString(fixed); m != "" {
		return m
	}
	return fixed
}

func extractLinks(text string) []string {
	links := []string{}
	protoList := []string{"vless://", "vmess://", "trojan://", "ss://"}
	for _, proto := range protoList {
		re := regexp.MustCompile(regexp.QuoteMeta(proto) + `[^\s"'<>]+`)
		for _, m := range re.FindAllString(text, -1) {
			links = append(links, strings.TrimSpace(m))
		}
	}
	if len(links) == 0 {
		for _, p := range protoList {
			if strings.HasPrefix(strings.TrimSpace(text), p) {
				links = append(links, strings.TrimSpace(text))
				break
			}
		}
	}
	// dedupe in order
	seen := map[string]struct{}{}
	out := []string{}
	for _, l := range links {
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

// Xray config builders
func buildConfigFromLink(link string, port int) (map[string]interface{}, error) {
	link, _ = url.QueryUnescape(strings.TrimSpace(link))
	if i := strings.Index(link, "#"); i >= 0 {
		link = link[:i]
	}
	// Detect mislabeled ss that actually carry vless-style params
	if strings.HasPrefix(link, "ss://") {
		if regexp.MustCompile(`(type=|encryption=|serviceName=|authority=|security=|sni=|flow=)`).FindStringIndex(link) != nil {
			link = "vless://" + strings.TrimPrefix(link, "ss://")
		}
	}

	var outbound map[string]interface{}
	// VLESS
	if strings.HasPrefix(link, "vless://") {
		re := regexp.MustCompile(`^vless://([^@]+)@([^:]+):(\d+)(?:\?(.*))?`)
		m := re.FindStringSubmatch(link)
		if m == nil {
			return nil, errors.New("bad vless")
		}
		uid, host, portStr, q := m[1], m[2], m[3], ""
		if len(m) >= 5 {
			q = m[4]
		}
		p, _ := url.ParseQuery(q)
		portNum := atoiSafe(portStr)
		outbound = map[string]interface{}{
			"protocol": "vless",
			"settings": map[string]interface{}{
				"vnext": []interface{}{map[string]interface{}{
					"address": host,
					"port":    portNum,
					"users": []interface{}{map[string]interface{}{
						"id":         uid,
						"encryption": "none",
					}},
				}},
			},
			"streamSettings": map[string]interface{}{
				"network":  firstNonEmpty(p.Get("type"), "tcp"),
				"security": firstNonEmpty(p.Get("security"), "none"),
			},
		}
		if p.Get("security") == "reality" {
			ss := outbound["streamSettings"].(map[string]interface{})
			ss["realitySettings"] = map[string]interface{}{
				"serverName":  p.Get("sni"),
				"publicKey":   p.Get("pbk"),
				"shortId":     p.Get("sid"),
				"spiderX":     mustURLDecode(firstNonEmpty(p.Get("spx"), "/")),
				"fingerprint": firstNonEmpty(p.Get("fp"), "chrome"),
			}
		} else if v := p.Get("sni"); v != "" {
			ss := outbound["streamSettings"].(map[string]interface{})
			if _, ok := ss["tlsSettings"]; !ok {
				ss["tlsSettings"] = map[string]interface{}{}
			}
			ss["tlsSettings"].(map[string]interface{})["serverName"] = v
		}
		// VMESS
	} else if strings.HasPrefix(link, "vmess://") {
		raw := strings.TrimPrefix(link, "vmess://")
		data, err := base64.StdEncoding.DecodeString(raw + "==")
		if err != nil {
			return nil, fmt.Errorf("vmess base64 decode failed: %w", err)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, err
		}
		outbound = map[string]interface{}{
			"protocol": "vmess",
			"settings": map[string]interface{}{
				"vnext": []interface{}{map[string]interface{}{
					"address": str(v["add"]),
					"port":    atoiSafe(str(v["port"])),
					"users": []interface{}{map[string]interface{}{
						"id":       str(v["id"]),
						"alterId":  atoiSafe(strOrZero(v["aid"])),
						"security": "auto",
					}},
				}},
			},
			"streamSettings": map[string]interface{}{
				"network":  firstNonEmpty(str(v["net"]), "tcp"),
				"security": firstNonEmpty(str(v["tls"]), "none"),
			},
		}
		// TROJAN
	} else if strings.HasPrefix(link, "trojan://") {
		re := regexp.MustCompile(`^trojan://([^@]+)@([^:]+):(\d+)(?:\?(.*))?`)
		m := re.FindStringSubmatch(link)
		if m == nil {
			return nil, errors.New("bad trojan")
		}
		pwd, host, portStr, q := m[1], m[2], m[3], ""
		if len(m) >= 5 {
			q = m[4]
		}
		p, _ := url.ParseQuery(q)
		outbound = map[string]interface{}{
			"protocol": "trojan",
			"settings": map[string]interface{}{
				"servers": []interface{}{map[string]interface{}{
					"address":  host,
					"port":     atoiSafe(portStr),
					"password": pwd,
				}},
			},
			"streamSettings": map[string]interface{}{
				"network":  firstNonEmpty(p.Get("type"), "tcp"),
				"security": firstNonEmpty(p.Get("security"), "tls"),
			},
		}
		if v := p.Get("sni"); v != "" {
			ss := outbound["streamSettings"].(map[string]interface{})
			if _, ok := ss["tlsSettings"]; !ok {
				ss["tlsSettings"] = map[string]interface{}{}
			}
			ss["tlsSettings"].(map[string]interface{})["serverName"] = v
		}
		// SHADOWSOCKS (best effort)
	} else if strings.HasPrefix(link, "ss://") {
		cfg, err := buildShadowsocks(link)
		if err != nil {
			return nil, err
		}
		outbound = cfg
	} else {
		return nil, errors.New("unsupported link")
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "none"},
		"inbounds": []interface{}{map[string]interface{}{
			"port":     port,
			"listen":   "127.0.0.1",
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": true},
		}},
		"outbounds": []interface{}{outbound},
	}
	return cfg, nil
}

func buildShadowsocks(link string) (map[string]interface{}, error) {
	// Robust parsing similar to Python
	raw := strings.TrimPrefix(link, "ss://")
	var method, password, host string
	var port int
	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		creds, rest := parts[0], parts[1]
		hostport := rest
		if i := strings.IndexAny(hostport, "/?#"); i >= 0 {
			hostport = hostport[:i]
		}
		if hp := strings.SplitN(hostport, ":", 2); len(hp) == 2 {
			host = hp[0]
			port = atoiSafe(strings.SplitN(hp[1], "/", 2)[0])
		}
		if b, err := base64.StdEncoding.DecodeString(creds + "=="); err == nil {
			if s := string(b); strings.Contains(s, ":") {
				pp := strings.SplitN(s, ":", 2)
				method, password = strings.TrimSpace(pp[0]), strings.TrimSpace(pp[1])
			} else {
				method, password = "aes-128-gcm", strings.TrimSpace(s)
			}
		} else if strings.Contains(creds, ":") {
			pp := strings.SplitN(creds, ":", 2)
			method, password = pp[0], pp[1]
		} else {
			method, password = "aes-128-gcm", creds
		}
	} else {
		basePart := raw
		if i := strings.IndexAny(basePart, "#/"); i >= 0 {
			basePart = basePart[:i]
		}
		b, err := base64.StdEncoding.DecodeString(basePart + "==")
		if err != nil {
			return nil, fmt.Errorf("bad ss parse: %w", err)
		}
		s := string(b)
		if strings.Contains(s, "@") {
			pp := strings.SplitN(s, "@", 2)
			creds, rest := pp[0], pp[1]
			if strings.Contains(creds, ":") {
				mm := strings.SplitN(creds, ":", 2)
				method, password = mm[0], mm[1]
			}
			hostport := rest
			if i := strings.IndexAny(hostport, "/?#"); i >= 0 {
				hostport = hostport[:i]
			}
			if hp := strings.SplitN(hostport, ":", 2); len(hp) == 2 {
				host = hp[0]
				port = atoiSafe(hp[1])
			}
		} else {
			if i := strings.IndexByte(s, ':'); i >= 0 {
				method, password = s[:i], s[i+1:]
			}
			host, port = "0.0.0.0", 0
		}
	}
	return map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []interface{}{map[string]interface{}{
				"address":  host,
				"port":     port,
				"method":   strings.TrimSpace(method),
				"password": strings.TrimSpace(password),
				"udp":      true,
			}},
		},
		"streamSettings": map[string]interface{}{"network": "tcp", "security": "none"},
	}, nil
}

// Utilities
func atoiSafe(s string) int {
	var n int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func strOrZero(v interface{}) string {
	if v == nil {
		return "0"
	}
	return fmt.Sprintf("%v", v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func mustURLDecode(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// Port helper
func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Worker
type workerResult struct {
	OK         bool   `json:"ok"`
	Reason     string `json:"reason"`
	XrayError  string `json:"xrayError"`
	ConfigFile string `json:"configFile"`
	LogFile    string `json:"logFile"`
	Link       string `json:"link"`
}

func runWorker(link string, xrayBin string, curlBin string) workerResult {
	port, err := getFreePort()
	if err != nil {
		return workerResult{OK: false, Reason: "no_port", Link: link}
	}
	cfg, err := buildConfigFromLink(link, port)
	if err != nil {
		return workerResult{OK: false, Reason: "build_err:" + err.Error(), Link: link}
	}

	cfgFile, err := os.CreateTemp("", "xray_cfg_*.json")
	if err != nil {
		return workerResult{OK: false, Reason: "tmp_cfg_err", Link: link}
	}
	_ = cfgFile.Close()
	cfgPath := cfgFile.Name()
	{ // write config
		f, _ := os.Create(cfgPath)
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cfg)
		f.Close()
	}

	logFile, _ := os.CreateTemp("", "xray_log_*.log")
	logPath := logFile.Name()
	_ = logFile.Close()

	// Start xray
	cmd := exec.Command(xrayBin, "run", "-c", cfgPath, "-format", "json")
	lf, _ := os.Create(logPath)
	cmd.Stdout = lf
	cmd.Stderr = lf
	_ = cmd.Start()

	defer func() {
		// ensure process cleanup
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = cmd.Process.Signal(os.Kill)
		_ = cmd.Wait()
		_ = ctx.Err()
	}()

	// Wait for socks port readiness
	deadline := time.Now().Add(timeoutS * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	xlogTail := lastBytes(logPath, 1000)
	if !ready {
		return workerResult{OK: false, Reason: "no_socks", XrayError: xlogTail, ConfigFile: cfgPath, LogFile: logPath, Link: link}
	}

	// curl through socks
	ctx, cancel := context.WithTimeout(context.Background(), (timeoutS+1)*time.Second)
	defer cancel()
	cmdCurl := exec.CommandContext(ctx, curlBin, "--socks5-hostname", fmt.Sprintf("127.0.0.1:%d", port), "--max-time", fmt.Sprintf("%d", timeoutS), "-sS", "-o", "/dev/null", "-w", "%{http_code}", checkURL)
	stdout, err := cmdCurl.StdoutPipe()
	if err != nil {
		return workerResult{OK: false, Reason: "curl_pipe", XrayError: xlogTail, ConfigFile: cfgPath, LogFile: logPath, Link: link}
	}
	_ = cmdCurl.Start()
	code := ""
	s := bufio.NewScanner(stdout)
	for s.Scan() {
		code += s.Text()
	}
	_ = cmdCurl.Wait()
	ok := code == "204" || code == "200"
	return workerResult{OK: ok, Reason: code, XrayError: xlogTail, ConfigFile: cfgPath, LogFile: logPath, Link: link}
}

func lastBytes(path string, max int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(b) <= max {
		return string(b)
	}
	return string(b[len(b)-max:])
}

// Data types
type apiItem struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type decodedEntry struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Skipped bool   `json:"skipped,omitempty"`
	Raw     string `json:"raw,omitempty"`
	Fixed   string `json:"fixed,omitempty"`
	Error   string `json:"error,omitempty"`
}

func nowISO() string {
	return time.Now().Format(time.RFC3339)
}

func fetchAPI() ([]apiItem, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range apiHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	// Try {"data": [...]} first
	var wrap struct {
		Data []apiItem `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err == nil && len(wrap.Data) > 0 {
		return wrap.Data, nil
	}
	// Try plain array
	var arr []apiItem
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr, nil
	}
	// Try object with single item
	var single apiItem
	if err := json.Unmarshal(body, &single); err == nil && single.ID != 0 {
		return []apiItem{single}, nil
	}
	return nil, errors.New("cannot parse API response")
}

func main() {
	fmt.Println("📡 Fetching API data (GET)...")
	items, err := fetchAPI()
	if err != nil {
		fmt.Println("❌ API Error:", err)
		os.Exit(1)
	}

	seen := loadSeen(seenFile)
	initialSeen := len(seen)

	decodedItems := []decodedEntry{}
	allLinks := []string{}
	duplicates := 0
	newIDs := []int{}

	fmt.Printf("🔍 Found %d encrypted items. Seen before: %d\n", len(items), initialSeen)
	for _, it := range items {
		if _, ok := seen[it.ID]; ok {
			duplicates++
			decodedItems = append(decodedItems, decodedEntry{ID: it.ID, Name: it.Name, Skipped: true})
			continue
		}
		plain, err := utils.DecryptValue(it.Value, it.ID)
		if err != nil {
			decodedItems = append(decodedItems, decodedEntry{ID: it.ID, Name: it.Name, Error: err.Error()})
			newIDs = append(newIDs, it.ID)
			continue
		}
		fixed := cleanAndFixDecoded(plain)
		decodedItems = append(decodedItems, decodedEntry{ID: it.ID, Name: it.Name, Raw: plain, Fixed: fixed})
		for _, l := range extractLinks(fixed) {
			allLinks = append(allLinks, l)
		}
		newIDs = append(newIDs, it.ID)
	}
	// dedupe links
	allLinks = dedupeStrings(allLinks)

	_ = os.MkdirAll(filepath.Dir(outDecoded), 0o755)
	{
		f, _ := os.Create(outDecoded)
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]interface{}{
			"decoded":            decodedItems,
			"links":              allLinks,
			"fetchedAt":          nowISO(),
			"duplicates_skipped": duplicates,
		})
		f.Close()
	}

	fmt.Printf("🧩 Extracted %d links from decoded data. Skipped %d duplicates, will check %d new ids.\n", len(allLinks), duplicates, len(newIDs))

	// Prepare binaries
	xrayBin, err := findXrayBinary()
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	curlBin := findCurlBinary()

	working := []string{}
	failed := []map[string]string{}
	logs := []map[string]string{}

	for i, link := range allLinks {
		fmt.Printf("[%d/%d] Testing: %s...\n", i+1, len(allLinks), truncate(link, 120))
		res := runWorker(link, xrayBin, curlBin)
		checkedAt := nowISO()
		status := "FAIL"
		if res.OK {
			status = "OK"
		}
		logs = append(logs, map[string]string{
			"link":       res.Link,
			"status":     status,
			"reason":     res.Reason,
			"checkedAt":  checkedAt,
			"configFile": res.ConfigFile,
			"logFile":    res.LogFile,
			"xrayError":  res.XrayError,
		})
		if res.OK {
			working = append(working, res.Link)
			fmt.Println("✅ OK")
		} else {
			failed = append(failed, map[string]string{
				"link":       res.Link,
				"failReason": res.Reason,
				"configFile": res.ConfigFile,
				"logFile":    res.LogFile,
				"xrayError":  res.XrayError,
			})
			fmt.Printf("❌ FAIL (%s)\n", res.Reason)
		}
	}

	for _, id := range newIDs {
		seen[id] = struct{}{}
	}
	saveSeen(seenFile, seen)

	// Save outputs
	writeJSON(outWorking, map[string]interface{}{"links": working, "checkedAt": nowISO()})
	writeJSON(outFailed, map[string]interface{}{"links": failed, "checkedAt": nowISO()})
	writeJSON(outLogs, map[string]interface{}{"logs": logs, "checkedAt": nowISO()})

	fmt.Printf("\n✅ %d working | ❌ %d failed\n", len(working), len(failed))
	fmt.Printf("🔁 New ids checked: %d | Duplicates skipped: %d | Total seen now: %d\n", len(newIDs), duplicates, len(seen))
	fmt.Printf("📁 Decoded: %s\n", outDecoded)
	fmt.Printf("📁 Working: %s\n", outWorking)
	fmt.Printf("📁 Failed: %s\n", outFailed)
	fmt.Printf("📁 Logs: %s\n", outLogs)
	fmt.Printf("📁 Seen IDs file: %s\n", seenFile)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func dedupeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func writeJSON(path string, v interface{}) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		fmt.Println("warning: cannot write", path, ":", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
