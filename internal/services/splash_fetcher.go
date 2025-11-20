package services

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"vpnpannel/internal/config"
	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/utils"
)

type splashItem struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Price    int    `json:"price"`
	Usage    int    `json:"usage"`
	ServerID int    `json:"serverId"`
}

// StartSplashFetcher launches a background ticker that periodically fetches splash protocols
// and inserts new ones into the database while skipping duplicates by primary key.
func StartSplashFetcher(ctx context.Context) {
	interval := config.Current.SplashInterval
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// immediate run
		fetchAndStoreSplash()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchAndStoreSplash()
			}
		}
	}()
}

func fetchAndStoreSplash() {
	client := &http.Client{Timeout: 20 * time.Second}
	url := config.Current.SplashURL
	if url == "" {
		url = "https://wooddentools.com/api/protocols/splash"
	}
	fetchAndSplashNew()
	log.Printf("start fetch ")
	req, err := http.NewRequest(http.MethodGet, url, strings.NewReader("{}"))
	if err != nil {
		log.Printf("splash: new request: %v", err)
		return
	}

	// ensure JSON content-type as curl had
	req.Header.Add("giat", "")
	req.Header.Add("build", "false")
	req.Header.Add("seen", "1")
	req.Header.Add("sign", "w8z946T8GvQ0OYHgSASIgg==")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("token", "bf8009ecdd7c41a3")
	req.Header.Add("firebase_token", "cmmd8qHrTseaQMjZksQn_C:APA91bGwOlYixYil3Wi8k44T2IftbrtEPCTTmQUcZCvNt1r2U-Hl6GnWKHDYWhVNlB4CAWYfAgoOuCi_VTwchDV2eiOejjT2AIG6tav24lrrONY4Nq5JvwA")
	req.Header.Add("sha_hexadecimal", "6a28befce23991c20d92f4a64b7faf9922308c8e10c5f687ef811ad885d03ee0")
	req.Header.Add("version_code", "1005697")
	req.Header.Add("app_name", "co.vpn.plus")
	req.Header.Add("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N976N Build/QP1A.190711.020)")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("splash: request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("splash: non-2xx status: %s", resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("splash: read body failed: %v", err)
		return
	}
	if len(body) == 0 {
		log.Printf("splash: empty body")
		return
	}

	var items []splashItem
	if err := json.Unmarshal(body, &items); err != nil {
		// try {"data": [...]}
		var wrap struct {
			Data []splashItem `json:"data"`
		}
		if err2 := json.Unmarshal(body, &wrap); err2 == nil && len(wrap.Data) > 0 {
			items = wrap.Data
		} else {
			// try single object
			var single splashItem
			if err3 := json.Unmarshal(body, &single); err3 == nil && single.ID != 0 {
				items = []splashItem{single}
			} else {
				log.Printf("splash: decode failed: %v, body: %s", err, string(body))
				return
			}
		}
	}
	if len(items) == 0 {
		return
	}

	// Test each decrypted item via xray before inserting
	xrayBin, err := findXrayBinary()
	if err != nil {
		log.Printf("splash: xray not available: %v", err)
		return
	}
	curlBin := findCurlBinary()

	working := make([]models.SplashProtocol, 0, len(items))
	for _, it := range items {
		plain, err := utils.DecryptValue(it.Value, int(it.ID))
		if err != nil {
			continue
		}
		fixed := cleanAndFixDecoded(plain)
		links := extractLinks(fixed)
		ok := false
		bestPing := 0
		for _, l := range links {
			r := runWorker(l, xrayBin, curlBin)
			if r.OK {
				ok = true
				bestPing = r.PingMs
				break
			}
		}
		if ok {
			working = append(working, models.SplashProtocol{
				ID:       it.ID,
				Name:     it.Name,
				Value:    it.Value,
				Price:    it.Price,
				Usage:    it.Usage,
				ServerID: it.ServerID,
				PingMs:   bestPing,
			})
		}
	}

	if len(working) == 0 {
		log.Printf("splash: no working items to insert")
		return
	}

	if err := database.DB.Create(&working).Error; err != nil {
		// fallback per-row with duplicate tolerance
		inserted := 0
		for _, rec := range working {
			if err2 := database.DB.Create(&rec).Error; err2 != nil {
				lower := strings.ToLower(err2.Error())
				if strings.Contains(lower, "duplicate") || strings.Contains(lower, "unique") || strings.Contains(lower, "constraint") {
					continue
				}
				log.Printf("splash: insert %d failed: %v", rec.ID, err2)
				continue
			}
			inserted++
		}
		log.Printf("splash: inserted %d/%d working (fallback)", inserted, len(working))
		return
	}
	log.Printf("splash: inserted %d working items", len(working))
}
func fetchAndSplashNew() {
	client := &http.Client{Timeout: 20 * time.Second}
	url := "https://managev1.xyz/api/protocols/splash"
	if url == "" {
		url = "https://managev1.xyz/api/protocols/splash"
	}

	log.Printf("start fetch new ")
	req, err := http.NewRequest(http.MethodGet, url, strings.NewReader("{}"))
	if err != nil {
		log.Printf("splash: new request: %v", err)
		return
	}

	// ensure JSON content-type as curl had
	req.Header.Add("giat", "")
	req.Header.Add("build", "false")
	req.Header.Add("seen", "1")
	req.Header.Add("sign", "nyS5SxIAh1sqpLIhAYnoFg==")
	req.Header.Add("Host", "managev1.xyz")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("token", "bf8009ecdd7c41a3")
	req.Header.Add("firebase_token", "cmmd8qHrTseaQMjZksQn_C:APA91bGwOlYixYil3Wi8k44T2IftbrtEPCTTmQUcZCvNt1r2U-Hl6GnWKHDYWhVNlB4CAWYfAgoOuCi_VTwchDV2eiOejjT2AIG6tav24lrrONY4Nq5JvwA")
	req.Header.Add("sha_hexadecimal", "6a28befce23991c20d92f4a64b7faf9922308c8e10c5f687ef811ad885d03ee0")
	req.Header.Add("version_code", "1005697")
	req.Header.Add("app_name", "co.vpn.plus")
	req.Header.Add("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N976N Build/QP1A.190711.020)")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("splash: request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("splash: non-2xx status: %s", resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("splash: read body failed: %v", err)
		return
	}
	if len(body) == 0 {
		log.Printf("splash: empty body")
		return
	}

	var items []splashItem
	if err := json.Unmarshal(body, &items); err != nil {
		// try {"data": [...]}
		var wrap struct {
			Data []splashItem `json:"data"`
		}
		if err2 := json.Unmarshal(body, &wrap); err2 == nil && len(wrap.Data) > 0 {
			items = wrap.Data
		} else {
			// try single object
			var single splashItem
			if err3 := json.Unmarshal(body, &single); err3 == nil && single.ID != 0 {
				items = []splashItem{single}
			} else {
				log.Printf("splash: decode failed: %v, body: %s", err, string(body))
				return
			}
		}
	}
	if len(items) == 0 {
		return
	}

	// Test each decrypted item via xray before inserting
	xrayBin, err := findXrayBinary()
	if err != nil {
		log.Printf("splash: xray not available: %v", err)
		return
	}
	curlBin := findCurlBinary()

	working := make([]models.SplashProtocol, 0, len(items))
	for _, it := range items {
		plain, err := utils.DecryptValue(it.Value, int(it.ID))
		if err != nil {
			continue
		}
		fixed := cleanAndFixDecoded(plain)
		links := extractLinks(fixed)
		ok := false
		bestPing := 0
		for _, l := range links {
			r := runWorker(l, xrayBin, curlBin)
			if r.OK {
				ok = true
				bestPing = r.PingMs
				break
			}
		}
		if ok {
			working = append(working, models.SplashProtocol{
				ID:       it.ID,
				Name:     it.Name,
				Value:    it.Value,
				Price:    it.Price,
				Usage:    it.Usage,
				ServerID: it.ServerID,
				PingMs:   bestPing,
			})
		}
	}

	if len(working) == 0 {
		log.Printf("splash: no working items to insert")
		return
	}

	if err := database.DB.Create(&working).Error; err != nil {
		// fallback per-row with duplicate tolerance
		inserted := 0
		for _, rec := range working {
			if err2 := database.DB.Create(&rec).Error; err2 != nil {
				lower := strings.ToLower(err2.Error())
				if strings.Contains(lower, "duplicate") || strings.Contains(lower, "unique") || strings.Contains(lower, "constraint") {
					continue
				}
				log.Printf("splash: insert %d failed: %v", rec.ID, err2)
				continue
			}
			inserted++
		}
		log.Printf("splash: inserted %d/%d working (fallback)", inserted, len(working))
		return
	}
	log.Printf("splash: inserted %d working items", len(working))
}

// createIfNotExists removed in favor of batch logic above

// ---- Helpers copied/adapted from CLI implementation ----

func findXrayBinary() (string, error) {
	paths := []string{"/usr/local/bin/xray", "/usr/bin/xray"}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("xray binary not found")
}

func findCurlBinary() string {
	if p, err := exec.LookPath("curl"); err == nil {
		return p
	}
	return "/usr/bin/curl"
}

func cleanAndFixDecoded(plain string) string {
	reLeading := regexp.MustCompile(`^[^\x20-\x7E]+`)
	fixed := strings.TrimSpace(reLeading.ReplaceAllString(plain, ""))
	if strings.Contains(fixed, "://") {
		return fixed
	}
	if regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@`).FindStringIndex(fixed) != nil {
		return "vless://" + fixed
	}
	if regexp.MustCompile(`^[^:\s@]{1,60}@[\w\.-]+:\d+`).MatchString(fixed) {
		return "trojan://" + fixed
	}
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
	// dedupe
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

func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type workerResult struct {
	OK         bool
	Reason     string
	XrayError  string
	ConfigFile string
	LogFile    string
	Link       string
	PingMs     int
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

	cfgFile, _ := os.CreateTemp("", "xray_cfg_*.json")
	_ = cfgFile.Close()
	cfgPath := cfgFile.Name()
	{
		f, _ := os.Create(cfgPath)
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cfg)
		f.Close()
	}

	logFile, _ := os.CreateTemp("", "xray_log_*.log")
	logPath := logFile.Name()
	_ = logFile.Close()

	cmd := exec.Command(xrayBin, "run", "-c", cfgPath, "-format", "json")
	lf, _ := os.Create(logPath)
	cmd.Stdout = lf
	cmd.Stderr = lf
	_ = cmd.Start()
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Second)
	defer cancel()
	cmdCurl := exec.CommandContext(ctx, curlBin, "--socks5-hostname", fmt.Sprintf("127.0.0.1:%d", port), "--max-time", "10", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://www.google.com/generate_204")
	stdout, err := cmdCurl.StdoutPipe()
	if err != nil {
		return workerResult{OK: false, Reason: "curl_pipe", XrayError: xlogTail, ConfigFile: cfgPath, LogFile: logPath, Link: link}
	}
	start := time.Now()
	_ = cmdCurl.Start()
	code := ""
	s := bufio.NewScanner(stdout)
	for s.Scan() {
		code += s.Text()
	}
	_ = cmdCurl.Wait()
	ok := code == "204" || code == "200"
	pingMs := int(time.Since(start) / time.Millisecond)
	return workerResult{OK: ok, Reason: code, XrayError: xlogTail, ConfigFile: cfgPath, LogFile: logPath, Link: link, PingMs: pingMs}
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

func buildConfigFromLink(link string, port int) (map[string]interface{}, error) {
	link, _ = url.QueryUnescape(strings.TrimSpace(link))
	if i := strings.Index(link, "#"); i >= 0 {
		link = link[:i]
	}
	if strings.HasPrefix(link, "ss://") {
		if regexp.MustCompile(`(type=|encryption=|serviceName=|authority=|security=|sni=|flow=)`).FindStringIndex(link) != nil {
			link = "vless://" + strings.TrimPrefix(link, "ss://")
		}
	}
	var outbound map[string]interface{}
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
		outbound = map[string]interface{}{
			"protocol": "vless",
			"settings": map[string]interface{}{
				"vnext": []interface{}{map[string]interface{}{
					"address": host,
					"port":    atoiSafe(portStr),
					"users":   []interface{}{map[string]interface{}{"id": uid, "encryption": "none"}},
				}},
			},
			"streamSettings": map[string]interface{}{"network": firstNonEmpty(p.Get("type"), "tcp"), "security": firstNonEmpty(p.Get("security"), "none")},
		}
		if p.Get("security") == "reality" {
			ss := outbound["streamSettings"].(map[string]interface{})
			ss["realitySettings"] = map[string]interface{}{"serverName": p.Get("sni"), "publicKey": p.Get("pbk"), "shortId": p.Get("sid"), "spiderX": mustURLDecode(firstNonEmpty(p.Get("spx"), "/")), "fingerprint": firstNonEmpty(p.Get("fp"), "chrome")}
		} else if v := p.Get("sni"); v != "" {
			ss := outbound["streamSettings"].(map[string]interface{})
			if _, ok := ss["tlsSettings"]; !ok {
				ss["tlsSettings"] = map[string]interface{}{}
			}
			ss["tlsSettings"].(map[string]interface{})["serverName"] = v
		}
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
					"users":   []interface{}{map[string]interface{}{"id": str(v["id"]), "alterId": atoiSafe(strOrZero(v["aid"])), "security": "auto"}},
				}},
			},
			"streamSettings": map[string]interface{}{"network": firstNonEmpty(str(v["net"]), "tcp"), "security": firstNonEmpty(str(v["tls"]), "none")},
		}
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
				"servers": []interface{}{map[string]interface{}{"address": host, "port": atoiSafe(portStr), "password": pwd}},
			},
			"streamSettings": map[string]interface{}{"network": firstNonEmpty(p.Get("type"), "tcp"), "security": firstNonEmpty(p.Get("security"), "tls")},
		}
		if v := p.Get("sni"); v != "" {
			ss := outbound["streamSettings"].(map[string]interface{})
			if _, ok := ss["tlsSettings"]; !ok {
				ss["tlsSettings"] = map[string]interface{}{}
			}
			ss["tlsSettings"].(map[string]interface{})["serverName"] = v
		}
	} else if strings.HasPrefix(link, "ss://") {
		cfg, err := buildShadowsocks(link)
		if err != nil {
			return nil, err
		}
		outbound = cfg
	} else {
		return nil, errors.New("unsupported link")
	}
	return map[string]interface{}{
		"log":       map[string]interface{}{"loglevel": "none"},
		"inbounds":  []interface{}{map[string]interface{}{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true}}},
		"outbounds": []interface{}{outbound},
	}, nil
}

func buildShadowsocks(link string) (map[string]interface{}, error) {
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
			port = atoiSafe(hp[1])
		}
		if b, err := base64.StdEncoding.DecodeString(creds + "=="); err == nil {
			s := string(b)
			if strings.Contains(s, ":") {
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
		"protocol":       "shadowsocks",
		"settings":       map[string]interface{}{"servers": []interface{}{map[string]interface{}{"address": host, "port": port, "method": strings.TrimSpace(method), "password": strings.TrimSpace(password), "udp": true}}},
		"streamSettings": map[string]interface{}{"network": "tcp", "security": "none"},
	}, nil
}

func atoiSafe(s string) int {
	n := 0
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

// FetchSplashAndReturn performs a live fetch of splash protocols and returns the working items
// without persisting them to the database. The returned records contain encrypted Value fields,
// which can be decrypted by callers with utils.DecryptValue (same as ApiSPlash).
func FetchSplashAndReturn() ([]models.SplashProtocol, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	url := "https://managev1.xyz/api/protocols/splash"
	if url == "" {
		url = "https://managev1.xyz/api/protocols/splash"
	}

	log.Printf("start fetch new ")
	req, err := http.NewRequest(http.MethodGet, url, strings.NewReader("{}"))
	if err != nil {
		log.Printf("splash: new request: %v", err)
		return nil, err
	}

	// ensure JSON content-type as curl had
	req.Header.Add("giat", "")
	req.Header.Add("build", "false")
	req.Header.Add("seen", "1")
	req.Header.Add("sign", "nyS5SxIAh1sqpLIhAYnoFg==")
	req.Header.Add("Host", "managev1.xyz")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("token", "bf8009ecdd7c41a3")
	req.Header.Add("firebase_token", "cmmd8qHrTseaQMjZksQn_C:APA91bGwOlYixYil3Wi8k44T2IftbrtEPCTTmQUcZCvNt1r2U-Hl6GnWKHDYWhVNlB4CAWYfAgoOuCi_VTwchDV2eiOejjT2AIG6tav24lrrONY4Nq5JvwA")
	req.Header.Add("sha_hexadecimal", "6a28befce23991c20d92f4a64b7faf9922308c8e10c5f687ef811ad885d03ee0")
	req.Header.Add("version_code", "1005697")
	req.Header.Add("app_name", "co.vpn.plus")
	req.Header.Add("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N976N Build/QP1A.190711.020)")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("splash: request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("splash: non-2xx status: %s", resp.Status)
		return nil, fmt.Errorf("splash: non-2xx status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("splash: read body failed: %v", err)
		return nil, err
	}
	if len(body) == 0 {
		log.Printf("splash: empty body")
		return nil, nil
	}
	var items []splashItem
	if err := json.Unmarshal(body, &items); err != nil {
		var wrap struct {
			Data []splashItem `json:"data"`
		}
		if err2 := json.Unmarshal(body, &wrap); err2 == nil && len(wrap.Data) > 0 {
			items = wrap.Data
		} else {
			var single splashItem
			if err3 := json.Unmarshal(body, &single); err3 == nil && single.ID != 0 {
				items = []splashItem{single}
			} else {
				return nil, fmt.Errorf("splash: decode failed: %v", err)
			}
		}
	}
	if len(items) == 0 {
		return []models.SplashProtocol{}, nil
	}
	// Return items directly without ping/Xray validation
	out := make([]models.SplashProtocol, 0, len(items))
	for _, it := range items {
		out = append(out, models.SplashProtocol{
			ID:       it.ID,
			Name:     it.Name,
			Value:    it.Value,
			Price:    it.Price,
			Usage:    it.Usage,
			ServerID: it.ServerID,
			PingMs:   0,
		})
	}
	return out, nil
}
