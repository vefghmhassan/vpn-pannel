package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

// --- shared payload types -------------------------------------------------
//
// models.V2RayNode carries no json tags, so the API emits Go field names
// ("Address", not "address"). Only the fields the invariants care about are
// decoded here.

type confNode struct {
	ID       uint
	Name     string
	Address  string
	Ads      bool
	IsActive bool
}

type confPayload struct {
	NoAds     confNode   `json:"no_ads"`
	Ads       confNode   `json:"ads"`
	NoAdsList []confNode `json:"no_ads_list"`
	AdsList   []confNode `json:"ads_list"`
}

// postSplashConf issues one request without touching *testing.T, so it is safe
// to call from many goroutines at once. Every failure is returned rather than
// fataled — t.Fatalf from a non-test goroutine is undefined behaviour.
func postSplashConf(app *fiber.App, body []byte, contentType string) (status int, raw []byte, err error) {
	req := httptest.NewRequest("POST", "/api/v1/splash/conf", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// -1 disables fiber's test timeout: with a capped connection pool a request
	// under heavy concurrency legitimately waits its turn.
	resp, err := app.Test(req, -1)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

func jsonBody(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// --- invariants -----------------------------------------------------------

// confExpectation is what a response should look like. Lengths are exact when
// Exact is true; otherwise only the upper bounds are enforced, which is all a
// test can know when the settings are being changed underneath it.
type confExpectation struct {
	Exact     bool
	WantAds   int
	WantNoAds int
	// Upper bounds used when Exact is false.
	MaxAds   int
	MaxNoAds int
}

// checkConf verifies every promise the endpoint makes, and returns the list of
// violations instead of failing, so it can run inside a goroutine.
func checkConf(p confPayload, want confExpectation) []string {
	var problems []string
	add := func(format string, args ...interface{}) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if want.Exact {
		if len(p.AdsList) != want.WantAds {
			add("ads_list length = %d, want %d", len(p.AdsList), want.WantAds)
		}
		if len(p.NoAdsList) != want.WantNoAds {
			add("no_ads_list length = %d, want %d", len(p.NoAdsList), want.WantNoAds)
		}
	} else {
		if len(p.AdsList) < 1 || len(p.AdsList) > want.MaxAds {
			add("ads_list length = %d, want between 1 and %d", len(p.AdsList), want.MaxAds)
		}
		if len(p.NoAdsList) < 1 || len(p.NoAdsList) > want.MaxNoAds {
			add("no_ads_list length = %d, want between 1 and %d", len(p.NoAdsList), want.MaxNoAds)
		}
	}

	// The ads promise: never two configs from the same server, never a node from
	// the wrong pool, never an inactive node.
	seenAdsAddr := map[string]bool{}
	seenID := map[uint]bool{}
	for _, n := range p.AdsList {
		if !n.Ads {
			add("non-ads node %q (id %d) leaked into ads_list", n.Name, n.ID)
		}
		if !n.IsActive {
			add("inactive node %q (id %d) returned in ads_list", n.Name, n.ID)
		}
		if n.Address == "" {
			add("ads node id %d has an empty address", n.ID)
		}
		if seenAdsAddr[n.Address] {
			add("ads address %q returned more than once", n.Address)
		}
		seenAdsAddr[n.Address] = true
		if seenID[n.ID] {
			add("ads node id %d returned more than once", n.ID)
		}
		seenID[n.ID] = true
	}

	for _, n := range p.NoAdsList {
		if n.Ads {
			add("ads node %q (id %d) leaked into no_ads_list", n.Name, n.ID)
		}
		if !n.IsActive {
			add("inactive node %q (id %d) returned in no_ads_list", n.Name, n.ID)
		}
		if seenID[n.ID] {
			add("node id %d appears in both lists", n.ID)
		}
	}

	// The singular fields are the legacy view of the lists and must agree.
	if len(p.AdsList) > 0 && p.Ads.ID != p.AdsList[0].ID {
		add("ads (id %d) does not match ads_list[0] (id %d)", p.Ads.ID, p.AdsList[0].ID)
	}
	if len(p.NoAdsList) > 0 && p.NoAds.ID != p.NoAdsList[0].ID {
		add("no_ads (id %d) does not match no_ads_list[0] (id %d)", p.NoAds.ID, p.NoAdsList[0].ID)
	}
	return problems
}

// --- inventory helpers ----------------------------------------------------

func distinctActiveAddresses(t *testing.T, ads bool) int {
	t.Helper()
	var n int64
	if err := database.DB.Model(&models.V2RayNode{}).
		Where("is_active = ? AND ads = ?", true, ads).
		Distinct("address").Count(&n).Error; err != nil {
		t.Fatalf("failed to count distinct addresses (ads=%v): %v", ads, err)
	}
	return int(n)
}

func activeNodeCount(t *testing.T, ads bool) int {
	t.Helper()
	var n int64
	if err := database.DB.Model(&models.V2RayNode{}).
		Where("is_active = ? AND ads = ?", true, ads).Count(&n).Error; err != nil {
		t.Fatalf("failed to count nodes (ads=%v): %v", ads, err)
	}
	return int(n)
}

func loadSettings(t *testing.T) models.AppSettings {
	t.Helper()
	var s models.AppSettings
	if err := database.DB.First(&s, 1).Error; err != nil {
		t.Fatalf("failed to load settings: %v", err)
	}
	return s
}

// seedConfNodes creates perAddress nodes of the given kind on each address.
// Transactional tests only — it makes no attempt to clean up after itself.
func seedConfNodes(t *testing.T, ads bool, perAddress int, addresses ...string) {
	t.Helper()
	prefix := "noads"
	port := 443
	if ads {
		prefix, port = "ads", 8443
	}
	for _, addr := range addresses {
		for i := 0; i < perAddress; i++ {
			if err := database.DB.Create(&models.V2RayNode{
				Name: testutil.UniqueName(prefix), Address: addr, Port: port,
				Protocol: "vless", IsActive: true, Ads: ads,
			}).Error; err != nil {
				t.Fatalf("failed to seed node on %s: %v", addr, err)
			}
		}
	}
}

// --- 1. the exhaustive matrix (deterministic, transactional) ---------------

// TestApiSplashConf_Matrix walks every combination that changes the shape of the
// response: the multi-ads toggle, the configured ads count (including the
// nonsensical values an admin or a bad import can produce), how many ads servers
// actually exist, the total conf count, and the unrelated non-ads spreading
// toggle. Each case runs in its own rolled-back transaction over seeded data, so
// the expected lengths are exact.
func TestApiSplashConf_Matrix(t *testing.T) {
	cases := []struct {
		name string
		// settings
		splashConfCount int
		diverse         bool
		multiEnabled    bool
		adsCount        int
		// seeded topology
		adsAddrs     []string
		adsPerAddr   int
		noAdsAddrs   []string
		noAdsPerAddr int
		// expectations
		wantAds   int
		wantNoAds int
	}{
		{
			name: "multi off ignores the count entirely",
			// The count is set high but the toggle is off, so nothing changes.
			splashConfCount: 5, diverse: true, multiEnabled: false, adsCount: 5,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 1, wantNoAds: 4,
		},
		{
			name:            "multi on with count 1 keeps the single-node path",
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 1,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 1, wantNoAds: 4,
		},
		{
			name: "multi on with count 0 falls back to one",
			// 0 can reach the row through an imported backup, bypassing the form.
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 0,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 1, wantNoAds: 4,
		},
		{
			name:            "multi on with a negative count falls back to one",
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: -7,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 1, wantNoAds: 4,
		},
		{
			name:            "multi on, count below the number of ads servers",
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 2,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 2, wantNoAds: 4,
		},
		{
			name:            "multi on, count exactly the number of ads servers",
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 3,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 3, wantNoAds: 4,
		},
		{
			name: "multi on, count above the number of ads servers is capped",
			// The agreed behaviour: fewer configs rather than two from one server.
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 6,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 3, wantNoAds: 4,
		},
		{
			name:            "multi on with an absurd count is still capped",
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 100000,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 3, wantNoAds: 4,
		},
		{
			name: "multi on with a single ads server yields one config",
			// Many ads nodes, but all on one address: dedup must win over count.
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 4,
			adsAddrs: []string{"ads1"}, adsPerAddr: 20,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 1, wantNoAds: 4,
		},
		{
			name: "multi on is independent of the non-ads spreading toggle",
			// splash_diverse_servers off must not disable ads spreading.
			splashConfCount: 5, diverse: false, multiEnabled: true, adsCount: 3,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 3,
			wantAds: 3, wantNoAds: 4,
		},
		{
			name: "ads count is additive, not taken out of splash_conf_count",
			// splash_conf_count 9 sizes the non-ads list alone: 8 + 3 ads = 11.
			splashConfCount: 9, diverse: true, multiEnabled: true, adsCount: 3,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2", "n3", "n4"}, noAdsPerAddr: 5,
			wantAds: 3, wantNoAds: 8,
		},
		{
			name: "splash_conf_count below its minimum is clamped to two",
			// Clamped to 2, so the non-ads list holds exactly one node.
			splashConfCount: 1, diverse: true, multiEnabled: true, adsCount: 3,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2"}, noAdsPerAddr: 3,
			wantAds: 3, wantNoAds: 1,
		},
		{
			name: "non-ads list shrinks to what exists without touching ads",
			// Only two non-ads nodes exist against a request for four.
			splashConfCount: 5, diverse: true, multiEnabled: true, adsCount: 3,
			adsAddrs: []string{"ads1", "ads2", "ads3"}, adsPerAddr: 4,
			noAdsAddrs: []string{"n1", "n2"}, noAdsPerAddr: 1,
			wantAds: 3, wantNoAds: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := apptest.New(t)
			isolateSplashConfNodes(t)
			seedConfNodes(t, true, tc.adsPerAddr, tc.adsAddrs...)
			seedConfNodes(t, false, tc.noAdsPerAddr, tc.noAdsAddrs...)
			setSplashConf(t, tc.splashConfCount, tc.diverse)
			setMultiAds(t, tc.multiEnabled, tc.adsCount)

			// Repeated because the selection is randomised: one pass can pass by
			// luck even when the per-address dedup is broken.
			for attempt := 0; attempt < 8; attempt++ {
				status, raw, err := postSplashConf(app,
					jsonBody(map[string]string{"client_key": testutil.UniqueName("ck")}),
					fiber.MIMEApplicationJSON)
				if err != nil {
					t.Fatalf("attempt %d: request failed: %v", attempt, err)
				}
				if status != http.StatusOK {
					t.Fatalf("attempt %d: expected 200, got %d (%s)", attempt, status, raw)
				}
				var p confPayload
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatalf("attempt %d: invalid JSON: %v", attempt, err)
				}
				problems := checkConf(p, confExpectation{
					Exact: true, WantAds: tc.wantAds, WantNoAds: tc.wantNoAds,
				})
				for _, problem := range problems {
					t.Errorf("attempt %d: %s", attempt, problem)
				}
				if t.Failed() {
					return
				}
			}
		})
	}
}

// TestApiSplashConf_RotatesNodesWithinEachAdsServer covers the other half of the
// request: not just one config per server, but a *randomly chosen* one, so two
// clients hitting the same server rarely get the same config.
func TestApiSplashConf_RotatesNodesWithinEachAdsServer(t *testing.T) {
	app := apptest.New(t)
	isolateSplashConfNodes(t)
	seedConfNodes(t, true, 8, "ads1", "ads2", "ads3")
	seedConfNodes(t, false, 3, "n1", "n2")
	setSplashConf(t, 3, true)
	setMultiAds(t, true, 3)

	// address -> the set of distinct node ids seen for it.
	seen := map[string]map[uint]bool{}
	for attempt := 0; attempt < 30; attempt++ {
		status, raw, err := postSplashConf(app,
			jsonBody(map[string]string{"client_key": testutil.UniqueName("ck")}),
			fiber.MIMEApplicationJSON)
		if err != nil || status != http.StatusOK {
			t.Fatalf("attempt %d: status %d err %v", attempt, status, err)
		}
		var p confPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("attempt %d: invalid JSON: %v", attempt, err)
		}
		for _, n := range p.AdsList {
			if seen[n.Address] == nil {
				seen[n.Address] = map[uint]bool{}
			}
			seen[n.Address][n.ID] = true
		}
	}

	if len(seen) != 3 {
		t.Fatalf("expected all 3 ads servers to appear across 30 requests, got %d", len(seen))
	}
	for addr, ids := range seen {
		// With 8 nodes per server over 30 draws, seeing only one is effectively
		// impossible unless the pick within a server is not random at all.
		if len(ids) < 2 {
			t.Errorf("server %q always returned the same node (%d distinct) across 30 requests", addr, len(ids))
		}
	}
}

// --- 2. one thousand concurrent clients -----------------------------------

const concurrentClients = 1000

// TestApiSplashConf_ThousandConcurrentClients drives the endpoint from 1000
// goroutines at once against the real database and its live settings, asserting
// that every single response is well-formed and obeys the ads invariants.
//
// It runs over the shared connection pool rather than a transaction (see
// testutil.SetupSharedDB) and is strictly read-only: it seeds nothing, changes
// no settings, and deletes nothing, so it is safe against live operator data.
// Expectations are derived from the inventory at start-up, so it is correct
// whatever topology and settings the database happens to hold.
func TestApiSplashConf_ThousandConcurrentClients(t *testing.T) {
	if testing.Short() {
		t.Skip("load test skipped in -short mode")
	}
	app := apptest.NewShared(t)

	settings := loadSettings(t)
	adsServers := distinctActiveAddresses(t, true)
	nonAdsNodes := activeNodeCount(t, false)
	if adsServers == 0 || nonAdsNodes == 0 {
		t.Skip("needs active ads and non-ads nodes in the database")
	}

	confCount := settings.SplashConfCount
	if confCount < 2 {
		confCount = 2
	}
	wantAds := 1
	if settings.AdsMultiConfigEnabled && settings.AdsConfigCount > 1 {
		wantAds = settings.AdsConfigCount
	}
	if wantAds > adsServers {
		wantAds = adsServers // capped by however many ads servers exist
	}
	wantNoAds := confCount - 1
	if wantNoAds > nonAdsNodes {
		wantNoAds = nonAdsNodes
	}
	t.Logf("inventory: %d ads servers, %d non-ads nodes; settings: multi=%v count=%d splash_conf_count=%d",
		adsServers, nonAdsNodes, settings.AdsMultiConfigEnabled, settings.AdsConfigCount, confCount)
	t.Logf("expecting %d ads and %d non-ads configs per response", wantAds, wantNoAds)

	var (
		mu           sync.Mutex
		failures     []string
		statusCounts = map[int]int{}
		// address -> how many times it was handed out, to prove the load is
		// actually spread over the ads servers rather than pinned to one.
		adsHits    = map[string]int{}
		adsNodeIDs = map[string]map[uint]bool{}
		completed  atomic.Int64
	)
	record := func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		// Cap the collected failures: 1000 goroutines failing identically would
		// otherwise bury the signal in noise.
		if len(failures) < 25 {
			failures = append(failures, fmt.Sprintf(format, args...))
		}
	}

	// Every goroutine is released at once so the handlers genuinely overlap
	// rather than trickling through one at a time.
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < concurrentClients; i++ {
		done.Add(1)
		go func(client int) {
			defer done.Done()
			start.Wait()

			status, raw, err := postSplashConf(app, jsonBody(map[string]string{
				"client_key": fmt.Sprintf("load-client-%d", client),
				"device_id":  fmt.Sprintf("device-%d", client),
			}), fiber.MIMEApplicationJSON)
			if err != nil {
				record("client %d: transport error: %v", client, err)
				return
			}
			completed.Add(1)

			mu.Lock()
			statusCounts[status]++
			mu.Unlock()

			if status != http.StatusOK {
				record("client %d: status %d, body %s", client, status, truncate(raw, 200))
				return
			}
			var p confPayload
			if err := json.Unmarshal(raw, &p); err != nil {
				record("client %d: invalid JSON: %v (%s)", client, err, truncate(raw, 200))
				return
			}
			for _, problem := range checkConf(p, confExpectation{
				Exact: true, WantAds: wantAds, WantNoAds: wantNoAds,
			}) {
				record("client %d: %s", client, problem)
			}

			mu.Lock()
			for _, n := range p.AdsList {
				adsHits[n.Address]++
				if adsNodeIDs[n.Address] == nil {
					adsNodeIDs[n.Address] = map[uint]bool{}
				}
				adsNodeIDs[n.Address][n.ID] = true
			}
			mu.Unlock()
		}(i)
	}
	start.Done()
	done.Wait()

	if got := completed.Load(); got != concurrentClients {
		t.Errorf("only %d of %d requests completed", got, concurrentClients)
	}
	t.Logf("status codes: %v", statusCounts)
	t.Logf("ads server hits: %v", adsHits)
	for _, problem := range failures {
		t.Errorf("%s", problem)
	}
	if n := len(failures); n > 0 {
		t.Errorf("%d requests (first %d shown) violated the response contract", n, len(failures))
	}

	// Fairness: when the count reaches every ads server each one must appear in
	// every response; when it is lower they must still all get traffic over 1000
	// draws rather than the same few winning every time.
	if len(adsHits) != adsServers {
		t.Errorf("only %d of %d ads servers were ever returned across %d requests: %v",
			len(adsHits), adsServers, concurrentClients, adsHits)
	}
	if wantAds >= adsServers {
		for addr, hits := range adsHits {
			if hits != concurrentClients {
				t.Errorf("ads server %q appeared in %d of %d responses; with count >= server total it must appear in all",
					addr, hits, concurrentClients)
			}
		}
	} else {
		// Expected share per server; allow a wide margin since this is random.
		expected := wantAds * concurrentClients / adsServers
		for addr, hits := range adsHits {
			if hits < expected/4 {
				t.Errorf("ads server %q was starved: %d hits against an expected ~%d", addr, hits, expected)
			}
		}
	}
	for addr, ids := range adsNodeIDs {
		t.Logf("ads server %s: %d hits across %d distinct nodes", addr, adsHits[addr], len(ids))
	}
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- 3. the monkey test ---------------------------------------------------

// monkeyPayloads is the hostile-input corpus. The handler deliberately ignores
// body-parse errors (the body is optional), so none of these may produce a 5xx,
// and none may reach the database as anything but a hashed request key.
func monkeyPayloads() []struct {
	name        string
	body        []byte
	contentType string
} {
	long := strings.Repeat("A", 256*1024)
	return []struct {
		name        string
		body        []byte
		contentType string
	}{
		{"empty body", nil, fiber.MIMEApplicationJSON},
		{"empty object", []byte(`{}`), fiber.MIMEApplicationJSON},
		{"null", []byte(`null`), fiber.MIMEApplicationJSON},
		{"null fields", []byte(`{"client_key":null,"device_id":null}`), fiber.MIMEApplicationJSON},
		{"wrong field types", []byte(`{"client_key":12345,"device_id":true}`), fiber.MIMEApplicationJSON},
		{"nested object as key", []byte(`{"client_key":{"a":[1,2,3]}}`), fiber.MIMEApplicationJSON},
		{"json array", []byte(`[1,2,3]`), fiber.MIMEApplicationJSON},
		{"truncated json", []byte(`{"client_key":`), fiber.MIMEApplicationJSON},
		{"not json at all", []byte(`<xml><client_key/></xml>`), fiber.MIMEApplicationJSON},
		{"binary garbage", []byte{0x00, 0xFF, 0xFE, 0x01, 0x7F, 0x00}, fiber.MIMEApplicationJSON},
		{"no content type", []byte(`{"client_key":"plain"}`), ""},
		{"form content type", []byte(`client_key=formish`), fiber.MIMEApplicationForm},
		{"unicode and rtl", []byte(`{"client_key":"کلید-تست-🔑"}`), fiber.MIMEApplicationJSON},
		{"escaped nul in value", []byte(`{"client_key":"before\u0000after"}`), fiber.MIMEApplicationJSON},
		{"sql injection in client_key", []byte(`{"client_key":"x'; DROP TABLE v2_ray_nodes; --"}`), fiber.MIMEApplicationJSON},
		{"sql injection in device_id", []byte(`{"device_id":"1 OR 1=1; DELETE FROM app_settings"}`), fiber.MIMEApplicationJSON},
		{"template injection", []byte(`{"client_key":"{{.}}${jndi:ldap://x}"}`), fiber.MIMEApplicationJSON},
		{"very long client_key", jsonBody(map[string]string{"client_key": long}), fiber.MIMEApplicationJSON},
		{"deeply duplicated keys", []byte(`{"client_key":"a","client_key":"b","client_key":"c"}`), fiber.MIMEApplicationJSON},
		{"whitespace only", []byte("   \n\t  "), fiber.MIMEApplicationJSON},
		{"unknown extra fields", []byte(`{"client_key":"ok","surprise":{"deep":{"deeper":[1,2,3]}}}`), fiber.MIMEApplicationJSON},
	}
}

// TestApiSplashConf_MonkeyMalformedPayloads throws the hostile corpus at the
// endpoint concurrently and asserts it never 5xxs, never returns a malformed
// body, and — crucially — that the node and settings tables are untouched
// afterwards, which is what would break if any of this input reached SQL.
func TestApiSplashConf_MonkeyMalformedPayloads(t *testing.T) {
	if testing.Short() {
		t.Skip("monkey test skipped in -short mode")
	}
	app := apptest.NewShared(t)

	if activeNodeCount(t, true) == 0 || activeNodeCount(t, false) == 0 {
		t.Skip("needs active ads and non-ads nodes in the database")
	}
	beforeNodes := activeNodeCount(t, true) + activeNodeCount(t, false)
	beforeSettings := loadSettings(t)

	payloads := monkeyPayloads()
	var (
		mu           sync.Mutex
		failures     []string
		statusCounts = map[int]int{}
	)

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	// Every payload is fired from many goroutines at once, so the corpus is also
	// a concurrency test rather than a sequential walk.
	const repeats = 50
	for r := 0; r < repeats; r++ {
		for idx := range payloads {
			done.Add(1)
			go func(round, i int) {
				defer done.Done()
				start.Wait()
				p := payloads[i]

				status, raw, err := postSplashConf(app, p.body, p.contentType)
				mu.Lock()
				if err != nil {
					if len(failures) < 25 {
						failures = append(failures, fmt.Sprintf("%s: transport error: %v", p.name, err))
					}
					mu.Unlock()
					return
				}
				statusCounts[status]++
				mu.Unlock()

				if status >= 500 {
					mu.Lock()
					if len(failures) < 25 {
						failures = append(failures,
							fmt.Sprintf("%s: server error %d, body %s", p.name, status, truncate(raw, 200)))
					}
					mu.Unlock()
					return
				}
				if status == http.StatusOK {
					// A 200 must still be a well-formed, contract-abiding body:
					// a garbage request must not yield a garbage response.
					var parsed confPayload
					if err := json.Unmarshal(raw, &parsed); err != nil {
						mu.Lock()
						if len(failures) < 25 {
							failures = append(failures,
								fmt.Sprintf("%s: 200 with invalid JSON: %v", p.name, err))
						}
						mu.Unlock()
						return
					}
					problems := checkConf(parsed, confExpectation{
						MaxAds: 1024, MaxNoAds: 1024,
					})
					if len(problems) > 0 {
						mu.Lock()
						if len(failures) < 25 {
							failures = append(failures, fmt.Sprintf("%s: %s", p.name, problems[0]))
						}
						mu.Unlock()
					}
				}
			}(r, idx)
		}
	}
	start.Done()
	done.Wait()

	t.Logf("monkey status codes over %d requests: %v", repeats*len(payloads), statusCounts)
	for _, f := range failures {
		t.Errorf("%s", f)
	}

	// The real point of the exercise: nothing got through to the data.
	if after := activeNodeCount(t, true) + activeNodeCount(t, false); after != beforeNodes {
		t.Errorf("node count changed from %d to %d — hostile input reached the database", beforeNodes, after)
	}
	afterSettings := loadSettings(t)
	if afterSettings.AdsConfigCount != beforeSettings.AdsConfigCount ||
		afterSettings.AdsMultiConfigEnabled != beforeSettings.AdsMultiConfigEnabled ||
		afterSettings.SplashConfCount != beforeSettings.SplashConfCount {
		t.Errorf("settings changed during the monkey run: before %+v after %+v",
			beforeSettings, afterSettings)
	}
}

// TestApiSplashConf_ChaosSettingsFlipUnderLoad changes the ads settings while
// hundreds of requests are in flight. Exact lengths are unknowable mid-flip, so
// it asserts the invariants that must hold under every setting: a successful,
// well-formed response whose ads configs are always distinct and always drawn
// from the ads pool.
//
// It restores the original settings row on cleanup, including after a failure.
func TestApiSplashConf_ChaosSettingsFlipUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test skipped in -short mode")
	}
	app := apptest.NewShared(t)

	adsServers := distinctActiveAddresses(t, true)
	nonAdsNodes := activeNodeCount(t, false)
	if adsServers == 0 || nonAdsNodes == 0 {
		t.Skip("needs active ads and non-ads nodes in the database")
	}

	original := loadSettings(t)
	t.Cleanup(func() {
		// Restore by targeted update rather than Save so an unrelated column
		// written by something else in the meantime is left alone.
		if err := database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).
			Updates(map[string]interface{}{
				"ads_multi_config_enabled": original.AdsMultiConfigEnabled,
				"ads_config_count":         original.AdsConfigCount,
				"splash_conf_count":        original.SplashConfCount,
				"splash_diverse_servers":   original.SplashDiverseServers,
			}).Error; err != nil {
			t.Errorf("failed to restore the settings row: %v", err)
		}
	})

	maxNoAds := nonAdsNodes
	stop := make(chan struct{})
	var flipper sync.WaitGroup
	flipper.Add(1)
	go func() {
		defer flipper.Done()
		// Cycle through every meaningful configuration, including the degenerate
		// ones, while the load is running.
		configs := []struct {
			multi    bool
			adsCount int
			conf     int
			diverse  bool
		}{
			{true, 1, 5, true},
			{true, 3, 9, true},
			{false, 3, 5, false},
			{true, 100, 2, true},
			{true, 0, 7, false},
			{true, 2, 4, true},
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c := configs[i%len(configs)]
			database.DB.Model(&models.AppSettings{}).Where("id = ?", 1).
				Updates(map[string]interface{}{
					"ads_multi_config_enabled": c.multi,
					"ads_config_count":         c.adsCount,
					"splash_conf_count":        c.conf,
					"splash_diverse_servers":   c.diverse,
				})
		}
	}()

	var (
		mu           sync.Mutex
		failures     []string
		statusCounts = map[int]int{}
	)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	const chaosClients = 400
	for i := 0; i < chaosClients; i++ {
		done.Add(1)
		go func(client int) {
			defer done.Done()
			start.Wait()

			status, raw, err := postSplashConf(app, jsonBody(map[string]string{
				"client_key": fmt.Sprintf("chaos-%d", client),
			}), fiber.MIMEApplicationJSON)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if len(failures) < 25 {
					failures = append(failures, fmt.Sprintf("client %d: transport error: %v", client, err))
				}
				return
			}
			statusCounts[status]++
			if status != http.StatusOK {
				if len(failures) < 25 {
					failures = append(failures,
						fmt.Sprintf("client %d: status %d, body %s", client, status, truncate(raw, 200)))
				}
				return
			}
			var p confPayload
			if err := json.Unmarshal(raw, &p); err != nil {
				if len(failures) < 25 {
					failures = append(failures, fmt.Sprintf("client %d: invalid JSON: %v", client, err))
				}
				return
			}
			for _, problem := range checkConf(p, confExpectation{
				MaxAds: adsServers, MaxNoAds: maxNoAds,
			}) {
				if len(failures) < 25 {
					failures = append(failures, fmt.Sprintf("client %d: %s", client, problem))
				}
			}
		}(i)
	}
	start.Done()
	done.Wait()
	close(stop)
	flipper.Wait()

	t.Logf("chaos status codes: %v", statusCounts)
	for _, f := range failures {
		t.Errorf("%s", f)
	}
}
