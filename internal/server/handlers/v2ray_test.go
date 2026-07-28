package handlers_test

import (
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"vpnpannel/internal/database"
	"vpnpannel/internal/models"
	"vpnpannel/internal/testutil"
	"vpnpannel/internal/testutil/apptest"
)

func TestV2RayCreate_ManualMode(t *testing.T) {
	app := apptest.New(t)
	name := testutil.UniqueName("node")

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"name": {name}, "address": {"1.2.3.4"}, "port": {"443"}, "protocol": {"vless"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect after creating a node, got %d", resp.StatusCode)
	}

	var node models.V2RayNode
	if err := database.DB.Where("name = ?", name).First(&node).Error; err != nil {
		t.Fatalf("expected the node to be created: %v", err)
	}
	if !node.IsActive {
		t.Errorf("expected a newly-created node to be active by default")
	}
}

func TestV2RayCreate_DuplicateNameRejected(t *testing.T) {
	app := apptest.New(t)
	name := testutil.UniqueName("dup-node")
	database.DB.Create(&models.V2RayNode{Name: name, Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true})

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/new", url.Values{
		"name": {name}, "address": {"2.2.2.2"}, "port": {"443"}, "protocol": {"vless"},
	}, adminAuth(t))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for a duplicate node name, got %d", resp.StatusCode)
	}
}

func TestV2RayUpdate_ValidationErrors(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	cases := []struct {
		name   string
		values url.Values
	}{
		{"missing name", url.Values{"name": {""}, "address": {"1.1.1.1"}, "port": {"443"}, "protocol": {"vless"}}},
		{"missing address", url.Values{"name": {node.Name}, "address": {""}, "port": {"443"}, "protocol": {"vless"}}},
		{"invalid port", url.Values{"name": {node.Name}, "address": {"1.1.1.1"}, "port": {"0"}, "protocol": {"vless"}}},
		{"missing protocol", url.Values{"name": {node.Name}, "address": {"1.1.1.1"}, "port": {"443"}, "protocol": {""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/edit", tc.values, adminAuth(t))
			if resp.StatusCode != 400 {
				t.Errorf("expected 400 for %s, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}

func TestV2RayUpdate_CanDeactivateNode(t *testing.T) {
	// Regression test for the gorm:"default:true" zero-value bug: explicitly
	// saving IsActive=false must actually persist as false, not silently
	// revert to true.
	testutil.SetupDB(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	node.IsActive = false
	if err := database.DB.Save(&node).Error; err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	var reloaded models.V2RayNode
	database.DB.First(&reloaded, node.ID)
	if reloaded.IsActive {
		t.Errorf("expected IsActive=false to persist, but the node came back active")
	}
}

func TestV2RayUpdate_DuplicateNameExceptSelfAllowed(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	// Saving the node with its own unchanged name must succeed (not treated as a duplicate).
	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/edit", url.Values{
		"name": {node.Name}, "address": {"9.9.9.9"}, "port": {"8443"}, "protocol": {"vmess"},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect when a node keeps its own name, got %d", resp.StatusCode)
	}
}

func TestV2RayList_FiltersByActive(t *testing.T) {
	app := apptest.New(t)
	activeName := testutil.UniqueName("active-node")
	database.DB.Create(&models.V2RayNode{Name: activeName, Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true})
	inactiveName := testutil.UniqueName("inactive-node")
	inactiveNode := models.V2RayNode{Name: inactiveName, Address: "2.2.2.2", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&inactiveNode)
	inactiveNode.IsActive = false
	database.DB.Save(&inactiveNode)

	resp := testutil.DoJSON(t, app, "GET", "/admin/v2ray?active=false", nil, adminAuth(t))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if !strings.Contains(text, inactiveName) {
		t.Errorf("expected the inactive-only filter to include %q", inactiveName)
	}
	if strings.Contains(text, activeName) {
		t.Errorf("expected the inactive-only filter to exclude %q", activeName)
	}
}

func TestV2RayDelete(t *testing.T) {
	app := apptest.New(t)
	node := models.V2RayNode{Name: testutil.UniqueName("node"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&node)

	resp := testutil.DoJSON(t, app, "POST", "/admin/v2ray/"+strconv.FormatUint(uint64(node.ID), 10)+"/delete", nil, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.V2RayNode{}).Where("id = ?", node.ID).Count(&count)
	if count != 0 {
		t.Errorf("expected the node to be deleted")
	}
}

func TestV2RayBatchDelete(t *testing.T) {
	app := apptest.New(t)
	n1 := models.V2RayNode{Name: testutil.UniqueName("n1"), Address: "1.1.1.1", Port: 443, Protocol: "vless", IsActive: true}
	n2 := models.V2RayNode{Name: testutil.UniqueName("n2"), Address: "2.2.2.2", Port: 443, Protocol: "vless", IsActive: true}
	database.DB.Create(&n1)
	database.DB.Create(&n2)

	resp := testutil.DoForm(t, app, "POST", "/admin/v2ray/batch-delete", url.Values{
		"ids": {strconv.FormatUint(uint64(n1.ID), 10), strconv.FormatUint(uint64(n2.ID), 10)},
	}, adminAuth(t))
	if resp.StatusCode != 302 && resp.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	var count int64
	database.DB.Model(&models.V2RayNode{}).Where("id IN ?", []uint{n1.ID, n2.ID}).Count(&count)
	if count != 0 {
		t.Errorf("expected both nodes to be deleted, %d remain", count)
	}
}
