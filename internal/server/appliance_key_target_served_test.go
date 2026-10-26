// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A122: an appliance destination declares key_generation=appliance to have the
// appliance generate its key. The declaration is checked when the destination
// is saved: a family that can do it is accepted, and one that cannot, or a
// value that is not the mode, is refused with what to do.
func TestServedApplianceKeyGenerationIsCheckedWhenTheDestinationIsSaved(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "certs:read")
	create := func(connectorName string, cfg map[string]any) (int, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name": connectorName + "-vip", "connector": connectorName, "config": cfg, "enabled": true,
		})
		return status, string(body)
	}
	// The appliance is asked for its key by one named network relay.
	relayAgent := store.Agent{ID: uuid.NewString(), TenantID: h.tenant, Name: "dmz-relay", Status: "active", Roles: []string{"network"}}
	if err := h.store.UpsertAgent(t.Context(), relayAgent); err != nil {
		t.Fatal(err)
	}
	netscaler := map[string]any{"endpoint": "https://ns.example.test", "username": "nsroot",
		"password_ref": "secret://connectors/ns", "key_generation": "appliance", "required_agent_id": relayAgent.ID}
	if status, body := create("netscaler", netscaler); status != http.StatusCreated {
		t.Fatalf("NetScaler destination generating its key on the appliance = %d %s", status, body)
	}
	kemp := map[string]any{"endpoint": "https://kemp.example.test", "token_ref": "secret://connectors/kemp",
		"key_generation": "appliance"}
	if status, body := create("kemp", kemp); status != http.StatusUnprocessableEntity || !strings.Contains(body, "kemp") {
		t.Fatalf("Kemp destination declaring appliance keys = %d %s, want 422 naming the family", status, body)
	}
	netscaler["key_generation"] = "device"
	if status, body := create("netscaler", netscaler); status != http.StatusUnprocessableEntity || !strings.Contains(body, "appliance") {
		t.Fatalf("NetScaler destination declaring another mode = %d %s, want 422 naming the mode", status, body)
	}

	// The key custody readout says the NetScaler's keys are born on the
	// appliance and never leave it, and counts it as moved off the control
	// plane; an appliance still on sealed keys is told how to move.
	delete(kemp, "key_generation")
	if status, body := create("kemp", kemp); status != http.StatusCreated {
		t.Fatalf("Kemp destination = %d %s", status, body)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/endpoints/key-custody", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("key custody readout = %d %s", status, body)
	}
	var readout struct {
		Items []struct {
			Connector                 string `json:"connector"`
			Origin                    string `json:"origin"`
			KeyBytesLeaveControlPlane bool   `json:"key_bytes_leave_control_plane"`
			Detail                    string `json:"detail"`
		} `json:"items"`
		Summary struct {
			Targets            int `json:"targets"`
			ApplianceGenerated int `json:"appliance_generated"`
			MigratedPercent    int `json:"migrated_percent"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &readout); err != nil {
		t.Fatal(err)
	}
	for _, item := range readout.Items {
		switch item.Connector {
		case "netscaler":
			if item.Origin != "appliance" || item.KeyBytesLeaveControlPlane || !strings.Contains(item.Detail, "appliance") {
				t.Errorf("NetScaler readout = %+v, want keys generated on the appliance", item)
			}
		case "kemp":
			if item.Origin != "control_plane" || !item.KeyBytesLeaveControlPlane {
				t.Errorf("Kemp readout = %+v, want control-plane keys", item)
			}
		}
	}
	if readout.Summary.Targets != 2 || readout.Summary.ApplianceGenerated != 1 || readout.Summary.MigratedPercent != 50 {
		t.Fatalf("readout summary = %+v, want one of two targets generating on the appliance", readout.Summary)
	}
}
