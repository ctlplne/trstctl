// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/protocol"
)

type agentContract struct {
	Schema   string                  `json:"$schema,omitempty"`
	Contract string                  `json:"contract"`
	Codec    agentContractCodec      `json:"codec"`
	Metadata agentContractMetadata   `json:"metadata"`
	Service  agentContractService    `json:"service"`
	Messages map[string]agentMessage `json:"messages"`
}

type agentContractCodec struct {
	Name           string `json:"name"`
	ContentSubtype string `json:"content_subtype"`
}

type agentContractMetadata struct {
	AgentVersionKey       string   `json:"agent_version_key"`
	AgentProtocolKey      string   `json:"agent_protocol_key"`
	AgentCapabilitiesKey  string   `json:"agent_capabilities_key"`
	ServerProtocolKey     string   `json:"server_protocol_key"`
	ServerCapabilitiesKey string   `json:"server_capabilities_key"`
	Capabilities          []string `json:"capabilities"`
}

type agentContractService struct {
	Name     string                `json:"name"`
	Metadata string                `json:"metadata"`
	Methods  []agentContractMethod `json:"methods"`
}

type agentContractMethod struct {
	Name       string `json:"name"`
	FullMethod string `json:"full_method"`
	Request    string `json:"request"`
	Response   string `json:"response"`
}

type agentMessage struct {
	Fields []agentField `json:"fields"`
}

type agentField struct {
	Name     string `json:"name"`
	GoType   string `json:"go_type"`
	Presence string `json:"presence"`
}

type agentWireFixture struct {
	Codec string          `json:"codec"`
	Calls []agentWireCall `json:"calls"`
}

type agentWireCall struct {
	Name         string `json:"name"`
	FullMethod   string `json:"full_method"`
	RequestJSON  string `json:"request_json"`
	ResponseJSON string `json:"response_json"`
}

func TestAgentSteadyStateContractMatchesCommittedSchema(t *testing.T) {
	raw, err := os.ReadFile("agent_service_schema.json")
	if err != nil {
		t.Fatalf("read committed agent service schema: %v", err)
	}
	var expected agentContract
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatalf("decode committed agent service schema: %v", err)
	}
	expected.Schema = ""
	got := currentAgentContract()
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("agent service schema drifted\nwant:\n%s\n\ngot:\n%s", prettyJSON(expected), prettyJSON(got))
	}
}

func TestAgentSteadyStateWireGoldenFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/agent_service_wire.golden.json")
	if err != nil {
		t.Fatalf("read committed agent wire fixture: %v", err)
	}
	var fixture agentWireFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode committed agent wire fixture: %v", err)
	}
	if fixture.Codec != AgentCodecName {
		t.Fatalf("fixture codec = %q, want %q", fixture.Codec, AgentCodecName)
	}
	expected := map[string]struct {
		fullMethod string
		request    any
		response   any
	}{
		methodHeartbeat: {
			fullMethod: fullMethodHeartbeat,
			request: HeartbeatRequest{
				AgentID:    "edge-1",
				Version:    "v1.2.3",
				Status:     "active",
				CertSerial: "01:23",
				Inventory:  map[string]int64{"certificates": 2, "keys": 3},
			},
			response: HeartbeatResponse{TenantID: "11111111-1111-1111-1111-111111111111", NextHeartbeatSeconds: 30},
		},
		methodRenew: {
			fullMethod: fullMethodRenew,
			request:    RenewRequest{CSRDER: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
			response:   RenewResponse{CertChainPEM: []byte("-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"), NotAfterUnix: 1893456000},
		},
		methodInventory: {
			fullMethod: fullMethodInventory,
			request: InventoryRequest{
				SourceKind: "filesystem",
				Findings: []InventoryFinding{{
					Kind: "secret", Ref: "k8s://apps/web/tls", Provenance: "k8s-secret:apps/web/tls",
					RiskScore: 50, Metadata: map[string]string{"namespace": "apps"},
				}},
			},
			response: InventoryResponse{TenantID: "11111111-1111-1111-1111-111111111111", RunID: "22222222-2222-2222-2222-222222222222", Recorded: 1, Rejected: 0},
		},
		methodKubernetesPosture: {
			fullMethod: fullMethodKubernetesPosture,
			request: KubernetesPostureRequest{
				ReportID: "33333333-3333-3333-3333-333333333333", ClusterID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ReconcileIntervalSeconds: 30,
				CertificateSigning: KubernetesPostureSection{Complete: true, Resources: []KubernetesPostureResource{{
					Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed",
					PublicHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				}}},
				TrustBundles: KubernetesPostureSection{Complete: true, Resources: []KubernetesPostureResource{{
					Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "ready", Reason: "distributed",
					PublicHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				}}},
			},
			response: KubernetesPostureResponse{TenantID: "11111111-1111-1111-1111-111111111111", ReportID: "33333333-3333-3333-3333-333333333333", RecordedAtUnix: 1893456000},
		},
	}
	seen := map[string]bool{}
	for _, call := range fixture.Calls {
		want, ok := expected[call.Name]
		if !ok {
			t.Fatalf("fixture contains unexpected call %q", call.Name)
		}
		seen[call.Name] = true
		if call.FullMethod != want.fullMethod {
			t.Fatalf("%s full_method = %q, want %q", call.Name, call.FullMethod, want.fullMethod)
		}
		if got := marshalAgentJSON(t, want.request); got != call.RequestJSON {
			t.Fatalf("%s request JSON drifted\nwant %s\ngot  %s", call.Name, call.RequestJSON, got)
		}
		if got := marshalAgentJSON(t, want.response); got != call.ResponseJSON {
			t.Fatalf("%s response JSON drifted\nwant %s\ngot  %s", call.Name, call.ResponseJSON, got)
		}
	}
	for name := range expected {
		if !seen[name] {
			t.Fatalf("fixture missing call %q", name)
		}
	}
}

func currentAgentContract() agentContract {
	methods := make([]agentContractMethod, 0, len(agentServiceDesc.Methods))
	for _, method := range agentServiceDesc.Methods {
		msg := methodMessageTypes(method.MethodName)
		methods = append(methods, agentContractMethod{
			Name:       method.MethodName,
			FullMethod: "/" + agentServiceDesc.ServiceName + "/" + method.MethodName,
			Request:    msg.request,
			Response:   msg.response,
		})
	}
	return agentContract{
		Contract: agentServiceDesc.ServiceName,
		Codec:    agentContractCodec{Name: AgentCodecName, ContentSubtype: AgentCodecName},
		Metadata: agentContractMetadata{
			AgentVersionKey:       protocol.MetadataAgentVersion,
			AgentProtocolKey:      protocol.MetadataAgentProtocol,
			AgentCapabilitiesKey:  protocol.MetadataAgentCapabilities,
			ServerProtocolKey:     protocol.MetadataServerProtocol,
			ServerCapabilitiesKey: protocol.MetadataServerCapabilities,
			Capabilities:          []string{AgentCapabilityHeartbeat, AgentCapabilityRenew, AgentCapabilityInventory, AgentCapabilityKubernetesPosture, AgentCapabilityJobs},
		},
		Service: agentContractService{
			Name:     agentServiceDesc.ServiceName,
			Metadata: agentServiceDesc.Metadata.(string),
			Methods:  methods,
		},
		Messages: map[string]agentMessage{
			"HeartbeatRequest":          {Fields: jsonFieldsOf(HeartbeatRequest{})},
			"HeartbeatResponse":         {Fields: jsonFieldsOf(HeartbeatResponse{})},
			"RenewRequest":              {Fields: jsonFieldsOf(RenewRequest{})},
			"RenewResponse":             {Fields: jsonFieldsOf(RenewResponse{})},
			"InventoryFinding":          {Fields: jsonFieldsOf(InventoryFinding{})},
			"InventoryRequest":          {Fields: jsonFieldsOf(InventoryRequest{})},
			"InventoryResponse":         {Fields: jsonFieldsOf(InventoryResponse{})},
			"KubernetesPostureResource": {Fields: jsonFieldsOf(KubernetesPostureResource{})},
			"KubernetesPostureSection":  {Fields: jsonFieldsOf(KubernetesPostureSection{})},
			"KubernetesPostureRequest":  {Fields: jsonFieldsOf(KubernetesPostureRequest{})},
			"KubernetesPostureResponse": {Fields: jsonFieldsOf(KubernetesPostureResponse{})},
			"ClaimJobsRequest":          {Fields: jsonFieldsOf(ClaimJobsRequest{})},
			"ClaimedJob":                {Fields: jsonFieldsOf(ClaimedJob{})},
			"ClaimJobsResponse":         {Fields: jsonFieldsOf(ClaimJobsResponse{})},
			"ReportJobResultRequest":    {Fields: jsonFieldsOf(ReportJobResultRequest{})},
			"ReportJobResultResponse":   {Fields: jsonFieldsOf(ReportJobResultResponse{})},
			// B2. Pinned in the contract for a reason beyond completeness: the
			// security claim of host-generated renewal is that neither of these
			// messages can carry a private key. A committed field list turns
			// that from a property of today's struct into a change an author has
			// to make deliberately, in a diff a reviewer will see.
			"SignJobCSRRequest":  {Fields: jsonFieldsOf(SignJobCSRRequest{})},
			"SignJobCSRResponse": {Fields: jsonFieldsOf(SignJobCSRResponse{})},
			// B3: the workload-identity node API. Pinned for the same reason as
			// B2's: the security claim is that neither message can carry a
			// private key, and a committed field list makes that a change an
			// author has to make deliberately in a diff a reviewer will see.
			"FetchWorkloadSVIDRequest":  {Fields: jsonFieldsOf(FetchWorkloadSVIDRequest{})},
			"FetchWorkloadSVIDResponse": {Fields: jsonFieldsOf(FetchWorkloadSVIDResponse{})},
			"WorkloadX509SVID":          {Fields: jsonFieldsOf(WorkloadX509SVID{})},
			"WorkloadJWTSVID":           {Fields: jsonFieldsOf(WorkloadJWTSVID{})},
		},
	}
}

func methodMessageTypes(method string) struct{ request, response string } {
	switch method {
	case methodHeartbeat:
		return struct{ request, response string }{"HeartbeatRequest", "HeartbeatResponse"}
	case methodRenew:
		return struct{ request, response string }{"RenewRequest", "RenewResponse"}
	case methodInventory:
		return struct{ request, response string }{"InventoryRequest", "InventoryResponse"}
	case methodKubernetesPosture:
		return struct{ request, response string }{"KubernetesPostureRequest", "KubernetesPostureResponse"}
	case methodClaimJobs:
		return struct{ request, response string }{"ClaimJobsRequest", "ClaimJobsResponse"}
	case methodReportJobResult:
		return struct{ request, response string }{"ReportJobResultRequest", "ReportJobResultResponse"}
	case methodSignJobCSR:
		return struct{ request, response string }{"SignJobCSRRequest", "SignJobCSRResponse"}
	case methodFetchWorkloadSVID:
		return struct{ request, response string }{"FetchWorkloadSVIDRequest", "FetchWorkloadSVIDResponse"}
	default:
		return struct{ request, response string }{"", ""}
	}
}

func jsonFieldsOf(v any) []agentField {
	t := reflect.TypeOf(v)
	fields := make([]agentField, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		name, opts, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			name = sf.Name
		}
		presence := "required"
		if strings.Contains(opts, "omitempty") {
			presence = "optional"
		}
		fields = append(fields, agentField{Name: name, GoType: schemaGoType(sf.Type), Presence: presence})
	}
	return fields
}

func schemaGoType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int64:
		return "int64"
	case reflect.Int:
		return "int"
	case reflect.Bool:
		return "bool"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return "bytes_base64"
		}
		if t.Elem() == reflect.TypeOf(InventoryFinding{}) {
			return "[]InventoryFinding"
		}
		if t.Elem() == reflect.TypeOf(KubernetesPostureResource{}) {
			return "[]KubernetesPostureResource"
		}
	case reflect.Map:
		if t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.Int64 {
			return "map<string,int64>"
		}
		if t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.String {
			return "map<string,string>"
		}
	}
	return t.String()
}

func marshalAgentJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := jsonCodec{}.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(data.Materialize())
}

func prettyJSON(v any) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}
