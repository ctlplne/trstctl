// SPDX-License-Identifier: BUSL-1.1

// Command agent is the reference agent, built with Google's Agent Development Kit
// for Go. It reaches the tool server through ADK's own MCP toolset, authenticated
// with its trstctl agent identity and presenting its delegated credential on every
// request. A scripted model stands in for an LLM: it calls the one tool it is told
// to, then reports the tool's answer, so no model provider account is needed.
//
//	agent --server https://127.0.0.1:8443/mcp --tls-cert agent.pem --tls-key agent-key.pem \
//	      --server-ca ca.pem --credential credential.der --credential-id <id> \
//	      --call search --args '{"query":"invoices"}'
//
// It prints one JSON line: the tool it called and the tool's answer, which carries
// an "error" field when the relying service refused the call.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"iter"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/mcptoolset"
	"google.golang.org/genai"

	"trstctl.com/trstctl/test/interop/agentframeworks/present"
)

func main() {
	server := flag.String("server", "", "the tool server's MCP endpoint (https)")
	certFile := flag.String("tls-cert", "", "the agent identity certificate (PEM)")
	keyFile := flag.String("tls-key", "", "the agent identity key (PEM)")
	serverCA := flag.String("server-ca", "", "the CA that issued the tool server's certificate (PEM)")
	credentialFile := flag.String("credential", "", "the delegated credential (DER)")
	credentialID := flag.String("credential-id", "", "the delegated credential's ID")
	call := flag.String("call", "", "the tool the scripted model calls")
	rawArgs := flag.String("args", "{}", "the tool arguments (JSON object)")
	flag.Parse()

	var args map[string]any
	if err := json.Unmarshal([]byte(*rawArgs), &args); err != nil {
		fail(fmt.Errorf("--args: %w", err))
	}
	client, err := identityClient(*certFile, *keyFile, *serverCA, *credentialFile, *credentialID)
	if err != nil {
		fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	answer, err := run(ctx, *server, client, *call, args)
	if err != nil {
		fail(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"tool": *call, "answer": answer})
}

// run drives one agent turn and returns the tool's answer as the agent saw it.
func run(ctx context.Context, endpoint string, client *http.Client, call string, args map[string]any) (map[string]any, error) {
	tools, err := mcptoolset.New(mcptoolset.Config{
		Transport: &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client, DisableStandaloneSSE: true},
	})
	if err != nil {
		return nil, err
	}
	reference, err := llmagent.New(llmagent.Config{
		Name:        "reference_agent",
		Model:       &scriptedModel{call: call, args: args},
		Description: "Calls the tool server with a delegated credential.",
		Instruction: "Use the tool you are asked to use and report its answer.",
		Toolsets:    []tool.Toolset{tools},
	})
	if err != nil {
		return nil, err
	}
	sessions := session.InMemoryService()
	r, err := runner.New(runner.Config{AppName: "agentframeworks", Agent: reference, SessionService: sessions})
	if err != nil {
		return nil, err
	}
	created, err := sessions.Create(ctx, &session.CreateRequest{AppName: "agentframeworks", UserID: "operator"})
	if err != nil {
		return nil, err
	}
	var answer map[string]any
	for event, err := range r.Run(ctx, "operator", created.Session.ID(), genai.NewContentFromText("Run the scripted call.", genai.RoleUser), agent.RunConfig{}) {
		if err != nil {
			return nil, err
		}
		if event == nil || event.Content == nil {
			continue
		}
		for _, part := range event.Content.Parts {
			if part.FunctionResponse != nil && part.FunctionResponse.Name == call {
				answer = part.FunctionResponse.Response
			}
		}
	}
	if answer == nil {
		return nil, errors.New("the agent turn ended without the tool answering")
	}
	return answer, nil
}

// scriptedModel is an ADK model.LLM that calls one tool and then reports its
// answer, standing in for a model provider.
type scriptedModel struct {
	call string
	args map[string]any
}

func (m *scriptedModel) Name() string { return "scripted" }

func (m *scriptedModel) GenerateContent(_ context.Context, req *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		for _, content := range req.Contents {
			for _, part := range content.Parts {
				if part.FunctionResponse != nil && part.FunctionResponse.Name == m.call {
					report, _ := json.Marshal(part.FunctionResponse.Response)
					yield(&model.LLMResponse{Content: genai.NewContentFromText("The tool answered: "+string(report), genai.RoleModel), TurnComplete: true}, nil)
					return
				}
			}
		}
		yield(&model.LLMResponse{
			Content: &genai.Content{Role: genai.RoleModel, Parts: []*genai.Part{{
				FunctionCall: &genai.FunctionCall{Name: m.call, Args: m.args},
			}}},
			TurnComplete: true,
		}, nil)
	}
}

// identityClient authenticates with the agent's identity certificate and presents
// the delegated credential on every request.
func identityClient(certFile, keyFile, serverCA, credentialFile, credentialID string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("agent identity: %w", err)
	}
	caPEM, err := os.ReadFile(serverCA) // #nosec G304 -- operator-named CA file (CWE-22)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the server CA file holds no certificate")
	}
	credential, err := os.ReadFile(credentialFile) // #nosec G304 -- operator-named credential file (CWE-22)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: presentCredential{
			base: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
			}},
			credential: base64.StdEncoding.EncodeToString(credential),
			id:         credentialID,
		},
	}, nil
}

type presentCredential struct {
	base       http.RoundTripper
	credential string
	id         string
}

func (p presentCredential) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(present.CredentialHeader, p.credential)
	clone.Header.Set(present.CredentialIDHeader, p.id)
	return p.base.RoundTrip(clone)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent:", err)
	os.Exit(1)
}
