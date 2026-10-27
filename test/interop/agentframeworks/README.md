# Agent framework reference integrations

Two reference integrations that use trstctl agent identities and agent
delegation end to end, built on open-source agent frameworks without modifying
them:

| Piece | Built with | Version | License |
| --- | --- | --- | --- |
| `cmd/toolserver` — an MCP tool server that is the relying service | [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) | v1.8.0 | Apache-2.0 (earlier contributions MIT) |
| `cmd/agent` — an agent that calls the tool server | [Agent Development Kit for Go](https://github.com/google/adk-go) | v1.9.0 | Apache-2.0 |

`go.mod` pins both versions. This directory is its own Go module, so the
frameworks never enter the trstctl binaries' dependency graph.

## How a call is honored

1. The agent connects with mutual TLS using its trstctl agent identity, an
   X.509-SVID the agent identity broker issued for a key the agent holds.
2. On every request it presents its chain-bound delegated credential in two
   headers (`X-Trstctl-Agent-Credential`, base64 DER, and
   `X-Trstctl-Agent-Credential-Id`); see `present/`.
3. The tool server (`relying/`) honors a tool call only when:
   - the credential verifies offline against the tenant's issuing CA it pinned,
     and its bound agent stack, tool manifest and authority allow this tool's
     operation (trstctl's relying-party verifier);
   - the credential's delegation chain, read once from trstctl, starts at a
     pinned root principal, is signed hop by hop, ends at the chain head the
     credential binds, and was delegated to the agent on this connection;
   - trstctl reports the credential `active`, for the exact credential bytes
     presented. A status read is reused for at most `status_ttl_seconds`.
4. Every decision is one JSON line in the audit log, with the delegation path
   from the root principal to the agent.

A revoked delegation stops being honored within `status_ttl_seconds` after the
revocation's cascade reaches the credential in trstctl. If trstctl cannot be
read, the call is refused.

The agent uses a scripted model in place of an LLM: it calls the one tool it is
told to and reports the answer, so no model provider account is needed. A real
deployment swaps in any ADK model; nothing else changes.

## MCP authorization mode

With `"authorization": "oauth"` the tool server is instead an OAuth resource
server under MCP authorization: it publishes protected resource metadata and
accepts only tokens your authorization server issued for it (issuer, audience,
scope, allowed client). The agent, run with `--oauth-client-id`, follows the
metadata to that server and authenticates there with a `private_key_jwt`
assertion signed by its trstctl identity key, which the authorization server
checks against trstctl's agent key set; `--oauth-exchange` adds the server's
token exchange (`oauthclient/`). See
[MCP authorization with a trstctl agent identity](../../../docs/guides/mcp-authorization.md).

## Run it

```sh
toolserver pin   --config server.json   # pins the tenant's issuing CA and root anchors
toolserver serve --config server.json
agent --server https://127.0.0.1:8443/mcp --tls-cert agent.pem --tls-key agent-key.pem \
      --server-ca ca.pem --credential credential.der --credential-id '<credential_id>' \
      --call search --args '{"query":"open invoices"}'
```

`pin` prints the issuing CA's `spki_sha256`; compare it with
`GET /api/v1/agent-delegation/issuing-ca` before serving. The tool server's
trstctl token needs only `agents:read`.

The lab test `TestAGID_ReferenceFrameworks_MCPToolServerAndADKAgent_RealInfra`
(`internal/agentid/intwire`, build tag `integration`) builds both binaries and
runs them against the real signer process and the served agent-delegation API.
The full contract is in
[Agent delegation](../../../docs/features/agent-delegation.md#relying-services).
