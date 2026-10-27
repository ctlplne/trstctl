# MCP authorization with a trstctl agent identity

An MCP server that follows the MCP authorization specification (revision
2026-07-28) is an OAuth resource server: it accepts access tokens issued by your
authorization server for that MCP server only. This page shows how an agent that
holds a trstctl agent identity gets such a token. trstctl does not become the
authorization server. It issues the agent's identity and publishes the agent's
current public keys; your authorization server checks the agent against them.

## How it fits together

1. The agent holds a short-lived X.509 identity from the agent identity broker
   (`POST /api/v1/broker/agent-identities`, see
   [Workload identity](../features/workload-identity.md)). The agent generated the
   key; trstctl never sees it.
2. trstctl publishes the public keys of the agent's valid broker certificates at a
   public key set:

   ```http
   GET /agent-keys/<tenant_id>/<agent_id>/jwks.json
   ```

   Each key's `kid` is the hex SHA-256 of its SubjectPublicKeyInfo. An unknown
   tenant or agent, and an agent with no valid certificate, get the same empty set.
   Revoking the certificate (`POST /api/v1/certificates/bulk-revoke`) removes its
   key at once.
3. Your authorization server registers the agent as a confidential client that
   authenticates with `private_key_jwt` (RFC 7523) and reads its keys from that
   URL.
4. The agent calls the MCP server, gets `401` with
   `WWW-Authenticate: Bearer resource_metadata="…"`, reads the protected resource
   metadata (RFC 9728) to find your authorization server, discovers its token
   endpoint (RFC 8414 or OpenID discovery), and takes a client credentials grant
   authenticated with a client assertion signed by its identity key: `iss` and
   `sub` are its client ID, `aud` is the authorization server's issuer, `kid` names
   its key, and the assertion lives one minute. It sends the MCP server's
   canonical URI as `resource` (RFC 8707).
5. Where your authorization server offers token exchange (RFC 8693), the agent can
   exchange that token for one narrowed to the MCP server's scope before calling.
6. The MCP server checks the token's signature against your authorization
   server's keys, its issuer, expiry, audience (its own canonical URI) and scope.

## Keycloak

These settings were proven with Keycloak 26.8 as the authorization server.

- **The agent's client.** Client authenticator `Signed JWT` (`client-jwt`), with
  `Use JWKS URL` on and the JWKS URL set to the agent's trstctl key set; signature
  algorithm `ES256` for a P-256 identity. Turn on `Service accounts roles` for the
  client credentials grant and `Standard token exchange` to let the agent
  exchange its own tokens.
- **The MCP server's audience.** Keycloak honors the `resource` parameter only with
  the experimental `resource-indicators` feature. Without it, give the MCP server a
  client scope (for example `mcp:tools`, type Optional) with an `Audience` mapper
  whose `Included Custom Audience` is the MCP server's canonical URI, and add that
  scope to the agent's client as an optional scope. A token requested or
  exchanged with that scope then carries the MCP server as its audience.
- **How fast a revoked identity stops getting tokens.** Keycloak keeps a client's
  keys in its `keys` cache and, for a key ID it already holds, does not ask the key
  set again. By default an entry lives while it is in use, so a key trstctl no
  longer lists could keep authenticating the agent. Give the `keys` cache a
  lifespan with a cache configuration file (`--cache-config-file`):

  ```xml
  <infinispan xmlns="urn:infinispan:config:16.0">
      <cache-container name="keycloak">
          <local-cache name="keys" simple-cache="true">
              <expiration max-idle="-1" lifespan="60000"/>
              <memory max-count="1000"/>
          </local-cache>
      </cache-container>
  </infinispan>
  ```

  The lifespan is then the longest a revoked trstctl identity can still obtain a
  token. `public-key-storage` `max-cache-time` does not shorten it for keys looked
  up by key ID.

Tokens already issued stay valid until they expire, so keep the access token
lifespan short as well.

## The reference integration

`test/interop/agentframeworks` holds a reference MCP tool server (MCP Go SDK) and
an agent built with the Agent Development Kit for Go. Run the tool server with
`"authorization": "oauth"` to make it a resource server:

```json
{
  "listen": "0.0.0.0:8443",
  "tls_cert_file": "tool.pem",
  "tls_key_file": "tool-key.pem",
  "audit_file": "audit.jsonl",
  "authorization": "oauth",
  "oauth": {
    "resource": "https://tools.example.com:8443/mcp",
    "issuer": "https://keycloak.example.com/realms/agents",
    "jwks_url": "https://keycloak.example.com/realms/agents/protocol/openid-connect/certs",
    "scopes": ["mcp:tools"],
    "allowed_clients": ["agent-7"]
  }
}
```

and the agent with `--oauth-client-id agent-7 --oauth-exchange`, its identity key
as `--tls-key`. The agent prints the authorization steps it took. The lab test
`TestServedMCPAuthorizationWithKeycloak` (`internal/server`) runs the whole flow
against a Keycloak container and a revocation; it runs when Docker and the pinned
Keycloak image are present, and `TRSTCTL_REQUIRE_KEYCLOAK=1` makes their absence a
failure.
