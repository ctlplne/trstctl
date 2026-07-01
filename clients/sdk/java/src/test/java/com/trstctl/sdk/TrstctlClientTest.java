package com.trstctl.sdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class TrstctlClientTest {
  public static void main(String[] args) throws Exception {
    testGeneratedSchemaMetadataIsCommitted();
    testIssueAndSecretRoundTripSendsAuthTenantAndIdempotency();
    testProblemErrorParsesRetryAfterAndRetries();
    testRetryPreservesGeneratedMutationIdempotency();
  }

  private static void testGeneratedSchemaMetadataIsCommitted() {
    check(!OpenApiSchemas.NAMES.isEmpty(), "OpenApiSchemas names are generated");
    check(OpenApiSchemas.NAMES.contains("Problem"), "OpenApiSchemas includes the Problem schema");
  }

  private static void testIssueAndSecretRoundTripSendsAuthTenantAndIdempotency() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext("/", exchange -> {
      try {
        routeRoundTrip(exchange);
      } catch (Throwable t) {
        byte[] body = ("{\"title\":\"test failed\",\"detail\":\"" + escape(t.toString()) + "\"}").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
        exchange.sendResponseHeaders(500, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(body);
        }
      }
    });
    server.start();
    try {
      String base = "http://127.0.0.1:" + server.getAddress().getPort();
      try {
        TrstctlClient.builder().baseUrl(base).tenant("tenant-a").maxAttempts(1).build().listSecrets();
        throw new AssertionError("unauthenticated listSecrets unexpectedly succeeded");
      } catch (ProblemException exc) {
        check(exc.httpStatus() == 401, "want 401 problem");
      }

      TrstctlClient client = TrstctlClient.builder()
          .baseUrl(base)
          .token("fixture-token")
          .tenant("tenant-a")
          .maxAttempts(1)
          .build();
      PkiSecret issued = client.issuePkiSecret("java-sdk.unit.test", 300, "issue-1");
      check("SERIAL-1".equals(issued.serial()), "serial parsed");
      check(issued.certificate().contains("BEGIN CERTIFICATE"), "certificate parsed");
      check(issued.privateKey().contains("BEGIN PRIVATE KEY"), "private key parsed");

      Secret created = client.createSecret("sdk/java/password", "initial-fixture-value", "create-1");
      check(created.version() == 1, "created version");
      Secret read = client.getSecret("sdk/java/password");
      check("initial-fixture-value".equals(read.value()), "read secret value");
      Secret rotated = client.rotateSecret("sdk/java/password", "rotated-fixture-value", "rotate-1");
      check(rotated.version() == 2, "rotated version");
      client.deleteSecret("sdk/java/password", "delete-1");
    } finally {
      server.stop(0);
    }
  }

  private static void testProblemErrorParsesRetryAfterAndRetries() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/retry", exchange -> {
      int n = calls.incrementAndGet();
      if (n == 1) {
        exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
        exchange.getResponseHeaders().set("Retry-After", "0");
        write(exchange, 429, "{\"title\":\"rate limited\",\"detail\":\"slow down\"}");
        return;
      }
      write(exchange, 200, "{\"ok\":true}");
    });
    server.start();
    try {
      String base = "http://127.0.0.1:" + server.getAddress().getPort();
      TrstctlClient client = TrstctlClient.builder().baseUrl(base).maxAttempts(2).build();
      Object got = client.request("GET", "/retry", null, Map.of(), null);
      check(Json.asObject(got).containsKey("ok"), "retry response parsed");
      check(calls.get() == 2, "retry attempted exactly once");
    } finally {
      server.stop(0);
    }
  }

  private static void testRetryPreservesGeneratedMutationIdempotency() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    AtomicReference<String> firstIdempotencyKey = new AtomicReference<>();
    AtomicReference<String> secondIdempotencyKey = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/api/v1/secrets/store", exchange -> {
      int n = calls.incrementAndGet();
      String key = exchange.getRequestHeaders().getFirst("Idempotency-Key");
      if (n == 1) {
        firstIdempotencyKey.set(key);
        exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
        exchange.getResponseHeaders().set("Retry-After", "0");
        write(exchange, 503, "{\"title\":\"temporarily unavailable\"}");
        return;
      }
      secondIdempotencyKey.set(key);
      write(exchange, 201, "{\"name\":\"sdk/java/retry\",\"version\":1}");
    });
    server.start();
    try {
      String base = "http://127.0.0.1:" + server.getAddress().getPort();
      TrstctlClient client = TrstctlClient.builder().baseUrl(base).token("fixture-token").maxAttempts(2).build();
      Secret created = client.createSecret("sdk/java/retry", "value", null);
      check(created.version() == 1, "retry mutation response parsed");
      check(calls.get() == 2, "mutation retried exactly once");
      check(firstIdempotencyKey.get() != null && !firstIdempotencyKey.get().isBlank(), "generated Idempotency-Key on first attempt");
      check(firstIdempotencyKey.get().equals(secondIdempotencyKey.get()), "retry reused the generated Idempotency-Key");
    } finally {
      server.stop(0);
    }
  }

  private static void routeRoundTrip(HttpExchange exchange) throws Exception {
    String method = exchange.getRequestMethod();
    String path = exchange.getRequestURI().getPath();
    if ("GET".equals(method) && "/api/v1/secrets/store".equals(path)) {
      if (exchange.getRequestHeaders().getFirst("Authorization") == null) {
        exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
        write(exchange, 401, "{\"title\":\"unauthorized\",\"status\":401}");
        return;
      }
      write(exchange, 200, "{\"items\":[]}");
      return;
    }
    requireHeader(exchange, "Authorization", "Bearer fixture-token");
    requireHeader(exchange, "X-Tenant-ID", "tenant-a");
    if ("POST".equals(method) && "/api/v1/secrets/pki".equals(path)) {
      requireHeader(exchange, "Idempotency-Key", "issue-1");
      write(exchange, 201, "{\"serial\":\"SERIAL-1\",\"certificate\":\"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\"}");
      return;
    }
    if ("POST".equals(method) && "/api/v1/secrets/store".equals(path)) {
      requireHeader(exchange, "Idempotency-Key", "create-1");
      write(exchange, 201, "{\"name\":\"sdk/java/password\",\"value\":\"initial-fixture-value\",\"version\":1}");
      return;
    }
    if ("GET".equals(method) && "/api/v1/secrets/store/sdk/java/password".equals(path)) {
      write(exchange, 200, "{\"name\":\"sdk/java/password\",\"value\":\"initial-fixture-value\",\"version\":1}");
      return;
    }
    if ("PUT".equals(method) && "/api/v1/secrets/store/sdk/java/password".equals(path)) {
      requireHeader(exchange, "Idempotency-Key", "rotate-1");
      write(exchange, 200, "{\"name\":\"sdk/java/password\",\"value\":\"rotated-fixture-value\",\"version\":2}");
      return;
    }
    if ("DELETE".equals(method) && "/api/v1/secrets/store/sdk/java/password".equals(path)) {
      requireHeader(exchange, "Idempotency-Key", "delete-1");
      exchange.sendResponseHeaders(204, -1);
      exchange.close();
      return;
    }
    write(exchange, 404, "{\"title\":\"not found\"}");
  }

  private static void requireHeader(HttpExchange exchange, String name, String want) {
    String got = exchange.getRequestHeaders().getFirst(name);
    check(want.equals(got), name + " = " + got + ", want " + want);
  }

  private static void write(HttpExchange exchange, int status, String json) throws IOException {
    byte[] body = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", status >= 400 ? "application/problem+json" : "application/json");
    exchange.sendResponseHeaders(status, body.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(body);
    }
  }

  private static void check(boolean ok, String message) {
    if (!ok) {
      throw new AssertionError(message);
    }
  }

  private static String escape(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
