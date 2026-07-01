package com.trstctl.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.UUID;

/** Dependency-free Java client for the trstctl served OpenAPI contract. */
public final class TrstctlClient {
  public static final String DEFAULT_USER_AGENT = "trstctl-java-sdk/1";

  private final String baseUrl;
  private final String token;
  private final String tenant;
  private final Duration timeout;
  private final RetryPolicy retry;
  private final String userAgent;
  private final HttpClient httpClient;

  private TrstctlClient(Builder b) {
    if (b.baseUrl == null || b.baseUrl.isBlank()) {
      throw new IllegalArgumentException("trstctl: baseUrl is required");
    }
    this.baseUrl = stripTrailingSlash(b.baseUrl);
    this.token = b.token;
    this.tenant = b.tenant;
    this.timeout = b.timeout == null ? Duration.ofSeconds(30) : b.timeout;
    this.retry = b.retry == null ? RetryPolicy.DEFAULT : b.retry;
    this.userAgent = b.userAgent == null || b.userAgent.isBlank() ? DEFAULT_USER_AGENT : b.userAgent;
    this.httpClient = b.httpClient == null ? HttpClient.newBuilder().connectTimeout(this.timeout).build() : b.httpClient;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static TrstctlClient fromEnv() {
    String server = firstNonBlank(System.getenv("TRSTCTL_SERVER"), System.getenv("TRSTCTL_ENDPOINT"));
    if (server == null) {
      throw new IllegalArgumentException("TRSTCTL_SERVER is required");
    }
    return builder()
        .baseUrl(server)
        .token(System.getenv("TRSTCTL_TOKEN"))
        .tenant(System.getenv("TRSTCTL_TENANT"))
        .build();
  }

  public TrstctlClient withMaxAttempts(int attempts) {
    return builder()
        .baseUrl(baseUrl)
        .token(token)
        .tenant(tenant)
        .timeout(timeout)
        .retry(new RetryPolicy(attempts, retry.baseDelay(), retry.maxDelay()))
        .userAgent(userAgent)
        .httpClient(httpClient)
        .build();
  }

  public Object request(String method, String path, Object body, Map<String, ?> query, String idempotencyKey)
      throws IOException, InterruptedException, ProblemException {
    String upper = method.toUpperCase();
    String json = body == null ? null : Json.stringify(body);
    String stableIdempotencyKey = isMutating(upper) ? firstNonBlank(idempotencyKey, UUID.randomUUID().toString()) : null;
    Exception last = null;
    for (int attempt = 1; attempt <= retry.maxAttempts(); attempt++) {
      HttpRequest.Builder req = HttpRequest.newBuilder(uri(path, query))
          .timeout(timeout)
          .header("Accept", "application/json, application/problem+json")
          .header("User-Agent", userAgent);
      if (token != null && !token.isBlank()) {
        req.header("Authorization", "Bearer " + token);
      }
      if (tenant != null && !tenant.isBlank()) {
        req.header("X-Tenant-ID", tenant);
      }
      if (stableIdempotencyKey != null) {
        req.header("Idempotency-Key", stableIdempotencyKey);
      }
      if (json == null) {
        req.method(upper, HttpRequest.BodyPublishers.noBody());
      } else {
        req.header("Content-Type", "application/json");
        req.method(upper, HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
      }

      try {
        HttpResponse<String> res = httpClient.send(req.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (res.statusCode() >= 200 && res.statusCode() < 300) {
          return decodeSuccess(res.statusCode(), res.body());
        }
        ProblemException problem = problem(res);
        last = problem;
        if (isRetryable(res.statusCode()) && attempt < retry.maxAttempts()) {
          Thread.sleep(retry.delayFor(attempt, problem.retryAfterSeconds()).toMillis());
          continue;
        }
        throw problem;
      } catch (IOException exc) {
        last = exc;
        if (attempt < retry.maxAttempts()) {
          Thread.sleep(retry.delayFor(attempt, null).toMillis());
          continue;
        }
        throw exc;
      }
    }
    if (last instanceof IOException) {
      throw (IOException) last;
    }
    if (last instanceof InterruptedException) {
      throw (InterruptedException) last;
    }
    if (last instanceof ProblemException) {
      throw (ProblemException) last;
    }
    throw new IOException("trstctl request failed");
  }

  public List<Object> listSecrets() throws IOException, InterruptedException, ProblemException {
    Object value = request("GET", "/api/v1/secrets/store", null, Map.of(), null);
    if (value instanceof List) {
      return new ArrayList<>((List<?>) value);
    }
    if (value instanceof Map) {
      Object items = Json.asObject(value).get("items");
      if (items instanceof List) {
        return new ArrayList<>((List<?>) items);
      }
    }
    return List.of();
  }

  public PkiSecret issuePkiSecret(String commonName, int ttlSeconds, String idempotencyKey)
      throws IOException, InterruptedException, ProblemException {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("common_name", commonName);
    body.put("ttl_seconds", ttlSeconds);
    return PkiSecret.from(request("POST", "/api/v1/secrets/pki", body, Map.of(), idempotencyKey));
  }

  public Secret createSecret(String name, String value, String idempotencyKey)
      throws IOException, InterruptedException, ProblemException {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("name", name);
    body.put("value", value);
    return Secret.from(request("POST", "/api/v1/secrets/store", body, Map.of(), idempotencyKey));
  }

  public Secret getSecret(String name) throws IOException, InterruptedException, ProblemException {
    return Secret.from(request("GET", "/api/v1/secrets/store/" + secretPath(name), null, Map.of(), null));
  }

  public Secret rotateSecret(String name, String value, String idempotencyKey)
      throws IOException, InterruptedException, ProblemException {
    return Secret.from(request("PUT", "/api/v1/secrets/store/" + secretPath(name), Map.of("value", value), Map.of(), idempotencyKey));
  }

  public void deleteSecret(String name, String idempotencyKey) throws IOException, InterruptedException, ProblemException {
    request("DELETE", "/api/v1/secrets/store/" + secretPath(name), null, Map.of(), idempotencyKey);
  }

  private URI uri(String path, Map<String, ?> query) {
    StringBuilder out = new StringBuilder(baseUrl).append(path);
    if (query != null && !query.isEmpty()) {
      StringJoiner joiner = new StringJoiner("&");
      for (Map.Entry<String, ?> e : query.entrySet()) {
        if (e.getValue() == null || String.valueOf(e.getValue()).isBlank()) {
          continue;
        }
        joiner.add(encode(e.getKey()) + "=" + encode(String.valueOf(e.getValue())));
      }
      String q = joiner.toString();
      if (!q.isEmpty()) {
        out.append('?').append(q);
      }
    }
    return URI.create(out.toString());
  }

  private static Object decodeSuccess(int status, String body) {
    if (status == 204 || body == null || body.isBlank()) {
      return null;
    }
    return Json.parse(body);
  }

  private static ProblemException problem(HttpResponse<String> res) {
    Object parsed;
    try {
      parsed = res.body() == null || res.body().isBlank() ? Map.of() : Json.parse(res.body());
    } catch (IllegalArgumentException exc) {
      parsed = Map.of("detail", res.body() == null ? "" : res.body());
    }
    Map<String, Object> body = parsed instanceof Map ? Json.asObject(parsed) : Map.of("detail", String.valueOf(parsed));
    return new ProblemException(res.statusCode(), body, retryAfterSeconds(res.headers().firstValue("Retry-After")));
  }

  private static Long retryAfterSeconds(Optional<String> value) {
    if (value.isEmpty() || value.get().isBlank()) {
      return null;
    }
    String raw = value.get().trim();
    try {
      return Math.max(0, Long.parseLong(raw));
    } catch (NumberFormatException ignored) {
      // Fall through to HTTP-date parsing.
    }
    try {
      long seconds = ZonedDateTime.parse(raw, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME).toEpochSecond()
          - java.time.Instant.now().getEpochSecond();
      return Math.max(0, seconds);
    } catch (DateTimeParseException ignored) {
      return null;
    }
  }

  private static boolean isMutating(String method) {
    return method.equals("POST") || method.equals("PUT") || method.equals("PATCH") || method.equals("DELETE");
  }

  private static boolean isRetryable(int status) {
    return status == 429 || status == 502 || status == 503 || status == 504;
  }

  private static String secretPath(String name) {
    StringJoiner joiner = new StringJoiner("/");
    for (String part : name.split("/", -1)) {
      joiner.add(encode(part));
    }
    return joiner.toString();
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String stripTrailingSlash(String value) {
    String out = value;
    while (out.endsWith("/")) {
      out = out.substring(0, out.length() - 1);
    }
    return out;
  }

  private static String firstNonBlank(String... values) {
    for (String value : values) {
      if (value != null && !value.isBlank()) {
        return value;
      }
    }
    return null;
  }

  public static final class Builder {
    private String baseUrl;
    private String token;
    private String tenant;
    private Duration timeout;
    private RetryPolicy retry;
    private String userAgent;
    private HttpClient httpClient;

    public Builder baseUrl(String value) {
      this.baseUrl = value;
      return this;
    }

    public Builder token(String value) {
      this.token = value;
      return this;
    }

    public Builder tenant(String value) {
      this.tenant = value;
      return this;
    }

    public Builder timeout(Duration value) {
      this.timeout = value;
      return this;
    }

    public Builder retry(RetryPolicy value) {
      this.retry = value;
      return this;
    }

    public Builder maxAttempts(int value) {
      this.retry = new RetryPolicy(value, RetryPolicy.DEFAULT.baseDelay(), RetryPolicy.DEFAULT.maxDelay());
      return this;
    }

    public Builder userAgent(String value) {
      this.userAgent = value;
      return this;
    }

    public Builder httpClient(HttpClient value) {
      this.httpClient = value;
      return this;
    }

    public TrstctlClient build() {
      return new TrstctlClient(this);
    }
  }
}
