package com.trstctl.sdk;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** RFC 7807 problem+json response from the trstctl API. */
public final class ProblemException extends Exception {
  private final int httpStatus;
  private final String type;
  private final String title;
  private final Integer status;
  private final String detail;
  private final String instance;
  private final Long retryAfterSeconds;
  private final Map<String, Object> extensions;

  ProblemException(int httpStatus, Map<String, Object> body, Long retryAfterSeconds) {
    super(message(httpStatus, body));
    this.httpStatus = httpStatus;
    this.type = stringValue(body.get("type"));
    this.title = stringValue(body.get("title"));
    this.status = intValue(body.get("status"));
    this.detail = stringValue(body.get("detail"));
    this.instance = stringValue(body.get("instance"));
    this.retryAfterSeconds = retryAfterSeconds;
    Map<String, Object> ext = new LinkedHashMap<>(body);
    ext.remove("type");
    ext.remove("title");
    ext.remove("status");
    ext.remove("detail");
    ext.remove("instance");
    this.extensions = Collections.unmodifiableMap(ext);
  }

  public int httpStatus() {
    return httpStatus;
  }

  public String type() {
    return type;
  }

  public String title() {
    return title;
  }

  public Integer status() {
    return status;
  }

  public String detail() {
    return detail;
  }

  public String instance() {
    return instance;
  }

  public Long retryAfterSeconds() {
    return retryAfterSeconds;
  }

  public Map<String, Object> extensions() {
    return extensions;
  }

  public boolean isRateLimited() {
    return httpStatus == 429;
  }

  private static String message(int httpStatus, Map<String, Object> body) {
    String title = stringValue(body.get("title"));
    String detail = stringValue(body.get("detail"));
    if (title == null) {
      title = "";
    }
    if (detail != null && !detail.isEmpty()) {
      title = title.isEmpty() ? detail : title + ": " + detail;
    }
    return ("trstctl: " + httpStatus + " " + title).trim();
  }

  private static String stringValue(Object value) {
    return value instanceof String ? (String) value : null;
  }

  private static Integer intValue(Object value) {
    if (value instanceof Number) {
      return ((Number) value).intValue();
    }
    return null;
  }
}
