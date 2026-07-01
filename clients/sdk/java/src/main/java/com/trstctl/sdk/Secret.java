package com.trstctl.sdk;

import java.util.Map;

/** Secret-store response from /api/v1/secrets/store. */
public final class Secret {
  private final String name;
  private final String value;
  private final int version;

  public Secret(String name, String value, int version) {
    this.name = name == null ? "" : name;
    this.value = value == null ? "" : value;
    this.version = version;
  }

  public String name() {
    return name;
  }

  public String value() {
    return value;
  }

  public int version() {
    return version;
  }

  static Secret from(Object value) {
    Map<String, Object> map = Json.asObject(value);
    return new Secret(Json.string(map, "name"), Json.string(map, "value"), Json.integer(map, "version"));
  }
}
