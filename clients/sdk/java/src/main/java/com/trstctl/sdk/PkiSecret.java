package com.trstctl.sdk;

import java.util.Map;

/** Dynamic PKI issuance response from /api/v1/secrets/pki. */
public final class PkiSecret {
  private final String serial;
  private final String certificate;
  private final String privateKey;

  public PkiSecret(String serial, String certificate, String privateKey) {
    this.serial = serial == null ? "" : serial;
    this.certificate = certificate == null ? "" : certificate;
    this.privateKey = privateKey == null ? "" : privateKey;
  }

  public String serial() {
    return serial;
  }

  public String certificate() {
    return certificate;
  }

  public String privateKey() {
    return privateKey;
  }

  static PkiSecret from(Object value) {
    Map<String, Object> map = Json.asObject(value);
    return new PkiSecret(Json.string(map, "serial"), Json.string(map, "certificate"), Json.string(map, "private_key"));
  }
}
