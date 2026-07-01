package com.trstctl.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

final class Json {
  private Json() {}

  static Object parse(String input) {
    Parser p = new Parser(input);
    Object value = p.value();
    p.skipWhitespace();
    if (!p.done()) {
      throw new IllegalArgumentException("trailing JSON data");
    }
    return value;
  }

  static String stringify(Object value) {
    if (value == null) {
      return "null";
    }
    if (value instanceof String) {
      return quote((String) value);
    }
    if (value instanceof Number || value instanceof Boolean) {
      return String.valueOf(value);
    }
    if (value instanceof Map<?, ?>) {
      StringJoiner joiner = new StringJoiner(",", "{", "}");
      for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
        joiner.add(quote(String.valueOf(e.getKey())) + ":" + stringify(e.getValue()));
      }
      return joiner.toString();
    }
    if (value instanceof Iterable<?>) {
      StringJoiner joiner = new StringJoiner(",", "[", "]");
      for (Object item : (Iterable<?>) value) {
        joiner.add(stringify(item));
      }
      return joiner.toString();
    }
    return quote(String.valueOf(value));
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> asObject(Object value) {
    if (!(value instanceof Map)) {
      throw new IllegalArgumentException("expected JSON object");
    }
    return (Map<String, Object>) value;
  }

  static String string(Map<String, Object> map, String key) {
    Object value = map.get(key);
    return value instanceof String ? (String) value : "";
  }

  static int integer(Map<String, Object> map, String key) {
    Object value = map.get(key);
    return value instanceof Number ? ((Number) value).intValue() : 0;
  }

  private static String quote(String value) {
    StringBuilder out = new StringBuilder(value.length() + 2);
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"':
          out.append("\\\"");
          break;
        case '\\':
          out.append("\\\\");
          break;
        case '\b':
          out.append("\\b");
          break;
        case '\f':
          out.append("\\f");
          break;
        case '\n':
          out.append("\\n");
          break;
        case '\r':
          out.append("\\r");
          break;
        case '\t':
          out.append("\\t");
          break;
        default:
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
      }
    }
    out.append('"');
    return out.toString();
  }

  private static final class Parser {
    private final String input;
    private int i;

    Parser(String input) {
      this.input = input == null ? "" : input;
    }

    boolean done() {
      return i >= input.length();
    }

    void skipWhitespace() {
      while (!done() && Character.isWhitespace(input.charAt(i))) {
        i++;
      }
    }

    Object value() {
      skipWhitespace();
      if (done()) {
        throw new IllegalArgumentException("empty JSON");
      }
      char c = input.charAt(i);
      if (c == '{') {
        return object();
      }
      if (c == '[') {
        return array();
      }
      if (c == '"') {
        return string();
      }
      if (c == 't' || c == 'f') {
        return bool();
      }
      if (c == 'n') {
        literal("null");
        return null;
      }
      return number();
    }

    Map<String, Object> object() {
      expect('{');
      Map<String, Object> out = new LinkedHashMap<>();
      skipWhitespace();
      if (peek('}')) {
        i++;
        return out;
      }
      while (true) {
        String key = string();
        skipWhitespace();
        expect(':');
        out.put(key, value());
        skipWhitespace();
        if (peek('}')) {
          i++;
          return out;
        }
        expect(',');
      }
    }

    List<Object> array() {
      expect('[');
      List<Object> out = new ArrayList<>();
      skipWhitespace();
      if (peek(']')) {
        i++;
        return out;
      }
      while (true) {
        out.add(value());
        skipWhitespace();
        if (peek(']')) {
          i++;
          return out;
        }
        expect(',');
      }
    }

    String string() {
      expect('"');
      StringBuilder out = new StringBuilder();
      while (!done()) {
        char c = input.charAt(i++);
        if (c == '"') {
          return out.toString();
        }
        if (c != '\\') {
          out.append(c);
          continue;
        }
        if (done()) {
          throw new IllegalArgumentException("bad JSON escape");
        }
        char esc = input.charAt(i++);
        switch (esc) {
          case '"':
          case '\\':
          case '/':
            out.append(esc);
            break;
          case 'b':
            out.append('\b');
            break;
          case 'f':
            out.append('\f');
            break;
          case 'n':
            out.append('\n');
            break;
          case 'r':
            out.append('\r');
            break;
          case 't':
            out.append('\t');
            break;
          case 'u':
            if (i + 4 > input.length()) {
              throw new IllegalArgumentException("bad unicode escape");
            }
            out.append((char) Integer.parseInt(input.substring(i, i + 4), 16));
            i += 4;
            break;
          default:
            throw new IllegalArgumentException("bad JSON escape");
        }
      }
      throw new IllegalArgumentException("unterminated JSON string");
    }

    Boolean bool() {
      if (input.startsWith("true", i)) {
        i += 4;
        return Boolean.TRUE;
      }
      if (input.startsWith("false", i)) {
        i += 5;
        return Boolean.FALSE;
      }
      throw new IllegalArgumentException("bad JSON boolean");
    }

    Number number() {
      int start = i;
      if (peek('-')) {
        i++;
      }
      while (!done() && Character.isDigit(input.charAt(i))) {
        i++;
      }
      if (!done() && input.charAt(i) == '.') {
        i++;
        while (!done() && Character.isDigit(input.charAt(i))) {
          i++;
        }
      }
      if (!done() && (input.charAt(i) == 'e' || input.charAt(i) == 'E')) {
        i++;
        if (!done() && (input.charAt(i) == '+' || input.charAt(i) == '-')) {
          i++;
        }
        while (!done() && Character.isDigit(input.charAt(i))) {
          i++;
        }
      }
      String raw = input.substring(start, i);
      if (raw.contains(".") || raw.contains("e") || raw.contains("E")) {
        return Double.parseDouble(raw);
      }
      return Long.parseLong(raw);
    }

    void literal(String want) {
      if (!input.startsWith(want, i)) {
        throw new IllegalArgumentException("bad JSON literal");
      }
      i += want.length();
    }

    void expect(char want) {
      skipWhitespace();
      if (done() || input.charAt(i) != want) {
        throw new IllegalArgumentException("expected '" + want + "'");
      }
      i++;
    }

    boolean peek(char want) {
      return !done() && input.charAt(i) == want;
    }
  }
}
