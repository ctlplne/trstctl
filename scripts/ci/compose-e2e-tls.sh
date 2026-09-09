#!/usr/bin/env bash
# Shared stock-curl policy for the Compose lifecycle gate and CI readiness.
# Source this file; the caller owns the certificate snapshot and temporary files.

compose_e2e_tls_init() {
  local base_url="$1" trust_file="$2"
  CURL_TLS=() CURL=() Q=()
  case "$base_url" in
    https://?*) ;;
    *) printf 'compose-e2e: BASE_URL must use https://\n' >&2; return 2 ;;
  esac
  if [[ ! -f "$trust_file" || ! -r "$trust_file" || ! -s "$trust_file" ]] \
    || [[ "$(wc -c < "$trust_file")" -gt 4194304 ]]; then
    printf 'compose-e2e: readable, nonempty public CA file required (maximum 4 MiB)\n' >&2
    return 2
  fi
  # Accept only certificate PEM blocks, never the private internal-server.pem.
  if ! awk '
    { sub(/\r$/, "") }
    /^[ \t]*$/ { next }
    /^-----BEGIN CERTIFICATE-----$/ { if (inside) exit 1; inside=1; count++; next }
    /^-----END CERTIFICATE-----$/ { if (!inside) exit 1; inside=0; next }
    { if (!inside || $0 !~ /^[A-Za-z0-9+\/=]+$/) exit 1 }
    END { if (inside || !count) exit 1 }
  ' "$trust_file" \
    || ! openssl crl2pkcs7 -nocrl -certfile "$trust_file" -out /dev/null; then
    printf 'compose-e2e: trust must contain only valid public certificates\n' >&2
    return 2
  fi
  # --disable must be first: a private .curlrc must not override verification.
  CURL_TLS=(curl --disable --proto '=https' --cacert "$trust_file" --connect-timeout 5 --max-time 30)
  CURL=("${CURL_TLS[@]}" -fsS)
  Q=("${CURL_TLS[@]}" -sS -o /dev/null -w '%{http_code}')
}

# BASE_URL, tmpdir and AUTH are the lifecycle caller's existing values. Keep
# curl's native result separate from HTTP status, including for a partial 2xx.
compose_e2e_post() {
  local key="$1" path="$2" body="$3" out code native
  out="$(mktemp "$tmpdir/post.XXXXXX")" || return 1
  if code=$("${CURL_TLS[@]}" -sS "${AUTH[@]}" -H "Idempotency-Key: $key" -H 'Content-Type: application/json' \
    -XPOST "$BASE_URL$path" -d "$body" -w '%{http_code}' -o "$out"); then
    case "$code" in
      2[0-9][0-9])
        if cat "$out"; then native=0; else native=$?; fi
        rm -f "$out"
        return "$native"
        ;;
      *) printf '::error::compose-e2e: POST %s returned HTTP %s\n' "$path" "$code" >&2 ;;
    esac
  else
    native=$?
    printf '::error::compose-e2e: POST %s failed in curl (exit %s, HTTP %s)\n' "$path" "$native" "$code" >&2
    rm -f "$out"
    return "$native"
  fi
  sed 's/^/response: /' "$out" >&2
  rm -f "$out"
  return 1
}

# An absolute Bash SECONDS deadline lets CI include public-file acquisition in
# the same readiness budget. Each stock-curl request uses only the time left.
compose_e2e_wait_ready() {
  local url="$1" deadline="$2" remaining connect total code native pause
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    (( remaining > 0 )) || break
    connect=5; (( remaining < connect )) && connect=$remaining
    total=30; (( remaining < total )) && total=$remaining
    if code=$("${Q[@]}" --connect-timeout "$connect" --max-time "$total" "$url"); then
      (( SECONDS < deadline )) || break
      [[ "$code" == 200 ]] && return 0
      printf 'compose-e2e: readiness returned HTTP %s\n' "$code" >&2
    else
      native=$?
      # Startup can refuse/reset a connection or time out. A certificate,
      # protocol, trust-file or other tool error must not become readiness.
      case "$native" in 7|28|52|56) ;; *) return "$native" ;; esac
    fi
    remaining=$((deadline - SECONDS))
    (( remaining > 0 )) || break
    pause=2; (( remaining < pause )) && pause=$remaining
    sleep "$pause"
  done
  printf 'compose-e2e: readiness deadline expired\n' >&2
  return 1
}
