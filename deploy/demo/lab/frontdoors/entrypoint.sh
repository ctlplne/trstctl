#!/bin/sh
set -eu

export XDG_CONFIG_HOME=/lab/state/caddy-config
export XDG_DATA_HOME=/lab/state/caddy-data
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"

# Traefik watches this operator-owned dynamic document. Keep the immutable image
# copy as a template, but place the live file inside the same narrowly allowed
# credential volume so the connector can atomically replace it to trigger the
# file provider after referenced certificate bytes change.
if [ ! -s /lab/tls/traefik-dynamic.yml ]; then
  cp /lab/traefik-dynamic.template.yml /lab/tls/traefik-dynamic.yml
fi

for required in apache.crt apache.key nginx.crt nginx.key haproxy.pem caddy.crt caddy.key traefik.crt traefik.key; do
  if [ ! -s "/lab/tls/$required" ]; then echo "missing prepared /lab/tls/$required" >&2; exit 1; fi
done

/usr/local/apache2/bin/httpd -DFOREGROUND &
apache_pid=$!
/usr/sbin/nginx -g 'daemon off;' &
nginx_pid=$!
/usr/sbin/haproxy -W -db -f /lab/haproxy.cfg -p /lab/run/haproxy.pid &
haproxy_pid=$!
/usr/sbin/caddy run --config /lab/Caddyfile --adapter caddyfile &
caddy_pid=$!
/usr/sbin/traefik --configFile=/lab/traefik-static.yml &
traefik_pid=$!

terminate() {
  kill "$apache_pid" "$nginx_pid" "$haproxy_pid" "$caddy_pid" "$traefik_pid" "${agent_pid:-}" 2>/dev/null || true
}
trap terminate INT TERM EXIT

for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if /usr/local/apache2/bin/apachectl configtest >/dev/null 2>&1 && \
     /usr/sbin/nginx -t >/dev/null 2>&1 && \
     /usr/sbin/haproxy -c -f /lab/haproxy.cfg >/dev/null 2>&1 && \
     /usr/sbin/caddy validate --config /lab/Caddyfile --adapter caddyfile >/dev/null 2>&1 && \
     kill -0 "$traefik_pid" 2>/dev/null; then break; fi
  if [ "$attempt" -eq 10 ]; then echo "one or more real front doors failed initial validation" >&2; exit 1; fi
  sleep 1
done

/usr/local/bin/trstctl-agent "$@" &
agent_pid=$!
wait "$agent_pid"
