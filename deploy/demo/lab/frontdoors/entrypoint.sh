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

for required in apache.crt apache.key nginx.crt nginx.key haproxy.pem caddy.crt caddy.key traefik.crt traefik.key postgresql.crt postgresql.key; do
  if [ ! -s "/lab/tls/$required" ]; then echo "missing prepared /lab/tls/$required" >&2; exit 1; fi
done

postgres_data=/lab/state/postgresql
mkdir -p "$postgres_data" /lab/run
# A container restart (docker stop/start, a host reboot, a compose restart) keeps
# the run and state volumes — /lab/run is an image volume that compose also keeps
# across an ordinary recreate — so the lock, socket and pid files of the previous
# life are still there. PostgreSQL refuses to start over a stale lock file, the
# readiness loop below then fails ten times, the entrypoint exits, and the
# container restarts forever — with the trstctl agent never launched, which
# reads as "the agent does not reconnect". Nothing else owns these files at this
# point: every service is started below, after this line.
rm -f /lab/run/.s.PGSQL.10448.lock /lab/run/.s.PGSQL.10448 "$postgres_data/postmaster.pid" /lab/run/httpd.pid /lab/run/haproxy.pid
if [ ! -s "$postgres_data/PG_VERSION" ]; then
  /usr/bin/initdb -D "$postgres_data" --username=postgres --auth-local=trust --auth-host=reject --no-locale --encoding=UTF8 >/dev/null
fi
cp /lab/postgresql.conf "$postgres_data/postgresql.conf"
chmod 0600 "$postgres_data/postgresql.conf"

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
/usr/libexec/postgresql16/postgres -D "$postgres_data" &
postgres_pid=$!

terminate() {
  kill "$apache_pid" "$nginx_pid" "$haproxy_pid" "$caddy_pid" "$traefik_pid" "$postgres_pid" "${agent_pid:-}" 2>/dev/null || true
}
trap terminate INT TERM EXIT

# Thirty seconds, not ten: on a loaded evaluation host PostgreSQL alone can
# take longer than ten seconds to accept connections after a restart, and an
# entrypoint that gives up sooner turns a slow start into a restart loop.
attempt=0
while :; do
  attempt=$((attempt + 1))
  if /usr/local/apache2/bin/apachectl configtest >/dev/null 2>&1 && \
     /usr/sbin/nginx -t >/dev/null 2>&1 && \
     /usr/sbin/haproxy -c -f /lab/haproxy.cfg >/dev/null 2>&1 && \
     /usr/sbin/caddy validate --config /lab/Caddyfile --adapter caddyfile >/dev/null 2>&1 && \
     kill -0 "$traefik_pid" 2>/dev/null && \
     /usr/bin/pg_isready -h /lab/run -p 10448 -U postgres >/dev/null 2>&1; then break; fi
  if [ "$attempt" -ge 30 ]; then echo "one or more real local TLS services failed initial validation after ${attempt}s" >&2; exit 1; fi
  sleep 1
done

/usr/local/bin/trstctl-agent "$@" &
agent_pid=$!
wait "$agent_pid"
