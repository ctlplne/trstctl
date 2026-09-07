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
# The customer listener (provider journey) starts with its own self-signed
# baseline so NGINX can serve it before any customer agent exists.
mkdir -p /lab/tls/customer-edge
if [ ! -s /lab/tls/customer-edge/edge.crt ] || [ ! -s /lab/tls/customer-edge/edge.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=customer-edge.acme-robotics.example.com" \
    -addext "subjectAltName=DNS:customer-edge.acme-robotics.example.com" \
    -keyout /lab/tls/customer-edge/edge.key -out /lab/tls/customer-edge/edge.crt >/dev/null 2>&1
fi
chmod 0600 /lab/tls/customer-edge/edge.key

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
  kill "$apache_pid" "$nginx_pid" "$haproxy_pid" "$caddy_pid" "$traefik_pid" "$postgres_pid" "${agent_pid:-}" "${customer_watch_pid:-}" "${customer_pid:-}" 2>/dev/null || true
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

# Provider journey: a customer tenant enrolls its own agent for the customer
# listener. The lab's customer-enroll helper writes /lab/state/customer/args
# (one flag per line) once the tenant has minted its enrollment token; this
# loop starts that second agent with the customer-only host profile and keeps
# it running beside the partner-lab agent. Nothing starts until the file exists.
customer_pid=""
( while :; do
    if [ -z "$customer_pid" ] && [ -s /lab/state/customer/args ]; then
      set --
      while IFS= read -r line; do [ -n "$line" ] && set -- "$@" "$line"; done < /lab/state/customer/args
      /usr/local/bin/trstctl-agent "$@" --host-exec-profile=/lab/host-exec-profile-customer.json --host-rollback-dir=/lab/state/customer/rollbacks &
      customer_pid=$!
      echo "customer agent started for the customer listener (pid $customer_pid)"
    fi
    if [ -n "$customer_pid" ] && ! kill -0 "$customer_pid" 2>/dev/null; then
      echo "customer agent exited; restarting in 5s" >&2; customer_pid=""; sleep 5; continue
    fi
    sleep 2
  done ) &
customer_watch_pid=$!
wait "$agent_pid"
