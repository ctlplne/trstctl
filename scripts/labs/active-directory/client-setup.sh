#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
set -eu
chown 0:0 /run/ad-admin-password /run/ad-ca.pem
chmod 600 /run/ad-admin-password /run/ad-ca.pem
install -d -m 700 -o postgres -g postgres /var/lib/postgresql/ad-lab
runuser -u postgres -- /usr/lib/postgresql/15/bin/initdb -D /var/lib/postgresql/ad-lab -A trust > /run/pg-init.log
cat >> /var/lib/postgresql/ad-lab/postgresql.conf <<'CONFIG'
listen_addresses = '127.0.0.1'
port = 55432
unix_socket_directories = ''
CONFIG
runuser -u postgres -- /usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/ad-lab -l /var/lib/postgresql/ad-lab/server.log start
