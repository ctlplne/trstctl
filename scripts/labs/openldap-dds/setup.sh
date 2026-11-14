#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Writes slapd.conf with the admin password in /run/admin-pw (hashed), loads
# the base entries and starts slapd on 389. The dds overlay checks expiry
# every 5 seconds.
set -eu
hash=$(slappasswd -T /run/admin-pw)
cat > /etc/openldap/slapd.conf <<CONF
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
pidfile /run/openldap/slapd.pid
argsfile /run/openldap/slapd.args
modulepath /usr/lib/openldap
moduleload back_mdb.so
moduleload dds.so
database mdb
maxsize 1073741824
suffix "dc=lab,dc=test"
rootdn "cn=admin,dc=lab,dc=test"
rootpw $hash
directory /var/lib/openldap/openldap-data
index objectClass eq
index entryExpireTimestamp eq
overlay dds
dds-max-ttl 1d
dds-default-ttl 1h
dds-interval 5s
CONF
cat > /tmp/base.ldif <<LDIF
dn: dc=lab,dc=test
objectClass: dcObject
objectClass: organization
dc: lab
o: lab

dn: ou=leases,dc=lab,dc=test
objectClass: organizationalUnit
ou: leases

dn: ou=groups,dc=lab,dc=test
objectClass: organizationalUnit
ou: groups

dn: cn=readers,ou=groups,dc=lab,dc=test
objectClass: groupOfNames
cn: readers
member: cn=admin,dc=lab,dc=test
LDIF
slapadd -f /etc/openldap/slapd.conf -l /tmp/base.ldif
slapd -f /etc/openldap/slapd.conf -h "ldap:///"
for i in $(seq 1 50); do
  if ldapsearch -x -H ldap://127.0.0.1 -b dc=lab,dc=test -s base dn >/dev/null 2>&1; then exit 0; fi
  sleep 0.2
done
echo "slapd did not answer" >&2
exit 1
