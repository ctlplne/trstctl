# SPDX-License-Identifier: BUSL-1.1
# A239-L2 lab: stock OpenLDAP 2.6 with its dds overlay (RFC 2589 dynamic
# entries), from an approved cached Alpine 3.20 base and Alpine's own packages.
ARG BASE
FROM ${BASE}
RUN apk add --no-cache openldap openldap-back-mdb openldap-overlay-dds openldap-clients openldap-passwd-pbkdf2 \
 && mkdir -p /run/openldap /var/lib/openldap/openldap-data
COPY setup.sh /usr/local/bin/trstctl-ldap-dds-setup.sh
ENTRYPOINT ["sleep", "infinity"]
