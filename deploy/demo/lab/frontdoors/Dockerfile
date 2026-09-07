# syntax=docker/dockerfile:1.7

ARG TRSTCTL_IMAGE=ctlplne-demo-control:local
ARG APACHE_IMAGE=httpd:2.4-alpine@sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567

FROM ${TRSTCTL_IMAGE} AS trstctl
FROM ${APACHE_IMAGE}

RUN apk add --no-cache \
    nginx=1.30.4-r1 \
    haproxy=3.4.4-r0 \
    caddy=2.11.4-r1 \
    traefik=3.7.1-r1 \
    postgresql16=16.15-r0 \
    postgresql16-client=16.15-r0 \
    openssl=3.5.8-r0 \
    && addgroup -S -g 65532 trstctl \
    && adduser -S -D -H -u 65532 -G trstctl trstctl
COPY --from=trstctl /usr/local/bin/trstctl-agent /usr/local/bin/trstctl-agent
COPY deploy/demo/lab/frontdoors/httpd-lab.conf /usr/local/apache2/conf/extra/httpd-lab.conf
COPY deploy/demo/lab/frontdoors/nginx.conf /etc/nginx/nginx.conf
COPY deploy/demo/lab/frontdoors/haproxy.cfg /lab/haproxy.cfg
COPY deploy/demo/lab/frontdoors/Caddyfile /lab/Caddyfile
COPY deploy/demo/lab/frontdoors/traefik-dynamic.yml /lab/traefik-dynamic.template.yml
COPY deploy/demo/lab/frontdoors/traefik-static.yml /lab/traefik-static.yml
COPY deploy/demo/lab/frontdoors/postgresql.conf /lab/postgresql.conf
COPY deploy/demo/lab/frontdoors/host-exec-profile.json /lab/host-exec-profile.json
COPY deploy/demo/lab/frontdoors/host-exec-profile-customer.json /lab/host-exec-profile-customer.json
COPY deploy/demo/lab/frontdoors/reload-haproxy /lab/reload-haproxy
COPY deploy/demo/lab/frontdoors/entrypoint.sh /lab/entrypoint.sh

RUN set -eu; \
    sed -i \
      -e 's/^Listen 80$/Listen 10443/' \
      -e 's/^#LoadModule socache_shmcb_module/LoadModule socache_shmcb_module/' \
      -e 's/^#LoadModule ssl_module/LoadModule ssl_module/' \
      -e 's/^User www-data$/User #65532/' \
      -e 's/^Group www-data$/Group #65532/' \
      /usr/local/apache2/conf/httpd.conf; \
    printf '\nInclude conf/extra/httpd-lab.conf\n' >> /usr/local/apache2/conf/httpd.conf; \
    install -d -m 0700 -o 65532 -g 65532 /lab/state /lab/tls /lab/run /lab/state/rollbacks /lab/state/customer /lab/state/customer/rollbacks /lab/tls/customer-edge; \
    chown -R 65532:65532 /lab /usr/local/apache2/logs /var/lib/nginx /var/log/nginx; \
    chmod 0500 /lab/entrypoint.sh /lab/reload-haproxy

USER 65532:65532
WORKDIR /lab
EXPOSE 10443 10444 10445 10446 10447 10448 10449
ENTRYPOINT ["/lab/entrypoint.sh"]
