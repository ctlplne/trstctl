# A Debian host with OpenSSH and local service accounts, for the local-account
# rotator's proof (A240). Test-only: secret_static_rotation_unix_container_test.go
# builds it, installs the administrator's public key for root and pins the host
# key it generates at start. orders-svc-a and orders-svc-b share the orders
# group (a two-user role); orders-single is rotated in place. sudo is there
# so a non-root discovery administrator can list other accounts' rights
# (A260-L3).
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server passwd sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /root/.ssh \
    && chmod 0700 /root/.ssh \
    && groupadd orders \
    && useradd -m -s /bin/bash -G orders orders-svc-a \
    && useradd -m -s /bin/bash -G orders orders-svc-b \
    && useradd -m -s /bin/bash orders-single \
    && rm -f /etc/ssh/ssh_host_* \
    && printf '%s\n' 'PasswordAuthentication yes' 'KbdInteractiveAuthentication yes' 'PermitRootLogin prohibit-password' 'UsePAM yes' > /etc/ssh/sshd_config.d/lab.conf
EXPOSE 22
CMD ["/bin/sh", "-c", "ssh-keygen -A >/dev/null && exec /usr/sbin/sshd -D -e"]
