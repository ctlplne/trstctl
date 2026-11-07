# A Debian host with OpenSSH and rsyslog, for bypass detection's Linux proof
# (A274): sshd logs every sign-in through syslog to /var/log/auth.log, which
# the provider's administrator reads with the fixed sign-in report. Test-only:
# pam_signin_served_test.go builds it, installs the administrator's public key
# for root and pins the host key it generates at start. orders-single is the
# managed account.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server passwd rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /root/.ssh \
    && chmod 0700 /root/.ssh \
    && useradd -m -s /bin/bash orders-single \
    && rm -f /etc/ssh/ssh_host_* \
    && sed -i '/imklog/d' /etc/rsyslog.conf \
    && printf '%s\n' 'PasswordAuthentication yes' 'KbdInteractiveAuthentication yes' 'PermitRootLogin prohibit-password' 'UsePAM yes' > /etc/ssh/sshd_config.d/lab.conf
EXPOSE 22
CMD ["/bin/sh", "-c", "ssh-keygen -A >/dev/null && rsyslogd && exec /usr/sbin/sshd -D"]
