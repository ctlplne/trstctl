#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
set -eu
chown 0:0 /run/ad-reader-password /run/ad-desktop-password
chmod 600 /run/ad-reader-password /run/ad-desktop-password
cp /run/ad-ca.pem /etc/ssl/certs/a263-ca.pem
chmod 644 /etc/ssl/certs/a263-ca.pem
python3 /run/desktop-pam.py
groupadd -g 31001 a263-desktop
useradd -m -s /bin/bash -u 31001 -g 31001 a263-desktop
passwd -l a263-desktop
install -d -m 755 -o nslcd -g nslcd /run/nslcd
nslcd
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -keyout /run/rdp.key -out /run/rdp.crt -days 2 -subj /CN=localhost > /run/rdp-cert.log 2>&1
openssl x509 -in /run/rdp.crt -outform DER | openssl dgst -sha256 | awk '{print $2}' > /run/rdp-pin
sed -i 's|^certificate=.*|certificate=/run/rdp.crt|;s|^key_file=.*|key_file=/run/rdp.key|;s|^security_layer=.*|security_layer=tls|;s|^allow_channels=.*|allow_channels=false|' /etc/xrdp/xrdp.ini
printf '#!/bin/sh\nexec /usr/bin/xterm -geometry 90x28+0+0 -bg navy -fg white\n' > /etc/xrdp/startwm.sh
chmod 755 /etc/xrdp/startwm.sh
mkdir -p /run/xrdp/sockdir /run/sshd /run/dbus
chmod 755 /run/xrdp /run/sshd /run/dbus
chmod 3777 /run/xrdp/sockdir
/usr/sbin/xrdp-sesman
/usr/sbin/xrdp
sh /run/rdp-native/build.sh /run/rdp-helper
/run/rdp-helper --check
passwd -S a263-desktop
