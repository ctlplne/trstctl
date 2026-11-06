# SPDX-License-Identifier: BUSL-1.1
# Private owned lab fixture; never emits credential values.
from pathlib import Path
secret=Path('/run/ad-reader-password').read_text().strip()
text='''uid nslcd
gid nslcd
uri ldaps://ad263:636
base OU=TrstctlA263,DC=a263,DC=test
binddn CN=a263-reader,OU=TrstctlA263,DC=a263,DC=test
bindpw {password}
tls_reqcert demand
tls_cacertfile /etc/ssl/certs/a263-ca.pem
map passwd uid sAMAccountName
map passwd homeDirectory unixHomeDirectory
filter passwd (&(objectClass=user)(!(objectClass=computer)))
bind_timelimit 5
timelimit 5
'''.format(password=secret)
Path('/etc/nslcd.conf').write_text(text);Path('/etc/nslcd.conf').chmod(0o600)
Path('/etc/pam.d/xrdp-sesman').write_text('auth required pam_ldap.so\naccount required pam_ldap.so\nsession required pam_unix.so\nsession optional pam_mkhomedir.so skel=/etc/skel umask=0077\n')
