# SPDX-License-Identifier: BUSL-1.1
# Owned native fixture only. The stock Samba provisioner consumes a private file.
import logging
from pathlib import Path
from samba.provision import provision
from samba.auth import system_session
from samba import dsdb
provision(logging.getLogger('a263'), system_session(), smbconf='/etc/samba/smb.conf', targetdir='/var/lib/trstctl-ad', realm='A263.TEST', domain='A263', hostname='ad263', serverrole='active directory domain controller', dns_backend='SAMBA_INTERNAL', adminpass=Path('/run/ad-admin-password').read_text().strip(), dom_for_fun_level=dsdb.DS_DOMAIN_FUNCTION_2008_R2, useeadb=True, use_rfc2307=True, skip_sysvolacl=True)
