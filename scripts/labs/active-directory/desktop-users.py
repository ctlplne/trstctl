# SPDX-License-Identifier: BUSL-1.1
# Private owned lab fixture; never emits credential values.
from pathlib import Path
import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB
lp=LoadParm(); lp.load('/var/lib/trstctl-ad/etc/smb.conf')
sam=SamDB(session_info=system_session(),lp=lp)
for name,path in [('a263-reader','/run/ad-reader-password'),('a263-desktop','/run/ad-desktop-password')]:
 sam.newuser(name,Path(path).read_text().strip(),userou='OU=TrstctlA263')
m=ldb.Message();m.dn=ldb.Dn(sam,'CN=a263-desktop,OU=TrstctlA263,DC=a263,DC=test')
for key,value in [('uidNumber','31001'),('gidNumber','31001'),('unixHomeDirectory','/home/a263-desktop'),('loginShell','/bin/bash')]:
 m[key]=ldb.MessageElement(value,ldb.FLAG_MOD_REPLACE,key)
sam.modify(m)
