# SPDX-License-Identifier: BUSL-1.1
# Owned Samba fixture only; credentials stay in /run, public identity manifest only.
from pathlib import Path
import json, os, secrets
import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.sd_utils import SDUtils
from samba.ndr import ndr_unpack
from samba.dcerpc import security
lp=LoadParm()
lp.load('/var/lib/trstctl-ad/etc/smb.conf')
sam=SamDB(session_info=system_session(),lp=lp)
manifest=Path('/run/ad-reconcile-public.json')
base='OU=TrstctlA263,DC=a263,DC=test'
names=['a267-reconcile-target','a267-reconcile-foreign','a267-reconcile-writer']
def identity(name):
 dn='CN='+name+','+base
 rows=sam.search(base=dn,scope=ldb.SCOPE_BASE,attrs=['objectGUID','objectSid'])
 assert len(rows)==1
 return {'name':name,'dn':dn,'guid':bytes(rows[0]['objectGUID'][0]).hex(),'sid':str(ndr_unpack(security.dom_sid,bytes(rows[0]['objectSid'][0])))}
if manifest.exists():
 public=json.loads(manifest.read_text())
 assert public==[identity(n) for n in names], 'owned native identity changed; preserve and investigate'
 assert Path('/run/ad-reconcile-password').stat().st_mode & 0o077 == 0
 print(json.dumps(public))
 raise SystemExit(0)
for name in names:
 assert not sam.search(base=base,expression='(sAMAccountName='+name+')',attrs=['objectGUID']), 'pre-existing owned name without manifest; preserve and investigate'
for name in names:
 password='Tr5!'+secrets.token_hex(24)
 sam.newuser(name,password,userou='OU=TrstctlA263')
 if name.endswith('-writer'):
  fd=os.open('/run/ad-reconcile-password',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as stream: stream.write(password)
 password=None
public=[identity(n) for n in names]
# One object-only reset-password extended right, no inheritance or generic write.
sd=SDUtils(sam)
ace='(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;'+public[2]['sid']+')'
before=sd.get_sd_as_sddl(public[0]['dn'])
sd.dacl_add_ace(public[0]['dn'],ace)
after=sd.get_sd_as_sddl(public[0]['dn'])
assert ace in after
for original in before.split('(')[1:]:
 assert '('+original in after, 'unrelated DACL entry changed'
fd=os.open(manifest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream: json.dump(public,stream)
print(json.dumps(public))
