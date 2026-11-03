# SPDX-License-Identifier: BUSL-1.1
# A240 Windows local accounts lab, on the windows-latest runner itself: OpenSSH
# Server on 127.0.0.1:22, an administrator (trstctl_admin, in Administrators)
# and the lab's accounts (orders_app_a, orders_app_b, orders_single) with one
# generated initial password, then TestWindowsLocalAccountsLabA240 against
# them, which installs the administrator's key. The password lives only in a
# file under RUNNER_TEMP; nothing prints it.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$work = Join-Path $env:RUNNER_TEMP 'a240-windows'
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host ">> runner: $([Environment]::OSVersion.VersionString), $([Environment]::ProcessorCount) CPUs"
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
if ($capability.State -ne 'Installed') {
    $started = Get-Date
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
    Write-Host (">> installed {0} in {1:n0}s" -f $capability.Name, ((Get-Date) - $started).TotalSeconds)
}
Start-Service sshd
Write-Host ">> sshd: $((Get-Service sshd).Status)"
# sshd answers on 127.0.0.1:22 a moment after the service starts.
$deadline = (Get-Date).AddSeconds(30)
while (-not (Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw 'sshd is not listening on port 22' }
    Start-Sleep -Milliseconds 250
}
$config = Join-Path $env:ProgramData 'ssh\sshd_config'
Write-Host ">> sshd_config authentication lines:"
Select-String -Path $config -Pattern '^\s*#?\s*(PasswordAuthentication|KbdInteractiveAuthentication|PubkeyAuthentication|Match|AuthorizedKeysFile|AllowGroups|AllowUsers|DenyGroups|DenyUsers)' |
    ForEach-Object { Write-Host "   $($_.Line)" }

# One initial password meeting Windows' complexity rule (upper, lower, digit).
$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$initial = 'Aa1' + (-join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] }))
$initialFile = Join-Path $work 'initial-password'
[System.IO.File]::WriteAllText($initialFile, $initial)
$secure = ConvertTo-SecureString $initial -AsPlainText -Force

# The runner's sshd admits only the groups its AllowGroups names (it refused
# the accounts with "none of user's groups are listed in AllowGroups"). The lab
# accounts get a group of their own, which the directive is extended to admit;
# they stay ordinary users.
New-LocalGroup -Name 'trstctl_lab' -Description 'trstctl A240 lab accounts' | Out-Null
foreach ($name in 'orders_app_a', 'orders_app_b', 'orders_single') {
    New-LocalUser -Name $name -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
    # Users holds the network logon right sshd's password logon needs; a
    # member already there is fine.
    try { Add-LocalGroupMember -Group 'Users' -Member $name } catch [Microsoft.PowerShell.Commands.MemberExistsException] { }
    Add-LocalGroupMember -Group 'trstctl_lab' -Member $name
}
# AllowGroups may sit in sshd_config or in a file it includes.
$sshDir = Join-Path $env:ProgramData 'ssh'
$candidates = @($config) + @(Get-ChildItem -Path $sshDir -Recurse -Filter '*.conf' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$changed = $false
foreach ($file in $candidates) {
    $lines = Get-Content -Path $file
    if (-not ($lines | Where-Object { $_ -match '^\s*AllowGroups\s' })) { continue }
    $lines = $lines | ForEach-Object { if ($_ -match '^\s*AllowGroups\s') { "$_ trstctl_lab" } else { $_ } }
    Set-Content -Path $file -Value $lines -Encoding ascii
    Write-Host ">> AllowGroups in $($file): $((Select-String -Path $file -Pattern '^\s*AllowGroups\s').Line)"
    $changed = $true
}
if (-not $changed) { Write-Host '>> no AllowGroups directive found in the sshd configuration' }
# The administrator's key logon was accepted and the connection then closed
# while the rotation opened its session ("unexpected packet in response to
# channel open"), with nothing more in the Operational log. Debug logging,
# first in the file so no Match block scopes it, says why.
$labStarted = Get-Date
Set-Content -Path $config -Value (@('LogLevel DEBUG3') + (Get-Content -Path $config)) -Encoding ascii
Restart-Service sshd
$deadline = (Get-Date).AddSeconds(30)
while (-not (Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw 'sshd is not listening on port 22 after the restart' }
    Start-Sleep -Milliseconds 250
}
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$adminSecret = 'Aa1' + (-join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] }))
New-LocalUser -Name 'trstctl_admin' -Password (ConvertTo-SecureString $adminSecret -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group 'Administrators' -Member 'trstctl_admin'
Remove-Variable adminSecret

# The administrator's key is generated by the lab test itself, in memory; it
# writes only the public half to administrators_authorized_keys and restricts
# that file to Administrators and SYSTEM, as sshd requires. (ssh-keygen here
# took PowerShell's empty passphrase as a literal two-quote one.)
$authorized = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'

# Pin the host's Ed25519 key.
$hostKey = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub'
$fingerprint = ((& ssh-keygen.exe -lf $hostKey) -split '\s+')[1]
if ($fingerprint -notmatch '^SHA256:') { throw "unexpected host key fingerprint output" }
Write-Host ">> pinned host key $fingerprint"

$env:TRSTCTL_A240_WINDOWS_AUTHORIZED_KEYS = $authorized
$env:TRSTCTL_A240_WINDOWS_HOST_KEY = $fingerprint
$env:TRSTCTL_A240_WINDOWS_INITIAL_PASSWORD_FILE = $initialFile
$log = Join-Path $work 'lab.log'
& go test -count=1 -timeout 20m -run '^TestWindowsLocalAccountsLabA240$' -v ./internal/dynsecret/ 2>&1 | Tee-Object -FilePath $log
$status = $LASTEXITCODE
if ($status -ne 0 -or -not (Select-String -Path $log -Pattern 'A240_WINDOWS_OK' -Quiet)) {
    # Why a logon was refused, without any password: sshd's own log and the
    # Security log's failed-logon status codes.
    Write-Host '>> OpenSSH/Operational since the lab started, oldest first (sshd at LogLevel DEBUG3):'
    Get-WinEvent -FilterHashtable @{ LogName = 'OpenSSH/Operational'; StartTime = $labStarted } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated | Select-Object -Last 400 |
        ForEach-Object { Write-Host ("   {0:HH:mm:ss.fff} {1}" -f $_.TimeCreated, ($_.Message -replace '\s+', ' ')) }
    Write-Host '>> OpenSSH/Admin, newest 20:'
    Get-WinEvent -LogName 'OpenSSH/Admin' -MaxEvents 20 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("   {0:HH:mm:ss} {1}" -f $_.TimeCreated, ($_.Message -replace '\s+', ' ')) }
    Write-Host (">> trstctl_admin profile directory present: {0}" -f (Test-Path (Join-Path $env:SystemDrive 'Users\trstctl_admin')))
    Write-Host '>> Security 4625 (failed logon), newest 5:'
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625 } -MaxEvents 5 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            Write-Host ("   user={0} logonType={1} status={2} subStatus={3} process={4}" -f $d['TargetUserName'], $d['LogonType'], $d['Status'], $d['SubStatus'], $d['LogonProcessName'])
        }
    Write-Host '::error::a240-windows-accounts-lab: TestWindowsLocalAccountsLabA240 did not run and pass'
    exit 1
}
