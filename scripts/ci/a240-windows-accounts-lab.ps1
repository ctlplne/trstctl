# SPDX-License-Identifier: BUSL-1.1
# A240 Windows local accounts lab, on the windows-latest runner itself: OpenSSH
# Server on 127.0.0.1:22, an administrator (trstctl_admin, in Administrators,
# its ECDSA key in administrators_authorized_keys) and the lab's accounts
# (orders_app_a, orders_app_b, orders_single) with one generated initial
# password, then TestWindowsLocalAccountsLabA240 against them. The password
# and the private key live only in files under RUNNER_TEMP; nothing prints
# them.
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

# One initial password meeting Windows' complexity rule (upper, lower, digit).
$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
$bytes = New-Object byte[] 48
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$initial = 'Aa1' + (-join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] }))
$initialFile = Join-Path $work 'initial-password'
[System.IO.File]::WriteAllText($initialFile, $initial)
$secure = ConvertTo-SecureString $initial -AsPlainText -Force

foreach ($name in 'orders_app_a', 'orders_app_b', 'orders_single') {
    New-LocalUser -Name $name -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
    # Users holds the network logon right sshd's password logon needs; a
    # member already there is fine.
    try { Add-LocalGroupMember -Group 'Users' -Member $name } catch [Microsoft.PowerShell.Commands.MemberExistsException] { }
}
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$adminSecret = 'Aa1' + (-join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] }))
New-LocalUser -Name 'trstctl_admin' -Password (ConvertTo-SecureString $adminSecret -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group 'Administrators' -Member 'trstctl_admin'
Remove-Variable adminSecret

# The administrator's key: ECDSA P-256, PKCS#8 PEM, as the provider takes it.
$keyFile = Join-Path $work 'admin-key'
# --% passes the empty passphrase to ssh-keygen verbatim (PowerShell's own
# argument handling can turn "" into a literal two-quote passphrase).
$env:A240_ADMIN_KEY_FILE = $keyFile
& ssh-keygen.exe --% -q -t ecdsa -b 256 -m PKCS8 -N "" -f "%A240_ADMIN_KEY_FILE%"
if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed' }
if (-not (Select-String -Path $keyFile -Pattern '-----BEGIN PRIVATE KEY-----' -SimpleMatch -Quiet)) { throw 'the administrator key is not unencrypted PKCS#8' }
$authorized = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
Get-Content "$keyFile.pub" | Set-Content -Encoding ascii -Path $authorized
& icacls.exe $authorized /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }

# Pin the host's Ed25519 key.
$hostKey = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub'
$fingerprint = ((& ssh-keygen.exe -lf $hostKey) -split '\s+')[1]
if ($fingerprint -notmatch '^SHA256:') { throw "unexpected host key fingerprint output" }
Write-Host ">> pinned host key $fingerprint"

$env:TRSTCTL_A240_WINDOWS_ADMIN_KEY_FILE = $keyFile
$env:TRSTCTL_A240_WINDOWS_HOST_KEY = $fingerprint
$env:TRSTCTL_A240_WINDOWS_INITIAL_PASSWORD_FILE = $initialFile
$log = Join-Path $work 'lab.log'
& go test -count=1 -timeout 20m -run '^TestWindowsLocalAccountsLabA240$' -v ./internal/dynsecret/ 2>&1 | Tee-Object -FilePath $log
$status = $LASTEXITCODE
if ($status -ne 0 -or -not (Select-String -Path $log -Pattern 'A240_WINDOWS_OK' -Quiet)) {
    Write-Host '::error::a240-windows-accounts-lab: TestWindowsLocalAccountsLabA240 did not run and pass'
    exit 1
}
