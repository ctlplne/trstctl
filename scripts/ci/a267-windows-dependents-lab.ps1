# SPDX-License-Identifier: BUSL-1.1
# Real native APIs on exact test-owned accounts/services. No credential files,
# command-line passwords, domain changes or unrelated service modifications.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:TRSTCTL_A267_WINDOWS_SERVICES = '1'
$log = Join-Path $env:RUNNER_TEMP 'a267-windows-services.log'
& go test -count=1 -timeout 10m -run '^TestNativeWindowsServiceLifecycleA267$' -v ./internal/crypto/windependents 2>&1 | Tee-Object -FilePath $log
$status = $LASTEXITCODE
if ($status -ne 0 -or -not (Select-String -Path $log -Pattern 'A267_WINDOWS_SERVICE_OK' -Quiet)) {
    Write-Host '::error::a267 native service lifecycle did not run and pass'
    exit 1
}
