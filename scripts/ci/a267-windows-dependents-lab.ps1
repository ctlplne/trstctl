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

$env:TRSTCTL_A267_WINDOWS_AUTOMATION = '1'
$automationLog = Join-Path $env:RUNNER_TEMP 'a267-windows-automation.log'
& go test -count=1 -timeout 3m -run '^TestNativeAutomationBoundaryA267$' -v ./internal/crypto/windependents 2>&1 | Tee-Object -FilePath $automationLog
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Path $automationLog -Pattern 'A267_WINDOWS_AUTOMATION_OK' -Quiet)) {
    Write-Host '::error::a267 native Automation boundary did not run and pass'
    exit 1
}
$bufferLog = Join-Path $env:RUNNER_TEMP 'a267-windows-native-buffer.log'
& go test -count=1 -timeout 3m -run '^TestNativeWindowsForeignBufferA267$' -v ./internal/crypto/secret 2>&1 | Tee-Object -FilePath $bufferLog
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Path $bufferLog -Pattern 'A267_WINDOWS_NATIVE_BUFFER_OK' -Quiet)) {
    Write-Host '::error::a267 native foreign buffer did not run and pass'
    exit 1
}

# Enable this log only on the disposable owned CI runner. Product verification
# reads existing log policy and refuses to change it on an operator's host.
& wevtutil.exe sl Microsoft-Windows-TaskScheduler/Operational /e:true
if ($LASTEXITCODE -ne 0) { throw 'owned task operational log setup failed' }
$env:TRSTCTL_A267_WINDOWS_TASKS = '1'
$taskLog = Join-Path $env:RUNNER_TEMP 'a267-windows-tasks.log'
& go test -count=1 -timeout 10m -run '^TestNativeWindowsTaskLifecycleA267$' -v ./internal/crypto/windependents 2>&1 | Tee-Object -FilePath $taskLog
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Path $taskLog -Pattern 'A267_WINDOWS_TASK_OK' -Quiet)) {
    Write-Host '::error::a267 native task lifecycle did not run and pass'
    exit 1
}
