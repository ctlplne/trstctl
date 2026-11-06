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

# Inbox features only, with Windows Update access forbidden. Missing local
# payload is a concrete native-proof blocker, never a download or skipped pass.
$features = @('IIS-WebServerRole', 'IIS-ASPNET45', 'IIS-ManagementScriptingTools')
foreach ($featureName in $features) {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName
    if ($feature.State -eq 'DisabledWithPayloadRemoved') { throw "local inbox feature payload is missing: $featureName" }
    if ($feature.State -ne 'Enabled') {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -LimitAccess -NoRestart
        if ($result.RestartNeeded) { throw "native IIS fixture needs a runner restart: $featureName" }
    }
}
Start-Service WAS
Start-Service W3SVC
$env:TRSTCTL_A267_WINDOWS_IIS = '1'
$iisLog = Join-Path $env:RUNNER_TEMP 'a267-windows-iis.log'
& go test -count=1 -timeout 10m -run '^TestNativeWindowsIISPoolLifecycleA267$' -v ./internal/crypto/windependents 2>&1 | Tee-Object -FilePath $iisLog
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Path $iisLog -Pattern 'A267_WINDOWS_IIS_OK' -Quiet)) {
    Write-Host '::error::a267 native IIS pool lifecycle did not run and pass'
    exit 1
}

# The journal uses native Windows file locking and preserves failed/lost starts
# across a real abrupt child-process exit. Native task API execution is above.
$journalLog = Join-Path $env:RUNNER_TEMP 'a267-windows-task-journal.log'
& go test -count=1 -timeout 3m -run '^TestTaskExecution' -v ./internal/agent/reportstate 2>&1 | Tee-Object -FilePath $journalLog
if ($LASTEXITCODE -ne 0) { throw 'A267 native Windows task journal failed' }
Write-Host 'A267_WINDOWS_TASK_JOURNAL_OK: sealed native filesystem fence, lost replies, failed reports and abrupt child exit; full host coordination remains separate'

$env:TRSTCTL_A267_WINDOWS_INVENTORY = '1'
$inventoryLog = Join-Path $env:RUNNER_TEMP 'a267-windows-inventory.log'
& go test -count=1 -timeout 3m -run '^TestNativeWindowsInventoryCollectorA267$' -v ./internal/agent/relay 2>&1 | Tee-Object -FilePath $inventoryLog
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Path $inventoryLog -Pattern 'A267_WINDOWS_INVENTORY_OK' -Quiet)) {
    throw 'A267 native enrolled-host inventory collector did not run and pass'
}

# Compile the shipped receiver as a separate native executable so the crypto
# fixture can drive it through anonymous pipes without introducing an import
# cycle. Only public fixture paths appear in environment or command arguments.
$executor = Join-Path $env:RUNNER_TEMP 'a267-dependent-native-executor.test.exe'
& go test -c -o $executor ./internal/agent/relay
if ($LASTEXITCODE -ne 0) { throw 'A267 native receiver compilation failed' }
$env:TRSTCTL_A267_NATIVE_EXECUTOR = $executor
$env:TRSTCTL_A267_NATIVE_EXECUTOR_SHA256 = (Get-FileHash -LiteralPath $executor -Algorithm SHA256).Hash.ToLowerInvariant()
$env:TRSTCTL_A267_WINDOWS_EXECUTOR = '1'
$executorLog = Join-Path $env:RUNNER_TEMP 'a267-windows-dependent-executor.log'
& go test -count=1 -timeout 22m -run '^TestNativeWindowsDependentExecutorLifecycleA267$' -v ./internal/crypto/windependents 2>&1 | Tee-Object -FilePath $executorLog
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Path $executorLog -Pattern 'A267_WINDOWS_EXECUTOR_OK' -Quiet)) {
    throw 'A267 native shipped receiver lifecycle did not run and pass'
}
