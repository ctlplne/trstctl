# SPDX-License-Identifier: BUSL-1.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PriorMsi,

    [Parameter(Mandatory = $true)]
    [string]$CurrentMsi,

    [Parameter(Mandatory = $true)]
    [string]$CurrentExe,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'trstctl-agent'
$stateDirectory = Join-Path $env:ProgramData 'trstctl'
$tokenPath = Join-Path $stateDirectory 'bootstrap-token.txt'
$caPath = Join-Path $stateDirectory 'ca-bundle.pem'
$installedExe = Join-Path $env:ProgramFiles 'trstctl\trstctl-agent.exe'
$sinkJob = $null
$testCertificate = $null

New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
Set-Content -LiteralPath $tokenPath -Value 'qa-bootstrap-token-file-only' -NoNewline

function Invoke-Msi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$ReceiptName,
        [switch]$ExpectFailure
    )

    $logPath = Join-Path $EvidenceDirectory "$ReceiptName.log"
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList "$Arguments /l*v `"$logPath`"" -Wait -PassThru
    if ($ExpectFailure) {
        if ($process.ExitCode -eq 0) {
            throw "$ReceiptName unexpectedly succeeded"
        }
    } elseif ($process.ExitCode -ne 0) {
        throw "$ReceiptName failed with msiexec exit code $($process.ExitCode); inspect $logPath"
    }
    return $process.ExitCode
}

function Get-AgentService {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        throw "Windows service $serviceName is not registered"
    }
    return $service
}

function Wait-AgentRunning {
    param([int]$Seconds = 15)

    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Windows service $serviceName did not reach Running within $Seconds seconds"
}

function Assert-ServiceContract {
    param([string]$Stage)

    $service = Get-AgentService
    if ($service.StartMode -ne 'Auto') {
        throw "${Stage}: service StartMode is $($service.StartMode), want Auto"
    }
    if ($service.PathName -notmatch '--bootstrap-token-file') {
        throw "${Stage}: service command line does not use the bootstrap token file"
    }
    if ($service.PathName -match 'qa-bootstrap-token-file-only') {
        throw "${Stage}: bootstrap token value leaked into the service command line"
    }
    Wait-AgentRunning

    $failureActions = (sc.exe qfailure $serviceName 2>&1 | Out-String)
    $failureFlag = (sc.exe qfailureflag $serviceName 2>&1 | Out-String)
    if (($failureActions | Select-String -Pattern 'RESTART' -AllMatches).Matches.Count -lt 3) {
        throw "${Stage}: SCM does not report three restart recovery actions: $failureActions"
    }
    if ($failureFlag -notmatch 'TRUE|1') {
        throw "${Stage}: SCM is not configured to recover from non-crash error exits: $failureFlag"
    }

    [ordered]@{
        stage = $Stage
        state = (Get-Service -Name $serviceName).Status.ToString()
        startMode = $service.StartMode
        tokenFileArgument = $true
        tokenValueInCommandLine = $false
        restartActions = 3
        binarySha256 = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory "$Stage.json")
}

try {
    # The service needs to remain alive long enough for the installer and SCM
    # lifecycle assertions. This loopback TCP sink accepts the enrollment TLS
    # connection but deliberately never completes the handshake. No external
    # service, credential, or network access is involved.
    $sinkJob = Start-Job -ScriptBlock {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 18443)
        $listener.Start()
        try {
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try { Start-Sleep -Seconds 300 } finally { $client.Dispose() }
            }
        } finally {
            $listener.Stop()
        }
    }
    Start-Sleep -Seconds 1

    $testCertificate = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\CurrentUser\My'
    $base64 = [Convert]::ToBase64String($testCertificate.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    Set-Content -LiteralPath $caPath -Value "-----BEGIN CERTIFICATE-----`r`n$base64`r`n-----END CERTIFICATE-----`r`n" -NoNewline

    $properties = "ENROLLURL=https://127.0.0.1:18443 SERVER=127.0.0.1:19443 SERVERNAME=localhost CABUNDLE=`"$caPath`" BOOTSTRAPTOKENFILE=`"$tokenPath`""
    Invoke-Msi -Arguments "/i `"$PriorMsi`" /qn /norestart $properties" -ReceiptName '01-install-prior' | Out-Null
    Assert-ServiceContract -Stage '01-installed-prior'

    Stop-Service -Name $serviceName -Force
    Start-Service -Name $serviceName
    Wait-AgentRunning
    Assert-ServiceContract -Stage '02-scm-stop-start'

    Invoke-Msi -Arguments "/fa `"$PriorMsi`" /qn /norestart $properties" -ReceiptName '03-repair-prior' | Out-Null
    Assert-ServiceContract -Stage '03-repaired-prior'

    $priorHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash
    Invoke-Msi -Arguments "/i `"$CurrentMsi`" /qn /norestart $properties" -ReceiptName '04-upgrade-current' | Out-Null
    Assert-ServiceContract -Stage '04-upgraded-current'
    $installedHash = (Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash
    $currentHash = (Get-FileHash -LiteralPath $CurrentExe -Algorithm SHA256).Hash
    if ($installedHash -ne $currentHash) {
        throw "upgrade did not install the current agent binary"
    }
    if ($installedHash -eq $priorHash) {
        throw "upgrade binary is indistinguishable from the prior fixture"
    }

    $downgradeExit = Invoke-Msi -Arguments "/i `"$PriorMsi`" /qn /norestart $properties" -ReceiptName '05-downgrade-refused' -ExpectFailure
    Assert-ServiceContract -Stage '05-current-preserved-after-downgrade'

    Stop-Service -Name $serviceName -Force
    Start-Service -Name $serviceName
    Wait-AgentRunning
    Assert-ServiceContract -Stage '06-resume-simulation'

    Invoke-Msi -Arguments "/x `"$CurrentMsi`" /qn /norestart" -ReceiptName '07-uninstall-current' | Out-Null
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "uninstall left Windows service $serviceName registered"
    }
    if (Test-Path -LiteralPath $installedExe) {
        throw "uninstall left $installedExe behind"
    }

    [ordered]@{
        result = 'passed'
        install = 'passed'
        scmStopStart = 'passed'
        repair = 'passed'
        majorUpgrade = 'passed'
        downgradeRefusal = 'passed'
        downgradeExitCode = $downgradeExit
        resumeSimulation = 'passed'
        uninstall = 'passed'
        note = 'A hosted runner can validate SCM stop/start and recovery configuration. A literal machine reboot remains a self-hosted qualification boundary.'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-msi-lifecycle-summary.json')
} finally {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
    }
    if ($null -ne $sinkJob) {
        Stop-Job -Job $sinkJob -ErrorAction SilentlyContinue
        Remove-Job -Job $sinkJob -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $testCertificate) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($testCertificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $tokenPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $caPath -Force -ErrorAction SilentlyContinue
}
