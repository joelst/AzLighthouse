<#
.SYNOPSIS
    Runs all MSSP validation scripts end-to-end and produces a comprehensive pass/fail report.
.DESCRIPTION
    Executes Test-LighthouseDelegation, Test-RsocCustomerAccessBaseline,
    Test-TenantGovernanceAccess, Test-CustomerOnboardingAccount, and Test-MsspPrerequisites
    in sequence. Aggregates results into a JSON report and prints a color-coded summary table.
    Exits with code 1 if any test script fails.
#>

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$ManagedByTenantId,
    [string]$ContentRepoUrl,
    [string]$MsspManagementRepoPath,
    [string]$SchemaPath,
    [string]$PartnerTenantId,
    [string]$OutputPath = '.\evidence\e2e-report.json',
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$config    = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$shortName = $config.customer.shortName

if (-not (Test-Path $EvidenceOutputPath)) { New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null }
$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function Write-Evidence {
    param([hashtable]$Data)
    $ts      = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile = Join-Path $EvidenceOutputPath ("evidence-Test-EndToEndDeployment-{0}-{1}.json" -f $shortName, $ts)
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "[Evidence] Written: $outFile" -ForegroundColor Cyan
}

# Resolve script directory (same folder as this script)
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent }
if (-not $scriptDir) { $scriptDir = '.' }

$resolvedContentRepoUrl = $ContentRepoUrl
if (-not $resolvedContentRepoUrl -and $config.contentRepo) {
    $resolvedContentRepoUrl = $config.contentRepo.url
}

$prereqArgs = @(
    '-CustomerConfigPath', $CustomerConfigPath,
    '-ManagedByTenantId', $ManagedByTenantId
)
if (-not [string]::IsNullOrWhiteSpace($resolvedContentRepoUrl)) {
    $prereqArgs += @('-ContentRepoUrl', $resolvedContentRepoUrl)
}
if ($MsspManagementRepoPath) {
    $prereqArgs += @('-MsspManagementRepoPath', $MsspManagementRepoPath)
}
if ($SchemaPath) {
    $prereqArgs += @('-SchemaPath', $SchemaPath)
}

# Define test scripts in execution order
$testScripts = @(
    @{
        Name        = 'Test-MsspPrerequisites'
        ScriptPath  = Join-Path $scriptDir 'Test-MsspPrerequisites.ps1'
        Args        = $prereqArgs
        Description = 'Validates MSSP module dependencies and environment prerequisites'
    },
    @{
        Name        = 'Test-LighthouseDelegation'
        ScriptPath  = Join-Path $scriptDir 'Test-LighthouseDelegation.ps1'
        Args        = @('-CustomerConfigPath', $CustomerConfigPath, '-ManagedByTenantId', $ManagedByTenantId)
        Description = 'Verifies Lighthouse delegation is active and ARM access is working'
    },
    @{
        Name        = 'Test-RsocCustomerAccessBaseline'
        ScriptPath  = Join-Path $scriptDir 'Test-RsocCustomerAccessBaseline.ps1'
        Args        = @('-CustomerConfigPath', $CustomerConfigPath)
        Description = 'Checks RSOC role assignments and Sentinel workspace access'
    },
    @{
        Name        = 'Test-TenantGovernanceAccess'
        ScriptPath  = Join-Path $scriptDir 'Test-TenantGovernanceAccess.ps1'
        Args        = @('-CustomerConfigPath', $CustomerConfigPath)
        Description = 'Validates GDAP relationships and governance permissions'
    },
    @{
        Name        = 'Test-CustomerOnboardingAccount'
        ScriptPath  = Join-Path $scriptDir 'Test-CustomerOnboardingAccount.ps1'
        Args        = @('-CustomerConfigPath', $CustomerConfigPath)
        Description = 'Confirms onboarding account UPN, license, and MFA compliance'
    }
)

Write-Host "`n[Script 24] Test-EndToEndDeployment | Customer: $shortName" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor DarkGray
Write-Host "Running $($testScripts.Count) validation scripts ..." -ForegroundColor Cyan

$results     = [System.Collections.Generic.List[hashtable]]::new()
$overallPass = $true
$startTime   = Get-Date

foreach ($test in $testScripts) {
    $testStart = Get-Date
    Write-Host "`n  [RUN] $($test.Name)" -ForegroundColor Cyan
    Write-Host "        $($test.Description)" -ForegroundColor DarkGray

    $entry = @{
        scriptName  = $test.Name
        description = $test.Description
        passed      = $false
        errors      = @()
        startedAt   = $testStart.ToUniversalTime().ToString('o')
        completedAt = $null
        durationMs  = 0
    }

    if ($WhatIfMode) {
        Write-Host "  [WhatIf] Skipping execution of $($test.Name)" -ForegroundColor Yellow
        $entry.passed = $true
        $entry.errors = @('WhatIfMode: not executed')
        $entry.completedAt = (Get-Date).ToUniversalTime().ToString('o')
        $entry.durationMs  = ((Get-Date) - $testStart).TotalMilliseconds
        $results.Add($entry)
        continue
    }

    if (-not (Test-Path $test.ScriptPath)) {
        $msg = "Script not found: $($test.ScriptPath)"
        Write-Warning "  [SKIP] $msg"
        $entry.errors = @($msg)
        $entry.passed = $false
        $entry.completedAt = (Get-Date).ToUniversalTime().ToString('o')
        $entry.durationMs  = ((Get-Date) - $testStart).TotalMilliseconds
        $results.Add($entry)
        $overallPass = $false
        continue
    }

    try {
        $output = & $test.ScriptPath @($test.Args) 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $errLines = $output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() }
            if (-not $errLines) { $errLines = @("Script exited with code $exitCode") }
            $entry.errors = $errLines
            $entry.passed = $false
            $overallPass  = $false
            Write-Host "  [FAIL] $($test.Name) (exit $exitCode)" -ForegroundColor Red
        } else {
            $entry.passed = $true
            Write-Host "  [PASS] $($test.Name)" -ForegroundColor Green
        }
    } catch {
        $entry.errors = @($_.Exception.Message)
        $entry.passed = $false
        $overallPass  = $false
        Write-Host "  [FAIL] $($test.Name): $($_.Exception.Message)" -ForegroundColor Red
    }

    $entry.completedAt = (Get-Date).ToUniversalTime().ToString('o')
    $entry.durationMs  = ((Get-Date) - $testStart).TotalMilliseconds
    $results.Add($entry)
}

$totalDuration = ((Get-Date) - $startTime).TotalSeconds

# Print summary table
Write-Host "`n`n[SUMMARY TABLE]" -ForegroundColor White
Write-Host ("=" * 70) -ForegroundColor DarkGray
Write-Host ("{0,-40} {1,-10} {2,8}" -f "Test Script", "Result", "Duration") -ForegroundColor White
Write-Host ("-" * 70) -ForegroundColor DarkGray
foreach ($r in $results) {
    $color  = if ($r.passed) { 'Green' } else { 'Red' }
    $symbol = if ($r.passed) { 'PASS' } else { 'FAIL' }
    $dur    = [math]::Round($r.durationMs / 1000, 1)
    Write-Host ("{0,-40} {1,-10} {2,7}s" -f $r.scriptName, $symbol, $dur) -ForegroundColor $color
}
Write-Host ("-" * 70) -ForegroundColor DarkGray
$passCount = ($results | Where-Object { $_.passed }).Count
$failCount = ($results | Where-Object { -not $_.passed }).Count
$overallColor = if ($overallPass) { 'Green' } else { 'Red' }
Write-Host ("Overall: {0}/{1} passed | Total time: {2:F1}s" -f $passCount, $results.Count, $totalDuration) -ForegroundColor $overallColor
Write-Host ("=" * 70) -ForegroundColor DarkGray

$reportStatus = if ($WhatIfMode) { 'whatif-only' } elseif ($overallPass) { 'succeeded' } else { 'failed' }

$reportData = @{
    scriptName        = 'Test-EndToEndDeployment'
    customerShortName = $shortName
    status            = $reportStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    managedByTenantId = $ManagedByTenantId
    partnerTenantId   = $PartnerTenantId ?? ''
    overallPass       = $overallPass
    passCount         = $passCount
    failCount         = $failCount
    totalDurationSecs = [math]::Round($totalDuration, 2)
    testRequired      = @(
        'TEST_REQUIRED: All child test scripts must be present and executable',
        'TEST_REQUIRED: Run after full pipeline deployment completes',
        'TEST_REQUIRED: Requires active Az session with cross-tenant access'
    )
    testResults       = $results
}

# Write to both evidence dir and specified OutputPath
Write-Evidence -Data $reportData
$reportData | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "[Report] Written: $OutputPath" -ForegroundColor Cyan

if (-not $overallPass) { exit 1 }
