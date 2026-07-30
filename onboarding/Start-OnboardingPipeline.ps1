Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Orchestrates the full MSSP customer onboarding pipeline in ordered sequence.
.DESCRIPTION
    Loads or creates a state file, checks each step for prior completion (idempotent re-runs),
    and executes the deployment sequence. Updates state after each step. Supports -SkipSteps
    to bypass specific steps and -WhatIfMode for dry-run preview.
    TEST_REQUIRED: Full pipeline test in staging required; individual failures need manual intervention.
#>

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$ManagedByTenantId,
    [Parameter(Mandatory)][string]$DataConnectorLogicAppUri,
    [switch]$WhatIfMode,
    [string[]]$SkipSteps = @(),
    [string]$EvidenceOutputPath = '.\evidence'
)

$config    = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$shortName = $config.customer.shortName

if (-not (Test-Path $EvidenceOutputPath)) { New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null }

$stateDir  = '.\state'
if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
$stateFile = Join-Path $stateDir "$shortName-state.json"

function Write-Evidence {
    param([hashtable]$Data)
    $ts      = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile = Join-Path $EvidenceOutputPath ("evidence-Start-OnboardingPipeline-{0}-{1}.json" -f $shortName, $ts)
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "[Evidence] Written: $outFile" -ForegroundColor Cyan
}

function Load-State {
    if (Test-Path $stateFile) {
        return Get-Content $stateFile -Raw | ConvertFrom-Json
    }
    # Create initial state
    $initial = @{
        customerId        = $config.customer?.tenantId ?? ''
        customerShortName = $shortName
        lifecycleState    = 'WaitingForIntake'
        createdAt        = (Get-Date).ToUniversalTime().ToString('o')
        updatedAt        = (Get-Date).ToUniversalTime().ToString('o')
        steps            = @()
    }
    $initial | ConvertTo-Json -Depth 10 | Set-Content -Path $stateFile -Encoding UTF8
    return $initial | ConvertTo-Json -Depth 10 | ConvertFrom-Json
}

function Save-State {
    param($State)
    $State.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
    $State | ConvertTo-Json -Depth 10 | Set-Content -Path $stateFile -Encoding UTF8
}

function Get-StepState {
    param($State, [string]$StepName)
    foreach ($s in $State.steps) {
        if ($s.name -eq $StepName) { return $s }
    }
    return $null
}

function Set-StepState {
    param($State, [string]$StepName, [string]$Status, [string]$Notes = '', [string]$EvidencePath = '')
    $existing = $null
    $idx = -1
    for ($i = 0; $i -lt $State.steps.Count; $i++) {
        if ($State.steps[$i].name -eq $StepName) { $existing = $State.steps[$i]; $idx = $i; break }
    }
    $stepObj = @{
        name          = $StepName
        status        = $Status
        completedAt   = if ($Status -in @('succeeded','failed','manual-required')) { (Get-Date).ToUniversalTime().ToString('o') } else { $null }
        evidencePath  = $EvidencePath
        notes         = $Notes
    }
    if ($idx -ge 0) {
        # PSCustomObject array - rebuild
        $newSteps = @()
        for ($i = 0; $i -lt $State.steps.Count; $i++) {
            if ($i -eq $idx) { $newSteps += $stepObj } else { $newSteps += $State.steps[$i] }
        }
        $State.steps = $newSteps
    } else {
        $State.steps = @($State.steps) + @($stepObj)
    }
    Save-State -State $State
}

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent }
if (-not $scriptDir) { $scriptDir = '.' }

# Define the ordered pipeline steps
$pipeline = @(
    @{
        Name       = 'Test-MsspPrerequisites'
        Script     = Join-Path $scriptDir 'Test-MsspPrerequisites.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = $null
    },
    @{
        Name       = 'New-LighthouseDelegationPackage'
        Script     = Join-Path $scriptDir 'New-LighthouseDelegationPackage.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-ManagedByTenantId', $ManagedByTenantId, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = 'WaitingForLighthouseAcceptance'
    },
    @{
        Name       = 'Apply-RsocGovernanceBaseline'
        Script     = Join-Path $scriptDir 'Apply-RsocGovernanceBaseline.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = 'ReadyForDeployment'
    },
    @{
        Name       = 'Deploy-SentinelWorkspace'
        Script     = Join-Path $scriptDir 'Deploy-SentinelWorkspace.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = 'Deploying'
    },
    @{
        Name       = 'Register-OnboardingMonitor'
        Script     = Join-Path $scriptDir 'Register-OnboardingMonitor.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = $null
    },
    @{
        Name       = 'Enable-DataConnectors'
        Script     = Join-Path $scriptDir 'Enable-DataConnectors.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-LogicAppUri', $DataConnectorLogicAppUri, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = 'WaitingForConnectorConsent'
    },
    @{
        Name       = 'Deploy-SentinelContent'
        Script     = Join-Path $scriptDir 'Deploy-SentinelContent.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = 'ValidatingDeployment'
    },
    @{
        Name       = 'Send-CustomerInstructionPacket'
        Script     = Join-Path $scriptDir 'Send-CustomerInstructionPacket.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = $null
    },
    @{
        Name       = 'Test-EndToEndDeployment'
        Script     = Join-Path $scriptDir 'Test-EndToEndDeployment.ps1'
        Args       = @('-CustomerConfigPath', $CustomerConfigPath, '-ManagedByTenantId', $ManagedByTenantId, '-EvidenceOutputPath', $EvidenceOutputPath)
        LifecycleTransition = 'CustomerValidation'
    }
)

$state = Load-State
Write-Host "`n[Start-OnboardingPipeline] Customer: $shortName | Steps: $($pipeline.Count)" -ForegroundColor Green
Write-Host "State file: $stateFile" -ForegroundColor Gray
Write-Host "Lifecycle:  $($state.lifecycleState)" -ForegroundColor Gray
if ($WhatIfMode) { Write-Host "[WhatIf Mode Active]" -ForegroundColor Yellow }
if ($SkipSteps.Count -gt 0) { Write-Host "Skipping steps: $($SkipSteps -join ', ')" -ForegroundColor Yellow }

$pipelineResults = [System.Collections.Generic.List[hashtable]]::new()
$anyFailed = $false
$startTime = Get-Date

Write-Host "`n[PIPELINE PROGRESS]" -ForegroundColor White
Write-Host ("=" * 70) -ForegroundColor DarkGray

foreach ($step in $pipeline) {
    $stepName = $step.Name
    $stepStart = Get-Date

    # Check current state
    $existingStep = Get-StepState -State $state -StepName $stepName

    $result = @{
        stepName    = $stepName
        status      = 'pending'
        skipped     = $false
        durationMs  = 0
        notes       = ''
    }

    # Skip if already succeeded
    if ($existingStep?.status -eq 'succeeded') {
        Write-Host ("  [SKIP-DONE] {0,-42} already succeeded" -f $stepName) -ForegroundColor DarkGreen
        $result.status  = 'already-succeeded'
        $result.skipped = $true
        $pipelineResults.Add($result)
        continue
    }

    # Skip if in SkipSteps
    if ($SkipSteps -contains $stepName) {
        Write-Host ("  [SKIP-MANUAL] {0,-40} in SkipSteps" -f $stepName) -ForegroundColor Yellow
        $result.status  = 'skipped'
        $result.skipped = $true
        $pipelineResults.Add($result)
        continue
    }

    # WhatIf mode
    if ($WhatIfMode) {
        Write-Host ("  [WHATIF] {0,-44} would execute" -f $stepName) -ForegroundColor Yellow
        $result.status = 'whatif'
        $result.durationMs = ((Get-Date) - $stepStart).TotalMilliseconds
        $pipelineResults.Add($result)
        continue
    }

    # Check script exists
    if (-not (Test-Path $step.Script)) {
        $msg = "Script not found: $($step.Script)"
        Write-Host ("  [MISSING] {0,-43} {1}" -f $stepName, $msg) -ForegroundColor Red
        Set-StepState -State $state -StepName $stepName -Status 'failed' -Notes $msg
        $result.status = 'failed'
        $result.notes  = $msg
        $pipelineResults.Add($result)
        $anyFailed = $true
        continue
    }

    # Execute step
    Write-Host ("  [RUN] {0}" -f $stepName) -ForegroundColor Cyan
    Set-StepState -State $state -StepName $stepName -Status 'in-progress'

    try {
        $extraArgs = if ($WhatIfMode) { @('-WhatIfMode') } else { @() }
        & $step.Script @($step.Args) @extraArgs
        $exitCode = $LASTEXITCODE ?? 0

        if ($exitCode -ne 0) {
            throw "Script exited with code $exitCode"
        }

        Write-Host ("  [PASS] {0,-44} {1:F1}s" -f $stepName, (((Get-Date) - $stepStart).TotalSeconds)) -ForegroundColor Green
        Set-StepState -State $state -StepName $stepName -Status 'succeeded'

        if ($step.LifecycleTransition) {
            $state.lifecycleState = $step.LifecycleTransition
            Save-State -State $state
            Write-Host "         Lifecycle: $($state.lifecycleState)" -ForegroundColor DarkGray
        }
        $result.status = 'succeeded'
    } catch {
        $errMsg = $_.Exception.Message
        Write-Host ("  [FAIL] {0,-44} {1}" -f $stepName, $errMsg) -ForegroundColor Red
        Set-StepState -State $state -StepName $stepName -Status 'failed' -Notes $errMsg
        $result.status = 'failed'
        $result.notes  = $errMsg
        $anyFailed = $true
    }

    $result.durationMs = ((Get-Date) - $stepStart).TotalMilliseconds
    $pipelineResults.Add($result)
}

Write-Host ("=" * 70) -ForegroundColor DarkGray
$totalSecs = ((Get-Date) - $startTime).TotalSeconds
$successCount = ($pipelineResults | Where-Object { $_.status -eq 'succeeded' }).Count
$failCount    = ($pipelineResults | Where-Object { $_.status -eq 'failed' }).Count
$skipCount    = ($pipelineResults | Where-Object { $_.skipped }).Count
$overallColor = if (-not $anyFailed) { 'Green' } else { 'Red' }
Write-Host ("Pipeline complete: {0} succeeded | {1} failed | {2} skipped | {3:F1}s total" -f $successCount, $failCount, $skipCount, $totalSecs) -ForegroundColor $overallColor
Write-Host "Final lifecycle state: $($state.lifecycleState)" -ForegroundColor Cyan

$pipelineStatus = if ($WhatIfMode) { 'whatif-only' } elseif (-not $anyFailed) { 'succeeded' } else { 'partial-failure' }

Write-Evidence @{
    scriptName         = 'Start-OnboardingPipeline'
    customerShortName  = $shortName
    status             = $pipelineStatus
    timestampUtc       = (Get-Date).ToUniversalTime().ToString('o')
    managedByTenantId  = $ManagedByTenantId
    lifecycleState     = $state.lifecycleState
    stateFile          = $stateFile
    successCount       = $successCount
    failCount          = $failCount
    skipCount          = $skipCount
    totalDurationSecs  = [math]::Round($totalSecs, 2)
    testRequired       = @(
        'TEST_REQUIRED: Full pipeline test in staging required before production use',
        'TEST_REQUIRED: Individual step failures require manual review before re-run',
        'TEST_REQUIRED: DataConnectorLogicAppUri must be deployed and healthy before pipeline start'
    )
    pipelineResults    = $pipelineResults
}

if ($anyFailed) { exit 1 }
