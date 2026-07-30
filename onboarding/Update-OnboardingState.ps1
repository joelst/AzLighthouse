#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Creates or updates a customer onboarding state file with step status and lifecycle transitions.
.DESCRIPTION
    Manages the onboarding lifecycle state JSON file aligned to onboarding-state.schema.json.
    Creates if not exists, updates existing steps, transitions lifecycle state, prints summary.

    Lifecycle states (WaitingFor* schema):
      WaitingForIntake -> WaitingForGovernanceInvitation -> WaitingForGovernanceRequestSent ->
      WaitingForGovernanceApproval -> WaitingForGDAPAccessAssignments -> WaitingForBootstrapAccount ->
      WaitingForSubscriptionAcceptance -> WaitingForLighthouseAcceptance ->
      WaitingForGovernanceBaseline -> ReadyForDeployment -> Deploying ->
      WaitingForConnectorConsent -> ValidatingDeployment -> CustomerValidation ->
      InService -> Blocked -> Offboarding -> Offboarded

    TEST_REQUIRED:
      - Verify StateFilePath points to the correct customer state file
      - Confirm lifecycleState transitions follow the documented order above
      - State file structure must match onboarding-state.schema.json
#>
param(
    [Parameter(Mandatory)][string]$StateFilePath,
    [Parameter(Mandatory)][string]$StepName,
    [Parameter(Mandatory)]
    [ValidateSet('pending','in-progress','succeeded','failed','manual-required')]
    [string]$StepStatus,
    [ValidateSet(
        'WaitingForIntake',
        'WaitingForGovernanceInvitation',
        'WaitingForGovernanceRequestSent',
        'WaitingForGovernanceApproval',
        'WaitingForGDAPAccessAssignments',
        'WaitingForBootstrapAccount',
        'WaitingForSubscriptionAcceptance',
        'WaitingForLighthouseAcceptance',
        'WaitingForGovernanceBaseline',
        'ReadyForDeployment',
        'Deploying',
        'WaitingForConnectorConsent',
        'ValidatingDeployment',
        'CustomerValidation',
        'InService',
        'Blocked',
        'Offboarding',
        'Offboarded'
    )]
    [string]$LifecycleState,
    [string]$Notes,
    [string]$EvidencePath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

 Helpers # 
function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("state-update-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    Write-Host "  Evidence written: $file" -ForegroundColor DarkGray
    return $file
}

function Write-Status {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Get-StepStatusColor {
    param([string]$Status)
    switch ($Status) {
        'succeeded'       { 'Green' }
        'failed'          { 'Red' }
        'in-progress'     { 'Cyan' }
        'manual-required' { 'Yellow' }
        'pending'         { 'Gray' }
        default           { 'White' }
    }
}

 Default state structure (aligned to onboarding-state.schema.json) # 
$defaultState = [ordered]@{
    '$schema'         = 'onboarding-state.schema.json'
    customerId        = ''
    customerShortName = ''
    lifecycleState    = 'WaitingForIntake'
    createdAt         = (Get-Date).ToUniversalTime().ToString('o')
    updatedAt         = (Get-Date).ToUniversalTime().ToString('o')
    steps             = @()
}

$evidenceData = @{
    scriptName    = 'Update-OnboardingState'
    stateFilePath = $StateFilePath
    stepName      = $StepName
    stepStatus    = $StepStatus
    status        = 'started'
    timestampUtc  = (Get-Date).ToUniversalTime().ToString('o')
    testRequired  = @(
        'Verify StateFilePath points to the correct customer state file',
        'Confirm lifecycleState transitions are in correct order'
    )
    changes       = [ordered]@{}
}

 Load or create state file # 
$stateDir = Split-Path $StateFilePath -Parent
if ($stateDir -and -not (Test-Path $stateDir)) {
    $null = New-Item -ItemType Directory -Force -Path $stateDir
}

if (Test-Path $StateFilePath) {
    Write-Status "Loading existing state file: $StateFilePath"
    $state = Get-Content $StateFilePath -Raw | ConvertFrom-Json
    $stateObj = [ordered]@{
        '$schema'         = $state.'$schema' ?? 'onboarding-state.schema.json'
        customerId        = $state.customerId ?? ''
        customerShortName = $state.customerShortName ?? ''
        lifecycleState    = $state.lifecycleState ?? 'WaitingForIntake'
        createdAt         = $state.createdAt ?? (Get-Date).ToUniversalTime().ToString('o')
        updatedAt         = (Get-Date).ToUniversalTime().ToString('o')
        steps             = [System.Collections.Generic.List[object]]::new()
    }
    foreach ($s in $state.steps) {
        $stateObj.steps.Add([ordered]@{
            name         = $s.name
            status       = $s.status
            completedAt  = $s.completedAt
            evidencePath = $s.evidencePath
            notes        = $s.notes ?? ''
        })
    }
    $evidenceData.changes['fileAction'] = 'loaded-existing'
} else {
    Write-Status "State file not  creating new: $StateFilePath" -Color Yellowfound 
    $stateObj = $defaultState.Clone()
    $stateObj.steps = [System.Collections.Generic.List[object]]::new()
    $evidenceData.changes['fileAction'] = 'created-new'
}

$evidenceData.customerShortName = $stateObj.customerShortName
$previousLifecycle = $stateObj.lifecycleState

 Find or create step # 
$existingStep = $stateObj.steps | Where-Object { $_.name -eq $StepName }
$completionStatuses = @('succeeded', 'failed', 'manual-required')
$nowUtc = (Get-Date).ToUniversalTime().ToString('o')

if ($existingStep) {
    $previousStatus = $existingStep.status
    Write-Status "Updating step '$StepName': $previousStatus -> $StepStatus"

    $existingStep.status = $StepStatus
    if ($StepStatus -in $completionStatuses) { $existingStep.completedAt = $nowUtc }
    if ($EvidencePath) { $existingStep.evidencePath = $EvidencePath }
    if ($Notes) { $existingStep.notes = $Notes }

    $evidenceData.changes['stepAction']     = 'updated'
    $evidenceData.changes['previousStatus'] = $previousStatus
} else {
    Write-Status "Adding new step '$StepName' with status '$StepStatus'"
    $stateObj.steps.Add([ordered]@{
        name         = $StepName
        status       = $StepStatus
        completedAt  = if ($StepStatus -in $completionStatuses) { $nowUtc } else { $null }
        evidencePath = $EvidencePath ?? $null
        notes        = $Notes ?? ''
    })
    $evidenceData.changes['stepAction'] = 'added-new'
}

 Update lifecycle state # 
if ($LifecycleState) {
    Write-Status "Lifecycle transition: $previousLifecycle -> $LifecycleState" -Color Cyan
    $stateObj.lifecycleState = $LifecycleState
    $evidenceData.changes['lifecycleTransition'] = "$previousLifecycle -> $LifecycleState"
}

$stateObj.updatedAt = $nowUtc

 Write state file # 
if ($WhatIfMode) {
    Write-Status "[WHATIF] Would update step '$StepName' to '$StepStatus' in: $StateFilePath" -Color Magenta
    if ($LifecycleState) {
        Write-Status "[WHATIF] Would set lifecycle: $previousLifecycle -> $LifecycleState" -Color Magenta
    }
    $evidenceData.status = 'whatif-only'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    return
}

$stateObj | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFilePath -Encoding UTF8
Write-Status "State file updated: $StateFilePath" -Color Green
$evidenceData.changes['stateFilePath'] = $StateFilePath

 Print summary table # 
Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "  Customer     : $($stateObj.customerShortName)" -ForegroundColor White
Write-Host "  State File   : $StateFilePath" -ForegroundColor White
Write-Host ("  Lifecycle    : {0} -> {1}" -f $previousLifecycle, $stateObj.lifecycleState) `
    -ForegroundColor $(if ($LifecycleState) { 'Cyan' } else { 'Gray' })
Write-Host "================================================================" -ForegroundColor White
Write-Host ""
Write-Host ("  {0,-40} {1,-18} {2}" -f 'STEP', 'STATUS', 'COMPLETED') -ForegroundColor White
Write-Host ("  {0,-40} {1,-18} {2}" -f '----', '------', '---------') -ForegroundColor DarkGray

foreach ($step in $stateObj.steps) {
    $color     = Get-StepStatusColor -Status $step.status
    $completed = if ($step.completedAt) { ([datetime]$step.completedAt).ToString('yyyy-MM-dd HH:mm') } else { '' }
    $marker    = if ($step.name -eq $StepName) { '>' } else { ' ' }
    Write-Host ("  $marker {0,-38} " -f $step.name) -ForegroundColor White -NoNewline
    Write-Host ("{0,-18} " -f $step.status) -ForegroundColor $color -NoNewline
    Write-Host $completed -ForegroundColor DarkGray
}

Write-Host ""

$evidenceData.status = 'succeeded'
Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
Write-Status "=== Update-OnboardingState Complete ===" -Color Green
