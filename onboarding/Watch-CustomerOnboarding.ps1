#Requires -Version 7.0

# TEST_REQUIRED: Ensure RSOC context has delegation; Log Analytics query requires workspace access

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [int]$PollIntervalSeconds = 60,
    [int]$TimeoutMinutes      = 120,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = ".\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptName        = "Watch-CustomerOnboarding"
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$subscriptionId    = $config.deployment.subscriptionId
$resourceGroupName = $config.deployment.resourceGroupName
$workspaceName     = $config.deployment.sentinelWorkspaceName

function Write-Evidence {
    param([hashtable]$Data)
    if (-not (Test-Path $EvidenceOutputPath)) {
        New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null
    }
    $ts       = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $filePath = Join-Path $EvidenceOutputPath "$scriptName-$ts.json"
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
    return $filePath
}

function Get-StateFilePath {
    $stateDir = Split-Path $CustomerConfigPath -Parent
    return Join-Path $stateDir "onboarding-state.json"
}

function Read-State {
    $stateFile = Get-StateFilePath
    if (Test-Path $stateFile) {
        return Get-Content $stateFile -Raw | ConvertFrom-Json
    }
    return $null
}

function Write-StepStatus {
    param([string]$StepName, [string]$Status, [string]$Notes = "")
    $stateFile = Get-StateFilePath
    $state     = Read-State
    if ($null -eq $state) {
        Write-Host "  [Watch] State file not found; skipping state update for step '$StepName'" -ForegroundColor Gray
        return
    }
    $step = $state.steps | Where-Object { $_.name -eq $StepName } | Select-Object -First 1
    if ($null -eq $step) {
        $newStep = [PSCustomObject]@{
            name          = $StepName
            status        = $Status
            completedAt   = if ($Status -eq 'succeeded') { (Get-Date).ToUniversalTime().ToString("o") } else { $null }
            evidencePath  = ""
            notes         = $Notes
        }
        $stepsList = [System.Collections.Generic.List[object]]::new($state.steps)
        $stepsList.Add($newStep)
        $state.steps = $stepsList.ToArray()
    } else {
        $step.status = $Status
        $step.notes  = $Notes
        if ($Status -eq 'succeeded') {
            $step.completedAt = (Get-Date).ToUniversalTime().ToString("o")
        }
    }
    $state | ConvertTo-Json -Depth 10 | Out-File -FilePath $stateFile -Encoding utf8
}

function Write-StatusTable {
    param([hashtable]$CheckResults, [int]$Cycle, [datetime]$StartTime)
    $elapsed  = [int]((Get-Date) - $StartTime).TotalSeconds
    $remaining = ($TimeoutMinutes * 60) - $elapsed
    Write-Host "`n" -ForegroundColor DarkGray
    Write-Host " Watch-CustomerOnboarding  |  Cycle: $Cycle  |  Elapsed: ${elapsed}s  |  Remaining: ${remaining}s" -ForegroundColor Cyan
    Write-Host " Customer: $customerShortName  |  Subscription: $subscriptionId" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor DarkGray
    foreach ($key in @('LighthouseDelegation','SentinelWorkspace','AutomationAccount','ConnectorData')) {
        $result = $CheckResults[$key]
        $icon   = if ($result.passed) { '[OK] ' } else { '[--] ' }
        $color  = if ($result.passed) { 'Green' } else { 'Yellow' }
        Write-Host "$icon $key" -ForegroundColor $color -NoNewline
        Write-Host "  $($result.detail)" -ForegroundColor Gray
    }
    $allPassed = $CheckResults.Values | Where-Object { -not $_.passed } | Measure-Object
    if ($allPassed.Count -eq 0) {
        Write-Host "`n  All checks passed! Onboarding complete." -ForegroundColor Green
    } else {
        Write-Host "`n  Next poll in ${PollIntervalSeconds}s ..." -ForegroundColor DarkGray
    }
" -ForegroundColor DarkGray    Write-Host "
}

# WhatIf short-circuit
if ($WhatIfMode) {
    Write-Host "[WhatIf] Would poll subscription $subscriptionId every ${PollIntervalSeconds}s for up to ${TimeoutMinutes}m" -ForegroundColor Yellow
    $ep = Write-Evidence -Data @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString("o")
        testRequired      = @("Ensure RSOC context has delegation","Log Analytics query requires workspace access")
        pollIntervalSeconds = $PollIntervalSeconds
        timeoutMinutes    = $TimeoutMinutes
    }
    Write-Host "Evidence: $ep"
    exit 0
}

# Poll loop
Write-Host "`n=== Watch-CustomerOnboarding ===" -ForegroundColor Cyan
Write-Host "Polling every ${PollIntervalSeconds}s, timeout ${TimeoutMinutes}m`n"

$null = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop

$startTime  = Get-Date
$timeoutAt  = $startTime.AddMinutes($TimeoutMinutes)
$cycle      = 0
$cycleResults = [System.Collections.Generic.List[hashtable]]::new()

do {
    $cycle++
    $checks = @{}

    # 1. Lighthouse delegation
    try {
        $assignments = Get-AzManagedServicesAssignment -Scope "/subscriptions/$subscriptionId" -ErrorAction Stop
        $hasDelegation = $null -ne $assignments -and $assignments.Count -gt 0
        $checks['LighthouseDelegation'] = @{
            passed = $hasDelegation
            detail = if ($hasDelegation) { "$($assignments.Count) assignment(s) found" } else { "No assignments found" }
        }
        if ($hasDelegation) { Write-StepStatus -StepName 'lighthouse-accepted' -Status 'succeeded' }
    } catch {
        $checks['LighthouseDelegation'] = @{ passed = $false; detail = $_.Exception.Message }
    }

    # 2. Sentinel workspace
    try {
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName `
              -Name $workspaceName -ErrorAction Stop
        $wsOk = $ws.ProvisioningState -eq 'Succeeded'
        $checks['SentinelWorkspace'] = @{
            passed = $wsOk
            detail = "ProvisioningState: $($ws.ProvisioningState)  |  Location: $($ws.Location)"
        }
        if ($wsOk) { Write-StepStatus -StepName 'sentinel-deployed' -Status 'succeeded' }
    } catch {
        $checks['SentinelWorkspace'] = @{ passed = $false; detail = $_.Exception.Message }
    }

    # 3. Automation account
    try {
        $aa = Get-AzAutomationAccount -ResourceGroupName $resourceGroupName -ErrorAction Stop |
              Select-Object -First 1
        $aaOk = $null -ne $aa
        $checks['AutomationAccount'] = @{
            passed = $aaOk
            detail = if ($aaOk) { "Account: $($aa.AutomationAccountName)" } else { "Not found in $resourceGroupName" }
        }
        if ($aaOk) { Write-StepStatus -StepName 'automation-deployed' -Status 'succeeded' }
    } catch {
        $checks['AutomationAccount'] = @{ passed = $false; detail = $_.Exception.Message }
    }

    # 4. Connector data (recent rows in CommonSecurityLog or SecurityEvent)
    try {
        $workspaceId = (Get-AzOperationalInsightsWorkspace `
            -ResourceGroupName $resourceGroupName -Name $workspaceName -ErrorAction Stop).CustomerId.Guid
        $kqlQuery = @"
union isfuzzy=true
    (CommonSecurityLog | where TimeGenerated > ago(1h) | summarize Count=count()),
    (SecurityEvent     | where TimeGenerated > ago(1h) | summarize Count=count())
| summarize TotalRows=sum(Count)
"@
        $result   = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kqlQuery -ErrorAction Stop
        $rowCount = [int]($result.Results[0].TotalRows ?? 0)
        $dataOk   = $rowCount -gt 0
        $checks['ConnectorData'] = @{
            passed = $dataOk
            detail = "Rows in last 1h: $rowCount"
        }
        if ($dataOk) { Write-StepStatus -StepName 'connectors-enabled' -Status 'succeeded' }
    } catch {
        $checks['ConnectorData'] = @{ passed = $false; detail = $_.Exception.Message }
    }

    Write-StatusTable -CheckResults $checks -Cycle $cycle -StartTime $startTime

    $cycleResults.Add(@{
        cycle       = $cycle
        timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        checks      = $checks
    })

    $allPassed = ($checks.Values | Where-Object { -not $_.passed } | Measure-Object).Count -eq 0
    if ($allPassed) { break }

    if ((Get-Date) -lt $timeoutAt) {
        Start-Sleep -Seconds $PollIntervalSeconds
    }

} while ((Get-Date) -lt $timeoutAt)

$finalStatus = if ($allPassed) { 'passed' } else { 'timed-out' }
if ($finalStatus -eq 'timed-out') {
    Write-Host "`n[WARN] Watch timed out after $TimeoutMinutes minutes." -ForegroundColor Yellow
}

$evidenceData = @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = $finalStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString("o")
    testRequired      = @(
        "Ensure RSOC context has Lighthouse delegation",
        "Log Analytics query requires workspace Contributor or Reader"
    )
    totalCycles       = $cycle
    elapsedMinutes    = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
    finalChecks       = $checks
    cycleHistory      = $cycleResults.ToArray()
}

$ep = Write-Evidence -Data $evidenceData
Write-Host "Evidence: $ep"
