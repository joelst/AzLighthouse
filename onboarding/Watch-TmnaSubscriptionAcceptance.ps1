Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Polls until a TMNA-created Azure subscription reaches 'Enabled' state.
.DESCRIPTION
    Loads the expected subscription ID from state file or parameter, then polls
    Get-AzSubscription on a configurable interval until the subscription is Enabled,
    or times out. Updates the customer state file on confirmation. Handles
    PastDue/Disabled/Deleted states with billing escalation guidance.
    TEST_REQUIRED: EA subscription creation can take up to 30 minutes to appear;
    test timeout behavior; PastDue/Disabled states need billing team escalation.
#>

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [string]$ExpectedSubscriptionId,
    [int]$PollIntervalSeconds = 60,
    [int]$TimeoutMinutes = 60,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

$config    = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$shortName = $config.customer.shortName

if (-not (Test-Path $EvidenceOutputPath)) { New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null }

$stateDir  = '.\state'
$stateFile = Join-Path $stateDir "$shortName-state.json"

function Write-Evidence {
    param([hashtable]$Data)
    $ts      = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile = Join-Path $EvidenceOutputPath ("evidence-Watch-TmnaSubscriptionAcceptance-{0}-{1}.json" -f $shortName, $ts)
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "[Evidence] Written: $outFile" -ForegroundColor Cyan
}

function Get-StateValue {
    param([string]$Key)
    if (-not (Test-Path $stateFile)) { return $null }
    try {
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json
        return $state.PSObject.Properties[$Key]?.Value
    } catch { return $null }
}

function Update-StateFile {
    param([string]$SubscriptionId, [string]$SubscriptionState, [string]$LifecycleState)
    if (-not (Test-Path $stateFile)) { return }
    try {
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json

        foreach ($prop in @('billingSubscriptionId','billingSubscriptionState','lifecycleState','updatedAt')) {
            if (-not $state.PSObject.Properties[$prop]) {
                $state | Add-Member -MemberType NoteProperty -Name $prop -Value $null -Force
            }
        }
        $state.billingSubscriptionId    = $SubscriptionId
        $state.billingSubscriptionState = $SubscriptionState
        if ($LifecycleState) { $state.lifecycleState = $LifecycleState }
        $state.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        $state | ConvertTo-Json -Depth 10 | Set-Content -Path $stateFile -Encoding UTF8
        Write-Host "[State] Updated: $stateFile" -ForegroundColor Gray
    } catch {
        Write-Warning "Failed to update state file: $_"
    }
}

# Resolve subscription ID: parameter > state file
if (-not $ExpectedSubscriptionId) {
    $ExpectedSubscriptionId = Get-StateValue -Key 'billingSubscriptionId'
}
if (-not $ExpectedSubscriptionId) {
    throw "No ExpectedSubscriptionId provided and none found in state file '$stateFile'. Run New-TmnaBillingSubscriptionRequest first."
}

Write-Host "`n[Script 27] Watch-TmnaSubscriptionAcceptance | Customer: $shortName" -ForegroundColor Green
Write-Host "  Subscription ID    : $ExpectedSubscriptionId" -ForegroundColor Gray
Write-Host "  Poll Interval      : ${PollIntervalSeconds}s" -ForegroundColor Gray
Write-Host "  Timeout            : ${TimeoutMinutes}min" -ForegroundColor Gray

if ($WhatIfMode) {
    Write-Host "`n[WhatIf] Would poll subscription '$ExpectedSubscriptionId' every ${PollIntervalSeconds}s (max ${TimeoutMinutes}min)" -ForegroundColor Yellow
    Write-Evidence @{
        scriptName          = 'Watch-TmnaSubscriptionAcceptance'
        customerShortName   = $shortName
        status              = 'whatif-only'
        timestampUtc        = (Get-Date).ToUniversalTime().ToString('o')
        expectedSubId       = $ExpectedSubscriptionId
        pollIntervalSeconds = $PollIntervalSeconds
        timeoutMinutes      = $TimeoutMinutes
        testRequired        = @(
            'TEST_REQUIRED: EA subscription creation can take up to 30 minutes to appear',
            'TEST_REQUIRED: Test timeout behavior with a short TimeoutMinutes value',
            'TEST_REQUIRED: PastDue/Disabled states require billing team escalation'
        )
        subscriptionState   = 'whatif'
    }
    exit 0
}

# Validate Az module connectivity
try {
    $ctx = Get-AzContext -ErrorAction Stop
    if (-not $ctx) { throw "No Azure context. Run Connect-AzAccount first." }
    Write-Host "  Az Context         : $($ctx.Account) / $($ctx.Tenant.Id)" -ForegroundColor Gray
} catch {
    throw "Azure context check failed: $_"
}

$timeoutAt   = (Get-Date).AddMinutes($TimeoutMinutes)
$pollCount   = 0
$finalState  = 'unknown'
$confirmed   = $false
$startTime   = Get-Date

Write-Host "`n[Poll] Starting subscription state polling ..." -ForegroundColor Cyan
Write-Host ("  {0,-24} {1,-16} {2}" -f "Timestamp (UTC)", "Sub State", "Elapsed") -ForegroundColor White
Write-Host ("-" * 60) -ForegroundColor DarkGray

while ((Get-Date) -lt $timeoutAt) {
    $pollCount++
    $elapsed   = ((Get-Date) - $startTime)
    $elapsedFmt = "{0:mm\:ss}" -f $elapsed
    $nowUtc    = (Get-Date).ToUniversalTime().ToString('HH:mm:ss')

    try {
        $sub = Get-AzSubscription -SubscriptionId $ExpectedSubscriptionId -ErrorAction SilentlyContinue

        if ($null -eq $sub) {
            $finalState = 'not-found'
            $color = 'Yellow'
            Write-Host ("  {0,-24} {1,-16} {2}" -f $nowUtc, 'not-found', $elapsedFmt) -ForegroundColor $color
        } else {
            $finalState = $sub.State
            $color = switch ($sub.State) {
                'Enabled'   { 'Green'  }
                'PastDue'   { 'Red'    }
                'Disabled'  { 'Red'    }
                'Deleted'   { 'Red'    }
                'Warned'    { 'Yellow' }
                default     { 'Gray'   }
            }
            Write-Host ("  {0,-24} {1,-16} {2}" -f $nowUtc, $sub.State, $elapsedFmt) -ForegroundColor $color

            if ($sub.State -eq 'Enabled') {
                $confirmed = $true
                Write-Host "`n[SUCCESS] Subscription '$ExpectedSubscriptionId' is Enabled!" -ForegroundColor Green
                Update-StateFile -SubscriptionId $ExpectedSubscriptionId -SubscriptionState 'Enabled' -LifecycleState 'live'
                break
            }

            if ($sub.State -in @('Disabled', 'Deleted', 'Warned')) {
                Write-Host "`n[ALERT] Subscription state '$($sub.State)' requires immediate attention!" -ForegroundColor Red
                Write-Host "[ESCALATION] Contact billing team:" -ForegroundColor Red
                Write-Host "  - State '$($sub.State)' may indicate EA quota/spending limit issue" -ForegroundColor Yellow
                Write-Host "  - Navigate to https://ea.azure.com > Reports > Usage Summary" -ForegroundColor Yellow
                Write-Host "  - Contact: Azure Billing Support or TMNA Azure Admin team" -ForegroundColor Yellow
                Update-StateFile -SubscriptionId $ExpectedSubscriptionId -SubscriptionState $sub.State -LifecycleState $null
                break
            }

            if ($sub.State -eq 'PastDue') {
                Write-Host "`n[ALERT] Subscription is PastDue. Billing team escalation required." -ForegroundColor Red
                Write-Host "  Navigate to https://portal.azure.com > Subscriptions > $ExpectedSubscriptionId > Billing" -ForegroundColor Yellow
                Update-StateFile -SubscriptionId $ExpectedSubscriptionId -SubscriptionState 'PastDue' -LifecycleState $null
                break
            }
        }
    } catch {
        Write-Warning "  [Poll Error] $($_.Exception.Message)"
    }

    # Check timeout before sleeping
    $remaining = $timeoutAt - (Get-Date)
    if ($remaining.TotalSeconds -le $PollIntervalSeconds) {
        Write-Warning "[Timeout] Less than ${PollIntervalSeconds}s remaining. Stopping poll."
        break
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}

$totalElapsed = ((Get-Date) - $startTime)

if (-not $confirmed -and $finalState -ne 'Enabled') {
    if (((Get-Date) -ge $timeoutAt) -or $finalState -in @('not-found','unknown')) {
        Write-Warning "`n[Timeout] Subscription '$ExpectedSubscriptionId' did not reach Enabled state within ${TimeoutMinutes} minutes."
        Write-Host "[Next Steps]" -ForegroundColor Yellow
        Write-Host "  1. Check EA portal: https://ea.azure.com > Account > Manage Subscriptions" -ForegroundColor Yellow
        Write-Host "  2. Re-run this script with a longer -TimeoutMinutes value" -ForegroundColor Yellow
        Write-Host "  3. Verify New-TmnaBillingSubscriptionRequest completed successfully" -ForegroundColor Yellow
    }
}

$evidenceStatus = if ($confirmed) { 'succeeded' } elseif ($finalState -in @('PastDue','Disabled','Deleted')) { 'billing-escalation-required' } else { 'timed-out' }

Write-Host "`n[Summary] Polls: $pollCount | Final State: $finalState | Duration: $("{0:mm\:ss}" -f $totalElapsed)" -ForegroundColor Cyan

Write-Evidence @{
    scriptName          = 'Watch-TmnaSubscriptionAcceptance'
    customerShortName   = $shortName
    status              = $evidenceStatus
    timestampUtc        = (Get-Date).ToUniversalTime().ToString('o')
    expectedSubId       = $ExpectedSubscriptionId
    finalSubscriptionState = $finalState
    confirmed           = $confirmed
    pollCount           = $pollCount
    pollIntervalSeconds = $PollIntervalSeconds
    timeoutMinutes      = $TimeoutMinutes
    totalDurationSeconds = [math]::Round($totalElapsed.TotalSeconds, 2)
    stateFile           = $stateFile
    testRequired        = @(
        'TEST_REQUIRED: EA subscription creation can take up to 30 minutes to appear in ARM',
        'TEST_REQUIRED: Test timeout behavior with TimeoutMinutes=2 and a short PollIntervalSeconds=10',
        'TEST_REQUIRED: PastDue/Disabled states require billing team escalation process validation'
    )
}

if (-not $confirmed) { exit 1 }
