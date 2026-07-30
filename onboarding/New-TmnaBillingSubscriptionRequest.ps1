Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Requests a new Azure subscription under the TMNA Enterprise Agreement enrollment account.
.DESCRIPTION
    Attempts to create an EA subscription via the Azure Billing REST API (async POST). Polls the
    Location header for the result. Records the subscription ID to the customer state file when
    available. Falls back to a MANUAL_ACTION if automation is blocked by EA portal approval gates.
    TEST_REQUIRED: Requires EA Account Owner or Subscription Creator role; test in non-prod EA
    first; async creation can take minutes.
    MANUAL_ACTION: TMNA EA portal may require manual approval; navigate to https://ea.azure.com >
    Account > Manage Subscriptions > Add Subscription; confirm offer type MS-AZR-0017P (EA);
    notify Azure admin team.
#>

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$TmnaEnrollmentAccountId,
    [string]$SubscriptionOfferType = 'MS-AZR-0017P',
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

$config    = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$shortName = $config.customer.shortName
$custName  = $config.customer.displayName ?? $shortName
$subName   = "TMNA-MSSP-$shortName"

if (-not (Test-Path $EvidenceOutputPath)) { New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null }

$stateDir  = '.\state'
if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
$stateFile = Join-Path $stateDir "$shortName-state.json"

function Write-Evidence {
    param([hashtable]$Data)
    $ts      = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile = Join-Path $EvidenceOutputPath ("evidence-New-TmnaBillingSubscriptionRequest-{0}-{1}.json" -f $shortName, $ts)
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "[Evidence] Written: $outFile" -ForegroundColor Cyan
}

function Update-StateFile {
    param([string]$SubscriptionId, [string]$StatusMsg)
    if (-not (Test-Path $stateFile)) { return }
    try {
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json
        # Add or update billing subscription fields
        if (-not $state.PSObject.Properties['billingSubscriptionId']) {
            $state | Add-Member -MemberType NoteProperty -Name 'billingSubscriptionId' -Value $SubscriptionId -Force
        } else {
            $state.billingSubscriptionId = $SubscriptionId
        }
        if (-not $state.PSObject.Properties['billingStatus']) {
            $state | Add-Member -MemberType NoteProperty -Name 'billingStatus' -Value $StatusMsg -Force
        } else {
            $state.billingStatus = $StatusMsg
        }
        $state.updatedAt = (Get-Date).ToUniversalTime().ToString('o')
        $state | ConvertTo-Json -Depth 10 | Set-Content -Path $stateFile -Encoding UTF8
        Write-Host "[State] Updated state file: $stateFile" -ForegroundColor Gray
    } catch {
        Write-Warning "Failed to update state file: $_"
    }
}

function Get-ArmToken {
    try {
        return (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop).Token
    } catch {
        throw "Unable to acquire ARM token. Ensure Az.Accounts is connected: $_"
    }
}

function Poll-AsyncOperation {
    param([string]$Token, [string]$LocationUri, [int]$MaxWaitSeconds = 300)
    $headers     = @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $pollStart   = Get-Date
    $pollInterval = 15

    Write-Host "[Poll] Polling async subscription creation: $LocationUri" -ForegroundColor Cyan
    while ($true) {
        Start-Sleep -Seconds $pollInterval
        $elapsed = ((Get-Date) - $pollStart).TotalSeconds
        if ($elapsed -gt $MaxWaitSeconds) {
            Write-Warning "[Poll] Timed out after $($MaxWaitSeconds)s. Subscription may still be provisioning."
            return $null
        }
        try {
            $resp = Invoke-RestMethod -Uri $LocationUri -Method GET -Headers $headers -ErrorAction Stop
            $provState = $resp?.properties?.provisioningState ?? $resp?.status
            Write-Host "[Poll] Status: $provState ($([math]::Round($elapsed))s elapsed)" -ForegroundColor Gray
            if ($provState -in @('Succeeded', 'Completed')) {
                return $resp
            } elseif ($provState -in @('Failed', 'Canceled')) {
                Write-Warning "[Poll] Provisioning failed/canceled: $($resp | ConvertTo-Json -Depth 5)"
                return $null
            }
        } catch {
            if ($_.Exception.Response?.StatusCode -eq 202) {
                Write-Host "[Poll] Still provisioning ..." -ForegroundColor Gray
            } else {
                Write-Warning "[Poll] Error polling: $_"
            }
        }
    }
}

Write-Host "`n[Script 26] New-TmnaBillingSubscriptionRequest | Customer: $shortName" -ForegroundColor Green
Write-Host "  Enrollment Account : $TmnaEnrollmentAccountId" -ForegroundColor Gray
Write-Host "  Offer Type         : $SubscriptionOfferType" -ForegroundColor Gray
Write-Host "  Subscription Name  : $subName" -ForegroundColor Gray

# MANUAL_ACTION: If EA portal gates block automation, navigate to:
# https://ea.azure.com > Account > Manage Subscriptions > Add Subscription
# Confirm offer type MS-AZR-0017P (EA); notify Azure admin team
Write-Host "`n[Note] MANUAL_ACTION available if EA portal blocks automation:" -ForegroundColor Yellow
Write-Host "  Navigate to https://ea.azure.com > Account > Manage Subscriptions > Add Subscription" -ForegroundColor Yellow
Write-Host "  Offer type: MS-AZR-0017P | Subscription name: $subName" -ForegroundColor Yellow

if ($WhatIfMode) {
    Write-Host "`n[WhatIf] Would POST subscription creation to EA enrollment account '$TmnaEnrollmentAccountId'" -ForegroundColor Yellow
    Write-Evidence @{
        scriptName            = 'New-TmnaBillingSubscriptionRequest'
        customerShortName     = $shortName
        status                = 'whatif-only'
        timestampUtc          = (Get-Date).ToUniversalTime().ToString('o')
        enrollmentAccountId   = $TmnaEnrollmentAccountId
        subscriptionOfferType = $SubscriptionOfferType
        subscriptionName      = $subName
        testRequired          = @(
            'TEST_REQUIRED: Requires EA Account Owner or Subscription Creator role',
            'TEST_REQUIRED: Test in non-prod EA enrollment account first',
            'TEST_REQUIRED: Async creation can take 5-30 minutes'
        )
        manualAction          = 'Navigate to https://ea.azure.com > Account > Manage Subscriptions > Add Subscription if automation is blocked'
        subscriptionId        = $null
    }
    exit 0
}

$armToken = Get-ArmToken
$headers  = @{ 'Authorization' = "Bearer $armToken"; 'Content-Type' = 'application/json' }

$createUri = "https://management.azure.com/providers/Microsoft.Billing/enrollmentAccounts/$TmnaEnrollmentAccountId/providers/Microsoft.Subscription/createSubscription?api-version=2019-10-01-preview"

$body = @{
    displayName = $subName
    offerType   = $SubscriptionOfferType
    owners      = @(
        @{ objectId = (Get-AzContext).Account?.Id ?? '' }
    )
} | ConvertTo-Json -Depth 5

$subscriptionId  = $null
$finalStatus     = 'pending'
$asyncLocationUri = $null

Write-Host "`n[API] Submitting subscription creation request ..." -ForegroundColor Cyan

try {
    # EA subscription creation returns 202 Accepted with Location header
    $response = Invoke-WebRequest -Uri $createUri -Method POST -Headers $headers -Body $body -ErrorAction Stop

    if ($response.StatusCode -eq 202) {
        $asyncLocationUri = $response.Headers['Location']
        Write-Host "[API] Accepted (202). Async operation URI: $asyncLocationUri" -ForegroundColor Green

        if ($asyncLocationUri) {
            $pollResult = Poll-AsyncOperation -Token $armToken -LocationUri $asyncLocationUri -MaxWaitSeconds 300
            if ($pollResult) {
                $subscriptionId = $pollResult?.subscriptionLink -replace '.*/subscriptions/', ''
                if (-not $subscriptionId) { $subscriptionId = $pollResult?.id -replace '.*/subscriptions/', '' }
                $finalStatus = 'succeeded'
                Write-Host "[OK] Subscription created: $subscriptionId" -ForegroundColor Green
                Update-StateFile -SubscriptionId $subscriptionId -StatusMsg 'created'
            } else {
                $finalStatus = 'async-timeout'
                Write-Warning "[Pending] Subscription still provisioning. Check EA portal."
                Write-Host "[MANUAL_ACTION] Navigate to https://ea.azure.com to confirm subscription status." -ForegroundColor Yellow
            }
        } else {
            $finalStatus = 'submitted-no-location'
            Write-Warning "No Location header returned. Check EA portal for subscription status."
        }
    } elseif ($response.StatusCode -in @(200, 201)) {
        $respBody   = $response.Content | ConvertFrom-Json
        $subscriptionId = $respBody?.subscriptionLink -replace '.*/subscriptions/', ''
        $finalStatus = 'succeeded'
        Write-Host "[OK] Subscription created synchronously: $subscriptionId" -ForegroundColor Green
        Update-StateFile -SubscriptionId $subscriptionId -StatusMsg 'created'
    } else {
        $finalStatus = "unexpected-status-$($response.StatusCode)"
        Write-Warning "Unexpected response status: $($response.StatusCode)"
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Warning "[Error] Subscription creation API call failed: $errMsg"
    Write-Host "`n[MANUAL_ACTION] Automated creation failed. Please:" -ForegroundColor Red
    Write-Host "  1. Navigate to https://ea.azure.com" -ForegroundColor Yellow
    Write-Host "  2. Account > Manage Subscriptions > Add Subscription" -ForegroundColor Yellow
    Write-Host "  3. Subscription name: $subName | Offer: $SubscriptionOfferType" -ForegroundColor Yellow
    Write-Host "  4. Notify Azure admin team to approve" -ForegroundColor Yellow
    $finalStatus = 'manual-action-required'
}

Write-Evidence @{
    scriptName            = 'New-TmnaBillingSubscriptionRequest'
    customerShortName     = $shortName
    status                = $finalStatus
    timestampUtc          = (Get-Date).ToUniversalTime().ToString('o')
    enrollmentAccountId   = $TmnaEnrollmentAccountId
    subscriptionOfferType = $SubscriptionOfferType
    subscriptionName      = $subName
    subscriptionId        = $subscriptionId
    asyncLocationUri      = $asyncLocationUri
    stateFile             = $stateFile
    testRequired          = @(
        'TEST_REQUIRED: Requires EA Account Owner or Subscription Creator role on enrollment account',
        'TEST_REQUIRED: Test in non-prod EA enrollment account before production use',
        'TEST_REQUIRED: Async creation can take 5-30 minutes; confirm via EA portal'
    )
    manualAction          = 'If automation blocked: https://ea.azure.com > Account > Manage Subscriptions > Add Subscription'
}

if ($finalStatus -eq 'manual-action-required') { exit 2 }
