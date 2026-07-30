#Requires -Version 7.0
<#
.SYNOPSIS
    Connect-DefenderPortalSentinel.ps1 - Connects Microsoft Defender portal to Sentinel workspace.
.DESCRIPTION
    Verifies Sentinel workspace exists, checks caller roles, attempts to detect existing
    Defender/Sentinel connection via REST, then emits a MANUAL_ACTION block with exact
    portal steps because the connect operation requires human interaction in the Defender portal.
    MANUAL_ACTION: Navigate to https://security.microsoft.com > Settings > Microsoft Sentinel
                   and connect the workspace manually.
    TEST_REQUIRED: Defender workspace connection API is not publicly documented; using
                   Anomalies settings endpoint as a proxy to verify Sentinel is active.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
    [Parameter(Mandatory)]
    [string]$CustomerConfigPath,

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = ".\evidence"
)

$scriptName = "Connect-DefenderPortalSentinel"

 Config # 
$config             = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName  = $config.customer.shortName
$subscriptionId     = $config.deployment.subscriptionId
$resourceGroupName  = $config.deployment.resourceGroupName
$workspaceName      = $config.deployment.sentinelWorkspaceName

if (-not (Test-Path $EvidenceOutputPath)) {
    New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null
}

function Write-Evidence {
    param([hashtable]$Data)
    $ts   = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $file = Join-Path $EvidenceOutputPath "$scriptName-$customerShortName-$ts.json"
    $Data | ConvertTo-Json -Depth 10 | Set-Content $file -Encoding UTF8
    Write-Host "Evidence written: $file" -ForegroundColor Cyan
    return $file
}

$testRequired = @(
    "Defender workspace connection API endpoint not publicly documented; Anomalies endpoint used as proxy",
    "Defender/Sentinel portal connection requires human interaction at https://security.microsoft.com"
)

$checks = [System.Collections.Generic.List[hashtable]]::new()

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $checks.Add(@{ name = $Name; status = $Status; detail = $Detail })
    $color = switch ($Status) { 'pass' { 'Green' } 'warn' { 'Yellow' } default { 'Red' } }
    Write-Host "  [$Status] $Name : $Detail" -ForegroundColor $color
}

Write-Host "=== Connect-DefenderPortalSentinel ===" -ForegroundColor Yellow
Write-Host "Customer  : $customerShortName"
Write-Host "Workspace : $workspaceName"
Write-Host "Sub       : $subscriptionId"

 WhatIf early exit # 
if ($WhatIfMode) {
    Write-Host "[WHATIF] Would verify Sentinel workspace and emit manual connection steps." -ForegroundColor Magenta
    Write-Evidence @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        workspaceName     = $workspaceName
        subscriptionId    = $subscriptionId
        testRequired      = $testRequired
    }
    exit 0
}

 1. Verify Sentinel workspace exists # 
Write-Host "`n[1] Verifying Sentinel workspace..." -ForegroundColor Cyan
try {
    $workspace = Get-AzOperationalInsightsWorkspace `
        -ResourceGroupName $resourceGroupName `
        -Name $workspaceName `
        -ErrorAction Stop
    Add-Check "WorkspaceExists" "pass" "Workspace '$workspaceName' found in '$resourceGroupName' (sku=$($workspace.Sku))"
} catch {
    Add-Check "WorkspaceExists" "fail" "Could not retrieve workspace: $($_.Exception.Message)"
    Write-Evidence @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'failed'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        checks            = $checks
        testRequired      = $testRequired
    }
    throw
}

 2. Check caller role assignments # 
Write-Host "`n[2] Checking caller role assignments..." -ForegroundColor Cyan
$requiredRoles = @('Microsoft Sentinel Contributor', 'Security Administrator', 'Owner', 'Contributor')
try {
    $ctx           = Get-AzContext
    $callerObjectId = $ctx.Account.Id
    $scope          = "/subscriptions/$subscriptionId"
    $assignments    = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop

    $callerRoles = $assignments | Where-Object {
        $_.SignInName -eq $callerObjectId -or $_.ObjectId -eq $callerObjectId
    } | Select-Object -ExpandProperty RoleDefinitionName

    $hasSentinelContrib = $callerRoles -contains 'Microsoft Sentinel Contributor'
    $hasSecAdmin        = $callerRoles -contains 'Security Administrator'
    $hasOwner           = $callerRoles -contains 'Owner'

    if ($hasSentinelContrib) {
        Add-Check "RoleSentinelContributor" "pass" "Caller has Microsoft Sentinel Contributor"
    } else {
        Add-Check "RoleSentinelContributor" "warn" "Caller lacks Microsoft Sentinel Contributor (has: $($callerRoles -join ', '))"
    }

    if ($hasSecAdmin -or $hasOwner) {
        Add-Check "RoleSecurityAdmin" "pass" "Caller has Security Admin or Owner role"
    } else {
        Add-Check "RoleSecurityAdmin" "warn" "Caller may lack Security Administrator role; required for Defender connection"
    }
} catch {
    Add-Check "RoleCheck" "warn" "Could not enumerate roles: $($_.Exception.Message)"
}

 3. Check Sentinel is active via Anomalies settings endpoint # 
Write-Host "`n[3] Checking Sentinel activation via REST (Anomalies settings)..." -ForegroundColor Cyan
# TEST_REQUIRED: Defender workspace connection API endpoint not publicly documented;
# using Anomalies settings endpoint as proxy to verify Sentinel provider is registered.
$sentinelBase = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights"
$sentinelConnectionStatus = 'unknown'

try {
    $tokenResult = Get-AzAccessToken -ResourceUrl 'https://management.azure.com'
    $headers = @{
        'Authorization' = "Bearer $($tokenResult.Token)"
        'Content-Type'  = 'application/json'
    }
    $anomaliesUri = "$sentinelBase/settings/Anomalies?api-version=2023-02-01"
    $anomaliesResp = Invoke-RestMethod -Method GET -Uri $anomaliesUri -Headers $headers -ErrorAction Stop
    $sentinelConnectionStatus = 'sentinel-active'
    Add-Check "SentinelProviderActive" "pass" "Sentinel SecurityInsights provider is active on workspace (Anomalies settings returned successfully)"
} catch {
    $statusCode = $_.Exception.Response?.StatusCode.value__ ?? 0
    if ($statusCode -eq 404) {
        Add-Check "SentinelProviderActive" "warn" "Sentinel provider not yet active or workspace not onboarded (404 on Anomalies endpoint)"
        $sentinelConnectionStatus = 'sentinel-not-active'
    } else {
        Add-Check "SentinelProviderActive" "warn" "Could not check Anomalies endpoint (HTTP $statusCode): $($_.Exception.Message)"
        $sentinelConnectionStatus = 'check-failed'
    }
}

 4. MANUAL_ACTION block # 
Write-Host ""
" -ForegroundColor MagentaWrite-Host "
Write-Host "  MANUAL_ACTION REQUIRED: Connect Defender Portal to Sentinel" -ForegroundColor Magenta
" -ForegroundColor MagentaWrite-Host "
Write-Host "  The Defender portal <-> Sentinel workspace connection cannot" -ForegroundColor Magenta
Write-Host "  be automated via a documented public API. Follow these steps:" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Step 1: Navigate to https://security.microsoft.com" -ForegroundColor Yellow
Write-Host "  Step 2: Sign in with a Global Administrator or Security Administrator account" -ForegroundColor Yellow
Write-Host "  Step 3: Go to Settings (gear icon, bottom-left) > Microsoft Sentinel" -ForegroundColor Yellow
Write-Host "  Step 4: Click 'Connect a workspace'" -ForegroundColor Yellow
Write-Host "  Step 5: Select subscription: $subscriptionId" -ForegroundColor Yellow
Write-Host "  Step 6: Select resource group: $resourceGroupName" -ForegroundColor Yellow
Write-Host "  Step 7: Select workspace: $workspaceName" -ForegroundColor Yellow
Write-Host "  Step 8: Click 'Connect'" -ForegroundColor Yellow
Write-Host "  Step 9: Confirm the connection is established (green checkmark)" -ForegroundColor Yellow
Write-Host "  Step 10: Update state file to mark this step complete" -ForegroundColor Yellow
" -ForegroundColor MagentaWrite-Host "
Write-Host ""

$manualActions = @(
    "Navigate to https://security.microsoft.com",
    "Sign in as Global Administrator or Security Administrator",
    "Go to Settings > Microsoft Sentinel",
    "Click 'Connect a workspace'",
    "Select subscription: $subscriptionId",
    "Select resource group: $resourceGroupName",
    "Select workspace: $workspaceName",
    "Click Connect and confirm the green checkmark"
)

Write-Evidence @{
    scriptName                = $scriptName
    customerShortName         = $customerShortName
    status                    = 'manual-required'
    timestampUtc              = (Get-Date).ToUniversalTime().ToString('o')
    subscriptionId            = $subscriptionId
    resourceGroupName         = $resourceGroupName
    workspaceName             = $workspaceName
    sentinelConnectionStatus  = $sentinelConnectionStatus
    checks                    = $checks
    manualActions             = $manualActions
    testRequired              = $testRequired
}

Write-Host "Status: manual-required. Complete the Defender portal connection steps above." -ForegroundColor Magenta
