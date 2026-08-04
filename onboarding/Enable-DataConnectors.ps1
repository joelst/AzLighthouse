#Requires -Version 7.0
<#
.SYNOPSIS
    Enable-DataConnectors.ps1 - Enables Sentinel data connectors for the customer workspace.
.DESCRIPTION
    Enables automatable connectors (AzureActivity, MicrosoftDefenderForCloud) via Sentinel REST API,
    and emits MANUAL_ACTION instructions for connectors requiring portal GA steps
    (Office365, AzureActiveDirectory, MicrosoftThreatProtection).
    TEST_REQUIRED: Sentinel REST connector payloads differ per connector type; validate each body.
    TEST_REQUIRED: Some connectors require additional licensing (M365 E5, Defender licenses).
    MANUAL_ACTION: Office365, AzureActiveDirectory, MicrosoftThreatProtection require portal steps.
#>

param(
    [Parameter(Mandatory)]
    [string]$CustomerConfigPath,

    [string]$CustomerSubscriptionId,

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = ".\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptName = "Enable-DataConnectors"

# Config
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$tenantId          = $config.customer.tenantId
$subscriptionId    = $CustomerSubscriptionId `
                   ?? $config.deployment?.subscriptionId `
                   ?? (Get-AzContext).Subscription.Id
$resourceGroupName = $config.deployment.resourceGroupName
$workspaceName     = $config.deployment.sentinelWorkspaceName
$dataSources       = $config.dataSources ?? @()

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
    "Sentinel REST connector payloads differ per connector type; validate each body format against API docs",
    "Some connectors require additional M365 licensing (E5, Defender P2, etc.)",
    "api-version=2023-02-01 used for data connectors; verify currency at deployment time",
    "AzureActivity connector requires subscription-level Log Profile; validate scope"
)

$sentinelBase     = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights"
$connectorsBase   = "$sentinelBase/dataConnectors"
$apiVersion       = "api-version=2023-02-01"

$connectorResults = [System.Collections.Generic.List[hashtable]]::new()

Write-Host "=== Enable-DataConnectors ===" -ForegroundColor Yellow
Write-Host "Customer   : $customerShortName"
Write-Host "Workspace  : $workspaceName"
Write-Host "Sub        : $subscriptionId"
Write-Host "DataSources: $($dataSources -join ', ')"

# WhatIf early exit
if ($WhatIfMode) {
    Write-Host "[WHATIF] Would enable connectors for: $($dataSources -join ', ')" -ForegroundColor Magenta
    Write-Evidence @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        subscriptionId    = $subscriptionId
        workspaceName     = $workspaceName
        dataSources       = $dataSources
        testRequired      = $testRequired
    }
    exit 0
}

# Acquire management API token
Write-Host "`nAcquiring management API token..." -ForegroundColor Cyan
$tokenResult = Get-AzAccessToken -ResourceUrl 'https://management.azure.com'
$headers = @{
    'Authorization' = "Bearer $($tokenResult.Token)"
    'Content-Type'  = 'application/json'
}

# Helper: check if connector exists
function Get-ExistingConnector {
    param([string]$ConnectorId)
    try {
        $uri  = "$connectorsBase/$ConnectorId`?$apiVersion"
        $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
        return $resp
    } catch {
        $statusCode = $_.Exception.Response?.StatusCode.value__ ?? 0
        if ($statusCode -eq 404) { return $null }
        throw
    }
}

# Helper: PUT connector
function Set-SentinelConnector {
    param([string]$ConnectorId, [hashtable]$Body)
    $uri     = "$connectorsBase/$ConnectorId`?$apiVersion"
    $bodyJson = $Body | ConvertTo-Json -Depth 10
    $resp    = Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $bodyJson -ErrorAction Stop
    return $resp
}

# Define automatable connectors
# TEST_REQUIRED: Validate these connector body formats against Microsoft API docs before production.
$automatableConnectors = @{

    'AzureActivity' = @{
        connectorId = "AzureActivity-$subscriptionId"
        kind        = 'AzureActivityLog'
        properties  = @{
            linkedResourceId = "/subscriptions/$subscriptionId/providers/microsoft.insights/eventtypes/management"
        }
    }

    'AzureSecurityCenter' = @{
        connectorId = "AzureSecurityCenter-$subscriptionId"
        kind        = 'AzureSecurityCenter'
        properties  = @{
            subscriptionId = $subscriptionId
            dataTypes      = @{
                alerts = @{ state = 'Enabled' }
            }
        }
    }

    'MicrosoftDefenderForCloud' = @{
        connectorId = "MicrosoftDefenderForCloud-$subscriptionId"
        kind        = 'MicrosoftDefenderForCloud'
        properties  = @{
            subscriptionId = $subscriptionId
            dataTypes      = @{
                alerts = @{ state = 'Enabled' }
            }
        }
    }
}

# Define manual-only connectors
$manualConnectors = @{
    'Office365' = @{
        displayName = 'Microsoft Office 365'
        steps = @(
            "Go to https://portal.azure.com > Microsoft Sentinel > $workspaceName",
            "Navigate to: Configuration > Data connectors",
            "Search for 'Microsoft 365 (formerly Office 365)' and click Open connector page",
            "Check required licenses (Exchange Online, SharePoint, Teams)",
            "Under Configuration, check the boxes for Exchange, SharePoint, Teams",
            "Click Apply Changes"
        )
    }
    'AzureActiveDirectory' = @{
        displayName = 'Microsoft Entra ID (Azure AD)'
        steps = @(
            "Go to https://portal.azure.com > Microsoft Sentinel > $workspaceName",
            "Navigate to: Configuration > Data connectors",
            "Search for 'Microsoft Entra ID' and click Open connector page",
            "Under Configuration, select log types: Sign-in logs, Audit logs, Provisioning logs",
            "Click Connect",
            "Note: Requires Global Administrator or Security Administrator in customer tenant"
        )
    }
    'MicrosoftThreatProtection' = @{
        displayName = 'Microsoft Defender XDR (MTP)'
        steps = @(
            "Go to https://portal.azure.com > Microsoft Sentinel > $workspaceName",
            "Navigate to: Configuration > Data connectors",
            "Search for 'Microsoft Defender XDR' and click Open connector page",
            "Under Configuration, toggle 'Connect incidents & alerts'",
            "Select product filters as needed (Defender for Endpoint, Office, Identity, Cloud Apps)",
            "Click Apply Changes",
            "Note: Requires Microsoft 365 E5 or Defender for Endpoint P2 license"
        )
    }
}

# Process automatable connectors
Write-Host "`n[1] Processing automatable connectors..." -ForegroundColor Cyan

foreach ($connectorName in $automatableConnectors.Keys) {
    # Only process if in dataSources config (or if dataSources is empty = enable all)
    $inConfig = ($dataSources.Count -eq 0) -or ($dataSources | Where-Object { $_ -match $connectorName })
    if (-not $inConfig) {
        Write-Host "  [SKIP] $connectorName not in config dataSources." -ForegroundColor Gray
        $connectorResults.Add(@{ connector = $connectorName; status = 'skipped'; reason = 'not in dataSources config' })
        continue
    }

    $def         = $automatableConnectors[$connectorName]
    $connectorId = $def.connectorId
    $kind        = $def.kind
    $props       = $def.properties

    Write-Host "  Processing: $connectorName ($kind)..." -ForegroundColor Yellow
    try {
        $existing = Get-ExistingConnector -ConnectorId $connectorId
        if ($existing) {
            Write-Host "  [EXISTS] $connectorName connector already configured." -ForegroundColor Gray
            $connectorResults.Add(@{
                connector   = $connectorName
                connectorId = $connectorId
                kind        = $kind
                status      = 'exists'
            })
        } else {
            $body = @{
                kind       = $kind
                properties = $props
            }
            $result = Set-SentinelConnector -ConnectorId $connectorId -Body $body
            Write-Host "  [ENABLED] $connectorName connector created." -ForegroundColor Green
            $connectorResults.Add(@{
                connector   = $connectorName
                connectorId = $connectorId
                kind        = $kind
                status      = 'enabled'
                id          = $result.id ?? ''
            })
        }
    } catch {
        $errMsg = $_.Exception.Message
        Write-Warning "  [FAILED] $connectorName : $errMsg"
        $connectorResults.Add(@{
            connector   = $connectorName
            connectorId = $connectorId
            kind        = $kind
            status      = 'failed'
            error       = $errMsg
        })
    }
}

# Process manual connectors
Write-Host "`n[2] Manual-action required connectors..." -ForegroundColor Cyan
Write-Host ""

foreach ($connectorName in $manualConnectors.Keys) {
    $inConfig = ($dataSources.Count -eq 0) -or ($dataSources | Where-Object { $_ -match $connectorName })
    if (-not $inConfig) {
        Write-Host "  [SKIP] $connectorName not in config dataSources." -ForegroundColor Gray
        $connectorResults.Add(@{ connector = $connectorName; status = 'skipped'; reason = 'not in dataSources config' })
        continue
    }

    $def = $manualConnectors[$connectorName]
    Write-Host "" -ForegroundColor Magenta
    Write-Host "  MANUAL_ACTION: Enable $($def.displayName)" -ForegroundColor Magenta
    Write-Host "" -ForegroundColor Magenta
    $stepNum = 1
    foreach ($step in $def.steps) {
        Write-Host "    Step $($stepNum): $step" -ForegroundColor Yellow
        $stepNum++
    }
    Write-Host ""

    $connectorResults.Add(@{
        connector     = $connectorName
        displayName   = $def.displayName
        status        = 'manual-required'
        manualSteps   = $def.steps
    })
}

$failCount   = ($connectorResults | Where-Object { $_.status -eq 'failed' }).Count
$manualCount = ($connectorResults | Where-Object { $_.status -eq 'manual-required' }).Count
$enabledCount = ($connectorResults | Where-Object { $_.status -in @('enabled','exists') }).Count
$overallStatus = if ($failCount -gt 0) { 'partial-failure' } elseif ($manualCount -gt 0) { 'partial-manual' } else { 'succeeded' }

Write-Evidence @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = $overallStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    subscriptionId    = $subscriptionId
    workspaceName     = $workspaceName
    enabledCount      = $enabledCount
    manualCount       = $manualCount
    failCount         = $failCount
    connectorResults  = $connectorResults
    testRequired      = $testRequired
}

Write-Host "=== Enable-DataConnectors complete. Enabled: $enabledCount, Manual: $manualCount, Failed: $failCount ===" -ForegroundColor Cyan
