Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Detects and optionally remediates drift between a content manifest and deployed Sentinel resources.
.DESCRIPTION
    Loads a manifest JSON array per Config/content-drift-manifest.schema.json, checks each deployed
    item against ARM APIs for Sentinel analytics rules, automation rules, workbooks, watchlists, and
    KQL parser saved functions, then reports missing or modified items. With -Remediate, redeploys
    diverged/missing content via ARM PUT.

    Supported manifest types:
      analyticsRule  - Microsoft.SecurityInsights/alertRules
      automationRule - Microsoft.SecurityInsights/automationRules
      workbook       - Microsoft.Insights/workbooks (different ARM base path)
      watchlist      - Microsoft.SecurityInsights/watchlists
      parser         - Microsoft.OperationalInsights/workspaces/.../savedSearches (KQL function)

    Schema reference: Config/content-drift-manifest.schema.json
    Sample manifest:  Config/content-drift-manifest.sample.json
    E2E criteria:     Config/e2e-acceptance-criteria.json (contentDriftGate)
#>

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$ManifestPath,
    [switch]$Remediate,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

$config     = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$shortName  = $config.customer.shortName
$tenantId   = $config.customer.tenantId
$subId      = $config.deployment.subscriptionId
$rgName     = $config.deployment.resourceGroupName
$wsName     = $config.deployment.sentinelWorkspaceName

if (-not (Test-Path $EvidenceOutputPath)) { New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null }

function Write-Evidence {
    param([hashtable]$Data)
    $ts      = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile = Join-Path $EvidenceOutputPath ("evidence-Invoke-ContentDriftRemediation-{0}-{1}.json" -f $shortName, $ts)
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "[Evidence] Written: $outFile" -ForegroundColor Cyan
}

function Get-ArmToken {
    try {
        return (Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -TenantId $tenantId -ErrorAction Stop).Token
    } catch {
        throw "Unable to acquire ARM token. Ensure Az.Accounts is connected: $_"
    }
}

function Invoke-ArmGet {
    param([string]$Token, [string]$Uri)
    $headers = @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/json' }
    try {
        return Invoke-RestMethod -Uri $Uri -Method GET -Headers $headers -ErrorAction Stop
    } catch {
        if ($_.Exception.Response?.StatusCode -eq 404) { return $null }
        throw
    }
}

function Invoke-ArmPut {
    param([string]$Token, [string]$Uri, [string]$Body)
    $headers = @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/json' }
    return Invoke-RestMethod -Uri $Uri -Method PUT -Headers $headers -Body $Body -ErrorAction Stop
}

# Validate manifest
if (-not (Test-Path $ManifestPath)) { throw "ManifestPath '$ManifestPath' does not exist." }
$manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
if ($null -eq $manifest -or $manifest.Count -eq 0) {
    Write-Warning "Manifest is empty. Nothing to check."
    exit 0
}

Write-Host "[Script 23] Invoke-ContentDriftRemediation | Customer: $shortName | Items: $($manifest.Count)" -ForegroundColor Green
$armBase   = 'https://management.azure.com'
$apiVer    = '2023-02-01'
$wbApiVer  = '2022-04-01'
$sentinelBase = "$armBase/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.OperationalInsights/workspaces/$wsName/providers/Microsoft.SecurityInsights"

$driftReport = [System.Collections.Generic.List[hashtable]]::new()

if ($WhatIfMode) {
    Write-Host "[WhatIf] Would check $($manifest.Count) item(s) against Sentinel workspace '$wsName'" -ForegroundColor Yellow
    foreach ($item in $manifest) {
        Write-Host "  [WhatIf] $($item.type): $($item.name)" -ForegroundColor Yellow
        $driftReport.Add(@{ name = $item.name; type = $item.type; driftStatus = 'whatif' })
    }
    Write-Evidence @{
        scriptName        = 'Invoke-ContentDriftRemediation'
        customerShortName = $shortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        manifestPath      = $ManifestPath
        itemCount         = $manifest.Count
        testRequired      = @(
            'Schema: Config/content-drift-manifest.schema.json',
            'TEST_REQUIRED: Run against a live Sentinel workspace before production use to validate API versions per type',
            'TEST_REQUIRED: Workbooks use a different ARM base path — confirm api-version matches deployed templates'
        )
        driftReport       = $driftReport
    }
    exit 0
}

Write-Host "[Auth] Acquiring ARM token ..." -ForegroundColor Cyan
$armToken = Get-ArmToken

foreach ($item in $manifest) {
    $itemName   = $item.name
    $itemType   = $item.type
    $itemArmId  = $item?.armId
    $itemContent = if ($item?.content) { $item.content | ConvertTo-Json -Depth 20 } else { $null }

    Write-Host "  [Check] $itemType : $itemName" -ForegroundColor Gray

    $parserApiVer = '2020-08-01'
    $wsBase       = "$armBase/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.OperationalInsights/workspaces/$wsName"

    $deployedUri = switch ($itemType) {
        'analyticsRule'   { "$sentinelBase/alertRules/$itemName`?api-version=$apiVer" }
        'automationRule'  { "$sentinelBase/automationRules/$itemName`?api-version=$apiVer" }
        'workbook'        { "$armBase/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Insights/workbooks/$itemName`?api-version=$wbApiVer" }
        'watchlist'       { "$sentinelBase/watchlists/$itemName`?api-version=$apiVer" }
        'parser'          { "$wsBase/savedSearches/$itemName`?api-version=$parserApiVer" }
        default           { $null }
    }

    if ($null -eq $deployedUri) {
        Write-Warning "  Unknown type '$itemType' for item '$itemName'. Skipping."
        $driftReport.Add(@{ name = $itemName; type = $itemType; driftStatus = 'unknown-type' })
        continue
    }

    $deployed = Invoke-ArmGet -Token $armToken -Uri $deployedUri

    if ($null -eq $deployed) {
        Write-Host "  [MISSING] $itemType '$itemName' not deployed." -ForegroundColor Red
        $entry = @{ name = $itemName; type = $itemType; driftStatus = 'missing' }

        if ($Remediate -and $itemContent) {
            Write-Host "    [Remediate] Deploying $itemType '$itemName' ..." -ForegroundColor Yellow
            try {
                Invoke-ArmPut -Token $armToken -Uri ($deployedUri -replace '\?.*', '') -Body $itemContent | Out-Null
                $entry.driftStatus    = 'remediated-created'
                $entry.remediatedAt   = (Get-Date).ToUniversalTime().ToString('o')
                Write-Host "    [OK] Created." -ForegroundColor Green
            } catch {
                $entry.driftStatus = 'remediation-failed'
                $entry.error       = $_.Exception.Message
                Write-Warning "    [Fail] $($_.Exception.Message)"
            }
        } elseif ($Remediate) {
            $entry.driftStatus = 'missing-no-content'
            Write-Warning "    No content in manifest to redeploy '$itemName'."
        }
        $driftReport.Add($entry)
        continue
    }

    # Simple drift check: compare etag or name presence; deep compare if content provided
    $hasDrift = $false
    if ($itemContent) {
        $deployedJson   = $deployed | ConvertTo-Json -Depth 20 -Compress
        $manifestJson   = $item.content | ConvertTo-Json -Depth 20 -Compress
        # Compare properties (exclude etag/lastModified)
        $deployedProps  = ($deployed.properties | ConvertTo-Json -Depth 10 -Compress)
        $manifestProps  = try { ($item.content.properties | ConvertTo-Json -Depth 10 -Compress) } catch { $null }
        if ($manifestProps -and ($deployedProps -ne $manifestProps)) { $hasDrift = $true }
    }

    if ($hasDrift) {
        Write-Host "  [DRIFT] $itemType '$itemName' differs from manifest." -ForegroundColor Yellow
        $entry = @{ name = $itemName; type = $itemType; driftStatus = 'modified' }

        if ($Remediate -and $itemContent) {
            Write-Host "    [Remediate] Redeploying $itemType '$itemName' ..." -ForegroundColor Yellow
            try {
                Invoke-ArmPut -Token $armToken -Uri ($deployedUri -replace '\?.*', '') -Body $itemContent | Out-Null
                $entry.driftStatus  = 'remediated-updated'
                $entry.remediatedAt = (Get-Date).ToUniversalTime().ToString('o')
                Write-Host "    [OK] Updated." -ForegroundColor Green
            } catch {
                $entry.driftStatus = 'remediation-failed'
                $entry.error       = $_.Exception.Message
                Write-Warning "    [Fail] $($_.Exception.Message)"
            }
        }
        $driftReport.Add($entry)
    } else {
        Write-Host "  [OK] $itemType '$itemName' is current." -ForegroundColor Green
        $driftReport.Add(@{ name = $itemName; type = $itemType; driftStatus = 'ok' })
    }
}

$missing    = ($driftReport | Where-Object { $_.driftStatus -in @('missing','missing-no-content') }).Count
$drifted    = ($driftReport | Where-Object { $_.driftStatus -eq 'modified' }).Count
$remediated = ($driftReport | Where-Object { $_.driftStatus -like 'remediated-*' }).Count
$failed     = ($driftReport | Where-Object { $_.driftStatus -like '*failed*' }).Count
$ok         = ($driftReport | Where-Object { $_.driftStatus -eq 'ok' }).Count

Write-Host "`n[Summary] OK: $ok | Missing: $missing | Drifted: $drifted | Remediated: $remediated | Failed: $failed" -ForegroundColor Cyan

$overallStatus = if ($failed -gt 0) { 'partial-failure' } elseif (($missing + $drifted) -gt 0 -and -not $Remediate) { 'drift-detected' } else { 'succeeded' }

Write-Evidence @{
    scriptName        = 'Invoke-ContentDriftRemediation'
    customerShortName = $shortName
    status            = $overallStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    subscriptionId    = $subId
    resourceGroup     = $rgName
    workspaceName     = $wsName
    manifestPath      = $ManifestPath
    totalItems        = $manifest.Count
    okCount           = $ok
    missingCount      = $missing
    driftedCount      = $drifted
    remediatedCount   = $remediated
    failedCount       = $failed
    remediateFlag     = $Remediate.IsPresent
    testRequired      = @(
        'Schema: Config/content-drift-manifest.schema.json',
        'TEST_REQUIRED: Run against a live Sentinel workspace before production use',
        'TEST_REQUIRED: Workbooks use a different ARM base path than Sentinel resources'
    )
    driftReport       = $driftReport
}

if ($failed -gt 0) { exit 1 }
