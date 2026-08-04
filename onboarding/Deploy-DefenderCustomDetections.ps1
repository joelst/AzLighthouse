Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Deploys custom detection rules to Microsoft Defender via the security.microsoft.com API.
.DESCRIPTION
    Reads *.json rule files from DetectionRulesPath, checks for existing rules by name (idempotent),
    then creates or updates each rule. Requires Defender for Endpoint P2 licensing.
    TEST_REQUIRED: Requires Defender API auth with security.microsoft.com audience; needs
    CustomDetection.ReadWrite scope; verify customer has Defender for Endpoint P2 license first.
#>

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$DetectionRulesPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$shortName = $config.customer.shortName
$tenantId  = $config.customer.tenantId
$subId     = $config.deployment.subscriptionId

if (-not (Test-Path $EvidenceOutputPath)) { New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null }

function Write-Evidence {
    param([hashtable]$Data)
    $ts = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $outFile = Join-Path $EvidenceOutputPath ("evidence-Deploy-DefenderCustomDetections-{0}-{1}.json" -f $shortName, $ts)
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "[Evidence] Written: $outFile" -ForegroundColor Cyan
}

function Get-MsalToken {
    param([string]$TenantId, [string]$Audience)
    # TEST_REQUIRED: Replace with real MSAL token acquisition; use managed identity or service principal
    # In production: use Az module (Get-AzAccessToken -ResourceUrl $Audience) or MSAL.PS
    try {
        $token = (Get-AzAccessToken -ResourceUrl $Audience -TenantId $TenantId -ErrorAction Stop).Token
        return $token
    } catch {
        Write-Warning "Get-AzAccessToken failed, attempting fallback: $_"
        throw "Unable to acquire token for audience '$Audience'. Ensure Az.Accounts is connected. Error: $_"
    }
}

# Validate detection rules path
if (-not (Test-Path $DetectionRulesPath)) {
    throw "DetectionRulesPath '$DetectionRulesPath' does not exist."
}
$ruleFiles = Get-ChildItem -Path $DetectionRulesPath -Filter '*.json' -File
if ($ruleFiles.Count -eq 0) {
    Write-Warning "No *.json files found in '$DetectionRulesPath'. Nothing to deploy."
    Write-Evidence @{
        scriptName        = 'Deploy-DefenderCustomDetections'
        customerShortName = $shortName
        status            = 'skipped-no-rules'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        testRequired      = @(
            'Verify DetectionRulesPath contains valid rule JSON files',
            'Confirm Defender for Endpoint P2 license is assigned'
        )
        ruleFiles         = @()
    }
    exit 0
}

Write-Host "[Script 22] Deploy-DefenderCustomDetections | Customer: $shortName | Rules: $($ruleFiles.Count)" -ForegroundColor Green

$defenderAudience = 'https://api.security.microsoft.com'
$baseUri          = 'https://api.security.microsoft.com/api/customdetections'

$results      = [System.Collections.Generic.List[hashtable]]::new()
$successCount = 0
$failCount    = 0

if ($WhatIfMode) {
    Write-Host "[WhatIf] Would deploy $($ruleFiles.Count) detection rule(s) to $defenderAudience" -ForegroundColor Yellow
    foreach ($file in $ruleFiles) {
        Write-Host "  [WhatIf] Rule file: $($file.Name)" -ForegroundColor Yellow
        $results.Add(@{ file = $file.Name; status = 'whatif' })
    }
    Write-Evidence @{
        scriptName        = 'Deploy-DefenderCustomDetections'
        customerShortName = $shortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        testRequired      = @(
            'TEST_REQUIRED: Requires Defender API auth with security.microsoft.com audience',
            'TEST_REQUIRED: Needs CustomDetection.ReadWrite Graph scope',
            'TEST_REQUIRED: Confirm Defender for Endpoint P2 license on customer tenant'
        )
        ruleFiles         = ($ruleFiles | ForEach-Object { $_.Name })
        results           = $results
    }
    exit 0
}

# Acquire token
Write-Host "[Auth] Acquiring token for $defenderAudience ..." -ForegroundColor Cyan
$token = Get-MsalToken -TenantId $tenantId -Audience $defenderAudience
$headers = @{
    'Authorization' = "Bearer $token"
    'Content-Type'  = 'application/json'
}

# Fetch existing rules (for idempotency)
Write-Host "[API] Fetching existing custom detections ..." -ForegroundColor Cyan
$existingRules = @{}
try {
    $listResponse = Invoke-RestMethod -Uri $baseUri -Method GET -Headers $headers
    foreach ($rule in $listResponse.value) {
        $existingRules[$rule.displayName] = $rule.id
    }
    Write-Host "  Found $($existingRules.Count) existing rule(s)." -ForegroundColor Gray
} catch {
    Write-Warning "Failed to list existing rules: $_. Will attempt create-only mode."
}

foreach ($file in $ruleFiles) {
    $ruleName = $file.BaseName
    try {
        $ruleBody = Get-Content $file.FullName -Raw
        $ruleObj  = $ruleBody | ConvertFrom-Json

        # Prefer displayName from JSON, fallback to filename
        $displayName = $ruleObj?.displayName ?? $ruleName

        if ($existingRules.ContainsKey($displayName)) {
            $existingId = $existingRules[$displayName]
            Write-Host "  [Update] Rule '$displayName' (id: $existingId)" -ForegroundColor Yellow
            $updateUri = "$baseUri/$existingId"
            Invoke-RestMethod -Uri $updateUri -Method PATCH -Headers $headers -Body $ruleBody | Out-Null
            $results.Add(@{ file = $file.Name; ruleName = $displayName; action = 'updated'; status = 'success' })
        } else {
            Write-Host "  [Create] Rule '$displayName'" -ForegroundColor Green
            Invoke-RestMethod -Uri $baseUri -Method POST -Headers $headers -Body $ruleBody | Out-Null
            $results.Add(@{ file = $file.Name; ruleName = $displayName; action = 'created'; status = 'success' })
        }
        $successCount++
    } catch {
        $errMsg = $_.Exception.Message
        Write-Warning "  [Fail] Rule '$ruleName': $errMsg"
        $results.Add(@{ file = $file.Name; ruleName = $ruleName; action = 'error'; status = 'failed'; error = $errMsg })
        $failCount++
    }
}

$overallStatus = if ($failCount -eq 0) { 'succeeded' } else { 'partial-failure' }
Write-Host "`n[Summary] Success: $successCount | Failed: $failCount | Status: $overallStatus" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Yellow' })

Write-Evidence @{
    scriptName        = 'Deploy-DefenderCustomDetections'
    customerShortName = $shortName
    status            = $overallStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    tenantId          = $tenantId
    subscriptionId    = $subId
    detectionRulesPath = $DetectionRulesPath
    totalRules        = $ruleFiles.Count
    successCount      = $successCount
    failCount         = $failCount
    results           = $results
    testRequired      = @(
        'TEST_REQUIRED: Requires Defender API auth with security.microsoft.com audience',
        'TEST_REQUIRED: Needs CustomDetection.ReadWrite Graph scope',
        'TEST_REQUIRED: Confirm Defender for Endpoint P2 license on customer tenant'
    )
}

if ($failCount -gt 0) { exit 1 }
