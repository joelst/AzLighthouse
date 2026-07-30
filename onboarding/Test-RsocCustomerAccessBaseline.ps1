#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# TEST_REQUIRED: Run from RSOC tenant; ForeignGroup assignments may not list if Lighthouse not accepted

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = ".\evidence"
)

$scriptName        = "Test-RsocCustomerAccessBaseline"
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$subscriptionId    = $config.deployment.subscriptionId
$resourceGroupName = $config.deployment.resourceGroupName
$workspaceName     = $config.deployment.sentinelWorkspaceName

# Known RSOC group principal IDs
$rsocGroups = [ordered]@{
    'RSOC_Sentinel_Admin'                              = 'c1f4a285-1b26-46b8-9a97-d298861ad503'
    'RSOC_Sentinel_Onboarding'                         = 'cbe65060-f79c-4350-aaf2-fd901a95de33'
    'RSOC_Sentinel_Threat_Detection_Engineering_Tier1' = '440ba293-8d18-430c-b4cc-3ea789d655e9'
    'RSOC_Sentinel_Threat_Detection_Engineering_Tier2' = 'd4e11e0e-6300-4491-938f-e934a587f990'
    'RSOC_Sentinel_Security_Engineers'                 = '4fd628b1-a5f8-43a1-9949-88a84e7f053b'
    'RSOC_Sentinel_Red_Team'                           = 'a6539c63-c61b-459f-bdc6-22106aa0aed3'
    'RSOC_Sentinel_Incident_Response'                  = 'ef18438b-79fc-4b4a-8f3f-3b691f091aa2'
    'RSOC_Sentinel_Incident_Detection_Tier1'           = '0d593b30-eb20-4d83-a7eb-deff71e401d2'
    'RSOC_Sentinel_Incident_Detection_Tier2'           = 'fe773eea-b69d-40e7-9c90-0ccb5ea4447c'
}

$umiName = 'RSOC-Sentinel-Ingestion-UMI'

function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail = "")
    $prefix = if ($Passed) { '[PASS]' } else { '[FAIL]' }
    $color  = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host "$prefix $Name" -ForegroundColor $color
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor Gray }
}

function Write-Evidence {
    param([hashtable]$Data)
    if (-not (Test-Path $EvidenceOutputPath)) {
        New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null
    }
    $ts       = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $filePath = Join-Path $EvidenceOutputPath "$scriptName-$ts.json"
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
    Write-Host "Evidence written: $filePath" -ForegroundColor Cyan
    return $filePath
}

$checks = [System.Collections.Generic.List[hashtable]]::new()
function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail = "")
    Write-Check -Name $Name -Passed $Passed -Detail $Detail
    $checks.Add(@{ name = $Name; passed = $Passed; detail = $Detail })
}

Write-Host "`n=== RSOC Customer Access Baseline ===" -ForegroundColor Cyan
Write-Host "Customer: $customerShortName  |  Subscription: $subscriptionId`n"

$null = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop

$scope = "/subscriptions/$subscriptionId"

 Get all role assignments scoped to subscription, ForeignGroup type # 
Write-Host "Fetching role assignments (ForeignGroup) ..." -ForegroundColor Yellow
$allAssignments = @()
try {
    $allAssignments = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop |
        Where-Object { $_.ObjectType -eq 'ForeignGroup' }
    Write-Host "  Found $($allAssignments.Count) ForeignGroup assignment(s)" -ForegroundColor Gray
} catch {
    Write-Host "[WARN] Could not retrieve role assignments: $($_.Exception.Message)" -ForegroundColor Yellow
}

 Check each RSOC group # 
Write-Host "`n-- RSOC Group Role Assignments --" -ForegroundColor Cyan
$groupResults = [System.Collections.Generic.List[hashtable]]::new()

foreach ($groupName in $rsocGroups.Keys) {
    $principalId = $rsocGroups[$groupName]
    $groupAssignments = $allAssignments | Where-Object { $_.ObjectId -eq $principalId }
    $hasAssignment    = $null -ne $groupAssignments -and @($groupAssignments).Count -gt 0
    $roles            = @($groupAssignments | ForEach-Object { $_.RoleDefinitionName }) -join ', '
    $detail           = if ($hasAssignment) { "Roles: $roles" } else { "No assignment found (PrincipalId: $principalId)" }

    Add-Check -Name "Group has role assignment: $groupName" -Passed $hasAssignment -Detail $detail
    $groupResults.Add(@{
        groupName    = $groupName
        principalId  = $principalId
        hasAssignment = $hasAssignment
        roles        = $roles
    })
}

 Check UMI role assignments # 
Write-Host "`n-- UMI Role Assignments --" -ForegroundColor Cyan

$umiSentinelReaderOk    = $false
$umiLogAnalyticsReaderOk = $false
$umiObj                  = $null

try {
    # Find the UMI by name in the resource group
    $umiObj = Get-AzUserAssignedIdentity `
        -ResourceGroupName $resourceGroupName `
        -Name $umiName -ErrorAction Stop

    $umiAssignments = $allAssignments | Where-Object { $_.ObjectId -eq $umiObj.PrincipalId }

    # Also check at RG scope
    $rgScope            = "$scope/resourceGroups/$resourceGroupName"
    $umiRgAssignments   = @()
    try {
        $umiRgAssignments = Get-AzRoleAssignment -Scope $rgScope -ErrorAction Stop |
            Where-Object { $_.ObjectId -eq $umiObj.PrincipalId }
    } catch { }

    $allUmiAssignments  = @($umiAssignments) + @($umiRgAssignments) | Sort-Object -Property RoleDefinitionName -Unique

    $umiRoles = @($allUmiAssignments | ForEach-Object { $_.RoleDefinitionName })

    $umiSentinelReaderOk    = ($umiRoles -contains 'Microsoft Sentinel Reader') -or ($umiRoles -contains 'Microsoft Sentinel Contributor')
    $umiLogAnalyticsReaderOk = ($umiRoles -contains 'Log Analytics Reader') -or ($umiRoles -contains 'Log Analytics Contributor') -or ($umiRoles -contains 'Contributor')

    Add-Check -Name "UMI $umiName: has Sentinel Reader (or higher)" `
        -Passed $umiSentinelReaderOk `
        -Detail "Roles found: $($umiRoles -join ', ')"

    Add-Check -Name "UMI $umiName: has Log Analytics Reader (or higher)" `
        -Passed $umiLogAnalyticsReaderOk `
        -Detail "Roles found: $($umiRoles -join ', ')"

} catch {
    Add-Check -Name "UMI $umiName: found in resource group" -Passed $false `
        -Detail "Error: $($_.Exception.Message)"
    Add-Check -Name "UMI $umiName: has Sentinel Reader (or higher)"    -Passed $false -Detail "UMI not found"
    Add-Check -Name "UMI $umiName: has Log Analytics Reader (or higher)" -Passed $false -Detail "UMI not found"
}

 Evidence # 
$failCount = ($checks | Where-Object { -not $_.passed } | Measure-Object).Count
$status    = if ($WhatIfMode) { 'whatif-only' } elseif ($failCount -eq 0) { 'passed' } else { 'failed' }

$ep = Write-Evidence -Data @{
    scriptName              = $scriptName
    customerShortName       = $customerShortName
    status                  = $status
    timestampUtc            = (Get-Date).ToUniversalTime().ToString("o")
    testRequired            = @(
        "Run from RSOC tenant",
        "ForeignGroup assignments may not list if Lighthouse not accepted"
    )
    subscriptionId          = $subscriptionId
    scope                   = $scope
    foreignGroupAssignments = $allAssignments.Count
    rsocGroupResults        = $groupResults.ToArray()
    umiName                 = $umiName
    umiPrincipalId          = $umiObj?.PrincipalId
    umiSentinelReader       = $umiSentinelReaderOk
    umiLogAnalyticsReader   = $umiLogAnalyticsReaderOk
    checks                  = $checks.ToArray()
    failCount               = $failCount
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Checks: $($checks.Count)  Fail: $failCount  Status: $status"
Write-Host "Evidence: $ep`n"

if ($failCount -gt 0) { exit 1 }
