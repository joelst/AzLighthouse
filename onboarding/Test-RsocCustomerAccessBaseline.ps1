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

$lighthouseConfig = if ($config.PSObject.Properties.Name -contains 'lighthouse') { $config.lighthouse } else { $null }
$expectedAssignments = @(
    if (
        $lighthouseConfig -and
        ($lighthouseConfig.PSObject.Properties.Name -contains 'expectedForeignGroupAssignments')
    ) {
        $lighthouseConfig.expectedForeignGroupAssignments
    }
)

if ($expectedAssignments.Count -eq 0) {
    throw "Customer config must define lighthouse.expectedForeignGroupAssignments from the private approved group/role matrix."
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

function Get-NormalizedRoleDefinitionId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value.TrimEnd('/') -split '/')[-1].ToLowerInvariant()
}

Write-Host "`n=== RSOC Customer Access Baseline ===" -ForegroundColor Cyan
Write-Host "Customer: $customerShortName  |  Subscription: $subscriptionId`n"

$null = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop

$scope = "/subscriptions/$subscriptionId"
$rgScope = "$scope/resourceGroups/$resourceGroupName"

# Get subscription and Sentinel resource-group role assignments
Write-Host "Fetching role assignments at subscription and Sentinel resource-group scopes ..." -ForegroundColor Yellow
$subscriptionAssignments = @()
$resourceGroupAssignments = @()
$foreignGroupAssignments = @()
try {
    $subscriptionAssignments = @(Get-AzRoleAssignment -Scope $scope -ErrorAction Stop)
    $resourceGroupAssignments = @(Get-AzRoleAssignment -Scope $rgScope -ErrorAction Stop)
    $foreignGroupAssignments = @(($subscriptionAssignments + $resourceGroupAssignments) |
        Where-Object { $_.ObjectType -eq 'ForeignGroup' -or $_.ObjectType -eq 'Group' })
    Write-Host "  Found $($foreignGroupAssignments.Count) ForeignGroup/Group assignment(s)" -ForegroundColor Gray
} catch {
    Write-Host "[WARN] Could not retrieve role assignments: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Check each expected RSOC group/role pair
Write-Host "`n-- RSOC Group Role Assignments --" -ForegroundColor Cyan
$groupResults = [System.Collections.Generic.List[hashtable]]::new()

foreach ($expected in $expectedAssignments) {
    $groupName = [string]$expected.groupName
    $principalId = [string]$expected.principalId
    $roleName = [string]$expected.roleDefinitionName
    $roleDefinitionId = Get-NormalizedRoleDefinitionId -Value ([string]$expected.roleDefinitionId)
    $assignmentScope = [string]$expected.assignmentScope
    $expectedSourceScope = if ($assignmentScope -eq 'sentinelResourceGroup') { $rgScope } else { $scope }
    $sourceMatch = @($foreignGroupAssignments | Where-Object {
        $_.ObjectId -eq $principalId -and
        $_.RoleDefinitionName -eq $roleName -and
        (Get-NormalizedRoleDefinitionId -Value ([string]$_.RoleDefinitionId)) -eq $roleDefinitionId -and
        ([string]$_.Scope).TrimEnd('/') -eq $expectedSourceScope.TrimEnd('/')
    })
    $effectiveMatch = @($resourceGroupAssignments | Where-Object {
        $_.ObjectId -eq $principalId -and
        $_.RoleDefinitionName -eq $roleName -and
        (Get-NormalizedRoleDefinitionId -Value ([string]$_.RoleDefinitionId)) -eq $roleDefinitionId
    })
    $inheritsByScope = $expectedSourceScope -eq $scope
    $effectiveAtResourceGroup = $effectiveMatch.Count -gt 0 -or $inheritsByScope
    $hasAssignment = $sourceMatch.Count -gt 0 -and $effectiveAtResourceGroup
    $detail = "Role: $roleName; source: $expectedSourceScope; effective at Sentinel RG: $effectiveAtResourceGroup"

    Add-Check -Name "ForeignGroup access: $groupName / $roleName" -Passed $hasAssignment -Detail $detail
    $groupResults.Add(@{
        groupName = $groupName
        principalId = $principalId
        roleDefinitionName = $roleName
        roleDefinitionId = $roleDefinitionId
        expectedSourceScope = $expectedSourceScope
        foundAtSourceScope = $sourceMatch.Count -gt 0
        effectiveAtSentinelResourceGroup = $effectiveAtResourceGroup
    })
}

# Check UMI role assignments
Write-Host "`n-- UMI Role Assignments --" -ForegroundColor Cyan

$umiSentinelReaderOk    = $false
$umiLogAnalyticsReaderOk = $false
$umiObj                  = $null

try {
    # Find the UMI by name in the resource group
    $umiObj = Get-AzUserAssignedIdentity `
        -ResourceGroupName $resourceGroupName `
        -Name $umiName -ErrorAction Stop

    $umiAssignments = $subscriptionAssignments | Where-Object { $_.ObjectId -eq $umiObj.PrincipalId }

    # Also check at RG scope
    $umiRgAssignments   = @()
    try {
        $umiRgAssignments = Get-AzRoleAssignment -Scope $rgScope -ErrorAction Stop |
            Where-Object { $_.ObjectId -eq $umiObj.PrincipalId }
    } catch { }

    $allUmiAssignments  = @($umiAssignments) + @($umiRgAssignments) | Sort-Object -Property RoleDefinitionName -Unique

    $umiRoles = @($allUmiAssignments | ForEach-Object { $_.RoleDefinitionName })

    $umiSentinelReaderOk    = ($umiRoles -contains 'Microsoft Sentinel Reader') -or ($umiRoles -contains 'Microsoft Sentinel Contributor')
    $umiLogAnalyticsReaderOk = ($umiRoles -contains 'Log Analytics Reader') -or ($umiRoles -contains 'Log Analytics Contributor') -or ($umiRoles -contains 'Contributor')

    Add-Check -Name "UMI $($umiName): has Sentinel Reader (or higher)" `
        -Passed $umiSentinelReaderOk `
        -Detail "Roles found: $($umiRoles -join ', ')"

    Add-Check -Name "UMI $($umiName): has Log Analytics Reader (or higher)" `
        -Passed $umiLogAnalyticsReaderOk `
        -Detail "Roles found: $($umiRoles -join ', ')"

} catch {
    Add-Check -Name "UMI $($umiName): found in resource group" -Passed $false `
        -Detail "Error: $($_.Exception.Message)"
    Add-Check -Name "UMI $($umiName): has Sentinel Reader (or higher)"    -Passed $false -Detail "UMI not found"
    Add-Check -Name "UMI $($umiName): has Log Analytics Reader (or higher)" -Passed $false -Detail "UMI not found"
}

# Evidence
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
    foreignGroupAssignments = $foreignGroupAssignments.Count
    sentinelResourceGroupScope = $rgScope
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
