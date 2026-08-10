#Requires -Version 7.0
#Requires -Modules Az.ManagedServices, Az.Resources

<#
.SYNOPSIS
    Tests that Azure Lighthouse delegation is correctly configured for a customer subscription.
.DESCRIPTION
    Run from the RSOC managing tenant context. Checks for delegation assignment,
    managed services definition, and verifies the private expected group/role matrix
    is present as ForeignGroup assignments and applies to the Sentinel resource group.
#>
param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$ManagedByTenantId,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Helpers

function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("lighthouse-test-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    Write-Host "  Evidence written: $file" -ForegroundColor DarkGray
    return $file
}

function Write-Check {
    param(
        [string]$Label,
        [bool]$Passed,
        [string]$Detail = ''
    )
    if ($Passed) {
        Write-Host "  [PASS] $Label" -ForegroundColor Green -NoNewline
    } else {
        Write-Host "  [FAIL] $Label" -ForegroundColor Red -NoNewline
    }
    if ($Detail) { Write-Host "  $Detail" -ForegroundColor Gray } else { Write-Host '' }
    return $Passed
}

function Write-Status { param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color }

function Get-NormalizedRoleDefinitionId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value.TrimEnd('/') -split '/')[-1].ToLowerInvariant()
}

# Load Config

Write-Status "Loading customer config: $CustomerConfigPath"
$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json

$customerShortName = $config.customer.shortName
$subscriptionId    = $config.deployment.subscriptionId
$resourceGroupName = $config.deployment.resourceGroupName
$scope             = "/subscriptions/$subscriptionId"
$resourceGroupScope = "$scope/resourceGroups/$resourceGroupName"
$lighthouseConfig  = if ($config.PSObject.Properties.Name -contains 'lighthouse') { $config.lighthouse } else { $null }
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

Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

Write-Status "Customer: $customerShortName | Subscription: $subscriptionId"
Write-Host ""

$evidenceData = @{
    scriptName        = 'Test-LighthouseDelegation'
    customerShortName = $customerShortName
    subscriptionId    = $subscriptionId
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Run from RSOC managing tenant - must be authenticated to RSOC tenant',
        'Confirm ForeignGroup assignments are visible in customer subscription IAM',
        'Confirm each private expected group/role pair is assigned at its approved scope',
        'Confirm subscription-scoped assignments inherit to the Sentinel resource group'
    )
    checks            = [ordered]@{}
    groupResults      = [ordered]@{}
}

if ($WhatIfMode) {
    Write-Status "[WHATIF] Would test Lighthouse delegation for $customerShortName (sub: $subscriptionId)" -Color Magenta
    $evidenceData.status = 'whatif-only'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    return
}

$allPassed = $true
$managedDefinitions = @()

try {
    $managedDefinitions = @(Get-AzManagedServicesDefinition -Scope $scope -ErrorAction Stop | Where-Object {
        [string]$_.ManagedByTenantId -eq $ManagedByTenantId
    })
} catch {
    Write-Check 'Managed services definition query' $false "Error: $_"
    $evidenceData.checks['managedServicesDefinition'] = "error: $_"
    $allPassed = $false
}

# Check 1: Managed Services Assignment Exists

Write-Host "Check 1: Managed Services Assignment" -ForegroundColor White
try {
    $definitionIds = @($managedDefinitions | ForEach-Object { ([string]$_.Id).TrimEnd('/').ToLowerInvariant() })
    $assignments = @(Get-AzManagedServicesAssignment -Scope $scope -ErrorAction Stop | Where-Object {
        $directTenantMatch = [string]$_.ManagedByTenantId -eq $ManagedByTenantId
        $registrationDefinitionId = ([string]$_.RegistrationDefinitionId).TrimEnd('/').ToLowerInvariant()
        $directTenantMatch -or $definitionIds -contains $registrationDefinitionId
    })
    if ($assignments -and $assignments.Count -gt 0) {
        $passed = Write-Check 'Managed services assignment exists' $true "$($assignments.Count) assignment(s) found"
        $evidenceData.checks['managedServicesAssignment'] = "found: $($assignments.Count)"
        $evidenceData.assignmentIds = @($assignments | ForEach-Object { $_.Id })
    } else {
        $passed = Write-Check 'Managed services assignment exists' $false 'No assignments found'
        $evidenceData.checks['managedServicesAssignment'] = 'not-found'
        $allPassed = $false
    }
} catch {
    $passed = Write-Check 'Managed services assignment exists' $false "Error: $_"
    $evidenceData.checks['managedServicesAssignment'] = "error: $_"
    $allPassed = $false
}

# Check 2: Managed Services Definition

Write-Host ""
Write-Host "Check 2: Managed Services Definition" -ForegroundColor White
try {
    if ($managedDefinitions.Count -gt 0) {
        $passed = Write-Check 'Managed services definition found for managing tenant' $true "$($managedDefinitions.Count) definition(s)"
        $evidenceData.checks['managedServicesDefinition'] = 'found'
        $evidenceData.definitionIds = @($managedDefinitions | ForEach-Object { $_.Id })
    } else {
        Write-Check 'Managed services definition found for managing tenant' $false "ManagedByTenantId: $ManagedByTenantId"
        $evidenceData.checks['managedServicesDefinition'] = 'not-found-for-managing-tenant'
        $allPassed = $false
    }
} catch {
    Write-Check 'Managed services definition query' $false "Error: $_"
    $evidenceData.checks['managedServicesDefinition'] = "error: $_"
    $allPassed = $false
}

# Check 3: ForeignGroup Role Assignments and Sentinel Resource Group Inheritance

Write-Host ""
Write-Host "Check 3: Expected ForeignGroup Role Assignments" -ForegroundColor White

try {
    $subscriptionAssignments = @(Get-AzRoleAssignment -Scope $scope -ErrorAction Stop)
    $resourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
    $resourceGroupAssignments = @(
        if ($resourceGroup) {
            Get-AzRoleAssignment -Scope $resourceGroupScope -ErrorAction Stop
        }
    )
    $roleAssignments = @($subscriptionAssignments + $resourceGroupAssignments)
    $foreignGroupAssignments = @($roleAssignments | Where-Object {
        $_.ObjectType -eq 'ForeignGroup' -or $_.ObjectType -eq 'Group'
    })

    Write-Host "  Subscription assignments       : $($subscriptionAssignments.Count)" -ForegroundColor Gray
    Write-Host "  Resource-group assignments     : $($resourceGroupAssignments.Count)" -ForegroundColor Gray
    Write-Host "  ForeignGroup/Group assignments : $($foreignGroupAssignments.Count)" -ForegroundColor Gray
    Write-Host ""

    $assignmentPassCount = 0

    foreach ($expected in $expectedAssignments) {
        $groupName = [string]$expected.groupName
        $principalId = [string]$expected.principalId
        $roleName = [string]$expected.roleDefinitionName
        $roleDefinitionId = Get-NormalizedRoleDefinitionId -Value ([string]$expected.roleDefinitionId)
        $assignmentScope = [string]$expected.assignmentScope
        $expectedSourceScope = if ($assignmentScope -eq 'sentinelResourceGroup') {
            $resourceGroupScope
        } else {
            $scope
        }

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
        $passed = $sourceMatch.Count -gt 0 -and $effectiveAtResourceGroup
        $label = "$groupName / $roleName"

        if ($passed) {
            Write-Check "  $label" $true "Source: $expectedSourceScope; effective at Sentinel RG"
            $assignmentPassCount++
        } else {
            Write-Check "  $label" $false "Expected source: $expectedSourceScope; source found: $($sourceMatch.Count -gt 0); effective at RG: $effectiveAtResourceGroup"
            $allPassed = $false
        }

        $evidenceData.groupResults[$label] = @{
            foundAtSourceScope = $sourceMatch.Count -gt 0
            effectiveAtSentinelResourceGroup = $effectiveAtResourceGroup
            groupName = $groupName
            principalId = $principalId
            roleDefinitionName = $roleName
            roleDefinitionId = $roleDefinitionId
            expectedSourceScope = $expectedSourceScope
        }
    }

    Write-Host ""
    Write-Host "  Expected assignment score: $assignmentPassCount / $($expectedAssignments.Count)" -ForegroundColor $(if ($assignmentPassCount -eq $expectedAssignments.Count) { 'Green' } else { 'Yellow' })
    $evidenceData.checks['groupAssignmentScore'] = "$assignmentPassCount/$($expectedAssignments.Count)"
    $evidenceData.checks['sentinelResourceGroupScope'] = $resourceGroupScope
    $evidenceData.checks['sentinelResourceGroupExists'] = $null -ne $resourceGroup

} catch {
    Write-Check 'Role assignment query' $false "Error: $_"
    $evidenceData.checks['foreignGroupAssignments'] = "error: $_"
    $allPassed = $false
}

# Check 4: Customer Tenant Context

Write-Host ""
Write-Host "Check 4: Azure Context" -ForegroundColor White
try {
    $ctx = Get-AzContext
    $contextSub  = $ctx.Subscription.Id
    $contextTenant = $ctx.Tenant.Id
    $contextMatches = $contextSub -eq $subscriptionId
    Write-Check 'Active context subscription matches config' $contextMatches "Context: $contextSub"
    if (-not $contextMatches) { $allPassed = $false }
    $tenantMatches = $contextTenant -eq $ManagedByTenantId
    Write-Check 'Active context tenant matches managing tenant' $tenantMatches "Context: $contextTenant"
    if (-not $tenantMatches) { $allPassed = $false }
    $evidenceData.checks['contextSubscription'] = $contextSub
    $evidenceData.checks['contextTenant']        = $contextTenant
} catch {
    Write-Check 'Azure context check' $false "Error: $_"
    $allPassed = $false
}

# Summary

Write-Host ""
Write-Host "" -ForegroundColor White
if ($allPassed) {
    Write-Host "  OVERALL: PASS - Lighthouse delegation verified" -ForegroundColor Green
    $evidenceData.status = 'succeeded'
} else {
    Write-Host "  OVERALL: FAIL - One or more checks did not pass" -ForegroundColor Red
    $evidenceData.status = 'failed'
}
Write-Host "" -ForegroundColor White

$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
Write-Host "  Evidence: $evidenceFile"

# TEST_REQUIRED: Run from RSOC managing tenant; confirm ForeignGroup assignments visible
# TEST_REQUIRED: Validate the private expected group/role matrix matches the approved Lighthouse overlay

if (-not $allPassed) { exit 1 }
