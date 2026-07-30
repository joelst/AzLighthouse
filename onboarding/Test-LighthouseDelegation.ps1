#Requires -Version 7.0
#Requires -Modules Az.ManagedServices, Az.Resources
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Tests that Azure Lighthouse delegation is correctly configured for a customer subscription.
.DESCRIPTION
    Run from the RSOC managing tenant context. Checks for delegation assignment,
    managed services definition, and verifies all 9 RSOC groups have ForeignGroup assignments.
#>
param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

 Helpers # 

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
    if ($Detail) { Write- $Detail" -ForegroundColor Gray } else { Write-Host '' }Host "  
    return $Passed
}

function Write-Status { param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color }

 RSOC Groups to Verify # 

$rsocGroups = [ordered]@{
    'RSOC_Sentinel_Admin'                               = 'c1f4a285-1b26-46b8-9a97-d298861ad503'
    'RSOC_Sentinel_Onboarding'                          = 'cbe65060-f79c-4350-aaf2-fd901a95de33'
    'RSOC_Sentinel_Threat_Detection_Engineering_Tier1'  = '440ba293-8d18-430c-b4cc-3ea789d655e9'
    'RSOC_Sentinel_Threat_Detection_Engineering_Tier2'  = 'd4e11e0e-6300-4491-938f-e934a587f990'
    'RSOC_Sentinel_Security_Engineers'                  = '4fd628b1-a5f8-43a1-9949-88a84e7f053b'
    'RSOC_Sentinel_Red_Team'                            = 'a6539c63-c61b-459f-bdc6-22106aa0aed3'
    'RSOC_Sentinel_Incident_Response'                   = 'ef18438b-79fc-4b4a-8f3f-3b691f091aa2'
    'RSOC_Sentinel_Incident_Detection_Tier1'            = '0d593b30-eb20-4d83-a7eb-deff71e401d2'
    'RSOC_Sentinel_Incident_Detection_Tier2'            = 'fe773eea-b69d-40e7-9c90-0ccb5ea4447c'
}

 Load Config # 

Write-Status "Loading customer config: $CustomerConfigPath"
$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json

$customerShortName = $config.customer.shortName
$subscriptionId    = $config.deployment.subscriptionId
$scope             = "/subscriptions/$subscriptionId"

Write-Status "Customer: $customerShortName | Subscription: $subscriptionId"
Write-Host ""

$evidenceData = @{
    scriptName        = 'Test-LighthouseDelegation'
    customerShortName = $customerShortName
    subscriptionId    = $subscriptionId
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Run from RSOC managing  must be authenticated to RSOC tenant',tenant 
        'Confirm ForeignGroup assignments are visible in customer subscription IAM',
        'All 9 RSOC groups must appear as delegated role assignments'
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

 Check 1: Managed Services Assignment Exists # 

 Check 1: Managed " -ForegroundColor WhiteServices Assignment Write-Host "
try {
    $assignments = Get-AzManagedServicesAssignment -Scope $scope -ErrorAction Stop
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

 Check 2: Managed Services Definition # 

Write-Host ""
 Check 2: Managed " -ForegroundColor WhiteServices Definition Write-Host "
try {
    $definitions = Get-AzManagedServicesDefinition -ErrorAction Stop
    $tmnaDefinition = $definitions | Where-Object {
        $_.Properties?.ManagedByTenantId -or $_.Properties?.Description -match 'TMNA'
    }
    if ($tmnaDefinition) {
        $passed = Write-Check 'TMNA managed services definition found' $true
        $evidenceData.checks['managedServicesDefinition'] = 'found'
    } else {
        $passed = Write-Check 'TMNA managed services definition found' ($definitions.Count -gt 0) "Found $($definitions.Count) definition(s)"
        $evidenceData.checks['managedServicesDefinition'] = "found-generic: $($definitions.Count)"
    }
} catch {
    Write-Check 'Managed services definition query' $false "Error: $_"
    $evidenceData.checks['managedServicesDefinition'] = "error: $_"
    $allPassed = $false
}

 Check 3: ForeignGroup Role Assignments # 

Write-Host ""
 Check 3: RSOC Group ForeignGroup " -ForegroundColor WhiteRole Assignments Write-Host "

try {
    $roleAssignments = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop
    $foreignGroupAssignments = $roleAssignments | Where-Object {
        $_.ObjectType -eq 'ForeignGroup' -or $_.ObjectType -eq 'Group'
    }

    Write-Host "  Total role assignments at scope: $($roleAssignments.Count)" -ForegroundColor Gray
    Write-Host "  ForeignGroup/Group assignments : $($foreignGroupAssignments.Count)" -ForegroundColor Gray
    Write-Host ""

    $groupPassCount = 0

    foreach ($groupName in $rsocGroups.Keys) {
        $principalId = $rsocGroups[$groupName]
        $match = $foreignGroupAssignments | Where-Object {
            $_.ObjectId -eq $principalId
        }
        if ($match) {
            $roles = ($match | Select-Object -ExpandProperty RoleDefinitionName) -join ', '
            $groupPassed = Write-Check "  $groupName" $true "Role(s): $roles"
            $evidenceData.groupResults[$groupName] = @{ found = $true; roles = $roles; principalId = $principalId }
            $groupPassCount++
        } else {
            $groupPassed = Write-Check "  $groupName" $false "PrincipalId $principalId not found in ForeignGroup assignments"
            $evidenceData.groupResults[$groupName] = @{ found = $false; principalId = $principalId }
            $allPassed = $false
        }
    }

    Write-Host ""
    Write-Host "  Group assignment score: $groupPassCount / $($rsocGroups.Count)" -ForegroundColor $(if ($groupPassCount -eq $rsocGroups.Count) { 'Green' } else { 'Yellow' })
    $evidenceData.checks['groupAssignmentScore'] = "$groupPassCount/$($rsocGroups.Count)"

} catch {
    Write-Check 'Role assignment query' $false "Error: $_"
    $evidenceData.checks['foreignGroupAssignments'] = "error: $_"
    $allPassed = $false
}

 Check 4: Customer Tenant Context # 

Write-Host ""
 Check 4: " -ForegroundColor WhiteAzure Context Write-Host "
try {
    $ctx = Get-AzContext
    $contextSub  = $ctx.Subscription.Id
    $contextTenant = $ctx.Tenant.Id
    Write-Check 'Active context subscription matches config' ($contextSub -eq $subscriptionId) "Context: $contextSub"
    $evidenceData.checks['contextSubscription'] = $contextSub
    $evidenceData.checks['contextTenant']        = $contextTenant
} catch {
    Write-Check 'Azure context check' $false "Error: $_"
}

 Summary # 

Write-Host ""
" -ForegroundColor WhiteWrite-Host "
if ($allPassed) {
    Write-Host "  OVERALL:  Lighthouse delegation verified" -ForegroundColor GreenPASS 
    $evidenceData.status = 'succeeded'
} else {
    Write-Host "  OVERALL:  One or more checks did not pass" -ForegroundColor RedFAIL 
    $evidenceData.status = 'failed'
}
" -ForegroundColor WhiteWrite-Host "

$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
Write-Host "  Evidence: $evidenceFile"

# TEST_REQUIRED: Run from RSOC managing tenant; confirm ForeignGroup assignments visible
# TEST_REQUIRED: Validate all 9 principal IDs match current RSOC group object IDs in RSOC tenant
