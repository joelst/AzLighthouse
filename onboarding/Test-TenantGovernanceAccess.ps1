<#
.SYNOPSIS
    Validates an active Microsoft Entra Tenant Governance relationship between the RSOC
    (governing) tenant and a customer (governed) tenant.

.DESCRIPTION
    Queries the Graph beta Tenant Governance Services API to verify:
      1. An active governanceRelationship exists for the customer tenant.
      2. The relationship was established by the correct governing tenant.
      3. The policySnapshot contains the expected RSOC security group role assignments.

    API reference (beta):
      https://learn.microsoft.com/en-us/graph/api/resources/tenantgovernanceservices-governancerelationship

.PARAMETER CustomerConfigPath
    Path to the customer intake JSON.

.PARAMETER CustomerTenantId
    Override the governed tenant ID from config.customer.tenantId.

.PARAMETER GoverningTenantId
    Expected RSOC governing tenant ID. If provided, validates the relationship
    was established by this specific tenant.

.PARAMETER WhatIfMode
    Preview what would be tested without calling the API.

.PARAMETER EvidenceOutputPath
    Path for machine-readable evidence output.

.NOTES
    REQUIRES:
      - Microsoft.Graph.Authentication module
      - Scopes: TenantGovernance-Relationship.Read.All
      - User needs: Tenant Governance Administrator, Tenant Governance Relationship Reader,
        Global Reader, or Tenant Governance Reader Entra role

    TEST_REQUIRED:
      - API is Graph beta endpoints subject to change
      - Run from RSOC governing tenant context
      - policySnapshot role verification checks group IDs in governing tenant - confirm IDs
        match live RSOC group object IDs
      - Relationship must be active before running (customer must have approved the governance request
        via Defender portal: https://security.microsoft.com > System > Permissions > Delegated Access)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CustomerConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerTenantId,

    [Parameter(Mandatory = $false)]
    [string]$GoverningTenantId,

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = '.\evidence\Test-TenantGovernanceAccess.evidence.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TgBaseUrl = 'https://graph.microsoft.com/beta/directory/tenantGovernance'

# Expected RSOC group IDs in the policySnapshot delegatedAdministrationRoleAssignments
# IMPORTANT: Placeholder IDs — set actual values from mssp-management/Config/rsoc-groups.json
# Copy rsoc-groups.json from mssp-management and pass via -CustomerConfigPath, or update these
# before running in your environment. See README for setup instructions.
# TEST_REQUIRED: Verify these match live RSOC tenant group object IDs
$ExpectedGroupIds = @(
    @{ Id = '00000000-0000-0000-0000-000000000001'; Name = 'RSOC_Sentinel_Admin' },
    @{ Id = '00000000-0000-0000-0000-000000000002'; Name = 'RSOC_Sentinel_Onboarding' },
    @{ Id = '00000000-0000-0000-0000-000000000003'; Name = 'RSOC_Sentinel_Threat_Detection_Engineering_Tier1' },
    @{ Id = '00000000-0000-0000-0000-000000000004'; Name = 'RSOC_Sentinel_Threat_Detection_Engineering_Tier2' },
    @{ Id = '00000000-0000-0000-0000-000000000005'; Name = 'RSOC_Sentinel_Security_Engineers' },
    @{ Id = '00000000-0000-0000-0000-000000000006'; Name = 'RSOC_Sentinel_Red_Team' },
    @{ Id = '00000000-0000-0000-0000-000000000007'; Name = 'RSOC_Sentinel_Incident_Response' },
    @{ Id = '00000000-0000-0000-0000-000000000008'; Name = 'RSOC_Sentinel_Incident_Detection_Tier1' },
    @{ Id = '00000000-0000-0000-0000-000000000009'; Name = 'RSOC_Sentinel_Incident_Detection_Tier2' }
)

function Write-Evidence {
    param([hashtable]$Data)
    $dir = Split-Path -Parent $EvidenceOutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $EvidenceOutputPath -Encoding utf8
}

function Write-Check {
    param([string]$Label, [bool]$Pass, [string]$Detail = '')
    $icon  = if ($Pass) { '[PASS]' } else { '[FAIL]' }
    $color = if ($Pass) { 'Green' } else { 'Red' }
    Write-Host "$icon $Label" -ForegroundColor $color
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor Gray }
}

# Load config
if (-not (Test-Path $CustomerConfigPath)) { throw "Customer config not found: $CustomerConfigPath" }
$config           = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$governedTenantId = if ($CustomerTenantId) { $CustomerTenantId } else { $config.customer.tenantId }
if ([string]::IsNullOrWhiteSpace($governedTenantId)) { throw "No customer.tenantId in config." }

Write-Host ""
Write-Host "=== Test-TenantGovernanceAccess ===" -ForegroundColor Cyan
Write-Host "  Customer:        $($config.customer.shortName)"
Write-Host "  Governed tenant: $governedTenantId"
Write-Host ""

if ($WhatIfMode) {
    Write-Host "[WHATIF] Would query: GET $TgBaseUrl/governanceRelationships?`$filter=governedTenantId eq '$governedTenantId'" -ForegroundColor Yellow
    Write-Evidence @{
        script          = 'Test-TenantGovernanceAccess.ps1'
        customer        = $config.customer.shortName
        governedTenantId = $governedTenantId
        whatIf          = $true
        status          = 'whatif-only'
        timestampUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }
    return
}

# Connect to Graph
Connect-MgGraph -Scopes 'TenantGovernance-Relationship.Read.All' -NoWelcome
$ctx = Get-MgContext
Write-Host "Connected as: $($ctx.Account) in tenant: $($ctx.TenantId)"
Write-Host ""

$checks = @{}

# Check 1: Active governance relationship exists
Write-Host "[1] Checking governance relationship..." -ForegroundColor Cyan
try {
    $rels      = Invoke-MgGraphRequest -Method GET -Uri "$TgBaseUrl/governanceRelationships?`$filter=governedTenantId eq '$governedTenantId'"
    $activeRel = $rels.value | Where-Object { $_.status -ieq 'active' } | Select-Object -First 1

    $checks.RelationshipExists = $null -ne $activeRel
    Write-Check -Label "Active governance relationship found" -Pass ($null -ne $activeRel) -Detail $(
        if ($activeRel) { "ID: $($activeRel.id) | Created: $($activeRel.creationDateTime)" }
        else {
            $allRels = $rels.value
            "No active relationship. Total found: $($allRels.Count) | Statuses: $(($allRels | Select-Object -ExpandProperty status) -join ', ')"
        }
    )
} catch {
    $checks.RelationshipExists = $false
    Write-Check -Label "Active governance relationship found" -Pass $false -Detail $_.Exception.Message
    $activeRel = $null
}

# Check 2: Governing tenant ID matches expected
if ($activeRel -and $GoverningTenantId) {
    $tenantMatch = $activeRel.governingTenantId -eq $GoverningTenantId
    $checks.GoverningTenantMatch = $tenantMatch
    Write-Check -Label "Governing tenant ID matches" -Pass $tenantMatch -Detail (
        "Expected: $GoverningTenantId | Actual: $($activeRel.governingTenantId) ($($activeRel.governingTenantName))"
    )
} elseif ($activeRel) {
    Write-Host "       Governing tenant: $($activeRel.governingTenantId) ($($activeRel.governingTenantName))" -ForegroundColor Gray
}

# Check 3: Policy snapshot has RSOC group assignments
if ($activeRel -and $activeRel.policySnapshot) {
    Write-Host ""
    Write-Host "[2] Checking policySnapshot role assignments..." -ForegroundColor Cyan

    $snapshot           = $activeRel.policySnapshot
    $snapshotAssignments = $snapshot.delegatedAdministrationRoleAssignments ?? @()
    $snapshotGroupIds    = @($snapshotAssignments | ForEach-Object { $_.group.id } | Where-Object { $_ })

    $groupChecks = @{}
    foreach ($expected in $ExpectedGroupIds) {
        $found = $snapshotGroupIds -contains $expected.Id
        $groupChecks[$expected.Name] = $found
        Write-Check -Label "  Group: $($expected.Name)" -Pass $found -Detail (
            if (-not $found) { "Group ID $($expected.Id) not found in policySnapshot" } else { "" }
        )
    }

    $allGroupsPresent         = ($groupChecks.Values | Where-Object { $_ -eq $false }).Count -eq 0
    $checks.AllGroupsPresent  = $allGroupsPresent
    $checks.GroupDetails      = $groupChecks

    Write-Host ""
    $presentCount = ($groupChecks.Values | Where-Object { $_ }).Count
    Write-Check -Label "All $($ExpectedGroupIds.Count) RSOC groups in policySnapshot" -Pass $allGroupsPresent `
        -Detail "$presentCount/$($ExpectedGroupIds.Count) groups found"
} elseif ($activeRel) {
    Write-Host "  WARNING: Active relationship has no policySnapshot - cannot verify role assignments" -ForegroundColor Yellow
    $checks.AllGroupsPresent = $false
}

# Summary
Write-Host ""
$allPassed    = -not ($checks.Values | Where-Object { $_ -is [bool] -and $_ -eq $false })
$overallStatus = if ($allPassed) { 'passed' } else { 'failed' }

Write-Host "=== Result: $(if ($allPassed) { 'ALL CHECKS PASSED' } else { 'CHECKS FAILED - review above' })" `
    -ForegroundColor (if ($allPassed) { 'Green' } else { 'Red' })

if ($activeRel -and -not $allPassed) {
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  - If groups are missing from policySnapshot, the governance policy template"
    Write-Host "    may need to be updated. Create a new governance request with an updated template."
    Write-Host "  - Updating a template does NOT retroactively update existing relationships."
}

Write-Evidence @{
    script              = 'Test-TenantGovernanceAccess.ps1'
    customer            = $config.customer.shortName
    governedTenantId    = $governedTenantId
    relationshipId      = $activeRel?.id
    relationshipStatus  = $activeRel?.status
    creationDateTime    = $activeRel?.creationDateTime
    governingTenantId   = $activeRel?.governingTenantId
    governingTenantName = $activeRel?.governingTenantName
    checks              = $checks
    allPassed           = $allPassed
    status              = $overallStatus
    testRequired        = @(
        "API is Graph beta - verify endpoints before production run",
        "Run from RSOC governing tenant context",
        "Verify ExpectedGroupIds match live RSOC tenant group object IDs",
        "policySnapshot group.id fields require governance request to have been created with correct template"
    )
    timestampUtc        = (Get-Date).ToUniversalTime().ToString('o')
}
