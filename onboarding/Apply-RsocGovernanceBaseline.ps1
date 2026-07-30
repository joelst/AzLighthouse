#Requires -Version 7.0
<#
.SYNOPSIS
    Apply-RsocGovernanceBaseline.ps1 - Applies RBAC role assignments and policy initiative baseline.
.DESCRIPTION
    Idempotently applies role assignments from rbac-baseline.json and attempts to create
    a policy initiative from rsoc-sentinel-policy-initiative-placeholder.json.
    MANUAL_ACTION: Policy placeholder files need real policy definitions before production;
                   review Policies/*.json and replace with production-ready definitions.
    TEST_REQUIRED: Policy JSON files are placeholders; review rbac-baseline.json format.
    TEST_REQUIRED: Policy initiative creation requires Management Group or Subscription Owner.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
    [Parameter(Mandatory)]
    [string]$CustomerConfigPath,

    [string]$CustomerSubscriptionId,

    [string]$PoliciesDir = ".\Policies",

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = ".\evidence"
)

$scriptName = "Apply-RsocGovernanceBaseline"

# ─── Config ───────────────────────────────────────────────────────────────────
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$subscriptionId    = $CustomerSubscriptionId `
                   ?? $config.deployment?.subscriptionId `
                   ?? (Get-AzContext).Subscription.Id

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
    "Policy JSON files are placeholders; review and replace before production deployment",
    "rbac-baseline.json format: array of { roleDefinitionName, principalId, principalType, scope }",
    "Policy initiative creation requires Subscription Owner or Management Group Contributor"
)

Write-Host "=== Apply-RsocGovernanceBaseline ===" -ForegroundColor Yellow
Write-Host "Customer      : $customerShortName"
Write-Host "Subscription  : $subscriptionId"
Write-Host "PoliciesDir   : $PoliciesDir"

$rbacResults   = [System.Collections.Generic.List[hashtable]]::new()
$policyResults = [System.Collections.Generic.List[hashtable]]::new()

# ─── Locate rbac-baseline.json ────────────────────────────────────────────────
$scriptDir      = Split-Path $PSCommandPath -Parent
$rbacCandidates = @(
    (Join-Path $scriptDir "rbac-baseline.json"),
    (Join-Path $scriptDir "..\rbac-baseline.json"),
    (Join-Path (Split-Path $CustomerConfigPath -Parent) "rbac-baseline.json")
)
$rbacFile = $rbacCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $rbacFile) {
    Write-Warning "rbac-baseline.json not found in any candidate path. Skipping RBAC assignments."
    Write-Warning "Searched: $($rbacCandidates -join ', ')"
    $rbacResults.Add(@{ status = 'skipped'; reason = 'rbac-baseline.json not found' })
} else {
    Write-Host "Found rbac-baseline: $rbacFile" -ForegroundColor Cyan
    $rbacBaseline = Get-Content $rbacFile -Raw | ConvertFrom-Json
    $scope        = "/subscriptions/$subscriptionId"

    # ─── WhatIf ───────────────────────────────────────────────────────────────
    if ($WhatIfMode) {
        foreach ($entry in $rbacBaseline) {
            $roleName    = $entry.roleDefinitionName ?? $entry.RoleDefinitionName
            $principalId = $entry.principalId ?? $entry.PrincipalId
            $entryScope  = $entry.scope ?? $entry.Scope ?? $scope
            Write-Host "[WHATIF] Would assign role '$roleName' to '$principalId' at scope '$entryScope'" -ForegroundColor Magenta
            $rbacResults.Add(@{
                status       = 'whatif'
                role         = $roleName
                principalId  = $principalId
                scope        = $entryScope
            })
        }
    } else {
        # ─── Apply RBAC assignments idempotently ──────────────────────────────
        Write-Host "`n[1] Applying RBAC role assignments (idempotent)..." -ForegroundColor Cyan
        foreach ($entry in $rbacBaseline) {
            $roleName      = $entry.roleDefinitionName ?? $entry.RoleDefinitionName ?? ''
            $principalId   = $entry.principalId ?? $entry.PrincipalId ?? ''
            $principalType = $entry.principalType ?? $entry.PrincipalType ?? 'ServicePrincipal'
            $entryScope    = $entry.scope ?? $entry.Scope ?? $scope

            if (-not $roleName -or -not $principalId) {
                Write-Warning "Skipping entry with missing roleDefinitionName or principalId: $($entry | ConvertTo-Json -Compress)"
                $rbacResults.Add(@{ status = 'skipped'; reason = 'missing role or principalId'; entry = $entry })
                continue
            }

            try {
                $existing = Get-AzRoleAssignment `
                    -ObjectId $principalId `
                    -RoleDefinitionName $roleName `
                    -Scope $entryScope `
                    -ErrorAction SilentlyContinue

                if ($existing) {
                    Write-Host "  [EXISTS] '$roleName' already assigned to '$principalId'" -ForegroundColor Gray
                    $rbacResults.Add(@{
                        status      = 'exists'
                        role        = $roleName
                        principalId = $principalId
                        scope       = $entryScope
                    })
                } else {
                    $assignment = New-AzRoleAssignment `
                        -ObjectId $principalId `
                        -RoleDefinitionName $roleName `
                        -Scope $entryScope `
                        -PrincipalType $principalType `
                        -ErrorAction Stop
                    Write-Host "  [CREATED] '$roleName' assigned to '$principalId'" -ForegroundColor Green
                    $rbacResults.Add(@{
                        status              = 'created'
                        role                = $roleName
                        principalId         = $principalId
                        scope               = $entryScope
                        assignmentId        = $assignment.RoleAssignmentId
                    })
                }
            } catch {
                $errMsg = $_.Exception.Message
                Write-Warning "  [FAILED] '$roleName' for '$principalId': $errMsg"
                $rbacResults.Add(@{
                    status      = 'failed'
                    role        = $roleName
                    principalId = $principalId
                    scope       = $entryScope
                    error       = $errMsg
                })
            }
        }
    }
}

# ─── Load and apply Policy initiative ────────────────────────────────────────
Write-Host "`n[2] Processing policy initiative placeholder..." -ForegroundColor Cyan
$policyFile = Join-Path $PoliciesDir "rsoc-sentinel-policy-initiative-placeholder.json"

if (-not (Test-Path $policyFile)) {
    Write-Warning "Policy initiative placeholder not found: $policyFile"
    Write-Warning "MANUAL_ACTION: Create Policies/rsoc-sentinel-policy-initiative-placeholder.json with real policy definitions."
    $policyResults.Add(@{
        status = 'skipped'
        reason = "File not found: $policyFile"
    })
} else {
    Write-Host "Found policy initiative file: $policyFile" -ForegroundColor Cyan
    $policyJson = Get-Content $policyFile -Raw | ConvertFrom-Json

    $initiativeName        = $policyJson.name ?? "rsoc-sentinel-baseline-$customerShortName"
    $initiativeDisplayName = $policyJson.properties?.displayName ?? "RSOC Sentinel Baseline - $customerShortName"
    $initiativeDescription = $policyJson.properties?.description ?? "RSOC Sentinel governance baseline initiative"
    $managementGroupId     = $policyJson.managementGroupId ?? $null
    $initScope             = if ($managementGroupId) { "/providers/Microsoft.Management/managementGroups/$managementGroupId" } `
                             else { "/subscriptions/$subscriptionId" }

    if ($WhatIfMode) {
        Write-Host "[WHATIF] Would create/update policy initiative '$initiativeName' at scope '$initScope'" -ForegroundColor Magenta
        $policyResults.Add(@{ status = 'whatif'; initiativeName = $initiativeName; scope = $initScope })
    } else {
        # TEST_REQUIRED: Policy JSON files are placeholders; review before production use.
        # MANUAL_ACTION: Policy placeholder files need real policy definitions before production.
        Write-Host "  MANUAL_ACTION: Policy placeholder files need real policy definitions before production." -ForegroundColor Magenta
        Write-Host "  Review $policyFile and replace with production-ready definitions." -ForegroundColor Magenta

        try {
            $existingInitiative = Get-AzPolicySetDefinition -Name $initiativeName -ErrorAction SilentlyContinue
            if ($existingInitiative) {
                Write-Host "  [EXISTS] Policy initiative '$initiativeName' already exists." -ForegroundColor Gray
                $policyResults.Add(@{
                    status         = 'exists'
                    initiativeName = $initiativeName
                    scope          = $initScope
                    id             = $existingInitiative.PolicySetDefinitionId
                })
            } else {
                Write-Host "  [INFO] Policy initiative '$initiativeName' does not exist. Placeholder file present but definitions are not production-ready." -ForegroundColor Yellow
                Write-Host "  [SKIP] Skipping creation — review and update $policyFile before deploying." -ForegroundColor Yellow
                $policyResults.Add(@{
                    status         = 'manual-required'
                    initiativeName = $initiativeName
                    scope          = $initScope
                    reason         = "Placeholder policy file requires real policy definitions before creation"
                })
            }
        } catch {
            $errMsg = $_.Exception.Message
            Write-Warning "  Policy initiative check failed: $errMsg"
            $policyResults.Add(@{ status = 'failed'; initiativeName = $initiativeName; error = $errMsg })
        }
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host "  MANUAL_ACTION: Review Policies/*.json" -ForegroundColor Magenta
Write-Host "  Policy placeholder files require real Azure Policy definitions" -ForegroundColor Magenta
Write-Host "  before they can be deployed to production." -ForegroundColor Magenta
Write-Host "================================================================" -ForegroundColor Magenta

$overallStatus = if ($WhatIfMode) { 'whatif-only' }
                 elseif ($rbacResults | Where-Object { $_.status -eq 'failed' }) { 'partial-failure' }
                 else { 'succeeded' }

Write-Evidence @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = $overallStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    subscriptionId    = $subscriptionId
    rbacResults       = $rbacResults
    policyResults     = $policyResults
    manualActions     = @(
        "Review and replace Policies/*.json with production-ready Azure Policy definitions",
        "Verify rbac-baseline.json principal IDs are correct for this customer's environment"
    )
    testRequired      = $testRequired
}

Write-Host "=== Apply-RsocGovernanceBaseline complete. Status: $overallStatus ===" -ForegroundColor Cyan
