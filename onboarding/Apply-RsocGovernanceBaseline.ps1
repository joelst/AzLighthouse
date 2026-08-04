#Requires -Version 7.0
<#
.SYNOPSIS
    Apply-RsocGovernanceBaseline.ps1 - Applies RBAC role assignments and policy initiative baseline.
.DESCRIPTION
    Idempotently applies role assignments from rbac-baseline.json, upserts custom Azure
    Policy definitions from Policies/*.json, creates/updates the RSOC policy initiative,
    and assigns the initiative at subscription scope.
    TEST_REQUIRED: Validate policy aliases in your tenant and run in staging before switching
                   assignment effects from Audit to Deny.
    TEST_REQUIRED: Policy initiative creation requires Management Group or Subscription Owner.
#>
param(
    [Parameter(Mandatory)]
    [string]$CustomerConfigPath,

    [string]$CustomerSubscriptionId,

    [string]$PoliciesDir = ".\Policies",

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = ".\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    "rbac-baseline.json format: array of { roleDefinitionName, principalId, principalType, scope }",
    "Policy aliases for roleAssignments and tags must be validated in a staging subscription",
    "Start initiative effects in Audit before switching to Deny in production",
    "Policy initiative creation and assignment require Subscription Owner or Management Group Contributor"
)

Write-Host "=== Apply-RsocGovernanceBaseline ===" -ForegroundColor Yellow
Write-Host "Customer      : $customerShortName"
Write-Host "Subscription  : $subscriptionId"
Write-Host "PoliciesDir   : $PoliciesDir"

Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

$rbacResults   = [System.Collections.Generic.List[hashtable]]::new()
$policyResults = [System.Collections.Generic.List[hashtable]]::new()

# ─── Locate rbac-baseline.json ────────────────────────────────────────────────
$scriptDir      = Split-Path $PSCommandPath -Parent
$resolvedPoliciesDir = if ([System.IO.Path]::IsPathRooted($PoliciesDir)) {
    $PoliciesDir
} else {
    Join-Path $scriptDir $PoliciesDir
}
Write-Host "PoliciesPath  : $resolvedPoliciesDir"
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
Write-Host "`n[2] Applying policy baseline (definitions + initiative + assignment)..." -ForegroundColor Cyan
$initiativeCandidates = @(
    (Join-Path $resolvedPoliciesDir "rsoc-sentinel-policy-initiative.json"),
    (Join-Path $resolvedPoliciesDir "rsoc-sentinel-policy-initiative-placeholder.json")
)
$policyFile = $initiativeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $policyFile) {
    Write-Warning "Policy initiative file not found."
    Write-Warning "Searched: $($initiativeCandidates -join ', ')"
    $policyResults.Add(@{
        status = 'skipped'
        reason = "Initiative file not found"
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
    $assignmentName        = $policyJson.assignment?.name ?? "$initiativeName-assignment"
    $assignmentDisplayName = $policyJson.assignment?.displayName ?? $initiativeDisplayName
    $assignmentDescription = $policyJson.assignment?.description ?? $initiativeDescription
    $assignmentScope       = $policyJson.assignment?.scope ?? "/subscriptions/$subscriptionId"
    $assignmentParams      = $policyJson.assignment?.parameters
    $assignmentEnforcement = $policyJson.assignment?.enforcementMode ?? 'Default'

    $policyDefinitionFiles = Get-ChildItem -Path $resolvedPoliciesDir -Filter '*.json' -File |
        Where-Object { $_.FullName -ne $policyFile } |
        Sort-Object Name

    if (-not $policyDefinitionFiles) {
        Write-Warning "No custom policy definition files found in $resolvedPoliciesDir"
        $policyResults.Add(@{
            status = 'failed'
            reason = "No custom policy definition files found"
        })
    } else {
        $policyDefinitionIdByName = @{}

        foreach ($file in $policyDefinitionFiles) {
            try {
                $definitionJson = Get-Content $file.FullName -Raw | ConvertFrom-Json
                $definitionName = $definitionJson.name
                if (-not $definitionName -or -not $definitionJson.properties -or -not $definitionJson.properties.policyRule) {
                    throw "Invalid policy definition JSON schema in $($file.Name). Expected root 'name' and properties.policyRule."
                }

                $definitionDisplayName = $definitionJson.properties.displayName ?? $definitionName
                $definitionDescription = $definitionJson.properties.description ?? $definitionName
                $definitionMode        = $definitionJson.properties.mode ?? 'All'
                $definitionRuleJson    = $definitionJson.properties.policyRule | ConvertTo-Json -Depth 50 -Compress
                $definitionParamJson   = if ($definitionJson.properties.parameters) { $definitionJson.properties.parameters | ConvertTo-Json -Depth 50 -Compress } else { $null }
                $definitionMetaJson    = if ($definitionJson.properties.metadata) { $definitionJson.properties.metadata | ConvertTo-Json -Depth 50 -Compress } else { $null }

                if ($WhatIfMode) {
                    Write-Host "[WHATIF] Would create/update custom policy definition '$definitionName' from $($file.Name)" -ForegroundColor Magenta
                    $policyResults.Add(@{
                        status         = 'whatif'
                        stage          = 'policy-definition'
                        definitionName = $definitionName
                        sourceFile     = $file.Name
                    })
                    continue
                }

                $existingDefinition = Get-AzPolicyDefinition -Name $definitionName -ErrorAction SilentlyContinue
                if ($existingDefinition) {
                    Set-AzPolicyDefinition `
                        -Name $definitionName `
                        -DisplayName $definitionDisplayName `
                        -Description $definitionDescription `
                        -Policy $definitionRuleJson `
                        -Parameter $definitionParamJson `
                        -Mode $definitionMode `
                        -Metadata $definitionMetaJson `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [UPDATED] Policy definition '$definitionName'" -ForegroundColor Green
                } else {
                    New-AzPolicyDefinition `
                        -Name $definitionName `
                        -DisplayName $definitionDisplayName `
                        -Description $definitionDescription `
                        -Policy $definitionRuleJson `
                        -Parameter $definitionParamJson `
                        -Mode $definitionMode `
                        -Metadata $definitionMetaJson `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [CREATED] Policy definition '$definitionName'" -ForegroundColor Green
                }

                $resolvedDefinition = Get-AzPolicyDefinition -Name $definitionName -ErrorAction Stop
                $policyDefinitionIdByName[$definitionName] = $resolvedDefinition.PolicyDefinitionId
                $policyResults.Add(@{
                    status         = if ($existingDefinition) { 'updated' } else { 'created' }
                    stage          = 'policy-definition'
                    definitionName = $definitionName
                    definitionId   = $resolvedDefinition.PolicyDefinitionId
                    sourceFile     = $file.Name
                })
            } catch {
                $errMsg = $_.Exception.Message
                Write-Warning "  [FAILED] Policy definition file '$($file.Name)': $errMsg"
                $policyResults.Add(@{
                    status     = 'failed'
                    stage      = 'policy-definition'
                    sourceFile = $file.Name
                    error      = $errMsg
                })
            }
        }

        try {
            $policyDefinitionRefsRaw = $policyJson.properties?.policyDefinitions
            if (-not $policyDefinitionRefsRaw -or $policyDefinitionRefsRaw.Count -eq 0) {
                throw "Initiative file does not include properties.policyDefinitions."
            }

            $policyDefinitionRefs = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($ref in $policyDefinitionRefsRaw) {
                $resolvedId = $ref.policyDefinitionId
                if (-not $resolvedId -and $ref.policyDefinitionName) {
                    $resolvedId = $policyDefinitionIdByName[$ref.policyDefinitionName]
                }
                if (-not $resolvedId) {
                    throw "Unable to resolve policy definition reference '$($ref.policyDefinitionReferenceId)' (name: '$($ref.policyDefinitionName)')."
                }

                $refObj = @{
                    policyDefinitionId = $resolvedId
                    policyDefinitionReferenceId = ($ref.policyDefinitionReferenceId ?? $ref.policyDefinitionName ?? [guid]::NewGuid().ToString())
                }
                if ($ref.parameters) {
                    $refObj['parameters'] = $ref.parameters
                }
                $policyDefinitionRefs.Add($refObj)
            }

            if ($WhatIfMode) {
                Write-Host "[WHATIF] Would create/update policy initiative '$initiativeName' at scope '$initScope'" -ForegroundColor Magenta
                Write-Host "[WHATIF] Would create/update policy assignment '$assignmentName' at scope '$assignmentScope'" -ForegroundColor Magenta
                $policyResults.Add(@{
                    status         = 'whatif'
                    stage          = 'initiative'
                    initiativeName = $initiativeName
                    scope          = $initScope
                })
            } else {
                $initiativeParamsJson = if ($policyJson.properties?.parameters) { $policyJson.properties.parameters | ConvertTo-Json -Depth 50 -Compress } else { $null }
                $initiativeMetaJson   = if ($policyJson.properties?.metadata) { $policyJson.properties.metadata | ConvertTo-Json -Depth 50 -Compress } else { $null }
                $policyRefsJson       = $policyDefinitionRefs | ConvertTo-Json -Depth 50 -Compress

                $existingInitiative = Get-AzPolicySetDefinition -Name $initiativeName -ErrorAction SilentlyContinue
                if ($existingInitiative) {
                    Set-AzPolicySetDefinition `
                        -Name $initiativeName `
                        -DisplayName $initiativeDisplayName `
                        -Description $initiativeDescription `
                        -PolicyDefinition $policyRefsJson `
                        -Parameter $initiativeParamsJson `
                        -Metadata $initiativeMetaJson `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [UPDATED] Policy initiative '$initiativeName'" -ForegroundColor Green
                } else {
                    New-AzPolicySetDefinition `
                        -Name $initiativeName `
                        -DisplayName $initiativeDisplayName `
                        -Description $initiativeDescription `
                        -PolicyDefinition $policyRefsJson `
                        -Parameter $initiativeParamsJson `
                        -Metadata $initiativeMetaJson `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [CREATED] Policy initiative '$initiativeName'" -ForegroundColor Green
                }

                $initiativeDefinition = Get-AzPolicySetDefinition -Name $initiativeName -ErrorAction Stop
                $existingAssignment = Get-AzPolicyAssignment -Name $assignmentName -Scope $assignmentScope -ErrorAction SilentlyContinue
                if ($existingAssignment) {
                    Set-AzPolicyAssignment `
                        -Name $assignmentName `
                        -Scope $assignmentScope `
                        -PolicySetDefinition $initiativeDefinition `
                        -DisplayName $assignmentDisplayName `
                        -Description $assignmentDescription `
                        -PolicyParameterObject $assignmentParams `
                        -EnforcementMode $assignmentEnforcement `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [UPDATED] Policy assignment '$assignmentName'" -ForegroundColor Green
                    $assignmentState = 'updated'
                } else {
                    New-AzPolicyAssignment `
                        -Name $assignmentName `
                        -Scope $assignmentScope `
                        -PolicySetDefinition $initiativeDefinition `
                        -DisplayName $assignmentDisplayName `
                        -Description $assignmentDescription `
                        -PolicyParameterObject $assignmentParams `
                        -EnforcementMode $assignmentEnforcement `
                        -ErrorAction Stop | Out-Null
                    Write-Host "  [CREATED] Policy assignment '$assignmentName'" -ForegroundColor Green
                    $assignmentState = 'created'
                }

                $resolvedAssignment = Get-AzPolicyAssignment -Name $assignmentName -Scope $assignmentScope -ErrorAction Stop
                $policyResults.Add(@{
                    status         = $assignmentState
                    stage          = 'initiative-assignment'
                    initiativeName = $initiativeName
                    initiativeId   = $initiativeDefinition.PolicySetDefinitionId
                    assignmentName = $assignmentName
                    assignmentId   = $resolvedAssignment.PolicyAssignmentId
                    scope          = $assignmentScope
                })
            }
        } catch {
            $errMsg = $_.Exception.Message
            Write-Warning "  [FAILED] Policy initiative/assignment: $errMsg"
            $policyResults.Add(@{
                status         = 'failed'
                stage          = 'initiative-assignment'
                initiativeName = $initiativeName
                error          = $errMsg
            })
        }
    }
}

$overallStatus = if ($WhatIfMode) { 'whatif-only' }
                 elseif (($rbacResults | Where-Object { $_.status -eq 'failed' }) -or
                        ($policyResults | Where-Object { $_.status -eq 'failed' })) { 'partial-failure' }
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
        "Set approvedPrincipalIds in policy assignment parameters to RSOC-approved elevated principals before switching RBAC effect modes",
        "Keep policy effects in Audit during initial rollout; switch to Deny only after staged validation",
        "Verify rbac-baseline.json principal IDs are correct for this customer's environment"
    )
    testRequired      = $testRequired
}

Write-Host "=== Apply-RsocGovernanceBaseline complete. Status: $overallStatus ===" -ForegroundColor Cyan
