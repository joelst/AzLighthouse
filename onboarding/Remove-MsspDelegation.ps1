#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# MANUAL_ACTION: Coordinate with account team before removing; customer should review in
#                Azure Portal > Service Providers before this runs

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [string]$CustomerSubscriptionId,
    [switch]$RemoveResources,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = ".\evidence"
)

$scriptName        = "Remove-MsspDelegation"
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$subscriptionId    = $CustomerSubscriptionId ?? $config.deployment.subscriptionId
$resourceGroupName = $config.deployment.resourceGroupName

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

Write-Host "`n=== Remove-MsspDelegation ===" -ForegroundColor Cyan
Write-Host "Customer: $customerShortName  |  Subscription: $subscriptionId"
if ($WhatIfMode)      { Write-Host "[WhatIf mode - no changes will be made]" -ForegroundColor Yellow }
if ($RemoveResources) { Write-Host "[RemoveResources flag set - RG will also be removed]" -ForegroundColor Red }

# MANUAL_ACTION: Coordinate with account team before removing
Write-Host "`n[MANUAL_ACTION] Before proceeding:" -ForegroundColor Magenta
Write-Host "  1. Confirm removal is approved with account team" -ForegroundColor Magenta
Write-Host "  2. Advise customer to review Azure Portal > Service Providers" -ForegroundColor Magenta
Write-Host "     to see active delegations before they are removed`n" -ForegroundColor Magenta

$null = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop
$scope = "/subscriptions/$subscriptionId"

$actions = [System.Collections.Generic.List[hashtable]]::new()

 Find managed services assignments # 
Write-Host "Searching for Managed Services assignments on scope: $scope" -ForegroundColor Yellow
$assignments = @()
try {
    $assignments = @(Get-AzManagedServicesAssignment -Scope $scope -ErrorAction Stop)
    Write-Host "  Found $($assignments.Count) assignment(s)" -ForegroundColor Gray
} catch {
    Write-Host "[WARN] Could not retrieve assignments: $($_.Exception.Message)" -ForegroundColor Yellow
}

foreach ($assignment in $assignments) {
    $assignmentName  = $assignment.Name
    $definitionId    = $assignment.Properties?.RegistrationDefinitionId
    Write-Host "  Assignment: $assignmentName  |  DefinitionId: $definitionId" -ForegroundColor Gray

    if ($WhatIfMode) {
        Write-Host "[WhatIf] Would remove assignment: $assignmentName" -ForegroundColor Yellow
        $actions.Add(@{ action = 'remove-assignment'; name = $assignmentName; status = 'whatif'; definitionId = $definitionId })
    } else {
        try {
            Write-Host "Removing assignment: $assignmentName ..." -ForegroundColor Yellow
            Remove-AzManagedServicesAssignment -Name $assignmentName -Scope $scope -ErrorAction Stop
            Write-Host "  Removed assignment: $assignmentName" -ForegroundColor Green
            $actions.Add(@{ action = 'remove-assignment'; name = $assignmentName; status = 'removed'; definitionId = $definitionId })
        } catch {
            Write-Host "[ERROR] Failed to remove assignment $assignmentName : $($_.Exception.Message)" -ForegroundColor Red
            $actions.Add(@{ action = 'remove-assignment'; name = $assignmentName; status = 'failed'; error = $_.Exception.Message })
        }
    }
}

if ($assignments.Count -eq 0) {
    Write-Host "  No assignments found to remove" -ForegroundColor Gray
    $actions.Add(@{ action = 'remove-assignment'; status = 'none-found' })
}

 Find and remove managed services definitions # 
Write-Host "`nSearching for Managed Services definitions ..." -ForegroundColor Yellow
$definitions = @()
try {
    $definitions = @(Get-AzManagedServicesDefinition -Scope $scope -ErrorAction Stop)
    Write-Host "  Found $($definitions.Count) definition(s)" -ForegroundColor Gray
} catch {
    Write-Host "[WARN] Could not retrieve definitions: $($_.Exception.Message)" -ForegroundColor Yellow
}

foreach ($def in $definitions) {
    $defName        = $def.Name
    $offerName      = $def.Properties?.Description ?? $def.Properties?.RegistrationDefinitionName
    Write-Host "  Definition: $defName  |  Name: $offerName" -ForegroundColor Gray

    if ($WhatIfMode) {
        Write-Host "[WhatIf] Would remove definition: $defName" -ForegroundColor Yellow
        $actions.Add(@{ action = 'remove-definition'; name = $defName; status = 'whatif'; offerName = $offerName })
    } else {
        try {
            Write-Host "Removing definition: $defName ..." -ForegroundColor Yellow
            Remove-AzManagedServicesDefinition -Name $defName -Scope $scope -ErrorAction Stop
            Write-Host "  Removed definition: $defName" -ForegroundColor Green
            $actions.Add(@{ action = 'remove-definition'; name = $defName; status = 'removed'; offerName = $offerName })
        } catch {
            Write-Host "[ERROR] Failed to remove definition $defName : $($_.Exception.Message)" -ForegroundColor Red
            $actions.Add(@{ action = 'remove-definition'; name = $defName; status = 'failed'; error = $_.Exception.Message })
        }
    }
}

 Optionally remove resource group # 
$rgRemoved = $false
if ($RemoveResources) {
    Write-Host "`n[WARNING] RemoveResources flag is set. This will DELETE resource group: $resourceGroupName" -ForegroundColor Red
    if ($WhatIfMode) {
        Write-Host "[WhatIf] Would remove resource group: $resourceGroupName" -ForegroundColor Yellow
        $actions.Add(@{ action = 'remove-resource-group'; name = $resourceGroupName; status = 'whatif' })
    } else {
        $confirm = Read-Host "Type the resource group name to confirm deletion: $resourceGroupName"
        if ($confirm -eq $resourceGroupName) {
            try {
                Write-Host "Removing resource group: $resourceGroupName ..." -ForegroundColor Red
                Remove-AzResourceGroup -Name $resourceGroupName -Force -ErrorAction Stop
                Write-Host "  Resource group removed: $resourceGroupName" -ForegroundColor Green
                $rgRemoved = $true
                $actions.Add(@{ action = 'remove-resource-group'; name = $resourceGroupName; status = 'removed' })
            } catch {
                Write-Host "[ERROR] Failed to remove RG: $($_.Exception.Message)" -ForegroundColor Red
                $actions.Add(@{ action = 'remove-resource-group'; name = $resourceGroupName; status = 'failed'; error = $_.Exception.Message })
            }
        } else {
            Write-Host "  Confirmation did not match. Resource group NOT removed." -ForegroundColor Yellow
            $actions.Add(@{ action = 'remove-resource-group'; name = $resourceGroupName; status = 'skipped-confirmation-mismatch' })
        }
    }
}

 Evidence # 
$failedActions = $actions | Where-Object { $_.status -eq 'failed' } | Measure-Object
$status = if ($WhatIfMode) { 'whatif-only' } elseif ($failedActions.Count -gt 0) { 'partial-failure' } else { 'succeeded' }

$ep = Write-Evidence -Data @{
    scriptName         = $scriptName
    customerShortName  = $customerShortName
    status             = $status
    timestampUtc       = (Get-Date).ToUniversalTime().ToString("o")
    testRequired       = @()
    subscriptionId     = $subscriptionId
    scope              = $scope
    resourceGroupName  = $resourceGroupName
    assignmentsFound   = $assignments.Count
    definitionsFound   = $definitions.Count
    removeResources    = $RemoveResources.IsPresent
    rgRemoved          = $rgRemoved
    actions            = $actions.ToArray()
    manualActions      = @(
        "Coordinate with account team before removing delegation",
        "Customer should review Azure Portal > Service Providers before removal"
    )
}

Write-Host "`nStatus: $status  |  Evidence: $ep`n"
