#Requires -Version 7.0
#Requires -Modules Az.Resources, Az.ManagedServices

<#
.SYNOPSIS
    Deploys Azure Lighthouse delegation for a customer subscription to RSOC managing tenant.
.DESCRIPTION
    Checks caller permissions, checks for existing delegation, deploys the Lighthouse ARM template,
    verifies the deployment, and writes evidence JSON.
#>
param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$ManagedByTenantId,
    [string]$CustomerSubscriptionId,
    [string]$Location = 'eastus',
    # Local path to the Lighthouse ARM template. Defaults to the generic template
    # restored in this repository. Pass a private overlay for customer-specific values.
    [string]$LighthouseTemplatePath,
    [string]$LighthouseParametersPath,
    [string]$MspOfferName,
    [string]$MspOfferDescription,
    [string]$AdministratorGroupPrincipalId,
    [string]$AdministratorGroupPrincipalIdDisplayName,
    [string]$AnalystGroupPrincipalId,
    [string]$AnalystGroupPrincipalIdDisplayName,
    [string]$AutomationPrincipalId,
    [string]$AutomationPrincipalIdDisplayName,
    [switch]$PromptForLighthouseValues,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Helpers

function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("lighthouse-delegation-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    Write-Host "  Evidence written: $file" -ForegroundColor DarkGray
    return $file
}

function Write-Status {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

# Load Config

Write-Status "Loading customer config: $CustomerConfigPath"
$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$configLighthouse = if ($config.PSObject.Properties.Name -contains 'lighthouse') { $config.lighthouse } else { $null }

$customerShortName  = $config.customer.shortName
$subscriptionId     = if ($CustomerSubscriptionId) { $CustomerSubscriptionId } else { $config.deployment.subscriptionId }
$scope              = "/subscriptions/$subscriptionId"

Write-Status "Customer: $customerShortName | Subscription: $subscriptionId"

$evidenceData = @{
    scriptName        = 'New-LighthouseDelegationPackage'
    customerShortName = $customerShortName
    subscriptionId    = $subscriptionId
    managedByTenantId = $ManagedByTenantId
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Must run from customer Owner account or equivalent',
        'Verify delegation appears in Azure Lighthouse portal after deployment',
        'Confirm all 9 RSOC groups visible under delegated resources'
    )
    checks            = @{}
}

# Verify Caller Permissions

Write-Status "Checking caller role assignments at subscription scope..."
try {
    $callerRoles = Get-AzRoleAssignment -Scope $scope -ErrorAction Stop |
        Where-Object { $_.RoleDefinitionName -in @('Owner','User Access Administrator') }

    if (-not $callerRoles) {
        Write-Host "[WARN] No Owner or User Access Administrator role found for current caller at $scope" -ForegroundColor Yellow
        Write-Host "       Deployment may fail. Ensure you are signed in as a customer subscription Owner." -ForegroundColor Yellow
        $evidenceData.checks['callerPermissions'] = 'warning-not-found'
    } else {
        $roleList = ($callerRoles | Select-Object -ExpandProperty RoleDefinitionName) -join ', '
        Write-Status "  Caller has roles: $roleList" -Color Green
        $evidenceData.checks['callerPermissions'] = "found: $roleList"
    }
} catch {
    Write-Host "[WARN] Could not enumerate role assignments: $_" -ForegroundColor Yellow
    $evidenceData.checks['callerPermissions'] = "error: $_"
}

# Check Existing Lighthouse Assignment

Write-Status "Checking for existing Lighthouse assignment..."
$existingAssignment = $null
try {
    $assignments = Get-AzManagedServicesAssignment -Scope $scope -ErrorAction Stop
    $existingAssignment = $assignments | Where-Object {
        $_.Properties?.ManagedByTenantId -eq $ManagedByTenantId
    }
} catch {
    Write-Host "[WARN] Could not check existing assignments: $_" -ForegroundColor Yellow
}

if ($existingAssignment) {
    Write-Status "  Existing Lighthouse assignment found for tenant $ManagedByTenantId - skipping deployment." -Color Yellow
    $evidenceData.checks['existingAssignment'] = 'found-skipped'
    $evidenceData.status = 'skipped-already-exists'
    $evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
    Write-Status "Done (skipped - already delegated)." -Color Yellow
    return
}

$evidenceData.checks['existingAssignment'] = 'not-found'
Write-Status "  No existing delegation found - proceeding." -Color Green

# Deploy Lighthouse ARM Template

# Use the generic public template by default. The private execution repository may
# provide a customer-specific overlay through -LighthouseTemplatePath.
if (-not $LighthouseTemplatePath) {
    $configuredTemplatePath = if ($configLighthouse -and ($configLighthouse.PSObject.Properties.Name -contains 'templatePath')) {
        [string]$configLighthouse.templatePath
    } else {
        ''
    }
    if (-not [string]::IsNullOrWhiteSpace($configuredTemplatePath)) {
        $LighthouseTemplatePath = $configuredTemplatePath
    } else {
        $LighthouseTemplatePath = Join-Path $PSScriptRoot '..\lighthouse\lighthouse-offer1.json'
    }
}
if (-not (Test-Path $LighthouseTemplatePath)) {
    throw "Lighthouse ARM template not found at '$LighthouseTemplatePath'. Restore the generic AzLighthouse/lighthouse template or pass -LighthouseTemplatePath to a private overlay."
}
$LighthouseTemplatePath = (Resolve-Path $LighthouseTemplatePath -ErrorAction Stop).Path
$deploymentName = "lighthouse-$customerShortName-$(Get-Date -Format 'yyyyMMddHHmm')"

# Resolve values from explicit parameters, a private parameter file, or the
# customer config. The ARM template remains generic and contains no tenant data.
$lighthouseValues = @{}
if ($LighthouseParametersPath) {
    if (-not (Test-Path $LighthouseParametersPath)) {
        throw "Lighthouse parameter file not found at '$LighthouseParametersPath'."
    }
    $parameterFile = Get-Content $LighthouseParametersPath -Raw | ConvertFrom-Json
    foreach ($property in $parameterFile.PSObject.Properties) {
        $lighthouseValues[$property.Name] = $property.Value
    }
} elseif ($configLighthouse) {
    foreach ($property in $configLighthouse.PSObject.Properties) {
        $lighthouseValues[$property.Name] = $property.Value
    }
}

$explicitValues = @{
    mspOfferName = $MspOfferName
    mspOfferDescription = $MspOfferDescription
    administratorGroupPrincipalId = $AdministratorGroupPrincipalId
    administratorGroupPrincipalIdDisplayName = $AdministratorGroupPrincipalIdDisplayName
    analystGroupPrincipalId = $AnalystGroupPrincipalId
    analystGroupPrincipalIdDisplayName = $AnalystGroupPrincipalIdDisplayName
    automationPrincipalId = $AutomationPrincipalId
    automationPrincipalIdDisplayName = $AutomationPrincipalIdDisplayName
}
foreach ($key in $explicitValues.Keys) {
    if (-not [string]::IsNullOrWhiteSpace($explicitValues[$key])) {
        $lighthouseValues[$key] = $explicitValues[$key]
    }
}

$template = Get-Content $LighthouseTemplatePath -Raw | ConvertFrom-Json
$templateParameters = @{}
foreach ($property in $template.parameters.PSObject.Properties) {
    $templateParameters[$property.Name] = $property.Value
}

$parameterMap = @{
    managedByTenantId = $ManagedByTenantId
}
foreach ($parameterName in ($templateParameters.Keys | Where-Object { $_ -ne 'managedByTenantId' })) {
    $value = $lighthouseValues[$parameterName]
    if ([string]::IsNullOrWhiteSpace([string]$value) -and $PromptForLighthouseValues) {
        $label = $parameterName -replace '(?<=[a-z])([A-Z])', ' $1'
        $value = Read-Host "Enter $label"
    }

    $parameterDefinition = $templateParameters[$parameterName]
    $hasDefault = $parameterDefinition.PSObject.Properties.Name -contains 'defaultValue'
    if ([string]::IsNullOrWhiteSpace([string]$value) -and -not $hasDefault) {
        throw "Missing Lighthouse parameter '$parameterName'. Set config.lighthouse.$parameterName, pass the matching parameter, or use -PromptForLighthouseValues."
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
        if ($parameterName -match '(TenantId|PrincipalId)$' -and $value -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            throw "Lighthouse parameter '$parameterName' must be a GUID."
        }
        $parameterMap[$parameterName] = $value
    }
}

$armParams = @{
    managedByTenantId = $ManagedByTenantId
}
foreach ($key in $parameterMap.Keys) {
    $armParams[$key] = $parameterMap[$key]
}

if ($WhatIfMode) {
    Write-Status "[WHATIF] Would deploy Lighthouse template to subscription $subscriptionId" -Color Magenta
    Write-Status "[WHATIF] Template: $LighthouseTemplatePath" -Color Magenta
    Write-Status "[WHATIF] Params: $($armParams | ConvertTo-Json -Compress)" -Color Magenta
    $evidenceData.status = 'whatif-only'
    $evidenceData.checks['deployment'] = 'whatif-skipped'
    $evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
    return
}

Write-Status "Deploying Lighthouse ARM template..."
Write-Status "  Template file: $LighthouseTemplatePath"
Write-Status "  Deployment   : $deploymentName"
Write-Status "  Subscription : $subscriptionId"

try {
    $deployment = New-AzSubscriptionDeployment `
        -Name            $deploymentName `
        -Location        $Location `
        -TemplateFile    $LighthouseTemplatePath `
        -TemplateParameterObject $armParams `
        -SubscriptionId  $subscriptionId `
        -ErrorAction     Stop

    Write-Status "  Deployment completed: $($deployment.ProvisioningState)" -Color Green
    $evidenceData.checks['deployment'] = $deployment.ProvisioningState
    $evidenceData.deploymentName = $deploymentName
    $evidenceData.deploymentId   = $deployment.Id
} catch {
    Write-Host "[ERROR] Deployment failed: $_" -ForegroundColor Red
    $evidenceData.status = 'failed'
    $evidenceData.checks['deployment'] = "failed: $_"
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
    throw
}

# Verify Post-Deploy

Write-Status "Verifying Lighthouse assignment post-deploy..."
Start-Sleep -Seconds 5  # allow propagation
try {
    $postAssignments = Get-AzManagedServicesAssignment -Scope $scope -ErrorAction Stop
    $verified = $postAssignments | Where-Object {
        $_.Properties?.ManagedByTenantId -eq $ManagedByTenantId
    }
    if ($verified) {
        Write-Status "  Assignment verified: $($verified.Id)" -Color Green
        $evidenceData.checks['postDeployVerification'] = 'verified'
        $evidenceData.assignmentId = $verified.Id
    } else {
        Write-Host "[WARN] Assignment not yet visible - may require propagation time." -ForegroundColor Yellow
        $evidenceData.checks['postDeployVerification'] = 'not-yet-visible'
    }
} catch {
    Write-Host "[WARN] Post-deploy verification error: $_" -ForegroundColor Yellow
    $evidenceData.checks['postDeployVerification'] = "error: $_"
}

# Write Evidence

$evidenceData.status = 'succeeded'
$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData

Write-Status "=== New-LighthouseDelegationPackage Complete ===" -Color Green
Write-Host "  Evidence: $evidenceFile"

# TEST_REQUIRED: Must run from customer owner account; verify delegation appears in Azure Lighthouse portal
# TEST_REQUIRED: Confirm all 9 RSOC ForeignGroup assignments visible in customer subscription IAM
# MANUAL_ACTION: If deployment fails with AuthorizationFailed, customer must grant Owner role to the RSOC onboarding account first
