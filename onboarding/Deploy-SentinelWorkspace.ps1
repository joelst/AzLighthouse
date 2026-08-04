#Requires -Version 7.0
#Requires -Modules Az.Resources, Az.OperationalInsights

<#
.SYNOPSIS
    Deploys the Microsoft Sentinel workspace and solution using the custom All-in-One v2 ARM template.
.DESCRIPTION
    Creates the resource group if needed, deploys Sentinel, verifies workspace and solution
    deployment, and records manual actions for GA-required connectors.
#>
param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Helpers

function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("sentinel-deploy-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
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

$customerShortName = $config.customer.shortName
$subscriptionId    = $config.deployment.subscriptionId
$rgName            = $config.deployment.resourceGroupName
$workspaceName     = $config.deployment.sentinelWorkspaceName
$region            = $config.deployment.region ?? 'eastus'
$dataSources       = $config.dataSources ?? @()

# TEST_REQUIRED: Verify sentinel/custom/azuredeploy.json parameter names before production; inspect template for exact param names
$sentinelTemplateUri = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/sentinel/custom/azuredeploy.json'

Write-Status "Customer    : $customerShortName"
Write-Status "Subscription: $subscriptionId"
Write-Status "Resource RG : $rgName"
Write-Status "Workspace   : $workspaceName"
Write-Status "Region      : $region"

$evidenceData = @{
    scriptName        = 'Deploy-SentinelWorkspace'
    customerShortName = $customerShortName
    subscriptionId    = $subscriptionId
    resourceGroupName = $rgName
    workspaceName     = $workspaceName
    region            = $region
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Verify sentinel/custom/azuredeploy.json parameter names match before production run',
        'Inspect ARM template for exact param names (workspaceName vs workspaceDisplayName, etc.)',
        'Confirm workspace retention, daily cap settings match customer SLA'
    )
    checks            = [ordered]@{}
    manualActions     = @()
}

# Set Subscription Context

Write-Status "Setting subscription context: $subscriptionId"
Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

# Step 1: Ensure Resource Group Exists (Idempotent)

Write-Status "Checking resource group '$rgName'..."
$rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue

if ($rg) {
    Write-Status "  Resource group already exists (location: $($rg.Location))." -Color Green
    $evidenceData.checks['resourceGroup'] = 'already-exists'
} else {
    if ($WhatIfMode) {
        Write-Status "[WHATIF] Would create resource group '$rgName' in '$region'" -Color Magenta
        $evidenceData.checks['resourceGroup'] = 'whatif-would-create'
    } else {
        Write-Status "  Creating resource group '$rgName' in '$region'..."
        $rg = New-AzResourceGroup -Name $rgName -Location $region -ErrorAction Stop
        Write-Status "  Resource group created: $($rg.ResourceId)" -Color Green
        $evidenceData.checks['resourceGroup'] = 'created'
        $evidenceData.resourceGroupId = $rg.ResourceId
    }
}

# Step 2: Check for Existing Sentinel Workspace

Write-Status "Checking for existing Log Analytics workspace '$workspaceName'..."
$existingWorkspace = Get-AzOperationalInsightsWorkspace `
    -ResourceGroupName $rgName `
    -Name $workspaceName `
    -ErrorAction SilentlyContinue

if ($existingWorkspace) {
    Write-Status "  Workspace already exists (id: $($existingWorkspace.CustomerId))." -Color Yellow
    $evidenceData.checks['workspacePreExisting'] = 'exists'
    $evidenceData.workspaceId = $existingWorkspace.CustomerId
}

# Step 3: Deploy Sentinel ARM Template

$deploymentName = "sentinel-$customerShortName-$(Get-Date -Format 'yyyyMMddHHmm')"

# TEST_REQUIRED: Confirm exact ARM parameter names from template; names below are best-guess from common Sentinel All-in-One patterns
$armParams = @{
    workspaceName     = $workspaceName
    location          = $region
    enableSentinel    = $true
    dailyQuotaGb      = -1   # no cap by default; adjust per customer contract
    dataRetention     = 90
}

if ($WhatIfMode) {
    Write-Status "[WHATIF] Would deploy Sentinel All-in-One v2 ARM template" -Color Magenta
    Write-Status "[WHATIF] Template : $sentinelTemplateUri" -Color Magenta
    Write-Status "[WHATIF] RG       : $rgName" -Color Magenta
    Write-Status "[WHATIF] Params   : $($armParams | ConvertTo-Json -Compress)" -Color Magenta
    $evidenceData.status = 'whatif-only'
    $evidenceData.checks['deployment'] = 'whatif-skipped'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    return
}

Write-Status "Deploying Sentinel workspace ARM template..."
Write-Status "  Template  : $sentinelTemplateUri"
Write-Status "  Deployment: $deploymentName"

try {
    $deployment = New-AzResourceGroupDeployment `
        -Name                    $deploymentName `
        -ResourceGroupName       $rgName `
        -TemplateUri             $sentinelTemplateUri `
        -TemplateParameterObject $armParams `
        -ErrorAction             Stop

    Write-Status "  Deployment provisioning state: $($deployment.ProvisioningState)" -Color Green
    $evidenceData.checks['deployment']  = $deployment.ProvisioningState
    $evidenceData.deploymentName        = $deploymentName
    $evidenceData.deploymentId          = $deployment.DeploymentId ?? $deployment.Id
} catch {
    Write-Host "[ERROR] Deployment failed: $_" -ForegroundColor Red
    $evidenceData.status = 'failed'
    $evidenceData.checks['deployment'] = "failed: $_"
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    throw
}

# Step 4: Verify Workspace Post-Deploy

Write-Status "Verifying Log Analytics workspace post-deploy..."
Start-Sleep -Seconds 15
try {
    $workspace = Get-AzOperationalInsightsWorkspace `
        -ResourceGroupName $rgName `
        -Name $workspaceName `
        -ErrorAction Stop

    Write-Status "  Workspace verified: $($workspace.CustomerId)" -Color Green
    $evidenceData.checks['workspaceVerification'] = 'verified'
    $evidenceData.workspaceId       = $workspace.CustomerId
    $evidenceData.workspaceRetention = $workspace.RetentionInDays
    $evidenceData.workspaceSku      = $workspace.Sku
} catch {
    Write-Host "[WARN] Workspace verification failed: $_" -ForegroundColor Yellow
    $evidenceData.checks['workspaceVerification'] = "error: $_"
}

# Step 5: Verify Sentinel Solution

Write-Status "Verifying Microsoft Sentinel solution..."
try {
    # Attempt via Az.OperationalInsights or REST
    $solutions = Get-AzMonitorLogAnalyticsSolution `
        -ResourceGroupName $rgName `
        -ErrorAction Stop 2>$null

    $sentinelSolution = $solutions | Where-Object {
        $_.Name -match 'SecurityInsights' -or $_.Type -match 'OperationsManagement'
    }

    if ($sentinelSolution) {
        Write-Status "  Sentinel solution verified: $($sentinelSolution.Name)" -Color Green
        $evidenceData.checks['sentinelSolution'] = 'verified'
    } else {
        Write-Host "  [WARN] Sentinel solution not found in solution list - may require portal check." -ForegroundColor Yellow
        $evidenceData.checks['sentinelSolution'] = 'not-found-check-portal'
    }
} catch {
    # Fallback: check via resource type
    try {
        $sentinelResource = Get-AzResource `
            -ResourceGroupName $rgName `
            -ResourceType 'Microsoft.OperationsManagement/solutions' `
            -ErrorAction Stop | Where-Object { $_.Name -match 'SecurityInsights' }

        if ($sentinelResource) {
            Write-Status "  Sentinel solution verified via resource: $($sentinelResource.Name)" -Color Green
            $evidenceData.checks['sentinelSolution'] = 'verified-via-resource'
        } else {
            Write-Host "  [WARN] Sentinel solution not confirmed - check portal manually." -ForegroundColor Yellow
            $evidenceData.checks['sentinelSolution'] = 'unconfirmed'
        }
    } catch {
        $evidenceData.checks['sentinelSolution'] = "error: $_"
    }
}

# Step 6: Record GA-Required Connector Manual Actions

# MANUAL_ACTION: GA-required connectors (M365 Defender, Azure AD, Office 365) need customer GA admin to enable
$gaConnectors = $dataSources | Where-Object {
    $_.connectorName -in @(
        'MicrosoftDefenderAdvancedThreatProtection',
        'MicrosoftThreatProtection',
        'AzureActiveDirectory',
        'Office365',
        'MicrosoftCloudAppSecurity'
    )
}

$manualConnectorAction = @{
    action     = 'Customer Global Admin must enable GA-required connectors in Sentinel Data Connectors blade'
    connectors = @(
        'Microsoft 365 Defender (MicrosoftThreatProtection) - requires M365 GA Admin consent',
        'Azure Active Directory (AAD) - requires AAD GA Admin',
        'Office 365 - requires Exchange/SharePoint admin',
        'Microsoft Defender for Cloud Apps - requires MCAS admin'
    )
    instruction = 'Navigate to: Sentinel > Data connectors > [connector name] > Open connector page > Connect'
}

if ($gaConnectors -and $gaConnectors.Count -gt 0) {
    $manualConnectorAction.configuredConnectors = @($gaConnectors | ForEach-Object { $_.connectorName })
}

$evidenceData.manualActions += $manualConnectorAction

Write-Host ""
Write-Host "" -ForegroundColor Yellow
Write-Host "               MANUAL_ACTION - Customer GA Admin - REQUIRED" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Yellow
Write-Host "  The following connectors require customer GA Admin to enable:" -ForegroundColor Yellow
Write-Host "    Microsoft 365 Defender" -ForegroundColor Yellow
Write-Host "    Azure Active Directory" -ForegroundColor Yellow
Write-Host "    Office 365" -ForegroundColor Yellow
Write-Host "    Microsoft Defender for Cloud Apps" -ForegroundColor Yellow
Write-Host "  Portal: Sentinel > Data connectors > [connector] > Connect" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Yellow

# Write Evidence

$evidenceData.status = 'succeeded'
$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
Write-Status "=== Deploy-SentinelWorkspace Complete ===" -Color Green
Write-Host "  Evidence: $evidenceFile"
