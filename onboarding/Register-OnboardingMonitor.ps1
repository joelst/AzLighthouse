#Requires -Version 7.0
#Requires -Modules Az.Resources, Az.Automation, Az.ManagedServiceIdentity
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Deploys the RSOC Automation Account and registers the onboarding monitor for a customer.
.DESCRIPTION
    Verifies the UMI exists, deploys the automation account ARM template, verifies runbooks,
    and prints manual portal configuration steps with exact variable values.
#>
param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$DataConnectorLogicAppUri,
    [string]$CredentialRotationLogicAppUri,
    [string]$AutomationAccountName = 'RSOC-MSSP-Automation',
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

 Helpers # 

function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("automation-onboarding-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    Write-Host "  Evidence written: $file" -ForegroundColor DarkGray
    return $file
}

function Write-Status {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

 Load Config # 

Write-Status "Loading customer config: $CustomerConfigPath"
$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json

$customerShortName   = $config.customer.shortName
$subscriptionId      = $config.deployment.subscriptionId
$resourceGroupName   = $config.deployment.resourceGroupName
$sentinelWorkspace   = $config.deployment.sentinelWorkspaceName
$region              = $config.deployment.region ?? 'eastus'
$umiName             = 'RSOC-Sentinel-Ingestion-UMI'
$automationAccountTemplateUri = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/automation/automationAccount.json'

Write-Status "Customer: $customerShortName | RG: $resourceGroupName | Workspace: $sentinelWorkspace"

$evidenceData = @{
    scriptName        = 'Register-OnboardingMonitor'
    customerShortName = $customerShortName
    subscriptionId    = $subscriptionId
    resourceGroupName = $resourceGroupName
    automationAccount = $AutomationAccountName
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Verify UMI RSOC-Sentinel-Ingestion-UMI exists before running',
        'Verify runbook Runtime is set to PowerShell 7.4 in Portal after deploy',
        'Set all automation variables listed in MANUAL_ACTION section'
    )
    checks            = [ordered]@{}
    manualActions     = @()
}

 Set Subscription Context # 

Write-Status "Setting subscription context: $subscriptionId"
Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null

 Step 1: Verify UMI Exists # 

Write-Status "Verifying UMI '$umiName' in resource group '$resourceGroupName'..."
$umi = $null
try {
    $umi = Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $umiName -ErrorAction Stop
    Write-Status "  UMI found: $($umi.Id)" -Color Green
    $evidenceData.checks['umiExists'] = 'found'
    $evidenceData.umiClientId         = $umi.ClientId
    $evidenceData.umiPrincipalId      = $umi.PrincipalId
} catch {
    Write-Host "[ERROR] UMI '$umiName' not found in RG '$resourceGroupName': $_" -ForegroundColor Red
    Write-Host "        Deploy the UMI first using: " -ForegroundColor Yellow
    Write-Host "        Invoke-WebRequest 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/identity/umi/deploy-umi.ps1' | Invoke-Expression" -ForegroundColor Yellow
    $evidenceData.checks['umiExists'] = "not-found: $_"
    $evidenceData.status = 'failed-umi-missing'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    throw "UMI prerequisite not met. Deploy RSOC-Sentinel-Ingestion-UMI first."
}

 Step 2: Deploy Automation Account ARM Template # 

$deploymentName = "automation-$customerShortName-$(Get-Date -Format 'yyyyMMddHHmm')"

$armParams = @{
    automationAccountName                = $AutomationAccountName
    userAssignedIdentityName             = $umiName
    userAssignedIdentityClientId         = $umi.ClientId
    userAssignedIdentityResourceGroupName = $resourceGroupName
    sentinelResourceGroupName            = $resourceGroupName
    sentinelWorkspaceName                = $sentinelWorkspace
    dataConnectorLogicAppUri             = $DataConnectorLogicAppUri
}

if ($CredentialRotationLogicAppUri) {
    $armParams['credentialRotationLogicAppUri'] = $CredentialRotationLogicAppUri
}

if ($WhatIfMode) {
    Write-Status "[WHATIF] Would deploy automation account ARM template" -Color Magenta
    Write-Status "[WHATIF] Template : $automationAccountTemplateUri" -Color Magenta
    Write-Status "[WHATIF] RG       : $resourceGroupName" -Color Magenta
    Write-Status "[WHATIF] Params   : $($armParams | ConvertTo-Json -Compress)" -Color Magenta
    $evidenceData.status = 'whatif-only'
    $evidenceData.checks['deployment'] = 'whatif-skipped'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    return
}

Write-Status "Deploying automation account ARM template..."
Write-Status "  Template  : $automationAccountTemplateUri"
Write-Status "  Deployment: $deploymentName"

try {
    # Ensure resource group exists
    $rg = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
    if (-not $rg) {
        Write-Status "  Resource group not found; creating '$resourceGroupName' in '$region'..."
        New-AzResourceGroup -Name $resourceGroupName -Location $region -ErrorAction Stop | Out-Null
    }

    $deployment = New-AzResourceGroupDeployment `
        -Name                    $deploymentName `
        -ResourceGroupName       $resourceGroupName `
        -TemplateUri             $automationAccountTemplateUri `
        -TemplateParameterObject $armParams `
        -ErrorAction             Stop

    Write-Status "  Deployment completed: $($deployment.ProvisioningState)" -Color Green
    $evidenceData.checks['deployment'] = $deployment.ProvisioningState
    $evidenceData.deploymentName = $deploymentName
} catch {
    Write-Host "[ERROR] Deployment failed: $_" -ForegroundColor Red
    $evidenceData.status = 'failed'
    $evidenceData.checks['deployment'] = "failed: $_"
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    throw
}

 Step 3: Verify Runbooks # 

$expectedRunbooks = @(
    'Get-DataConnectorStatus',
    'Update-AppRegistrationCredential',
    'Get-AzurePolicies'
)

Write-Status "Verifying runbooks in automation account '$AutomationAccountName'..."
$foundRunbooks = @()
$missingRunbooks = @()

try {
    Start-Sleep -Seconds 10  # allow runbooks to appear
    $runbooks = Get-AzAutomationRunbook `
        -ResourceGroupName  $resourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -ErrorAction Stop

    foreach ($expected in $expectedRunbooks) {
        $rb = $runbooks | Where-Object { $_.Name -eq $expected }
        if ($rb) {
            Write-Host "  [OK] Runbook found: $expected" -ForegroundColor Green
            $foundRunbooks += $expected
        } else {
            Write-Host "  [MISSING] Runbook not found: $expected" -ForegroundColor Yellow
            $missingRunbooks += $expected
        }
    }

    $evidenceData.checks['runbooksFound']   = $foundRunbooks
    $evidenceData.checks['runbooksMissing'] = $missingRunbooks

} catch {
    Write-Host "[WARN] Could not verify runbooks: $_" -ForegroundColor Yellow
    $evidenceData.checks['runbookVerification'] = "error: $_"
}

 Step 4: Print Manual Configuration Instructions # 

$manualActionBlock = @"


              MANUAL_ACTION  Complete in Azure Portal              REQUIRED 
#

                                                                              
  1. SET RUNBOOK RUNTIME TO PowerShell 7.4                                   
     Portal: Automation Accounts > $AutomationAccountName
     > Runbooks > [each runbook] > Settings > Runtime version > 7.4          
     Apply to: Get-DataConnectorStatus, Update-AppRegistrationCredential,    
               Get-AzurePolicies                                              
                                                                              
  2. CREATE AUTOMATION VARIABLES (Automation > Shared Resources > Variables) 
                                                                              
     UMI_CLIENT_ID            = $($umi.ClientId)
     UMI_OBJECT_ID            = $($umi.PrincipalId)
     SUBSCRIPTION_ID          = $subscriptionId
     RESOURCE_GROUP_NAME      = $resourceGroupName
     WORKSPACE_NAME           = $sentinelWorkspace
     DATACONNECTOR_API        = $DataConnectorLogicAppUri
                                                                              
  3. ASSIGN UMI AS AUTOMATION ACCOUNT IDENTITY (if not done by ARM)         
     Portal: Automation Accounts > $AutomationAccountName
     > Identity > User assigned > Add > $umiName
                                                                              
"@

Write-Host $manualActionBlock -ForegroundColor Yellow

$manualAction = @{
    action       = 'Set runbook Runtime to PowerShell 7.4 in Portal (Settings > Runtime version)'
    variables    = @{
        UMI_CLIENT_ID        = $umi.ClientId
        UMI_OBJECT_ID        = $umi.PrincipalId
        SUBSCRIPTION_ID      = $subscriptionId
        RESOURCE_GROUP_NAME  = $resourceGroupName
        WORKSPACE_NAME       = $sentinelWorkspace
        DATACONNECTOR_API    = $DataConnectorLogicAppUri
    }
}
$evidenceData.manualActions += $manualAction

# MANUAL_ACTION: Set runbook Runtime to PowerShell 7.4 in Portal (Settings > Runtime version)
# MANUAL_ACTION: Set automation variables: UMI_CLIENT_ID, UMI_OBJECT_ID, SUBSCRIPTION_ID, RESOURCE_GROUP_NAME, WORKSPACE_NAME, DATACONNECTOR_API

 Write Evidence # 

$evidenceData.status = if ($missingRunbooks.Count -eq 0) { 'succeeded' } else { 'succeeded-with-warnings' }
$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
Write-Status "=== Register-OnboardingMonitor Complete ===" -Color Green
Write-Host "  Evidence: $evidenceFile"
