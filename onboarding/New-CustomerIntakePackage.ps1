#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Creates a new customer intake package: config JSON, state file, and README.
.DESCRIPTION
    Builds a customer-intake.schema.json-compliant config, a fresh onboarding state file,
    and a README.txt with next steps. Does NOT take -CustomerConfigPath; it CREATES the config.
#>
param(
    [Parameter(Mandatory)][string]$CustomerShortName,
    [Parameter(Mandatory)][string]$CustomerTenantId,
    [Parameter(Mandatory)][string]$CustomerDisplayName,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$SentinelWorkspaceName,
    [Parameter(Mandatory)][string]$Region,
    [Parameter(Mandatory)][string]$RsocOnboardingAccountUpn,
    [Parameter(Mandatory)][string]$ManagedByTenantId,
    [string]$OutputPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

 Helpers # 

function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("intake-package-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    Write-Host "  Evidence written: $file" -ForegroundColor DarkGray
    return $file
}

function Write-Status {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

 Defaults & Validation # 

if (-not $OutputPath) {
    $OutputPath = ".\customers\$CustomerShortName"
}

$rgNaming = "$CustomerShortName-Sentinel-Prod-rg"
if ($ResourceGroupName -ne $rgNaming) {
    Write-Host "[INFO] ResourceGroupName '$ResourceGroupName' does not follow standard naming '$rgNaming'." -ForegroundColor Yellow
    Write-Host "       Proceeding with provided name. Update if this is intentional." -ForegroundColor Yellow
}

$requiredFields = @{
    CustomerShortName         = $CustomerShortName
    CustomerTenantId          = $CustomerTenantId
    CustomerDisplayName       = $CustomerDisplayName
    SubscriptionId            = $SubscriptionId
    ResourceGroupName         = $ResourceGroupName
    SentinelWorkspaceName     = $SentinelWorkspaceName
    Region                    = $Region
    RsocOnboardingAccountUpn  = $RsocOnboardingAccountUpn
    ManagedByTenantId         = $ManagedByTenantId
}

$validationErrors = @()
foreach ($key in $requiredFields.Keys) {
    if ([string]::IsNullOrWhiteSpace($requiredFields[$key])) {
        $validationErrors += "Required field is empty: $key"
    }
}

# Validate GUID format for tenant/subscription IDs
$guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
if ($CustomerTenantId -notmatch $guidPattern) {
    $validationErrors += "CustomerTenantId does not appear to be a valid GUID: $CustomerTenantId"
}
if ($SubscriptionId -notmatch $guidPattern) {
    $validationErrors += "SubscriptionId does not appear to be a valid GUID: $SubscriptionId"
}
if ($ManagedByTenantId -notmatch $guidPattern) {
    $validationErrors += "ManagedByTenantId does not appear to be a valid GUID: $ManagedByTenantId"
}

if ($validationErrors.Count -gt 0) {
    Write-Host "[ERROR] Validation failed:" -ForegroundColor Red
    $validationErrors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    throw "Input validation failed. Correct the above errors and retry."
}

Write-Status "Validation passed. Building intake package for '$CustomerShortName'."

$evidenceData = @{
    scriptName        = 'New-CustomerIntakePackage'
    customerShortName = $CustomerShortName
    outputPath        = $OutputPath
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Send intake config to customer for review before running Lighthouse deployment',
        'Confirm RSOC onboarding account UPN is valid in RSOC AAD',
        'Confirm customer tenant ID and subscription ID with customer IT admin'
    )
    checks            = [ordered]@{}
}

 Build Config Object # 

$intakeConfig = [ordered]@{
    '$schema'  = 'customer-intake.schema.json'
    schemaVersion = '1.0.0'
    generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
    generatedBy   = 'New-CustomerIntakePackage.ps1'

    customer = [ordered]@{
        shortName   = $CustomerShortName
        tenantId    = $CustomerTenantId
        displayName = $CustomerDisplayName
    }

    deployment = [ordered]@{
        subscriptionId       = $SubscriptionId
        resourceGroupName    = $ResourceGroupName
        sentinelWorkspaceName = $SentinelWorkspaceName
        region               = $Region
    }

    rsocOnboardingAccount = [ordered]@{
        upn         = $RsocOnboardingAccountUpn
        displayName = "RSOC Onboarding Account"
    }

    managedBy = [ordered]@{
        tenantId    = $ManagedByTenantId
        offerName   = 'TMNA MSSP SOC Services'
    }

    tenantGovernance = [ordered]@{
        gdapRelationshipId = $null
        status             = 'pending'
    }

    dataSources = @()

    lighthouseUrls = [ordered]@{
        armTemplate    = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/lighthouse/tmna-mssp/lighthouse-offer.json'
        uiDefinition   = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/lighthouse/tmna-mssp/createUiDefinition.json'
        umiDeployScript = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/identity/umi/deploy-umi.ps1'
    }

    rsocGroups = [ordered]@{
        RSOC_Sentinel_Admin                              = 'c1f4a285-1b26-46b8-9a97-d298861ad503'
        RSOC_Sentinel_Onboarding                         = 'cbe65060-f79c-4350-aaf2-fd901a95de33'
        RSOC_Sentinel_Threat_Detection_Engineering_Tier1 = '440ba293-8d18-430c-b4cc-3ea789d655e9'
        RSOC_Sentinel_Threat_Detection_Engineering_Tier2 = 'd4e11e0e-6300-4491-938f-e934a587f990'
        RSOC_Sentinel_Security_Engineers                 = '4fd628b1-a5f8-43a1-9949-88a84e7f053b'
        RSOC_Sentinel_Red_Team                           = 'a6539c63-c61b-459f-bdc6-22106aa0aed3'
        RSOC_Sentinel_Incident_Response                  = 'ef18438b-79fc-4b4a-8f3f-3b691f091aa2'
        RSOC_Sentinel_Incident_Detection_Tier1           = '0d593b30-eb20-4d83-a7eb-deff71e401d2'
        RSOC_Sentinel_Incident_Detection_Tier2           = 'fe773eea-b69d-40e7-9c90-0ccb5ea4447c'
    }

    onboarding = [ordered]@{
        startedAt     = (Get-Date).ToUniversalTime().ToString('o')
        completedAt   = $null
        currentState  = 'intake'
        assignedTo    = $RsocOnboardingAccountUpn
    }
}

 Build State Object # 

$onboardingState = [ordered]@{
    '$schema'          = 'onboarding-state.schema.json'
    customerId         = $CustomerTenantId
    customerShortName  = $CustomerShortName
    lifecycleState     = 'intake'
    createdAt          = (Get-Date).ToUniversalTime().ToString('o')
    updatedAt          = (Get-Date).ToUniversalTime().ToString('o')
    steps              = @(
        [ordered]@{ name = 'intake';                  status = 'succeeded';      completedAt = (Get-Date).ToUniversalTime().ToString('o'); evidencePath = $null; notes = 'Intake package created' }
        [ordered]@{ name = 'lighthouse-delegation';   status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
        [ordered]@{ name = 'lighthouse-verification'; status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
        [ordered]@{ name = 'sentinel-deployment';     status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
        [ordered]@{ name = 'automation-deployment';   status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
        [ordered]@{ name = 'connector-enablement';    status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
        [ordered]@{ name = 'validation';              status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
        [ordered]@{ name = 'go-live';                 status = 'pending';        completedAt = $null; evidencePath = $null; notes = '' }
    )
}

 Write Files # 

if ($WhatIfMode) {
    Write-Status "[WHATIF] Would create directory: $OutputPath" -Color Magenta
    Write-Status "[WHATIF] Would write: $OutputPath\$CustomerShortName-config.json" -Color Magenta
    Write-Status "[WHATIF] Would write: $OutputPath\$CustomerShortName-state.json" -Color Magenta
    Write-Status "[WHATIF] Would write: $OutputPath\README.txt" -Color Magenta
    $evidenceData.status = 'whatif-only'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    return
}

# Create output directory
$null = New-Item -ItemType Directory -Force -Path $OutputPath
Write-Status "  Output directory: $OutputPath" -Color Green

# Write config
$configFile = Join-Path $OutputPath "$CustomerShortName-config.json"
$intakeConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
Write-Status "  Config written: $configFile" -Color Green
$evidenceData.checks['configFile'] = $configFile

# Write state
$stateFile = Join-Path $OutputPath "$CustomerShortName-state.json"
$onboardingState | ConvertTo-Json -Depth 10 | Set-Content -Path $stateFile -Encoding UTF8
Write-Status "  State file written: $stateFile" -Color Green
$evidenceData.checks['stateFile'] = $stateFile

# Write README
$readmeContent = @"
TMNA  Customer Onboarding PackageMSSP 
Customer  : $CustomerDisplayName ($CustomerShortName)
Tenant ID : $CustomerTenantId
Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC


NEXT STEPS FOR RSOC ONBOARDING ENGINEER


1. SEND TO CUSTOMER
   Send the following to the customer IT admin:
   - This intake package folder
   - Customer Instruction Packet (run Send-CustomerInstructionPacket.ps1)
   - Lighthouse deploy button URL (see lighthouseUrls in config)

2. LIGHTHOUSE DELEGATION (run as customer subscription Owner)
   .\New-LighthouseDelegationPackage.ps1 ``
       -CustomerConfigPath "$configFile" ``
       -ManagedByTenantId "$ManagedByTenantId"

3. SEND INSTRUCTION PACKET
   .\Send-CustomerInstructionPacket.ps1 ``
       -CustomerConfigPath "$configFile"

4. AFTER CUSTOMER ACCEPTS LIGHTHOUSE DELEGATION
   .\Test-LighthouseDelegation.ps1 ``
       -CustomerConfigPath "$configFile"

5. DEPLOY SENTINEL WORKSPACE (run from RSOC tenant via Lighthouse)
   .\Deploy-SentinelWorkspace.ps1 ``
       -CustomerConfigPath "$configFile"

6. DEPLOY AUTOMATION ACCOUNT
   .\Register-OnboardingMonitor.ps1 ``
       -CustomerConfigPath "$configFile" ``
       -DataConnectorLogicAppUri "<logic-app-uri>"

7. CUSTOMER: ENABLE GA-REQUIRED CONNECTORS
   Customer GA Admin must enable connectors in Sentinel portal.
   See Send-CustomerInstructionPacket.ps1 output for details.

8. TRACK PROGRESS
   .\Update-OnboardingState.ps1 ``
       -StateFilePath "$stateFile" ``
       -StepName "lighthouse-delegation" ``
       -StepStatus "succeeded"


CONFIG FILE   : $configFile
STATE FILE    : $stateFile

"@

$readmePath = Join-Path $OutputPath 'README.txt'
$readmeContent | Set-Content -Path $readmePath -Encoding UTF8
Write-Status "  README written: $readmePath" -Color Green
$evidenceData.checks['readme'] = $readmePath

 Console Summary # 

Write-Host ""
" -ForegroundColor GreenWrite-Host "
Write-         Intake Package Created " -ForegroundColor GreenSuccessfully              Host "
#Write-Host "
" -ForegroundColor Green
Write-  Customer    : $CustomerDisplayName" -ForegroundColor GreenHost "
Write-  Short Name  : $CustomerShortName" -ForegroundColor GreenHost "
Write-  Tenant ID   : $CustomerTenantId" -ForegroundColor GreenHost "
Write-  Subscription: $SubscriptionId" -ForegroundColor GreenHost "
Write-  Output Path : $OutputPath" -ForegroundColor GreenHost "
 -ForegroundColor GreenWrite-Host "
Write-Host ""
Write-Host "  Config : $configFile"
Write-Host "  State  : $stateFile"
Write-Host "  README : $readmePath"

$evidenceData.status = 'succeeded'
$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData
Write-Status "=== New-CustomerIntakePackage Complete ===" -Color Green
