#Requires -Version 7.0

<#
.SYNOPSIS
Deploys the Azure Automation template with prerequisite checks, input validation, optional local runbook upload, and post-deployment validation.

.DESCRIPTION
This script deploys automationAccount.json to a target resource group using automation.parameters.json,
validates required inputs, verifies deployment success, and optionally uploads local runbook scripts
into the deployed Automation Account.

.PARAMETER subscriptionId
Target Azure subscription ID.

.PARAMETER resourceGroupName
Target resource group name for deployment.

.PARAMETER location
Azure region for resource group creation when -createResourceGroup is specified.

.PARAMETER templateFile
Path to automation template file. Defaults to automationAccount.json in this folder.

.PARAMETER parameterFile
Path to deployment parameter file. Defaults to automation.parameters.json in this folder.

.PARAMETER createResourceGroup
Creates the resource group before deployment when it does not exist.

.PARAMETER installMissingModules
Installs missing Az modules for current user when needed.

.PARAMETER uploadLocalRunbooks
Uploads local runbook scripts to the deployed Automation Account and publishes them.

.PARAMETER runbookSourcePath
Folder containing local runbook .ps1 files. Defaults to this script folder.

.EXAMPLE
./Deploy-AutomationTemplate.ps1 -subscriptionId '<sub-id>' -resourceGroupName 'SOC-Automation-RG' -location 'eastus' -createResourceGroup

.EXAMPLE
./Deploy-AutomationTemplate.ps1 -subscriptionId '<sub-id>' -resourceGroupName 'SOC-Automation-RG' -location 'eastus' -uploadLocalRunbooks -runbookSourcePath '.'

.NOTES
Requires Az.Accounts, Az.Resources, and Az.Automation modules.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')]
  [string]$subscriptionId,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$resourceGroupName,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [ValidateSet('eastus', 'eastus2', 'westus2', 'australiacentral', 'brazilsouth', 'southeastasia')]
  [string]$location,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$templateFile = (Join-Path -Path $PSScriptRoot -ChildPath 'automationAccount.json'),

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$parameterFile = (Join-Path -Path $PSScriptRoot -ChildPath 'automation.parameters.json'),

  [Parameter()]
  [switch]$createResourceGroup,

  [Parameter()]
  [switch]$installMissingModules,

  [Parameter()]
  [switch]$uploadLocalRunbooks,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$runbookSourcePath = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-JsonFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$path
  )

  if (-not (Test-Path -Path $path -PathType Leaf)) {
    throw "File not found: $path"
  }

  $raw = Get-Content -Path $path -Raw
  if ([string]::IsNullOrWhiteSpace($raw)) {
    throw "File is empty: $path"
  }

  return ($raw | ConvertFrom-Json -Depth 100)
}

function Install-AzModulePrerequisites {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$moduleNames,

    [Parameter()]
    [switch]$allowInstall
  )

  if ($allowInstall) {
    try {
      $nugetProvider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($null -eq $nugetProvider) {
        Write-Verbose 'Installing NuGet package provider for non-interactive module installation.'
        Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop | Out-Null
      }
    }
    catch {
      throw "Unable to prepare non-interactive module installation prerequisites (NuGet/PSGallery): $($_.Exception.Message)"
    }
  }

  foreach ($moduleName in $moduleNames) {
    $available = Get-Module -Name $moduleName -ListAvailable | Select-Object -First 1
    if ($null -eq $available) {
      if ($allowInstall) {
        try {
          Write-Verbose "Installing missing module non-interactively: $moduleName"
          Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -Confirm:$false -ErrorAction Stop
        }
        catch {
          throw "Failed to install required module '$moduleName' in non-interactive mode. Ensure repository access/policy allows installs. Inner error: $($_.Exception.Message)"
        }
      }
      else {
        throw "Required module '$moduleName' is not installed. Re-run with -installMissingModules or install manually."
      }
    }

    Import-Module -Name $moduleName -ErrorAction Stop
  }
}

function Resolve-TemplateParameterValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$parameterName,

    [Parameter(Mandatory = $true)]
    [object]$templateJson,

    [Parameter(Mandatory = $true)]
    [object]$parameterJson
  )

  $hasParameterBlock = $null -ne $parameterJson -and $null -ne $parameterJson.parameters
  if ($hasParameterBlock) {
    $paramEntry = $parameterJson.parameters.PSObject.Properties[$parameterName]
    if ($null -ne $paramEntry -and $null -ne $paramEntry.Value) {
      $entryValue = $paramEntry.Value
      if ($entryValue.PSObject.Properties.Name -contains 'value') {
        return $entryValue.value
      }

      if ($entryValue.PSObject.Properties.Name -contains 'reference') {
        return '<keyvault-reference>'
      }
    }
  }

  $templateParam = $templateJson.parameters.PSObject.Properties[$parameterName]
  if ($null -ne $templateParam -and ($templateParam.Value.PSObject.Properties.Name -contains 'defaultValue')) {
    return $templateParam.Value.defaultValue
  }

  return $null
}

function Assert-RequiredDeploymentInputs {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [object]$templateJson,

    [Parameter(Mandatory = $true)]
    [object]$parameterJson,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$parameterFilePath
  )

  $requiredParameterNames = @(
    'automationAccountName',
    'userAssignedIdentityName',
    'userAssignedIdentityClientId',
    'sentinelWorkspaceResourceId',
    'servicePrincipalCredentialLogicAppUri',
    'dataConnectorLogicAppUri',
    'pricingTierLogicAppUri',
    'policyMonitoringLogicAppUri',
    'servicePrincipalCredentialAppReg',
    'runtimeEnvironmentName',
    'runtimeVersion'
  )

  foreach ($requiredName in $requiredParameterNames) {
    $value = Resolve-TemplateParameterValue -parameterName $requiredName -templateJson $templateJson -parameterJson $parameterJson
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
      throw "Required deployment parameter '$requiredName' is missing or empty in $parameterFilePath and has no usable template default."
    }
  }

  $runtimeVersion = [string](Resolve-TemplateParameterValue -parameterName 'runtimeVersion' -templateJson $templateJson -parameterJson $parameterJson)
  if ($runtimeVersion -notin @('7.2', '7.4')) {
    throw "Unsupported runtimeVersion '$runtimeVersion'. Allowed values: 7.2, 7.4"
  }
}

function Set-AzContextForSubscription {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$targetSubscriptionId
  )

  $context = Get-AzContext -ErrorAction SilentlyContinue
  if ($null -eq $context) {
    Write-Verbose 'No Azure context found. Prompting for sign-in.'
    Connect-AzAccount | Out-Null
  }

  Set-AzContext -SubscriptionId $targetSubscriptionId | Out-Null
}

function Publish-LocalRunbooks {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$automationAccountName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$targetResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$sourcePath,

    [Parameter(Mandatory = $true)]
    [object]$templateJson,

    [Parameter(Mandatory = $true)]
    [object]$parameterJson
  )

  if (-not (Test-Path -Path $sourcePath -PathType Container)) {
    throw "Runbook source folder not found: $sourcePath"
  }

  $runbookMap = @(
    @{ NameParameter = 'servicePrincipalCredentialRunbookName'; FileName = 'Update-AppRegistrationCredential.ps1' },
    @{ NameParameter = 'connectorRunbookName'; FileName = 'Get-DataConnectorStatus.ps1' },
    @{ NameParameter = 'pricingRunbookName'; FileName = 'Get-SentinelPricing.ps1' },
    @{ NameParameter = 'searchJobRunbookName'; FileName = 'Invoke-AzSentinelSearchJob.ps1' },
    @{ NameParameter = 'policyRunbookName'; FileName = 'Get-AzurePolicies.ps1' }
  )

  foreach ($entry in $runbookMap) {
    $runbookName = [string](Resolve-TemplateParameterValue -parameterName $entry.NameParameter -templateJson $templateJson -parameterJson $parameterJson)
    $runbookPath = Join-Path -Path $sourcePath -ChildPath $entry.FileName

    if (-not (Test-Path -Path $runbookPath -PathType Leaf)) {
      throw "Local runbook file missing: $runbookPath"
    }

    Write-Verbose "Uploading local runbook '$runbookName' from $runbookPath"
    Import-AzAutomationRunbook -ResourceGroupName $targetResourceGroupName -AutomationAccountName $automationAccountName -Type PowerShell -Name $runbookName -Path $runbookPath -Force | Out-Null
    Publish-AzAutomationRunbook -ResourceGroupName $targetResourceGroupName -AutomationAccountName $automationAccountName -Name $runbookName | Out-Null
  }
}

function Test-DeploymentState {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$automationAccountName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$targetResourceGroupName,

    [Parameter(Mandatory = $true)]
    [object]$templateJson,

    [Parameter(Mandatory = $true)]
    [object]$parameterJson
  )

  $automationAccount = Get-AzAutomationAccount -ResourceGroupName $targetResourceGroupName -Name $automationAccountName -ErrorAction Stop
  if ($null -eq $automationAccount) {
    throw "Automation Account was not found after deployment: $automationAccountName"
  }

  $runtimeEnvironmentName = [string](Resolve-TemplateParameterValue -parameterName 'runtimeEnvironmentName' -templateJson $templateJson -parameterJson $parameterJson)
  $runtimeResourceName = "$automationAccountName/$runtimeEnvironmentName"
  $runtimeResource = Get-AzResource -ResourceGroupName $targetResourceGroupName -ResourceType 'Microsoft.Automation/automationAccounts/runtimeEnvironments' -Name $runtimeResourceName -ErrorAction SilentlyContinue
  if ($null -eq $runtimeResource) {
    throw "Runtime environment resource not found: $runtimeResourceName"
  }

  $runbookNameParameters = @(
    'servicePrincipalCredentialRunbookName',
    'connectorRunbookName',
    'pricingRunbookName',
    'searchJobRunbookName',
    'policyRunbookName'
  )

  foreach ($runbookParam in $runbookNameParameters) {
    $runbookName = [string](Resolve-TemplateParameterValue -parameterName $runbookParam -templateJson $templateJson -parameterJson $parameterJson)
    $runbook = Get-AzAutomationRunbook -ResourceGroupName $targetResourceGroupName -AutomationAccountName $automationAccountName -Name $runbookName -ErrorAction SilentlyContinue
    if ($null -eq $runbook) {
      throw "Runbook not found after deployment: $runbookName"
    }
  }
}

try {
  Write-Verbose 'Loading template and parameter files.'
  $templateJson = Get-JsonFile -path $templateFile
  $parameterJson = Get-JsonFile -path $parameterFile

  Assert-RequiredDeploymentInputs -templateJson $templateJson -parameterJson $parameterJson -parameterFilePath $parameterFile

  Install-AzModulePrerequisites -moduleNames @('Az.Accounts', 'Az.Resources', 'Az.Automation') -allowInstall:$installMissingModules
  Set-AzContextForSubscription -targetSubscriptionId $subscriptionId

  if ($createResourceGroup) {
    $existingResourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $existingResourceGroup) {
      Write-Verbose "Creating resource group '$resourceGroupName' in location '$location'."
      New-AzResourceGroup -Name $resourceGroupName -Location $location | Out-Null
    }
  }

  $resourceGroupToDeploy = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
  if ($null -eq $resourceGroupToDeploy) {
    throw "Resource group '$resourceGroupName' does not exist. Use -createResourceGroup or create it first."
  }

  $deploymentName = 'automation-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
  $deploymentParameters = @{
    Name                  = $deploymentName
    ResourceGroupName     = $resourceGroupName
    TemplateFile          = $templateFile
    TemplateParameterFile = $parameterFile
    Verbose               = $true
  }

  Write-Verbose "Starting deployment '$deploymentName'."
  $deployment = New-AzResourceGroupDeployment @deploymentParameters

  if ($null -eq $deployment -or $deployment.ProvisioningState -ne 'Succeeded') {
    $state = if ($null -ne $deployment) { $deployment.ProvisioningState } else { 'Unknown' }
    throw "Deployment did not succeed. ProvisioningState: $state"
  }

  $automationAccountName = [string](Resolve-TemplateParameterValue -parameterName 'automationAccountName' -templateJson $templateJson -parameterJson $parameterJson)

  if ($uploadLocalRunbooks) {
    Publish-LocalRunbooks -automationAccountName $automationAccountName -targetResourceGroupName $resourceGroupName -sourcePath $runbookSourcePath -templateJson $templateJson -parameterJson $parameterJson
  }

  Test-DeploymentState -automationAccountName $automationAccountName -targetResourceGroupName $resourceGroupName -templateJson $templateJson -parameterJson $parameterJson

  $result = [PSCustomObject]@{
    DeploymentName        = $deploymentName
    ResourceGroupName     = $resourceGroupName
    AutomationAccountName = $automationAccountName
    UploadLocalRunbooks   = [bool]$uploadLocalRunbooks
    DeploymentState       = 'Succeeded'
  }

  Write-Output $result
}
catch {
  Write-Error "Deployment script failed: $($_.Exception.Message)"
  throw
}
