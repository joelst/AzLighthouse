<#
Disclaimer: This script is provided "as-is" without warranty of any kind.

.SYNOPSIS
Retrieves the Microsoft Sentinel / Log Analytics workspace pricing tier and posts it to a Logic App endpoint.

.DESCRIPTION
This runbook:
- Gets configuration from parameters or Azure Automation variables.
- Authenticates to Azure using a user-assigned managed identity (UAMI) clientId.
- Reads the Log Analytics workspace SKU and maps it to a human-friendly pricing tier.
- Posts a JSON payload to a Logic App endpoint.

Automation variable names used when parameters are omitted:
- UMI_ID
- SUBSCRIPTION_ID
- WORKSPACE_NAME
- RESOURCE_GROUP_NAME
- PRICINGTIER_API

.PARAMETER umiClientId
User-assigned managed identity (UAMI) clientId (GUID). Alias: UMIId.

.PARAMETER subscriptionId
Azure subscription ID (GUID). Alias: SubscriptionId.

.PARAMETER workspaceName
Log Analytics workspace name. Alias: workspaceName.

.PARAMETER resourceGroupName
Resource group name where the workspace exists. Alias: resourceGroup.

.PARAMETER pricingTierApi
Logic App HTTP endpoint URI to post the pricing tier payload. Alias: pricingTierApi.
#>

[CmdletBinding()]
param (
  [Parameter()]
  [Alias('UMIId')]
  [ValidateNotNullOrEmpty()]
  [string]
  $umiClientId,

  [Parameter()]
  [Alias('SubscriptionId')]
  [ValidateNotNullOrEmpty()]
  [string]
  $subscriptionId,

  [Parameter()]
  [Alias('workspaceName')]
  [ValidateNotNullOrEmpty()]
  [string]
  $workspaceName,

  [Parameter()]
  [Alias('resourceGroup')]
  [ValidateNotNullOrEmpty()]
  [string]
  $resourceGroupName,

  [Parameter()]
  [Alias('pricingTierApi')]
  [ValidateNotNullOrEmpty()]
  [string]
  $pricingTierApi
)

# Fail fast on errors so the runbook surfaces a single clear exception
# (Azure Automation runbooks can otherwise continue after non-terminating errors).
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Helper: Read an Automation variable when running in Azure Automation.
# When running locally (no Automation runtime), this returns $null so local testing is easier.
function Get-AutomationVariableSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $name
  )

  # In local PowerShell, Get-AutomationVariable won't exist.
  $cmd = Get-Command -Name 'Get-AutomationVariable' -ErrorAction SilentlyContinue
  if (-not $cmd) {
    return $null
  }

  try {
    return Get-AutomationVariable -Name $name
  }
  catch {
    Write-Verbose "Failed to read Automation variable '$name': $($_.Exception.Message)"
    return $null
  }
}

# Helper: StrictMode-safe property access.
# Azure cmdlets sometimes return objects whose shape varies across API versions/modules.
function Get-OptionalPropertyValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowNull()]
    [object]
    $inputObject,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $propertyName
  )

  if ($null -eq $inputObject) {
    return $null
  }

  $prop = $inputObject.PSObject.Properties[$propertyName]
  if ($null -eq $prop) {
    return $null
  }

  return $prop.Value
}

# Helper: Post to the Logic App with basic resiliency.
# - Retries 429 and 5xx (and network/unknown status) with backoff.
# - Honors Retry-After when provided.
function Invoke-RestMethodWithRetry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $uri,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $body,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]
    $maxAttempts = 5,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]
    $timeoutSec = 60
  )

  # NOTE: We intentionally do not log the request body here; it may contain identifiers.
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
      Write-Verbose "POST $uri (attempt $attempt/$maxAttempts)"
      return Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType 'application/json' -TimeoutSec $timeoutSec
    }
    catch {
      $ex = $_.Exception

      $statusCode = $null
      $retryAfterSec = $null

      # Some exception types expose a Response with status and headers; others don't.
      if ($ex.PSObject.Properties.Name -contains 'Response' -and $null -ne $ex.Response) {
        try {
          $statusCode = [int]$ex.Response.StatusCode
        }
        catch {
          $statusCode = $null
        }

        try {
          $retryAfterHeader = $ex.Response.Headers['Retry-After']
          if (-not [string]::IsNullOrWhiteSpace($retryAfterHeader)) {
            $retryAfterSec = [int]$retryAfterHeader
          }
        }
        catch {
          $retryAfterSec = $null
        }
      }

      # Treat 429 + 5xx as transient; also retry when status is unknown (e.g., network failure).
      $isTransient = ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599) -or $null -eq $statusCode)
      if (-not $isTransient -or $attempt -ge $maxAttempts) {
        throw
      }

      $baseDelay = [Math]::Min(2 * $attempt, 10)
      $delaySec = if ($null -ne $retryAfterSec -and $retryAfterSec -ge 1) { $retryAfterSec } else { $baseDelay }
      Write-Verbose "Transient failure (statusCode=$statusCode). Waiting ${delaySec}s before retry. Error: $($ex.Message)"
      Start-Sleep -Seconds $delaySec
    }
  }
}

# 1) Load configuration from parameters or (in Automation) from variables.
# Tip: Run with -Verbose for easier troubleshooting.
if ([string]::IsNullOrWhiteSpace($umiClientId)) {
  $umiClientId = Get-AutomationVariableSafe -name 'UMI_ID'
}
if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
  $subscriptionId = Get-AutomationVariableSafe -name 'SUBSCRIPTION_ID'
}
if ([string]::IsNullOrWhiteSpace($workspaceName)) {
  $workspaceName = Get-AutomationVariableSafe -name 'WORKSPACE_NAME'
}
if ([string]::IsNullOrWhiteSpace($resourceGroupName)) {
  $resourceGroupName = Get-AutomationVariableSafe -name 'RESOURCE_GROUP_NAME'
}
if ([string]::IsNullOrWhiteSpace($pricingTierApi)) {
  $pricingTierApi = Get-AutomationVariableSafe -name 'PRICINGTIER_API'
}

# 2) Validate inputs early so failures are obvious and actionable.
# These checks help catch misconfigured Automation variables or mis-wired deployment outputs.
if ([string]::IsNullOrWhiteSpace($umiClientId)) {
  throw "Missing required value 'umiClientId' (Automation variable UMI_ID)."
}
if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
  throw "Missing required value 'subscriptionId' (Automation variable SUBSCRIPTION_ID)."
}
if ([string]::IsNullOrWhiteSpace($workspaceName)) {
  throw "Missing required value 'workspaceName' (Automation variable WORKSPACE_NAME)."
}
if ([string]::IsNullOrWhiteSpace($resourceGroupName)) {
  throw "Missing required value 'resourceGroupName' (Automation variable RESOURCE_GROUP_NAME)."
}
if ([string]::IsNullOrWhiteSpace($pricingTierApi)) {
  throw "Missing required value 'pricingTierApi' (Automation variable PRICINGTIER_API)."
}

if (-not [Guid]::TryParse($umiClientId, [ref]([Guid]::Empty))) {
  throw "umiClientId is not a valid GUID: '$umiClientId'."
}
if (-not [Guid]::TryParse($subscriptionId, [ref]([Guid]::Empty))) {
  throw "subscriptionId is not a valid GUID: '$subscriptionId'."
}

try {
  $null = [Uri]$pricingTierApi
}
catch {
  throw "pricingTierApi is not a valid URI: '$pricingTierApi'."
}

# 3) Authenticate + set context.
# Common failures:
# - UAMI missing RBAC on the subscription/resource group
# - UAMI not assigned to the Automation Account
# - Wrong subscriptionId
Write-Verbose 'Authenticating to Azure (managed identity)'
Connect-AzAccount -Identity -AccountId $umiClientId | Out-Null

Write-Verbose "Setting subscription context to $subscriptionId"
Set-AzContext -SubscriptionId $subscriptionId | Out-Null

Write-Verbose "Retrieving Log Analytics workspace '$workspaceName' in resource group '$resourceGroupName'"
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroupName -Name $workspaceName

# 4) Normalize SKU information across module/API versions.
# Some versions expose workspace.Sku.Name; others return a string or a different object shape.
$skuName = $null
$sku = Get-OptionalPropertyValue -inputObject $workspace -propertyName 'Sku'
if ($null -ne $sku) {
    $skuName = Get-OptionalPropertyValue -inputObject $sku -propertyName 'Name'
}
if ([string]::IsNullOrWhiteSpace($skuName)) {
    $skuName = [string]$sku
}

switch ($skuName) {
    'PerGB2018' {
        $priceTier = 'Pay-As-You-Go'
    }
    'CapacityReservation' {
    # Capacity reservation may show up on the SKU object or on the workspace object.
        $capacity = Get-OptionalPropertyValue -inputObject $sku -propertyName 'CapacityReservationLevel'
        if ($null -eq $capacity) {
            $capacity = Get-OptionalPropertyValue -inputObject $workspace -propertyName 'CapacityReservationLevel'
        }
        $priceTier = if ($null -ne $capacity) { "${capacity} GB" } else { 'Commitment Tier' }
    }
    default {
    # Preserve the raw SKU value in output for troubleshooting.
        $priceTier = "Unknown ($skuName)"
    }
}

Write-Verbose "Resolved pricing tier: $priceTier"

# 5) Build payload.
# Keep it small and include the most useful identifiers for downstream logging/troubleshooting.
$jsonBody = @{
    PricingTier = $priceTier
    WorkspaceName = $workspace.Name
    WorkspaceResourceGroup = $resourceGroupName
    SubscriptionId = $subscriptionId
    SkuName = $skuName
} | ConvertTo-Json -Depth 5

# 6) Send payload.
# Common failures:
# - Logic App requires auth (SAS/token) but URI provided doesn't include it
# - Endpoint temporarily throttles (429) or returns 5xx (retry logic covers these)
Invoke-RestMethodWithRetry -Uri $pricingTierApi -Body $jsonBody | Out-Null

# Final output is intended for runbook job output and troubleshooting.
Write-Output ([pscustomobject]@{
  WorkspaceName = $workspace.Name
  PricingTier = $priceTier
  SkuName = $skuName
  PostedTo = $pricingTierApi
})