#Requires -Version 7.0

<#
Disclaimer: This script is provided "as-is" without warranty of any kind.

This script was not developed or tested by the repo owner. It was contributed by a community member and is provided for reference and educational purposes. Please review and test the script in a non-production environment before using it in production.

I do not have the code for the logic app that this runbook posts to, but the general idea is:
- This runbook is triggered on a schedule (e.g., daily) in Azure Automation.
- It retrieves the pricing tier of a Microsoft Sentinel / Log Analytics workspace.
- It posts this information to a Logic App endpoint, which can then log it, send notifications, or take other actions based on the pricing tier.


.SYNOPSIS
Retrieves the Microsoft Sentinel / Log Analytics workspace pricing tier and posts it to a Logic App endpoint.

.DESCRIPTION
This runbook:
- Resolves all inputs from parameters first, then environment variables, then Automation variables.
- Validates all required inputs before any Azure call.
- Authenticates to Azure using a user-assigned managed identity (UAMI) clientId.
- Reads the Log Analytics workspace SKU and maps it to a human-friendly pricing tier.
- Posts a JSON payload to a Logic App endpoint with retry and backoff.
- Emits a structured summary object for downstream automation and auditing.

Automation variable names used when parameters are omitted:
- UMI_ID (or UMI_CLIENT_ID)
- SUBSCRIPTION_ID
- WORKSPACE_NAME
- RESOURCE_GROUP_NAME
- PRICINGTIER_API

UAMI role requirements (minimum):
- Reader at subscription scope (covers workspace read operations)

.PARAMETER umiClientId
User-assigned managed identity (UAMI) clientId (GUID). Alias: UMIId.

.PARAMETER subscriptionId
Azure subscription ID (GUID).

.PARAMETER workspaceName
Log Analytics workspace name.

.PARAMETER resourceGroupName
Resource group name where the workspace exists. Alias: resourceGroup.

.PARAMETER pricingTierApi
Logic App HTTP endpoint URI (HTTPS with SAS token) to post the pricing tier payload.

.PARAMETER VerboseLogging
When specified, enables verbose-level log output for troubleshooting.

.EXAMPLE
.\Get-SentinelPricing.ps1 `
  -umiClientId '11111111-1111-1111-1111-111111111111' `
  -subscriptionId '22222222-2222-2222-2222-222222222222' `
  -workspaceName 'law-sentinel-eastus' `
  -resourceGroupName 'rg-sentinel-prod' `
  -pricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/.../triggers/manual/paths/invoke?...&sig=...'

Retrieves the pricing tier for the specified workspace and posts it to the Logic App.

.NOTES
Logic App URI handling: The URI is treated as a secret (SAS token in query string).
Only the host portion is ever logged. The full URI never appears in output, warning,
or verbose streams.

-WhatIf skips only the Logic App POST. Authentication, context-setting, and workspace
lookup still execute so you can verify wiring without sending data.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
  [Parameter()]
  [Alias('UMIId')]
  [ValidateNotNullOrEmpty()]
  [string]
  $umiClientId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $subscriptionId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $workspaceName,

  [Parameter()]
  [Alias('resourceGroup')]
  [ValidateNotNullOrEmpty()]
  [string]
  $resourceGroupName,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $pricingTierApi,

  [Parameter()]
  [switch]
  $VerboseLogging
)

# ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:RunbookVersion = '1.1.0'

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
Safely retrieves an Azure Automation variable without throwing if unavailable.

.PARAMETER Name
The name of the Automation variable to retrieve.
#>
function Get-AutomationVariableSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Name
  )

  $command = Get-Command -Name 'Get-AutomationVariable' -ErrorAction SilentlyContinue
  if (-not $command) {
    return $null
  }

  try {
    return Get-AutomationVariable -Name $Name
  }
  catch {
    Write-Verbose "Failed to read Automation variable '$Name': $($_.Exception.Message)"
    return $null
  }
}

<#
.SYNOPSIS
Resolves a configuration value from multiple sources in priority order.

.DESCRIPTION
Cascading resolution: parameter > environment variable > Automation variable.

.PARAMETER parameterValue
The value passed as a script parameter.

.PARAMETER environmentVariableNames
Array of environment/Automation variable names to check in order.

.PARAMETER parameterName
Friendly parameter name for error messages.
#>
function Resolve-ConfiguredValue {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [string]
    $parameterValue,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $environmentVariableNames,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $parameterName
  )

  if (-not [string]::IsNullOrWhiteSpace($parameterValue)) {
    return $parameterValue.Trim()
  }

  foreach ($envName in $environmentVariableNames) {
    $envValue = [Environment]::GetEnvironmentVariable($envName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
      return $envValue.Trim()
    }
  }

  foreach ($autoName in $environmentVariableNames) {
    $autoValue = Get-AutomationVariableSafe -Name $autoName
    if (-not [string]::IsNullOrWhiteSpace($autoValue)) {
      return ([string]$autoValue).Trim()
    }
  }

  throw "Missing required value '$parameterName'. Provide parameter '$parameterName' or set one of: $($environmentVariableNames -join ', ')."
}

<#
.SYNOPSIS
Validates that a string is a properly formatted GUID.

.PARAMETER value
The string to validate.

.PARAMETER parameterName
Friendly parameter name for error messages.
#>
function Assert-ValidGuid {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $value,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $parameterName
  )

  $trimmed = $value.Trim()
  if ($trimmed -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    throw "$parameterName must be a valid GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
  }
}

<#
.SYNOPSIS
Validates that a URI is an absolute HTTPS URI.

.PARAMETER uri
The URI string to validate.

.PARAMETER parameterName
Friendly parameter name for error messages.
#>
function Test-IsHttpsUri {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $uri,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $parameterName
  )

  try {
    $parsed = [Uri]::new($uri)
  }
  catch {
    throw "$parameterName is not a valid URI."
  }

  if (-not $parsed.IsAbsoluteUri) {
    throw "$parameterName must be an absolute URI."
  }

  if ($parsed.Scheme -ne 'https') {
    throw "$parameterName must use HTTPS scheme. Received scheme: '$($parsed.Scheme)'."
  }
}

<#
.SYNOPSIS
Extracts only the host portion of a URI for safe logging.

.DESCRIPTION
Logic App URIs contain SAS tokens in the query string. This function returns
only the host so the full URI (including secrets) is never logged.

.PARAMETER uri
The full URI string.
#>
function Get-UriHostForLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $uri
  )

  try {
    return ([Uri]::new($uri)).Host
  }
  catch {
    return '(invalid-uri)'
  }
}

<#
.SYNOPSIS
Masks a string for safe logging, showing only the last 4 characters.

.PARAMETER value
The string to mask.
#>
function Get-MaskedValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $value
  )

  if ($value.Length -le 4) {
    return '****'
  }
  return "$('*' * ($value.Length - 4))$($value.Substring($value.Length - 4))"
}

<#
.SYNOPSIS
Writes a structured log message with RunId, timestamp, and severity level.

.PARAMETER Level
Log level: INFO, WARN, ERROR, VERBOSE.

.PARAMETER Message
The message to log.
#>
function Write-Log {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('INFO', 'WARN', 'ERROR', 'VERBOSE')]
    [string]
    $Level,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Message
  )

  $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
  $formatted = "[$timestamp] [$Level] [RunId=$($script:RunId)] $Message"

  switch ($Level) {
    'INFO'    { Write-Information $formatted -InformationAction Continue }
    'WARN'    { Write-Warning $formatted }
    'ERROR'   { Write-Error $formatted -ErrorAction Continue }
    'VERBOSE' {
      if ($script:EnableVerboseLogging) {
        Write-Information $formatted -InformationAction Continue
      }
      else {
        Write-Verbose $formatted
      }
    }
  }
}

<#
.SYNOPSIS
StrictMode-safe property access for objects with varying shapes.

.PARAMETER inputObject
The object to read from.

.PARAMETER propertyName
The property name to read.
#>
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

<#
.SYNOPSIS
Posts a JSON body to a URI with retry logic for transient failures.

.PARAMETER uri
The target URI.

.PARAMETER body
The JSON body string.

.PARAMETER logicAppHost
Host-only string for safe logging (to avoid logging SAS tokens).

.PARAMETER maxAttempts
Maximum retry attempts.

.PARAMETER timeoutSec
HTTP timeout in seconds.
#>
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

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $logicAppHost,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]
    $maxAttempts = 5,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]
    $timeoutSec = 60
  )

  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
      Write-Log -Level VERBOSE -Message "POST to $logicAppHost (attempt $attempt/$maxAttempts)"
      return Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType 'application/json' -TimeoutSec $timeoutSec
    }
    catch {
      $ex = $_.Exception
      $statusCode = $null
      $retryAfterSec = $null

      if ($ex.PSObject.Properties.Name -contains 'Response' -and $null -ne $ex.Response) {
        try { $statusCode = [int]$ex.Response.StatusCode } catch { $statusCode = $null }
        try {
          $retryAfterHeader = $ex.Response.Headers['Retry-After']
          if (-not [string]::IsNullOrWhiteSpace($retryAfterHeader)) {
            $retryAfterSec = [int]$retryAfterHeader
          }
        }
        catch { $retryAfterSec = $null }
      }

      $isTransient = ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599) -or $null -eq $statusCode)
      if (-not $isTransient -or $attempt -ge $maxAttempts) {
        throw
      }

      $baseDelay = [Math]::Min(2 * $attempt, 10)
      $delaySec = if ($null -ne $retryAfterSec -and $retryAfterSec -ge 1) { $retryAfterSec } else { $baseDelay }
      Write-Log -Level WARN -Message "POST to $logicAppHost failed (statusCode=$statusCode, attempt $attempt/$maxAttempts). Retrying in $($delaySec)s."
      Start-Sleep -Seconds $delaySec
    }
  }
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

<#
.SYNOPSIS
Core orchestration function for retrieving workspace pricing tier and posting to Logic App.

.DESCRIPTION
Performs the complete workflow:
1. Resolves all configuration from parameters, environment, or Automation variables
2. Validates all inputs
3. Authenticates with user-assigned managed identity
4. Reads workspace SKU and maps to human-friendly pricing tier
5. Posts pricing payload to Logic App endpoint
6. Returns structured summary object

-WhatIf skips only the Logic App POST. Auth and workspace lookup still execute.
#>
function Invoke-SentinelPricingCheck {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter()] [string] $UmiClientId,
    [Parameter()] [string] $SubscriptionId,
    [Parameter()] [string] $WorkspaceName,
    [Parameter()] [string] $ResourceGroupName,
    [Parameter()] [string] $PricingTierApi,
    [Parameter()] [switch] $VerboseLogging
  )

  $script:RunId = [Guid]::NewGuid().ToString()
  $script:EnableVerboseLogging = $VerboseLogging.IsPresent -or $env:AZLH_VERBOSE_LOGGING -eq '1'
  $runStartUtc = [DateTime]::UtcNow

  Write-Log -Level INFO -Message "Starting Sentinel pricing check (version $($script:RunbookVersion))."

  # -------------------------------------------------------------------
  # STEP 1: Resolve configuration
  # -------------------------------------------------------------------

  $resolvedUmiClientId = Resolve-ConfiguredValue -parameterValue $UmiClientId -environmentVariableNames @('UMI_ID', 'UMI_CLIENT_ID') -parameterName 'umiClientId'
  $resolvedSubscriptionId = Resolve-ConfiguredValue -parameterValue $SubscriptionId -environmentVariableNames @('SUBSCRIPTION_ID') -parameterName 'subscriptionId'
  $resolvedWorkspaceName = Resolve-ConfiguredValue -parameterValue $WorkspaceName -environmentVariableNames @('WORKSPACE_NAME') -parameterName 'workspaceName'
  $resolvedResourceGroupName = Resolve-ConfiguredValue -parameterValue $ResourceGroupName -environmentVariableNames @('RESOURCE_GROUP_NAME') -parameterName 'resourceGroupName'
  $resolvedPricingTierApi = Resolve-ConfiguredValue -parameterValue $PricingTierApi -environmentVariableNames @('PRICINGTIER_API') -parameterName 'pricingTierApi'

  # -------------------------------------------------------------------
  # STEP 2: Validate inputs
  # -------------------------------------------------------------------

  Assert-ValidGuid -value $resolvedUmiClientId -parameterName 'umiClientId'
  Assert-ValidGuid -value $resolvedSubscriptionId -parameterName 'subscriptionId'
  Test-IsHttpsUri -uri $resolvedPricingTierApi -parameterName 'pricingTierApi'

  $logicAppHost = Get-UriHostForLog -uri $resolvedPricingTierApi
  Write-Log -Level INFO -Message "Configuration validated. Subscription=$(Get-MaskedValue $resolvedSubscriptionId), UMI=$(Get-MaskedValue $resolvedUmiClientId), Workspace=$resolvedWorkspaceName, RG=$resolvedResourceGroupName, LogicAppHost=$logicAppHost"

  # -------------------------------------------------------------------
  # STEP 3: Authenticate
  # -------------------------------------------------------------------

  Write-Log -Level INFO -Message 'Authenticating to Azure (managed identity).'
  Connect-AzAccount -Identity -AccountId $resolvedUmiClientId -ErrorAction Stop | Out-Null
  Set-AzContext -SubscriptionId $resolvedSubscriptionId -ErrorAction Stop | Out-Null

  # -------------------------------------------------------------------
  # STEP 4: Retrieve workspace and resolve pricing tier
  # -------------------------------------------------------------------

  Write-Log -Level INFO -Message "Retrieving Log Analytics workspace '$resolvedWorkspaceName' in resource group '$resolvedResourceGroupName'."
  $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resolvedResourceGroupName -Name $resolvedWorkspaceName -ErrorAction Stop

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
      $capacity = Get-OptionalPropertyValue -inputObject $sku -propertyName 'CapacityReservationLevel'
      if ($null -eq $capacity) {
        $capacity = Get-OptionalPropertyValue -inputObject $workspace -propertyName 'CapacityReservationLevel'
      }
      $priceTier = if ($null -ne $capacity) { "$capacity GB" } else { 'Commitment Tier' }
    }
    default {
      $priceTier = "Unknown ($skuName)"
    }
  }

  Write-Log -Level INFO -Message "Resolved pricing tier: $priceTier (SKU: $skuName)."

  # -------------------------------------------------------------------
  # STEP 5: Build and POST payload
  # -------------------------------------------------------------------

  $jsonBody = @{
    PricingTier            = $priceTier
    WorkspaceName          = $workspace.Name
    WorkspaceResourceGroup = $resolvedResourceGroupName
    SubscriptionId         = $resolvedSubscriptionId
    SkuName                = $skuName
  } | ConvertTo-Json -Depth 5

  $postStatus = 'NotAttempted'
  $postHttpStatus = $null

  if ($PSCmdlet.ShouldProcess($logicAppHost, 'Post Sentinel pricing tier')) {
    try {
      Write-Log -Level INFO -Message "Posting pricing tier to Logic App host: $logicAppHost"
      Invoke-RestMethodWithRetry -uri $resolvedPricingTierApi -body $jsonBody -logicAppHost $logicAppHost | Out-Null
      $postStatus = 'Success'
      Write-Log -Level INFO -Message 'Logic App POST succeeded.'
    }
    catch {
      $postStatus = 'Failed'
      if ($_.Exception -and $_.Exception.PSObject.Properties['Response']) {
        try { $postHttpStatus = [int]$_.Exception.Response.StatusCode } catch { $postHttpStatus = $null }
      }
      Write-Log -Level ERROR -Message "Logic App POST failed (httpStatus=$postHttpStatus). Check Logic App URI and SAS token validity."
    }
  }
  else {
    $postStatus = 'Skipped (WhatIf)'
    Write-Log -Level INFO -Message 'Logic App POST skipped (-WhatIf).'
  }

  # -------------------------------------------------------------------
  # STEP 6: Emit structured summary
  # -------------------------------------------------------------------

  $runEndUtc = [DateTime]::UtcNow
  $durationSec = [Math]::Round(($runEndUtc - $runStartUtc).TotalSeconds, 2)

  $summary = [PSCustomObject]@{
    RunId              = $script:RunId
    RunbookVersion     = $script:RunbookVersion
    StartTimeUtc       = $runStartUtc.ToString('o')
    EndTimeUtc         = $runEndUtc.ToString('o')
    DurationSeconds    = $durationSec
    WorkspaceName      = $workspace.Name
    PricingTier        = $priceTier
    SkuName            = $skuName
    SubscriptionId     = $resolvedSubscriptionId
    ResourceGroupName  = $resolvedResourceGroupName
    LogicAppHost       = $logicAppHost
    PostStatus         = $postStatus
    PostHttpStatus     = $postHttpStatus
  }

  Write-Log -Level INFO -Message "Runbook completed. PricingTier=$priceTier, SKU=$skuName, PostStatus=$postStatus, Duration=$($durationSec)s."

  return $summary
}

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

# Allow test frameworks to source functions without executing the runbook
if ($env:AZLH_SKIP_PRICING_RUN -eq '1') {
  Write-Verbose 'Skipping runbook execution because AZLH_SKIP_PRICING_RUN=1.'
  return
}

# Execute main function with all provided parameters
Invoke-SentinelPricingCheck `
  -UmiClientId $umiClientId `
  -SubscriptionId $subscriptionId `
  -WorkspaceName $workspaceName `
  -ResourceGroupName $resourceGroupName `
  -PricingTierApi $pricingTierApi `
  -VerboseLogging:$VerboseLogging