#Requires -Version 7.0

<#
Disclaimer: This script is provided "as-is" without warranty of any kind. Use at your own risk. The author is not liable for any damage or loss resulting from the use of this script.

This script was not developed or tested by the repo owner. It was contributed by a community member and is provided for reference and educational purposes. Please review and test the script in a non-production environment before using it in production.

I do not have the code for the logic app that this runbook posts to, but the general idea is:
- This runbook is triggered on a schedule (e.g., daily) in Azure Automation.
- It retrieves the policy assignments and definitions for a given Azure subscription.
- It posts this information to a Logic App endpoint, which can then log it, send notifications, or take other actions based on the policy inventory.


.SYNOPSIS
Collects Azure Policy assignments and definitions for a subscription and posts the inventory to a Logic App endpoint.

.DESCRIPTION
This Azure Automation runbook:
- Resolves all inputs from parameters first, then environment variables, then Automation variables.
- Validates all required inputs before any Azure call.
- Authenticates using a user-assigned managed identity (UAMI) only.
- Enumerates policy assignments at subscription scope.
- Resolves assignments to policy definitions and policy set (initiative) definitions for reporting.
- Posts a legacy-compatible JSON inventory payload to a Logic App endpoint with retry and backoff.
- Emits a structured summary object for downstream automation and auditing.

The posted Logic App payload:
- PolicyAssignments: AssignmentName, PolicyDefinitionId
- PolicyDefinitions: PolicyName, PolicyDefinitionId, PolicyRule, LastModifiedBy, LastModifiedOn
- CurrentSubscription
- WorkspaceName


Automation variable names used when parameters are omitted:
- UMI_ID (or UMI_CLIENT_ID)
- SUBSCRIPTION_ID
- WORKSPACE_NAME
- POLICYMONITORING_API

UAMI role requirements (minimum):
- Reader at subscription scope (covers policy assignment and definition read operations)

.PARAMETER UmiClientId
User-assigned managed identity client ID (GUID). Alias: UMIId.

.PARAMETER SubscriptionId
Azure subscription ID (GUID). Alias: SubscriptionID.

.PARAMETER WorkspaceName
Sentinel Log Analytics workspace name. Alias: workspaceName.

.PARAMETER LogicAppUri
Logic App HTTP endpoint URI (HTTPS with SAS token) to post the policy inventory payload.
Alias: policyMonitoringApi.

.PARAMETER VerboseLogging
When specified, enables verbose-level log output for troubleshooting.

.EXAMPLE
.\Get-AzurePolicies.ps1 `
  -UmiClientId '11111111-1111-1111-1111-111111111111' `
  -SubscriptionId '22222222-2222-2222-2222-222222222222' `
  -WorkspaceName 'law-sentinel-eastus' `
  -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/.../triggers/manual/paths/invoke?...&sig=...'

Collects all policy assignments and definitions for the subscription and posts
the legacy-compatible inventory to the specified Logic App. The posted JSON includes PolicyRule in each policy definition object.

.NOTES
Logic App URI handling: The URI is treated as a secret (SAS token in query string).
Only the host portion is ever logged. The full URI never appears in output, warning,
or verbose streams.

Payload compatibility: The posted JSON is intentionally limited to the fields expected by
the legacy Logic App workflow. Diagnostic metadata such as RunId, Scope, PolicySetDefinitions,
and FailedDefinitionLookups is returned in the script summary only; it is not posted.
PolicyRule is always posted for policy definitions.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter()]
  [Alias('UMIId')]
  [ValidateNotNullOrEmpty()]
  [string]
  $UmiClientId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $SubscriptionId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $WorkspaceName,

  [Parameter()]
  [Alias('policyMonitoringApi')]
  [ValidateNotNullOrEmpty()]
  [string]
  $LogicAppUri,

  [Parameter()]
  [switch]
  $VerboseLogging
)

# ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:RunbookVersion = '1.0.0'

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
Validates that a URI uses HTTPS scheme.

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
    'INFO' { Write-Information $formatted -InformationAction Continue }
    'WARN' { Write-Warning $formatted }
    'ERROR' { Write-Error $formatted -ErrorAction Continue }
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
Executes a script block with retry logic for transient failures.

.PARAMETER operationName
Friendly name for logging.

.PARAMETER scriptBlock
The code to execute.

.PARAMETER maximumAttempts
Maximum number of attempts.

.PARAMETER initialDelaySeconds
Base delay in seconds, multiplied by attempt number.
#>
function Invoke-WithRetry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $operationName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [scriptblock]
    $scriptBlock,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]
    $maximumAttempts = 3,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]
    $initialDelaySeconds = 2
  )

  for ($attempt = 1; $attempt -le $maximumAttempts; $attempt++) {
    try {
      return & $scriptBlock
    }
    catch {
      $statusCode = $null
      if ($_.Exception -and $_.Exception.PSObject.Properties['Response']) {
        try {
          $statusCode = [int]$_.Exception.Response.StatusCode
        }
        catch {
          $statusCode = $null
        }
      }

      $isTransient = ($null -eq $statusCode -or $statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599))

      if (-not $isTransient -or $attempt -ge $maximumAttempts) {
        throw
      }

      $delaySeconds = [Math]::Min($initialDelaySeconds * $attempt, 30)
      Write-Log -Level WARN -Message "Operation '$operationName' failed (attempt $attempt/$maximumAttempts). Retrying in $($delaySeconds)s. Error: $($_.Exception.Message)"
      Start-Sleep -Seconds $delaySeconds
    }
  }
}

<#
.SYNOPSIS
Posts a JSON body to a URI with retry logic for transient failures.

.PARAMETER uri
The target URI.

.PARAMETER body
The JSON body string.

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
      Write-Log -Level WARN -Message "POST to Logic App failed (statusCode=$statusCode, attempt $attempt/$maxAttempts). Retrying in $($delaySec)s."
      Start-Sleep -Seconds $delaySec
    }
  }
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

<#
.SYNOPSIS
Core orchestration function for collecting and posting Azure Policy inventory.

.DESCRIPTION
Performs the complete workflow:
1. Resolves all configuration from parameters, environment, or Automation variables
2. Validates all inputs
3. Authenticates with user-assigned managed identity
4. Enumerates policy assignments at subscription scope
5. Resolves each assignment to its policy definition or policy set definition
6. Posts the legacy-compatible inventory payload to a Logic App endpoint
7. Returns a structured summary object
#>
function Invoke-AzurePolicyInventory {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter()] [string] $UmiClientId,
    [Parameter()] [string] $SubscriptionId,
    [Parameter()] [string] $WorkspaceName,
    [Parameter()] [string] $LogicAppUri,
    [Parameter()] [switch] $VerboseLogging
  )

  # Generate RunId for correlation
  $script:RunId = [Guid]::NewGuid().ToString()
  $script:EnableVerboseLogging = $VerboseLogging.IsPresent -or $env:AZLH_VERBOSE_LOGGING -eq '1'
  $runStartUtc = [DateTime]::UtcNow

  Write-Log -Level INFO -Message "Starting Azure Policy inventory (version $($script:RunbookVersion))."

  # -------------------------------------------------------------------
  # STEP 1: Resolve configuration
  # -------------------------------------------------------------------

  $resolvedUmiClientId = Resolve-ConfiguredValue -parameterValue $UmiClientId -environmentVariableNames @('UMI_ID', 'UMI_CLIENT_ID') -parameterName 'UmiClientId'
  $resolvedSubscriptionId = Resolve-ConfiguredValue -parameterValue $SubscriptionId -environmentVariableNames @('SUBSCRIPTION_ID') -parameterName 'SubscriptionId'
  $resolvedWorkspaceName = Resolve-ConfiguredValue -parameterValue $WorkspaceName -environmentVariableNames @('WORKSPACE_NAME') -parameterName 'WorkspaceName'
  $resolvedLogicAppUri = Resolve-ConfiguredValue -parameterValue $LogicAppUri -environmentVariableNames @('POLICYMONITORING_API') -parameterName 'LogicAppUri'

  # -------------------------------------------------------------------
  # STEP 2: Validate inputs
  # -------------------------------------------------------------------

  Assert-ValidGuid -value $resolvedUmiClientId -parameterName 'UmiClientId'
  Assert-ValidGuid -value $resolvedSubscriptionId -parameterName 'SubscriptionId'
  Test-IsHttpsUri -uri $resolvedLogicAppUri -parameterName 'LogicAppUri'

  $logicAppHost = Get-UriHostForLog -uri $resolvedLogicAppUri
  Write-Log -Level INFO -Message "Configuration validated. Subscription=$(Get-MaskedValue $resolvedSubscriptionId), UMI=$(Get-MaskedValue $resolvedUmiClientId), Workspace=$resolvedWorkspaceName, LogicAppHost=$logicAppHost"

  # -------------------------------------------------------------------
  # STEP 3: Authenticate
  # -------------------------------------------------------------------

  Write-Log -Level INFO -Message 'Authenticating to Azure (managed identity).'
  Connect-AzAccount -Identity -AccountId $resolvedUmiClientId -ErrorAction Stop | Out-Null
  Set-AzContext -SubscriptionId $resolvedSubscriptionId -ErrorAction Stop | Out-Null

  # -------------------------------------------------------------------
  # STEP 4: Enumerate policy assignments
  # -------------------------------------------------------------------

  $scope = "/subscriptions/$resolvedSubscriptionId"
  Write-Log -Level INFO -Message "Retrieving policy assignments at scope: $scope"

  $rawAssignments = Invoke-WithRetry -operationName 'Get-AzPolicyAssignment' -scriptBlock {
    Get-AzPolicyAssignment -Scope $scope -ErrorAction Stop
  }

  if ($null -eq $rawAssignments) {
    $rawAssignments = @()
  }

  Write-Log -Level INFO -Message "Found $(@($rawAssignments).Count) policy assignment(s)."

  # -------------------------------------------------------------------
  # STEP 5: Process assignments and resolve definitions
  # -------------------------------------------------------------------

  $assignmentResults = [System.Collections.Generic.List[PSCustomObject]]::new()
  $definitionCache = @{}
  $policySetCache = @{}
  $definitionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
  $policySetResults = [System.Collections.Generic.List[PSCustomObject]]::new()
  $failedDefinitionCount = 0

  foreach ($assignment in @($rawAssignments)) {
    $assignmentName = Get-OptionalPropertyValue -inputObject $assignment -propertyName 'Name'
    $assignmentDisplayName = Get-OptionalPropertyValue -inputObject $assignment -propertyName 'DisplayName'
    $policyDefId = Get-OptionalPropertyValue -inputObject $assignment -propertyName 'PolicyDefinitionId'
    $enforcementMode = Get-OptionalPropertyValue -inputObject $assignment -propertyName 'EnforcementMode'
    $assignmentScope = Get-OptionalPropertyValue -inputObject $assignment -propertyName 'Scope'
    $assignmentParams = Get-OptionalPropertyValue -inputObject $assignment -propertyName 'Parameters'

    # Determine assignment type
    $assignmentType = 'Unknown'
    if (-not [string]::IsNullOrWhiteSpace($policyDefId)) {
      if ($policyDefId -match '/policySetDefinitions/') {
        $assignmentType = 'PolicySetDefinition'
      }
      elseif ($policyDefId -match '/policyDefinitions/') {
        $assignmentType = 'PolicyDefinition'
      }
    }

    $assignmentObj = [PSCustomObject]@{
      AssignmentName     = $assignmentName
      DisplayName        = $assignmentDisplayName
      AssignmentType     = $assignmentType
      PolicyDefinitionId = $policyDefId
      EnforcementMode    = $enforcementMode
      Scope              = $assignmentScope
      Parameters         = $assignmentParams
    }
    $assignmentResults.Add($assignmentObj)

    if ([string]::IsNullOrWhiteSpace($policyDefId)) {
      Write-Log -Level WARN -Message "Skipping assignment '$assignmentName' - PolicyDefinitionId is empty."
      continue
    }

    # Resolve policy definition or policy set definition
    if ($assignmentType -eq 'PolicySetDefinition') {
      if (-not $policySetCache.ContainsKey($policyDefId)) {
        try {
          $policySet = Invoke-WithRetry -operationName "Get-AzPolicySetDefinition ($assignmentName)" -scriptBlock {
            Get-AzPolicySetDefinition -Id $policyDefId -ErrorAction Stop
          }
          $policySetObj = [PSCustomObject]@{
            PolicySetName         = Get-OptionalPropertyValue -inputObject $policySet -propertyName 'Name'
            DisplayName           = Get-OptionalPropertyValue -inputObject $policySet -propertyName 'DisplayName'
            PolicySetDefinitionId = $policyDefId
            PolicyType            = Get-OptionalPropertyValue -inputObject $policySet -propertyName 'PolicyType'
            Description           = Get-OptionalPropertyValue -inputObject $policySet -propertyName 'Description'
            LastModifiedBy        = Get-OptionalPropertyValue -inputObject $policySet -propertyName 'SystemDataLastModifiedBy'
            LastModifiedOn        = Get-OptionalPropertyValue -inputObject $policySet -propertyName 'SystemDataLastModifiedAt'
          }
          $policySetResults.Add($policySetObj)
          $policySetCache[$policyDefId] = $true
        }
        catch {
          $failedDefinitionCount++
          Write-Log -Level WARN -Message "Failed to resolve policy set definition for assignment '$assignmentName': $($_.Exception.Message)"
          $policySetCache[$policyDefId] = $false
        }
      }
    }
    elseif ($assignmentType -eq 'PolicyDefinition') {
      if (-not $definitionCache.ContainsKey($policyDefId)) {
        try {
          $definition = Invoke-WithRetry -operationName "Get-AzPolicyDefinition ($assignmentName)" -scriptBlock {
            Get-AzPolicyDefinition -Id $policyDefId -ErrorAction Stop
          }
          $defObj = [PSCustomObject]@{
            PolicyName         = Get-OptionalPropertyValue -inputObject $definition -propertyName 'Name'
            DisplayName        = Get-OptionalPropertyValue -inputObject $definition -propertyName 'DisplayName'
            PolicyDefinitionId = $policyDefId
            PolicyType         = Get-OptionalPropertyValue -inputObject $definition -propertyName 'PolicyType'
            Description        = Get-OptionalPropertyValue -inputObject $definition -propertyName 'Description'
            PolicyRule         = Get-OptionalPropertyValue -inputObject $definition -propertyName 'PolicyRule'
            LastModifiedBy     = Get-OptionalPropertyValue -inputObject $definition -propertyName 'SystemDataLastModifiedBy'
            LastModifiedOn     = Get-OptionalPropertyValue -inputObject $definition -propertyName 'SystemDataLastModifiedAt'
          }
          $definitionResults.Add($defObj)
          $definitionCache[$policyDefId] = $true
        }
        catch {
          $failedDefinitionCount++
          Write-Log -Level WARN -Message "Failed to resolve policy definition for assignment '$assignmentName': $($_.Exception.Message)"
          $definitionCache[$policyDefId] = $false
        }
      }
    }
  }

  Write-Log -Level INFO -Message "Resolved $($definitionResults.Count) policy definition(s), $($policySetResults.Count) policy set definition(s), $failedDefinitionCount failed lookup(s)."

  # -------------------------------------------------------------------
  # STEP 6: Build and POST legacy-compatible payload
  # -------------------------------------------------------------------

  $definitionProperties = @('PolicyName', 'PolicyDefinitionId', 'PolicyRule', 'LastModifiedBy', 'LastModifiedOn')

  # Build the posted payload to match _Get-AzurePolicies.ps1. Do not add diagnostic
  # summary fields here because the Logic App expects this exact shape.
  $payload = @{
    PolicyAssignments   = @($assignmentResults | ForEach-Object {
        [PSCustomObject]@{
          AssignmentName     = $_.AssignmentName
          PolicyDefinitionId = $_.PolicyDefinitionId
        }
      })
    PolicyDefinitions   = @($definitionResults | ForEach-Object {
        $_ | Select-Object -Property $definitionProperties
      })
    CurrentSubscription = $resolvedSubscriptionId
    WorkspaceName       = $resolvedWorkspaceName
  }
  $jsonBody = $payload | ConvertTo-Json -Depth 20

  Write-Log -Level VERBOSE -Message "Payload size: $($jsonBody.Length) characters, $($assignmentResults.Count) assignment(s)."

  $postStatus = 'NotAttempted'
  $postHttpStatus = $null

  if ($PSCmdlet.ShouldProcess($logicAppHost, 'Post Azure Policy inventory')) {
    try {
      Write-Log -Level INFO -Message "Posting inventory to Logic App host: $logicAppHost"
      Invoke-RestMethodWithRetry -uri $resolvedLogicAppUri -body $jsonBody | Out-Null
      $postStatus = 'Success'
      Write-Log -Level INFO -Message 'Logic App POST succeeded.'
    }
    catch {
      $postStatus = 'Failed'
      $postHttpStatus = $null
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
  # STEP 7: Emit structured summary
  # -------------------------------------------------------------------

  $runEndUtc = [DateTime]::UtcNow
  $durationSec = [Math]::Round(($runEndUtc - $runStartUtc).TotalSeconds, 2)

  $summary = [PSCustomObject]@{
    RunId                    = $script:RunId
    RunbookVersion           = $script:RunbookVersion
    StartTimeUtc             = $runStartUtc.ToString('o')
    EndTimeUtc               = $runEndUtc.ToString('o')
    DurationSeconds          = $durationSec
    SubscriptionId           = $resolvedSubscriptionId
    Scope                    = $scope
    WorkspaceName            = $resolvedWorkspaceName
    AssignmentCount          = $assignmentResults.Count
    PolicyDefinitionCount    = $definitionResults.Count
    PolicySetDefinitionCount = $policySetResults.Count
    FailedDefinitionLookups  = $failedDefinitionCount
    LogicAppHost             = $logicAppHost
    PostStatus               = $postStatus
    PostHttpStatus           = $postHttpStatus
  }

  Write-Log -Level INFO -Message "Runbook completed. Assignments=$($assignmentResults.Count), Definitions=$($definitionResults.Count), PolicySets=$($policySetResults.Count), Failed=$failedDefinitionCount, PostStatus=$postStatus, Duration=$($durationSec)s."

  return $summary
}

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

# Allow test frameworks to source functions without executing the runbook
if ($env:AZLH_SKIP_POLICY_RUN -eq '1') {
  Write-Verbose 'Skipping runbook execution because AZLH_SKIP_POLICY_RUN=1.'
  return
}

# Execute main function with all provided parameters
Invoke-AzurePolicyInventory `
  -UmiClientId $UmiClientId `
  -SubscriptionId $SubscriptionId `
  -WorkspaceName $WorkspaceName `
  -LogicAppUri $LogicAppUri `
  -VerboseLogging:$VerboseLogging