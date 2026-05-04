<#
Disclaimer: This script is provided "as-is" without warranty of any kind.

.SYNOPSIS
Submits a Microsoft Sentinel search job (asynchronous operation). The runbook uses a managed identity in the local tenant to execute the search job. This approach works around the limitation of cross-tenant search jobs not supported.

# See note at the end of this section: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/search-jobs?tabs=portal-1%2Cportal-2#permissions-required

https://learn.microsoft.com/en-us/azure/azure-monitor/logs/search-jobs?tabs=portal-1%2Cportal-2#permissions-required

The script resolves configuration from parameters, environment variables, or Azure Automation variables, validates inputs, and handles existing output tables based on the specified policy.

.DESCRIPTION
This Azure Automation runbook:
- Resolves all inputs from parameters first, then environment/Automation variables.
- Validates all required inputs before any Azure call.
- Authenticates using user-assigned managed identity only.
- Submits a search job via New-AzOperationalInsightsSearchTable.
- Returns immediately with job status (does NOT wait for completion).

IMPORTANT: Search jobs run asynchronously and may take minutes to hours to complete
depending on the data volume and time range. The script returns after submitting the
job. To check results later, query the output table in Log Analytics or use
Get-AzOperationalInsightsTable to check the ProvisioningState.

KQL LIMITATIONS: Search jobs support a subset of KQL and are optimized for scanning
one table at a time. Queries must start with a table name and use supported operators
for search jobs. See SearchQuery parameter for detailed limitations.

Variable names used for fallback when parameters are omitted:
- UMI_ID (or UMI_CLIENT_ID)
- SUBSCRIPTION_ID
- RESOURCE_GROUP_NAME
- WORKSPACE_NAME
- SEARCH_TABLE_NAME
- SEARCH_QUERY
- SEARCH_START_TIME_UTC
- SEARCH_END_TIME_UTC
- SEARCH_RETENTION_DAYS
- SEARCH_LIMIT
- IF_TABLE_EXISTS

.EXAMPLE
.\Invoke-AzSentinelSearchJob.ps1 `
  -UmiClientId '11111111-1111-1111-1111-111111111111' `
  -SubscriptionId '22222222-2222-2222-2222-222222222222' `
  -ResourceGroupName 'rg-sentinel-prod' `
  -WorkspaceName 'law-sentinel-eastus' `
  -OutputTableName 'FailedSignInAnalysis' `
  -SearchQuery 'SigninLogs | where ResultType != 0 | project TimeGenerated, UserPrincipalName, ResultType, Location' `
  -StartSearchTime '2026-02-01T00:00:00Z' `
  -EndSearchTime '2026-02-07T23:59:59Z' `
  -RetentionInDays 30 `
  -Limit 10000 `
  -IfTableExists AutoRename

Submits a search job to query failed sign-ins over a 7-day period. Results are stored
in a table named 'FailedSignInAnalysis_SRCH' (or with timestamp suffix if AutoRename is used).
The script returns immediately; the search job runs asynchronously in the background.

.EXAMPLE
.\Invoke-AzSentinelSearchJob.ps1 `
  -UmiClientId '11111111-1111-1111-1111-111111111111' `
  -SubscriptionId '22222222-2222-2222-2222-222222222222' `
  -ResourceGroupName 'rg-sentinel-prod' `
  -WorkspaceName 'law-sentinel-eastus' `
  -OutputTableName 'SecurityEvents_HighSeverity' `
  -SearchQuery 'SecurityEvent | where Level <= 2 | project TimeGenerated, Activity, Computer' `
  -StartSearchTime '2026-01-15T00:00:00-05:00' `
  -EndSearchTime '2026-01-22T23:59:59-05:00'

Searches for high-severity security events using Eastern Time zone timestamps (automatically
converted to UTC). Uses default retention (14 days) and no limit on result count. Note that
search jobs only support a subset of KQL operators (see SearchQuery parameter documentation).

.NOTES
Search job KQL guidance in this script is based on Microsoft Learn:
- Article: Run search jobs in Azure Monitor
- Section: Considerations > KQL query considerations
- URL: https://learn.microsoft.com/azure/azure-monitor/logs/search-jobs
- Page last updated (per Microsoft Learn): 2025-12-16
- Verified for this script on: 2026-02-25

If Azure Monitor search job capabilities change, revalidate this help text against
the latest Microsoft Learn documentation before modifying supported/unsupported
operator guidance.

.PARAMETER UmiClientId
User-assigned managed identity client ID (GUID).

.PARAMETER SubscriptionId
Azure subscription ID (GUID).

.PARAMETER ResourceGroupName
Resource group containing the Log Analytics workspace.

.PARAMETER WorkspaceName
Log Analytics workspace name.

.PARAMETER OutputTableName
Search job output table name. If it does not end with _SRCH, the suffix is added.

.PARAMETER SearchQuery
KQL (Kusto Query Language) query to execute against Log Analytics workspace tables.
The query can reference any table accessible in the workspace (e.g., SecurityEvent,
SigninLogs, Heartbeat, custom tables). Do NOT include '| take <limit>' at the end
if using the Limit parameter, as it will be appended automatically.

IMPORTANT - Search Job KQL Limitations:
Search jobs use a subset of KQL and are optimized for scanning one table at a time:
  - Query MUST start with a table name (for example: SecurityEvent | ...)
  - Supported tabular operators: where, extend, project, project-away, project-keep,
    project-rename, project-reorder, parse, and parse-where
  - All functions and binary operators within the supported operators are usable
  - The contains string operator is blocked for search jobs; use has where possible
  - Query executes in a single workspace (WorkspaceName)
  - If both query text and StartSearchTime/EndSearchTime define time filters,
    Azure Monitor uses the union of those time ranges

Examples:
  'SecurityEvent | where TimeGenerated > ago(1d)'
  'SigninLogs | where ResultType != 0 | project TimeGenerated, UserPrincipalName, ResultType'
  'Heartbeat | where TimeGenerated > ago(7d) | project TimeGenerated, Computer, OSType'
  'SecurityAlert | where Severity == "High" | project-away TenantId'

.PARAMETER StartSearchTime
Search window start time. Accepts any format parseable by .NET DateTimeOffset, including:
  - ISO 8601: '2026-01-15T00:00:00Z' or '2026-01-15T00:00:00-05:00'
  - Sortable: '2026-01-15 00:00:00'
  - RFC 1123: 'Wed, 15 Jan 2026 00:00:00 GMT'

The value is automatically converted to UTC for the Azure API. Time zone-aware formats
are recommended. Relative time expressions like 'ago(7d)' are NOT supported; use absolute
timestamps only. Maximum search window: 30 days.

.PARAMETER EndSearchTime
Search window end time. Accepts the same formats as StartSearchTime:
  - ISO 8601: '2026-01-22T23:59:59Z' or '2026-01-22T23:59:59-05:00'
  - Sortable: '2026-01-22 23:59:59'
  - RFC 1123: 'Wed, 22 Jan 2026 23:59:59 GMT'

Must be after StartSearchTime. Automatically converted to UTC. Maximum search window: 30 days.

.PARAMETER RetentionInDays
Retention period for search results table.

.PARAMETER Limit
Optional cap of returned records. Applied by appending '| take <limit>' to the search query.

.PARAMETER MaxRetryAttempts
Maximum retry attempts for transient Azure API failures.

.PARAMETER InitialRetryDelaySeconds
Initial retry delay between transient failures.

.PARAMETER IfTableExists
Action to take if the output table already exists:
- Error: Fail with an error (default)
- Skip: Skip creation and return existing table info
- Replace: Delete existing table and create new search job
- AutoRename: Append datetime string to create unique table name (e.g., TableName_SRCH_20260225_143052)
#>

[CmdletBinding()]
param(

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $SearchQuery,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $StartSearchTime,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]
  $EndSearchTime,

  [Parameter()]
  [Alias('tableName')]
  [ValidateNotNullOrEmpty()]
  [string]
  $OutputTableName,

  [Parameter()]
  [ValidateSet('Error', 'Skip', 'Replace', 'AutoRename')]
  [string]
  $IfTableExists = 'Error',
  [Parameter()]
  [ValidateRange(1, 730)]
  [int]
  $RetentionInDays = 14,

  [Parameter()]
  [ValidateRange(0, 1000000)]
  [int]
  $Limit = 0,

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
  [Alias('resourceGroup')]
  [ValidateNotNullOrEmpty()]
  [string]
  $ResourceGroupName,

  [Parameter()]
  [Alias('workspace')]
  [ValidateNotNullOrEmpty()]
  [string]
  $WorkspaceName,

  [Parameter()]
  [ValidateRange(1, 10)]
  [int]
  $MaxRetryAttempts = 3,

  [Parameter()]
  [ValidateRange(1, 120)]
  [int]
  $InitialRetryDelaySeconds = 2
)

# ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================

# Stop on any error to ensure failures are caught immediately
$ErrorActionPreference = 'Stop'

# Enforce strict mode to catch common scripting errors (undefined variables, etc.)
Set-StrictMode -Version Latest

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

<#
  .SYNOPSIS
  Safely retrieves an Azure Automation variable without throwing if unavailable.

  .DESCRIPTION
  This function checks if the Get-AutomationVariable cmdlet exists (indicating
  we're running in an Azure Automation context), then attempts to retrieve the
  specified variable. Returns $null if the cmdlet doesn't exist or the variable
  isn't found, allowing graceful fallback to other configuration sources.

.PARAMETER Name
The name of the Automation variable to retrieve.

.OUTPUTS
The variable value if found, otherwise $null.
#>
function Get-AutomationVariableSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Name
  )

  # Check if running in Azure Automation context by testing for the cmdlet
  $command = Get-Command -Name 'Get-AutomationVariable' -ErrorAction SilentlyContinue
  if (-not $command) {
    return $null
  }

  try {
    return Get-AutomationVariable -Name $Name
  }
  catch {
    # Log but don't fail - allows graceful fallback to other sources
    Write-Verbose "Failed reading Automation variable '$Name': $($_.Exception.Message)"
    return $null
  }
}

<#
.SYNOPSIS
Resolves a configuration value from multiple sources in priority order.

.DESCRIPTION
Implements a cascading configuration pattern:
1. Parameter value (highest priority)
2. Environment variables
3. Azure Automation variables (lowest priority)

This allows flexible deployment patterns - parameters for ad-hoc runs,
environment variables for containerized scenarios, and Automation variables
for scheduled runbooks.

.PARAMETER parameterValue
The value passed as a script parameter.

.PARAMETER environmentVariableNames
Array of environment/Automation variable names to check in order.

.PARAMETER parameterName
Friendly parameter name for error messages.

.OUTPUTS
The resolved configuration value.

.THROWS
Terminating error if no value found from any source.
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

  # Priority 1: Use parameter value if provided
  if (-not [string]::IsNullOrWhiteSpace($parameterValue)) {
    return $parameterValue.Trim()
  }

  # Priority 2: Check environment variables (supports container/local scenarios)
  foreach ($environmentVariableName in $environmentVariableNames) {
    $environmentValue = [Environment]::GetEnvironmentVariable($environmentVariableName)
    if (-not [string]::IsNullOrWhiteSpace($environmentValue)) {
      return $environmentValue.Trim()
    }
  }

  # Priority 3: Check Azure Automation variables (supports scheduled runbooks)
  foreach ($automationVariableName in $environmentVariableNames) {
    $automationValue = Get-AutomationVariableSafe -Name $automationVariableName
    if (-not [string]::IsNullOrWhiteSpace($automationValue)) {
      return ([string]$automationValue).Trim()
    }
  }

  # No value found from any source - fail with helpful error
  throw "Missing required value '$parameterName'. Provide parameter '$parameterName' or set one of: $($environmentVariableNames -join ', ')."
}

<#
.SYNOPSIS
Validates that a string is a properly formatted GUID.

.DESCRIPTION
Uses regex to ensure the value matches the standard GUID format:
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (case-insensitive)

.PARAMETER value
The string to validate.

.PARAMETER parameterName
Friendly parameter name for error messages.

.THROWS
Terminating error if the value is not a valid GUID format.
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
  # Validate standard GUID format with regex (8-4-4-4-12 hex groups)
  if ($trimmed -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    throw "$parameterName must be a valid GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
  }
}

<#
.SYNOPSIS
Validates Azure resource group name against Azure naming rules.

.DESCRIPTION
Azure resource group names must:
- Be 1-90 characters long
- Contain only letters, numbers, periods, underscores, hyphens, and parentheses

.PARAMETER value
The resource group name to validate.

.THROWS
Terminating error if the name doesn't meet Azure requirements.
#>
function Assert-ValidResourceGroupName {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $value
  )

  # Validate against Azure resource group naming constraints
  if ($value.Length -gt 90 -or $value -notmatch '^[A-Za-z0-9._()\-]+$') {
    throw 'resourceGroupName is invalid. Allowed length: 1-90, allowed chars: letters, numbers, ., _, -, (, ).'
  }
}

<#
.SYNOPSIS
Validates Log Analytics workspace name against Azure naming rules.

.DESCRIPTION
Log Analytics workspace names must:
- Be 4-63 characters long
- Start with a letter
- End with a letter or number
- Contain only letters, numbers, and hyphens

.PARAMETER value
The workspace name to validate.

.THROWS
Terminating error if the name doesn't meet Azure requirements.
#>
function Assert-ValidWorkspaceName {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $value
  )

  # Validate against Log Analytics workspace naming constraints
  if ($value.Length -lt 4 -or $value.Length -gt 63 -or $value -notmatch '^[A-Za-z][A-Za-z0-9\-]+[A-Za-z0-9]$') {
    throw 'workspaceName is invalid. Allowed length: 4-63, start with letter, and contain only letters, numbers, and hyphen.'
  }
}

<#
.SYNOPSIS
Validates and converts a search job table name to the required format.

.DESCRIPTION
Search job table names must:
- Start with a letter
- Contain only letters, numbers, and underscores
- Be 3-100 characters long
- End with _SRCH suffix (automatically appended if missing)

Uses approved PowerShell verb 'ConvertTo' for transformation operations.

.PARAMETER value
The table name to convert.

.OUTPUTS
The standardized table name with _SRCH suffix.

.THROWS
Terminating error if the base name doesn't meet requirements.
#>
function ConvertTo-SearchTableName {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $value
  )

  $trimmed = $value.Trim()
  # Validate base table name format
  if ($trimmed -notmatch '^[A-Za-z][A-Za-z0-9_]{2,99}$') {
    throw 'outputTableName is invalid. Start with a letter and use only letters, numbers, or underscore.'
  }

  # Check if _SRCH suffix already present (case-insensitive)
  if ($trimmed.EndsWith('_SRCH', [System.StringComparison]::OrdinalIgnoreCase)) {
    return $trimmed
  }

  # Append required _SRCH suffix for search job tables
  return "${trimmed}_SRCH"
}

<#
.SYNOPSIS
Parses a datetime string and converts it to UTC.

.DESCRIPTION
Uses DateTimeOffset for flexible parsing of various datetime formats,
including ISO 8601, RFC 3339, and culture-specific formats.
Automatically handles timezone conversion to UTC.

.PARAMETER value
The datetime string to parse.

.PARAMETER parameterName
Friendly parameter name for error messages.

.OUTPUTS
A DateTime object in UTC.

.THROWS
Terminating error if the string cannot be parsed as a valid datetime.
#>
function Convert-ToUtcDateTime {
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

  $parsed = [System.DateTimeOffset]::MinValue
  # Use DateTimeOffset for flexible parsing with timezone awareness
  if (-not [System.DateTimeOffset]::TryParse($value, [ref]$parsed)) {
    throw "$parameterName must be a valid date/time value. Received: '$value'."
  }

  # Return as UTC DateTime for consistency with Azure APIs
  return $parsed.UtcDateTime
}

<#
.SYNOPSIS
Resolves an integer configuration value from multiple sources with range validation.

.DESCRIPTION
Similar to Resolve-ConfiguredValue but specifically for integer values.
Parsing and range validation are applied regardless of source.

.PARAMETER parameterValue
The value passed as a script parameter.

.PARAMETER environmentVariableNames
Array of environment/Automation variable names to check.

.PARAMETER parameterName
Friendly parameter name for error messages.

.PARAMETER minimum
Minimum allowed value (inclusive).

.PARAMETER maximum
Maximum allowed value (inclusive).

.OUTPUTS
The resolved integer value.

.THROWS
Terminating error if value cannot be parsed or is out of range.
#>
function Resolve-IntegerSetting {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [int]
    $parameterValue,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $environmentVariableNames,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $parameterName,

    [Parameter(Mandatory = $true)]
    [int]
    $minimum,

    [Parameter(Mandatory = $true)]
    [int]
    $maximum
  )

  # Check environment variables first
  foreach ($environmentVariableName in $environmentVariableNames) {
    $environmentValue = [Environment]::GetEnvironmentVariable($environmentVariableName)
    if (-not [string]::IsNullOrWhiteSpace($environmentValue)) {
      $candidate = 0
      # Parse string to integer
      if (-not [int]::TryParse($environmentValue, [ref]$candidate)) {
        throw "$parameterName from environment variable '$environmentVariableName' must be an integer."
      }
      # Validate range
      if ($candidate -lt $minimum -or $candidate -gt $maximum) {
        throw "$parameterName from environment variable '$environmentVariableName' must be between $minimum and $maximum."
      }
      return $candidate
    }
  }

  # Check Azure Automation variables
  foreach ($automationVariableName in $environmentVariableNames) {
    $automationValue = Get-AutomationVariableSafe -name $automationVariableName
    if (-not [string]::IsNullOrWhiteSpace($automationValue)) {
      $candidate = 0
      # Parse string to integer (Automation variables are stored as strings)
      if (-not [int]::TryParse(([string]$automationValue), [ref]$candidate)) {
        throw "$parameterName from Automation variable '$automationVariableName' must be an integer."
      }
      # Validate range
      if ($candidate -lt $minimum -or $candidate -gt $maximum) {
        throw "$parameterName from Automation variable '$automationVariableName' must be between $minimum and $maximum."
      }
      return $candidate
    }
  }

  # Fall back to parameter value and validate its range
  if ($parameterValue -lt $minimum -or $parameterValue -gt $maximum) {
    throw "$parameterName must be between $minimum and $maximum."
  }

  return $parameterValue
}

<#
.SYNOPSIS
Executes a script block with automatic retry logic for transient failures.

.DESCRIPTION
Implements exponential backoff for transient HTTP errors:
- HTTP 429 (Too Many Requests)
- HTTP 5xx (Server Errors)
- Network failures (no HTTP status)

Non-transient errors (4xx except 429) are not retried.
Delay increases with each attempt, capped at 30 seconds.

.PARAMETER operationName
Friendly name for logging.

.PARAMETER scriptBlock
The code to execute.

.PARAMETER maximumAttempts
Maximum number of attempts (including initial try).

.PARAMETER initialDelaySeconds
Base delay in seconds, multiplied by attempt number.

.OUTPUTS
The result of the script block if successful.

.THROWS
Rethrows the exception if all retry attempts are exhausted or error is non-transient.
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
      # Execute the provided script block
      return & $scriptBlock
    }
    catch {
      # Extract HTTP status code if available
      $statusCode = $null
      if ($_.Exception -and $_.Exception.PSObject.Properties['Response']) {
        try {
          $statusCode = [int]$_.Exception.Response.StatusCode
        }
        catch {
          # Some exceptions don't have parseable status codes
          $statusCode = $null
        }
      }

      # Determine if error is transient (worth retrying)
      # Transient: no HTTP status (network), 429 (throttle), or 5xx (server error)
      $isTransient = ($null -eq $statusCode -or $statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599))

      # Don't retry if error is permanent or we've exhausted attempts
      if (-not $isTransient -or $attempt -ge $maximumAttempts) {
        throw
      }

      # Calculate exponential backoff delay (capped at 30 seconds)
      $delaySeconds = [Math]::Min($initialDelaySeconds * $attempt, 30)
      Write-Verbose "Operation '$operationName' failed with transient error. Retrying in $delaySeconds second(s). Attempt $attempt/$maximumAttempts."
      Start-Sleep -Seconds $delaySeconds
    }
  }
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

<#
.SYNOPSIS
Core orchestration function for submitting a Sentinel search job.

.DESCRIPTION
Performs the complete workflow:
1. Resolves all configuration from parameters, environment, or Automation variables
2. Validates all inputs against Azure requirements
3. Authenticates with user-assigned managed identity
4. Checks if output table already exists and handles conflicts per IfTableExists policy
5. Submits the search job (asynchronous operation - does NOT wait for completion)
6. Returns structured result object with job status

IMPORTANT: This function submits the search job and returns immediately.
The search job executes asynchronously in the background. Depending on the
data volume and time range, completion may take minutes to hours.

Table Conflict Handling:
- If the output table already exists, behavior is controlled by IfTableExists parameter:
  * Error (default): Fail with descriptive error message
  * Skip: Return existing table information without creating new search job
  * Replace: Delete existing table and create new search job
  * AutoRename: Append datetime string to create unique table name (preserves historical searches)

To check job status later:
- Query the output table: <TableName> | take 10
- Check provisioning state: Get-AzOperationalInsightsTable -ResourceGroupName <rg> -WorkspaceName <ws> -TableName <table>

This function is designed to work in multiple contexts:
- Azure Automation runbook (with Automation variables)
- Container/Docker (with environment variables)
- Direct execution (with parameters)
#>
function Invoke-SentinelSearchJob {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string]
    $UmiClientId,

    [Parameter()]
    [string]
    $SubscriptionId,

    [Parameter()]
    [string]
    $ResourceGroupName,

    [Parameter()]
    [string]
    $WorkspaceName,

    [Parameter()]
    [string]
    $OutputTableName,

    [Parameter()]
    [string]
    $SearchQuery,

    [Parameter()]
    [string]
    $StartSearchTime,

    [Parameter()]
    [string]
    $EndSearchTime,

    [Parameter()]
    [int]
    $RetentionInDays = 30,

    [Parameter()]
    [int]
    $Limit = 0,

    [Parameter()]
    [int]
    $MaxRetryAttempts = 3,

    [Parameter()]
    [int]
    $InitialRetryDelaySeconds = 2,

    [Parameter()]
    [string]
    $IfTableExists = 'Error'
  )

  # -------------------------------------------------------------------------
  # STEP 1: Resolve all configuration values from cascading sources
  # -------------------------------------------------------------------------

  $resolvedUmiClientId = Resolve-ConfiguredValue -parameterValue $UmiClientId -environmentVariableNames @('UMI_ID', 'UMI_CLIENT_ID') -parameterName 'UmiClientId'
  $resolvedSubscriptionId = Resolve-ConfiguredValue -parameterValue $SubscriptionId -environmentVariableNames @('SUBSCRIPTION_ID') -parameterName 'SubscriptionId'
  $resolvedResourceGroupName = Resolve-ConfiguredValue -parameterValue $ResourceGroupName -environmentVariableNames @('RESOURCE_GROUP_NAME') -parameterName 'ResourceGroupName'
  $resolvedWorkspaceName = Resolve-ConfiguredValue -parameterValue $WorkspaceName -environmentVariableNames @('WORKSPACE_NAME') -parameterName 'WorkspaceName'
  $resolvedOutputTableName = Resolve-ConfiguredValue -parameterValue $OutputTableName -environmentVariableNames @('SEARCH_TABLE_NAME') -parameterName 'OutputTableName'
  $resolvedSearchQuery = Resolve-ConfiguredValue -parameterValue $SearchQuery -environmentVariableNames @('SEARCH_QUERY') -parameterName 'SearchQuery'
  $resolvedStartSearchTime = Resolve-ConfiguredValue -parameterValue $StartSearchTime -environmentVariableNames @('SEARCH_START_TIME_UTC') -parameterName 'StartSearchTime'
  $resolvedEndSearchTime = Resolve-ConfiguredValue -parameterValue $EndSearchTime -environmentVariableNames @('SEARCH_END_TIME_UTC') -parameterName 'EndSearchTime'

  # Resolve integer settings with range validation
  $resolvedRetentionInDays = Resolve-IntegerSetting -parameterValue $RetentionInDays -environmentVariableNames @('SEARCH_RETENTION_DAYS') -parameterName 'RetentionInDays' -minimum 1 -maximum 730
  $resolvedLimit = Resolve-IntegerSetting -parameterValue $Limit -environmentVariableNames @('SEARCH_LIMIT') -parameterName 'Limit' -minimum 0 -maximum 1000000

  # Resolve IfTableExists with default fallback
  $resolvedIfTableExists = $IfTableExists
  $envIfTableExists = [Environment]::GetEnvironmentVariable('IF_TABLE_EXISTS')
  if (-not [string]::IsNullOrWhiteSpace($envIfTableExists) -and $IfTableExists -eq 'Error') {
    $candidate = $envIfTableExists.Trim()
    if ($candidate -in @('Error', 'Skip', 'Replace', 'AutoRename')) {
      $resolvedIfTableExists = $candidate
    }
    else {
      Write-Warning "IF_TABLE_EXISTS environment variable has invalid value '$candidate'. Must be Error, Skip, Replace, or AutoRename. Using default: Error"
    }
  }
  $autoIfTableExists = Get-AutomationVariableSafe -name 'IF_TABLE_EXISTS'
  if (-not [string]::IsNullOrWhiteSpace($autoIfTableExists) -and $IfTableExists -eq 'Error') {
    $candidate = ([string]$autoIfTableExists).Trim()
    if ($candidate -in @('Error', 'Skip', 'Replace', 'AutoRename')) {
      $resolvedIfTableExists = $candidate
    }
    else {
      Write-Warning "IF_TABLE_EXISTS Automation variable has invalid value '$candidate'. Must be Error, Skip, Replace, or AutoRename. Using default: Error"
    }
  }

  # -------------------------------------------------------------------------
  # STEP 2: Validate all resolved configuration
  # -------------------------------------------------------------------------

  # Validate GUID formats for Azure identity and subscription
  Assert-ValidGuid -value $resolvedUmiClientId -parameterName 'umiClientId'
  Assert-ValidGuid -value $resolvedSubscriptionId -parameterName 'subscriptionId'

  # Validate Azure resource names
  Assert-ValidResourceGroupName -value $resolvedResourceGroupName
  Assert-ValidWorkspaceName -value $resolvedWorkspaceName

  # Validate KQL query length (reasonable bounds)
  if ($resolvedSearchQuery.Trim().Length -lt 3 -or $resolvedSearchQuery.Length -gt 10000) {
    throw 'SearchQuery must be between 3 and 10000 characters.'
  }

  # Convert table name to standard format (adds _SRCH suffix if missing)
  $normalizedTableName = ConvertTo-SearchTableName -value $resolvedOutputTableName

  # Parse and convert datetime values to UTC
  $startUtc = Convert-ToUtcDateTime -value $resolvedStartSearchTime -parameterName 'StartSearchTime'
  $endUtc = Convert-ToUtcDateTime -value $resolvedEndSearchTime -parameterName 'EndSearchTime'

  # Validate time range logic
  if ($startUtc -ge $endUtc) {
    throw 'StartSearchTime must be earlier than EndSearchTime.'
  }

  # Enforce search window constraints (Azure limitation)
  $searchWindow = $endUtc - $startUtc
  if ($searchWindow.TotalDays -gt 30) {
    throw 'Search window cannot exceed 30 days.'
  }

  # -------------------------------------------------------------------------
  # STEP 3: Prepare search query with optional limit
  # -------------------------------------------------------------------------

  $effectiveSearchQuery = $resolvedSearchQuery
  if ($resolvedLimit -gt 0) {
    # Append KQL 'take' operator to limit result set
    $effectiveSearchQuery = "${effectiveSearchQuery}`n| take $resolvedLimit"
  }

  # -------------------------------------------------------------------------
  # STEP 4: Verify required cmdlet is available
  # -------------------------------------------------------------------------

  $createSearchTableCommand = Get-Command -Name 'New-AzOperationalInsightsSearchTable' -ErrorAction SilentlyContinue
  if (-not $createSearchTableCommand) {
    throw "Required cmdlet 'New-AzOperationalInsightsSearchTable' was not found. Ensure Az.OperationalInsights module is installed in the Automation Account."
  }

  # -------------------------------------------------------------------------
  # STEP 5: Authenticate with Azure using managed identity
  # -------------------------------------------------------------------------

  # Connect using user-assigned managed identity (UMI)
  Connect-AzAccount -Identity -AccountId $resolvedUmiClientId -ErrorAction Stop | Out-Null

  # Set subscription context for all subsequent Azure calls
  Set-AzContext -SubscriptionId $resolvedSubscriptionId -ErrorAction Stop | Out-Null

  # -------------------------------------------------------------------------
  # STEP 6: Verify workspace exists
  # -------------------------------------------------------------------------

  $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resolvedResourceGroupName -Name $resolvedWorkspaceName -ErrorAction Stop
  if ($null -eq $workspace) {
    throw "Workspace '$resolvedWorkspaceName' was not found in resource group '$resolvedResourceGroupName'."
  }

  # -------------------------------------------------------------------------
  # STEP 6.5: Check if table already exists and handle accordingly
  # -------------------------------------------------------------------------

  $existingTable = $null
  try {
    $existingTable = Get-AzOperationalInsightsTable -ResourceGroupName $resolvedResourceGroupName -WorkspaceName $resolvedWorkspaceName -TableName $normalizedTableName -ErrorAction SilentlyContinue
  }
  catch {
    # Table doesn't exist - this is expected for new searches
    Write-Verbose "Table '$normalizedTableName' does not exist yet."
  }

  if ($null -ne $existingTable) {
    Write-Verbose "Table '$normalizedTableName' already exists. IfTableExists policy: $resolvedIfTableExists"

    switch ($resolvedIfTableExists) {
      'Error' {
        throw "Table '$normalizedTableName' already exists in workspace '$resolvedWorkspaceName'. Use -IfTableExists Skip to return existing table info, -IfTableExists Replace to delete and recreate, or -IfTableExists AutoRename to create with unique name."
      }
      'Skip' {
        Write-Warning "Table '$normalizedTableName' already exists. Skipping creation and returning existing table information."
        $requestTimestamp = [DateTime]::UtcNow
        return [PSCustomObject]@{
          Operation          = 'CreateSentinelSearchJob'
          Status             = 'Skipped'
          ProvisioningState  = $existingTable.ProvisioningState
          SubscriptionId     = $resolvedSubscriptionId
          ResourceGroupName  = $resolvedResourceGroupName
          WorkspaceName      = $resolvedWorkspaceName
          OutputTableName    = $normalizedTableName
          StartSearchTimeUtc = $startUtc.ToString('o')
          EndSearchTimeUtc   = $endUtc.ToString('o')
          RetentionInDays    = $resolvedRetentionInDays
          AppliedLimit       = $resolvedLimit
          SubmittedAtUtc     = $requestTimestamp.ToString('o')
          StatusCheckQuery   = "$normalizedTableName | getschema | project TableName, ColumnName, DataType | take 10"
          Result             = $existingTable
        }
      }
      'Replace' {
        Write-Warning "Table '$normalizedTableName' already exists. Deleting existing table before creating new search job."
        try {
          Remove-AzOperationalInsightsTable -ResourceGroupName $resolvedResourceGroupName -WorkspaceName $resolvedWorkspaceName -TableName $normalizedTableName -ErrorAction Stop | Out-Null
          Write-Verbose "Successfully deleted existing table '$normalizedTableName'."
          # Brief delay to ensure deletion completes
          Start-Sleep -Seconds 2
        }
        catch {
          throw "Failed to delete existing table '$normalizedTableName': $($_.Exception.Message)"
        }
      }
      'AutoRename' {
        # Generate unique table name by appending datetime string
        $timestamp = [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss')
        # Remove _SRCH suffix temporarily, add timestamp, then re-add _SRCH
        $baseTableName = $normalizedTableName -replace '_SRCH$', ''
        $normalizedTableName = "${baseTableName}_${timestamp}_SRCH"
        Write-Warning "Table already exists. Creating search job with unique name: $normalizedTableName"
      }
    }
  }

  # -------------------------------------------------------------------------
  # STEP 7: Submit search job (asynchronous operation)
  # -------------------------------------------------------------------------

  # IMPORTANT: New-AzOperationalInsightsSearchTable submits the search job
  # and returns immediately. The search job executes asynchronously in the
  # background and may take minutes to hours depending on data volume and
  # time range. The cmdlet does NOT wait for the job to complete.

  $searchResult = Invoke-WithRetry -operationName 'New-AzOperationalInsightsSearchTable' -maximumAttempts $MaxRetryAttempts -initialDelaySeconds $InitialRetryDelaySeconds -scriptBlock {
    # Build parameter hashtable for splatting
    $createSplat = @{
      ResourceGroupName = $resolvedResourceGroupName
      WorkspaceName     = $resolvedWorkspaceName
      TableName         = $normalizedTableName
      SearchQuery       = $effectiveSearchQuery
      StartSearchTime   = $startUtc
      EndSearchTime     = $endUtc
      ErrorAction       = 'Stop'
    }

    # Handle different parameter names across Az module versions
    # Newer versions use TotalRetentionInDays, older use RetentionInDays
    if ($createSearchTableCommand.Parameters.ContainsKey('TotalRetentionInDays')) {
      $createSplat['TotalRetentionInDays'] = $resolvedRetentionInDays
    }
    elseif ($createSearchTableCommand.Parameters.ContainsKey('RetentionInDays')) {
      $createSplat['RetentionInDays'] = $resolvedRetentionInDays
    }

    # Submit the search job (returns immediately, job runs in background)
    New-AzOperationalInsightsSearchTable @createSplat
  }

  # Extract provisioning state from the response
  # Common states: InProgress, Updating, Succeeded, Failed
  $provisioningState = if ($searchResult.PSObject.Properties['ProvisioningState']) {
    $searchResult.ProvisioningState
  }
  else {
    'Unknown'
  }

  # -------------------------------------------------------------------------
  # STEP 8: Return structured result with job status
  # -------------------------------------------------------------------------

  $requestTimestamp = [DateTime]::UtcNow

  # Return flat object with all operation details and Azure result
  # Note: The search job is running asynchronously. Check the ProvisioningState
  # and query the table later to see results.
  return [PSCustomObject]@{
    Operation          = 'CreateSentinelSearchJob'
    Status             = 'Submitted'  # Job submitted, not completed
    ProvisioningState  = $provisioningState
    SubscriptionId     = $resolvedSubscriptionId
    ResourceGroupName  = $resolvedResourceGroupName
    WorkspaceName      = $resolvedWorkspaceName
    OutputTableName    = $normalizedTableName
    StartSearchTimeUtc = $startUtc.ToString('o')  # ISO 8601 format
    EndSearchTimeUtc   = $endUtc.ToString('o')    # ISO 8601 format
    RetentionInDays    = $resolvedRetentionInDays
    AppliedLimit       = $resolvedLimit
    SubmittedAtUtc     = $requestTimestamp.ToString('o')  # ISO 8601 format
    StatusCheckQuery   = "$normalizedTableName | getschema | project TableName, ColumnName, DataType | take 10"
    Result             = $searchResult  # Raw Azure API response
  }

  # TO CHECK JOB STATUS LATER:
  # 1. Query the table in Log Analytics: <OutputTableName> | take 10
  # 2. If empty or table doesn't exist, search job is still running
  # 3. Use Get-AzOperationalInsightsTable to check ProvisioningState:
  #    Get-AzOperationalInsightsTable -ResourceGroupName <rg> -WorkspaceName <ws> -TableName <table>
}

# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

# Allow test frameworks to source functions without executing the runbook
if ($env:AZLH_SKIP_SEARCHJOB_RUN -eq '1') {
  Write-Verbose 'Skipping runbook execution because AZLH_SKIP_SEARCHJOB_RUN=1.'
  return
}

# Execute main function with all provided parameters
Invoke-SentinelSearchJob `
  -UmiClientId $UmiClientId `
  -SubscriptionId $SubscriptionId `
  -ResourceGroupName $ResourceGroupName `
  -WorkspaceName $WorkspaceName `
  -OutputTableName $OutputTableName `
  -SearchQuery $SearchQuery `
  -StartSearchTime $StartSearchTime `
  -EndSearchTime $EndSearchTime `
  -RetentionInDays $RetentionInDays `
  -Limit $Limit `
  -MaxRetryAttempts $MaxRetryAttempts `
  -InitialRetryDelaySeconds $InitialRetryDelaySeconds `
  -IfTableExists $IfTableExists
