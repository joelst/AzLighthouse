#requires -Version 7.0
#requires -Modules Az.Accounts

<#
.SYNOPSIS
  Retrieve the status of all Data Connectors in an Azure Sentinel workspace via REST API.
.DESCRIPTION
  This script connects to the Azure Resource Manager REST API to list all Data Connectors
  in a specified Azure Sentinel workspace. For each connector, it retrieves detailed information,
  including its definition, UI configuration, and connectivity queries. Optional switches allow
  for a concise summary table or a full raw dump of connector metadata (which may contain
  sensitive data, so guard logs accordingly).
.PARAMETER SubscriptionId
  The Azure Subscription ID containing the Sentinel workspace.
.PARAMETER ResourceGroupName
  The Resource Group name containing the Sentinel workspace.
.PARAMETER WorkspaceName
  The name of the Sentinel workspace.
.PARAMETER ShowTable
  When specified, output an easy-to-read summary table of connectors.
.PARAMETER ShowRaw
  Dumps the full result and connector payloads; may include sensitive metadata.
.PARAMETER SkipLoginPrompt
  Prevents interactive login prompts; the script throws if no Az context exists.
.OUTPUTS
  A custom object containing the list of data connectors and their details.
.NOTES
  Requires PowerShell 7.0+ and the Az.Accounts module with permissions to access the Azure Sentinel workspace.
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
  [Parameter(ValueFromPipelineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $SubscriptionId,
  [Parameter(ValueFromPipelineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $ResourceGroupName,
  [Parameter(ValueFromPipelineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $WorkspaceName,
  [switch] $ShowTable,
  [switch] $ShowRaw,
  [switch] $SkipLoginPrompt
)

# Use the latest known preview unless you have a hard requirement for GA
$DataConnectorApiVersion = '2025-09-01'
$DataConnectorDefinitionApiVersion = '2025-09-01'
$definitionCache = @{}
$script:DefinitionCacheHits = 0
$script:DefinitionFetches = 0
$operationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Helper: Build base URI safely ---------------------------------------------
$armRoot = 'https://management.azure.com'

function Test-IsInteractiveSession {
  if ($SkipLoginPrompt.IsPresent) {
    return $false
  }

  $automationHints = @(
    $env:AZUREPS_HOST_ENVIRONMENT,
    $env:TF_BUILD,
    $env:CI,
    $env:BUILD_BUILDID
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

  if ($automationHints.Count -gt 0) {
    return $false
  }

  $hostName = $Host.Name
  if ($hostName -in @('ConsoleHost', 'ServerRemoteHost', 'Visual Studio Code Host')) {
    return [System.Environment]::UserInteractive
  }

  return $false
}

function Resolve-RequiredParameter {
  param(
    [Parameter(Mandatory)] [string] $Name,
    [string] $CurrentValue,
    [string] $PromptMessage,
    [scriptblock] $Validator,
    [string] $ValidationError = 'Invalid value provided.',
    [switch] $MaskInput
  )

  if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
    $trimmed = $CurrentValue.Trim()
    if (-not $Validator -or (& $Validator $trimmed)) {
      return $trimmed
    }
    if (-not (Test-IsInteractiveSession)) {
      throw "Parameter '$Name' failed validation."
    }
  }

  if (Test-IsInteractiveSession) {
    while ($true) {
      $promptArgs = @{ Prompt = $PromptMessage }
      if ($MaskInput) {
        $promptArgs['MaskInput'] = $true
      }
      $CurrentValue = Read-Host @promptArgs
      $CurrentValue = if ($CurrentValue) {
        $CurrentValue.Trim() 
      } else {
        '' 
      }
      if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        continue
      }
      if ($Validator -and -not (& $Validator $CurrentValue)) {
        Write-Warning $ValidationError
        continue
      }
      return $CurrentValue
    }
  }

  throw "Parameter '$Name' is required when running non-interactively."
}

function Test-SubscriptionIdFormat {
  param(
    [string] $Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $false
  }

  $trimmed = $Value.Trim()
  $parsed = [Guid]::Empty
  return [Guid]::TryParse($trimmed, [ref]$parsed)
}

function Test-GenericName {
  param(
    [string] $Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $false
  }

  return $Value.Trim().Length -gt 0
}

$SubscriptionId = Resolve-RequiredParameter -Name 'SubscriptionId' -CurrentValue $SubscriptionId -PromptMessage 'Enter the Subscription ID' -Validator { param($value) Test-SubscriptionIdFormat -Value $value } -ValidationError 'Please enter a valid GUID-formatted Subscription ID.' -MaskInput
$ResourceGroupName = Resolve-RequiredParameter -Name 'ResourceGroupName' -CurrentValue $ResourceGroupName -PromptMessage 'Enter the Resource Group name' -Validator { param($value) Test-GenericName -Value $value } -ValidationError 'Resource Group name cannot be empty.'
$WorkspaceName = Resolve-RequiredParameter -Name 'WorkspaceName' -CurrentValue $WorkspaceName -PromptMessage 'Enter the Workspace name' -Validator { param($value) Test-GenericName -Value $value } -ValidationError 'Workspace name cannot be empty.'

function Use-AzContext {
  $context = Get-AzContext -ErrorAction SilentlyContinue
  if ($context) {
    return
  }

  $isInteractive = Test-IsInteractiveSession
  if ($isInteractive) {
    Write-Verbose 'No existing Az context detected. Prompting for login.'
    Connect-AzAccount -ErrorAction Stop | Out-Null
  } else {
    throw 'No existing Az context detected. Authenticate via Connect-AzAccount before running this script.'
  }
}

function Get-ConnectorUri {
  param(
    [string] $ConnectorName,
    [switch] $List
  )

  $encodedSub = [System.Uri]::EscapeDataString($SubscriptionId)
  $encodedRg = [System.Uri]::EscapeDataString($ResourceGroupName)
  $encodedWs = [System.Uri]::EscapeDataString($WorkspaceName)
  $encodedConnector = if ($ConnectorName) {
    '/' + [System.Uri]::EscapeDataString($ConnectorName) 
  } else {
    '' 
  }
  $path = "/subscriptions/$encodedSub/resourceGroups/$encodedRg/providers/Microsoft.OperationalInsights/workspaces/$encodedWs/providers/Microsoft.SecurityInsights/dataConnectors$encodedConnector"
  $builder = [System.UriBuilder]::new($armRoot)
  $builder.Path = $path.TrimStart('/')
  $builder.Query = "api-version=$DataConnectorApiVersion"
  return $builder.Uri.AbsoluteUri
}

function Get-ConnectorDefinitionUri {
  param(
    [Parameter(Mandatory)] [string] $DefinitionName
  )

  $encodedSub = [System.Uri]::EscapeDataString($SubscriptionId)
  $encodedRg = [System.Uri]::EscapeDataString($ResourceGroupName)
  $encodedWs = [System.Uri]::EscapeDataString($WorkspaceName)
  $encodedDefinition = [System.Uri]::EscapeDataString($DefinitionName)

  $path = "/subscriptions/$encodedSub/resourceGroups/$encodedRg/providers/Microsoft.OperationalInsights/workspaces/$encodedWs/providers/Microsoft.SecurityInsights/dataConnectorDefinitions/$encodedDefinition"
  $builder = [System.UriBuilder]::new($armRoot)
  $builder.Path = $path.TrimStart('/')
  $builder.Query = "api-version=$DataConnectorDefinitionApiVersion"
  return $builder.Uri.AbsoluteUri
}

function Get-ConnectorDefinition {
  param(
    [string] $DefinitionName
  )

  if ([string]::IsNullOrWhiteSpace($DefinitionName)) {
    return $null
  }

  $definitionToken = $DefinitionName
  if ($DefinitionName -like '*/dataConnectorDefinitions/*') {
    $definitionToken = ($DefinitionName -split '/')[-1]
  }

  if ($definitionCache.ContainsKey($definitionToken)) {
    $script:DefinitionCacheHits++
    return $definitionCache[$definitionToken]
  }

  $definitionUri = Get-ConnectorDefinitionUri -DefinitionName $definitionToken
  try {
    $payload = Invoke-AzSecurityInsightsRequest -Uri $definitionUri
    if ($payload) {
      $definitionCache[$definitionToken] = $payload
      $script:DefinitionFetches++
    }
    return $payload
  } catch {
    Write-Warning "Definition lookup failed for $definitionToken : $($_.Exception.Message)"
    return $null
  }
}

function Get-RetryAfterSecondsFromHeader {
  param(
    $Headers
  )

  if (-not $Headers) {
    return $null
  }

  $retryHeader = $null
  if ($Headers.PSObject.Properties['RetryAfter']) {
    $retryHeader = $Headers.RetryAfter
  } elseif ($Headers.PSObject.Properties['Retry-After']) {
    $retryHeader = $Headers.'Retry-After'
  }

  if (-not $retryHeader) {
    return $null
  }

  if ($retryHeader -is [TimeSpan]) {
    return [math]::Max(0, $retryHeader.TotalSeconds)
  }

  if ($retryHeader -is [DateTime]) {
    return [math]::Max(0, ($retryHeader - (Get-Date)).TotalSeconds)
  }

  if ($retryHeader.PSObject.Properties['Delta']) {
    $delta = $retryHeader.Delta
    if ($delta) {
      return [math]::Max(0, $delta.TotalSeconds)
    }
  }

  $retryString = $retryHeader.ToString()
  $numericSeconds = 0.0
  if ([double]::TryParse($retryString, [ref]$numericSeconds)) {
    return [math]::Max(0, $numericSeconds)
  }

  $retryDate = Get-Date
  if ([DateTime]::TryParse($retryString, [ref]$retryDate)) {
    return [math]::Max(0, ($retryDate - (Get-Date)).TotalSeconds)
  }

  return $null
}

function Get-RetryMetadataFromError {
  param(
    [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord
  )

  $statusCode = $null
  $retryAfterSeconds = $null

  $response = $null
  if ($ErrorRecord.Exception.PSObject.Properties['Response']) {
    $response = $ErrorRecord.Exception.Response
  } elseif ($ErrorRecord.Exception.PSObject.Properties['ResponseMessage']) {
    $response = $ErrorRecord.Exception.ResponseMessage
  }

  if ($response) {
    if ($response.StatusCode) {
      $statusCode = [int]$response.StatusCode
    } elseif ($response.PSObject.Properties['StatusCode']) {
      $statusCode = [int]$response.PSObject.Properties['StatusCode'].Value
    }
    $retryAfterSeconds = Get-RetryAfterSecondsFromHeader -Headers $response.Headers
  }

  if (-not $statusCode -and $ErrorRecord.Exception.PSObject.Properties['StatusCode']) {
    $statusCode = [int]$ErrorRecord.Exception.StatusCode
  }

  if (-not $retryAfterSeconds -and $ErrorRecord.Exception.PSObject.Properties['ResponseHeaders']) {
    $retryAfterSeconds = Get-RetryAfterSecondsFromHeader -Headers $ErrorRecord.Exception.ResponseHeaders
  }

  if (-not $statusCode) {
    $message = $ErrorRecord.Exception.Message
    if ($message -match 'StatusCode\s*:\s*(\d{3})') {
      $statusCode = [int]$matches[1]
    }
  }

  [pscustomobject]@{
    StatusCode        = $statusCode
    RetryAfterSeconds = $retryAfterSeconds
  }
}

function Get-RetryDelaySeconds {
  param(
    [Parameter(Mandatory)] [pscustomobject] $RetryMetadata,
    [Parameter(Mandatory)] [int] $Attempt,
    [int] $BaseDelaySeconds = 2,
    [int] $MaxDelaySeconds = 30
  )

  $hint = $RetryMetadata.RetryAfterSeconds
  if ($hint -and $hint -gt 0) {
    return [Math]::Min($MaxDelaySeconds, [int][Math]::Ceiling($hint))
  }

  $computed = $BaseDelaySeconds * [math]::Pow(2, [math]::Max(0, $Attempt - 1))
  return [Math]::Min($MaxDelaySeconds, [int][Math]::Ceiling($computed))
}

# Helper: Invoke Security Insights REST call with retries --------------------
function Invoke-AzSecurityInsightsRequest {
  param(
    [Parameter(Mandatory)] [string] $Uri,
    [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')] [string] $Method = 'GET',
    $Payload
  )

  $bodyParams = @{}
  if ($Payload) {
    $bodyParams['Payload'] = ($Payload | ConvertTo-Json -Depth 64)
  }

  $maxAttempts = 4
  $attempt = 0

  while ($attempt -lt $maxAttempts) {
    $attempt++
    try {
      $response = Invoke-AzRestMethod -Method $Method -Uri ([System.Uri]$Uri) -ErrorAction Stop @bodyParams

      if ($null -ne $response -and $response.Content) {
        try {
          return $response.Content | ConvertFrom-Json -Depth 64
        } catch {
          Write-Verbose 'Failed to parse response content as JSON. Returning raw content.'
          return $response.Content
        }
      }

      return $response
    } catch {
      $retryMetadata = Get-RetryMetadataFromError -ErrorRecord $_
      $statusCode = $retryMetadata.StatusCode
      $shouldRetry = $statusCode -and ($statusCode -eq 429 -or $statusCode -ge 500)

      if (-not $shouldRetry -or $attempt -ge $maxAttempts) {
        throw
      }

      $delaySeconds = Get-RetryDelaySeconds -RetryMetadata $retryMetadata -Attempt $attempt
      Write-Verbose (
        'Request {0} {1} failed with status {2}. Retrying in {3}s (attempt {4}/{5}).' -f 
        $Method,
        $Uri,
        $statusCode,
        $delaySeconds,
        $attempt,
        $maxAttempts
      )
      Start-Sleep -Seconds $delaySeconds
    }
  }
}

# Ensure we have an authenticated context before hitting ARM -----------------
Use-AzContext

# Build list endpoint and retrieve every connector
$listUri = Get-ConnectorUri -List
$pageNumber = 0
$allConnectorRecords = @()

# Follow nextLink until every connector page has been retrieved
while ($listUri) {
  $pageNumber++
  Write-Verbose ('Fetching connector page {0}' -f $pageNumber)
  $listResponse = Invoke-AzSecurityInsightsRequest -Uri $listUri
  if ($listResponse -and $listResponse.value) {
    $allConnectorRecords += $listResponse.value
    Write-Verbose ('Connector count after page {0}: {1}' -f $pageNumber, $allConnectorRecords.Count)
  }
  if ($listResponse -and $listResponse.nextLink) {
    $listUri = $listResponse.nextLink
  } else {
    $listUri = $null
  }
}

if (-not $allConnectorRecords) {
  Write-Warning 'No data connectors were returned by the Security Insights API.'
  return
}

$connectors = @()

foreach ($connector in $allConnectorRecords) {
  $connectorName = $connector.name
  $detailUri = Get-ConnectorUri -ConnectorName $connectorName
  $detail = $null
  try {
    $detail = Invoke-AzSecurityInsightsRequest -Uri $detailUri
  } catch {
    Write-Warning "Detail lookup failed for $($connectorName) : $($_.Exception.Message)"
  }
  $connectorProps = $connector.properties
  $detailProps = if ($detail) {
    $detail.properties 
  } else {
    $null 
  }

  $definitionName = $null
  if ($detailProps -and $detailProps.connectorDefinitionName) {
    $definitionName = $detailProps.connectorDefinitionName
  } elseif ($connectorProps -and $connectorProps.connectorDefinitionName) {
    $definitionName = $connectorProps.connectorDefinitionName
  }

  $definition = $null
  if ($definitionName) {
    $definition = Get-ConnectorDefinition -DefinitionName $definitionName
  }

  $definitionUi = if ($definition -and $definition.properties) {
    $definition.properties.connectorUiConfig 
  } else {
    $null 
  }
  $detailUi = if ($detailProps) {
    $detailProps.connectorUiConfig 
  } else {
    $null 
  }
  $uiConfig = if ($detailUi) {
    $detailUi 
  } elseif ($definitionUi) {
    $definitionUi 
  } else {
    $null 
  }

  $title = if ($uiConfig -and $uiConfig.title) {
    $uiConfig.title 
  } else {
    $connectorName 
  }
  $publisher = if ($uiConfig) {
    $uiConfig.publisher 
  } else {
    $null 
  }
  $description = if ($uiConfig) {
    $uiConfig.descriptionMarkdown 
  } else {
    $null 
  }
  $connectivityQueries = $null
  if ($uiConfig -and $uiConfig.connectivityCriteria) {
    $connectivityQueries = @()
    foreach ($criterion in $uiConfig.connectivityCriteria) {
      if ($criterion.type -eq 'IsConnectedQuery' -and $criterion.value) {
        $connectivityQueries += $criterion.value
      }
    }
  }

  $connectors += [pscustomobject]@{
    Name                = $connectorName
    Type                = $connector.type
    ConnectorKind       = if ($connector.kind) {
      $connector.kind 
    } elseif ($connectorProps) {
      $connectorProps.kind 
    } else {
      $null 
    }
    ResourceId          = $connector.id
    DefinitionName      = $definitionName
    Title               = $title
    Publisher           = $publisher
    DescriptionMarkdown = $description
    ConnectivityQueries = $connectivityQueries
    SampleQueries       = if ($uiConfig) {
      $uiConfig.sampleQueries 
    } else {
      $null 
    }
    DataTypes           = if ($uiConfig) {
      $uiConfig.dataTypes 
    } else {
      $null 
    }
    GraphQueries        = if ($uiConfig) {
      $uiConfig.graphQueries 
    } else {
      $null 
    }
    Detail              = $detail
    Definition          = $definition
    ConnectorUiConfig   = $uiConfig
  }
}

$result = [pscustomobject]@{
  SubscriptionId                 = $SubscriptionId
  ResourceGroup                  = $ResourceGroupName
  Workspace                      = $WorkspaceName
  DataConnectorApiVersion        = $DataConnectorApiVersion
  DataConnectorDefinitionVersion = $DataConnectorDefinitionApiVersion
  RetrievedUtc                   = (Get-Date).ToUniversalTime()
  ConnectorCount                 = $connectors.Count
  Connectors                     = $connectors
}

$operationStopwatch.Stop()

# Emit verbose metrics for troubleshooting latency or throttling
Write-Verbose (
  'Retrieved {0} connectors in {1:n2}s (definition cache hits: {2}, definition fetches: {3})' -f 
  $result.ConnectorCount,
  $operationStopwatch.Elapsed.TotalSeconds,
  $script:DefinitionCacheHits,
  $script:DefinitionFetches
)

$subscriptionSuffix = if ($SubscriptionId.Length -gt 4) {
  $SubscriptionId.Substring($SubscriptionId.Length - 4)
} else {
  $SubscriptionId
}

Write-Information -MessageData (
  'Connector inventory complete for workspace {0}/{1} (Subscription {2}) with {3} connector(s).' -f 
  $ResourceGroupName,
  $WorkspaceName,
  $subscriptionSuffix,
  $result.ConnectorCount
) -InformationAction Continue

# Pretty summary plus return full object in final output stream -------------
if ($ShowTable.IsPresent) {
  $connectors | Select-Object Name, ConnectorKind, Title, Publisher, DefinitionName | Format-Table -AutoSize
}

if ($ShowRaw.IsPresent) {
  Write-Warning 'ShowRaw output may include sensitive connector metadata. Ensure logs are protected.'
  $result | Format-List -Property * -Force
  $result.Connectors | Format-List -Property * -Force
}
$result

