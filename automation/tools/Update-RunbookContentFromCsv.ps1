<#

DISCLAIMER: This script is provided "as-is" without warranty of any kind.

.SYNOPSIS
    Bulk-updates Azure Automation runbook content from a CSV.

.DESCRIPTION
  Reads a CSV containing SubscriptionId and ResourceGroupName (required), then invokes
  Update-RunbookContent.ps1 for each row to update runbook content from a local file.

  AutomationAccountName and RunbookName can be supplied either:
  - as columns in the CSV (per-row), or
  - as parameters to this script (defaults applied to all rows).

    By default, a single LocalFilePath is applied to all rows. Optionally, include a LocalFilePath
    column in the CSV to specify a per-runbook file.

  .PARAMETER CsvPath
    Path to the CSV file.

  .PARAMETER LocalFilePath
    Path to the local .ps1 file to upload as the runbook content (used for all rows unless the CSV
    provides a LocalFilePath column).

  .PARAMETER AutomationAccountName
    Optional default Automation Account name applied to all rows unless the CSV provides an
    AutomationAccountName column.

  .PARAMETER RunbookName
    Optional default runbook name applied to all rows unless the CSV provides a RunbookName column.

  .PARAMETER Publish
    If specified, publishes the runbook after updating.

  .PARAMETER RecreateAsPowerShell
    If specified, recreates an existing runbook as a classic PowerShell runbook when needed.

  .PARAMETER RunAfter
    If specified, starts each runbook after updating (see Update-RunbookContent.ps1 for behavior).

  .PARAMETER UpdateScriptPath
    Path to Update-RunbookContent.ps1. Defaults to the script in the same folder.

  .EXAMPLE
    # CSV headers: SubscriptionId,ResourceGroupName
    .\Update-RunbookContentFromCsv.ps1 -CsvPath .\targets.csv -AutomationAccountName 'MSSP-Automation' -RunbookName 'Get-DataConnectorStatus' \
      -LocalFilePath .\Get-DataConnectorStatus.ps1 -Publish -Verbose

  .EXAMPLE
    # Dry-run first (recommended)
    .\Update-RunbookContentFromCsv.ps1 -CsvPath .\targets.csv -LocalFilePath .\Get-DataConnectorStatus.ps1 -WhatIf

  .EXAMPLE
    # Per-row local files (CSV includes LocalFilePath column)
    .\Update-RunbookContentFromCsv.ps1 -CsvPath .\targets.csv -LocalFilePath .\default.ps1 -Verbose

  .NOTES
    - Requires Az modules indirectly (Update-RunbookContent.ps1 loads Az.Accounts and Az.Automation).
    - This script is a thin orchestrator; the heavy lifting is done by Update-RunbookContent.ps1.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$CsvPath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$LocalFilePath,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$AutomationAccountName,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$RunbookName,

  [Parameter()]
  [switch]$Publish,

  [Parameter()]
  [switch]$RecreateAsPowerShell,

  [Parameter()]
  [datetime]$RunAfter,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$UpdateScriptPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Update-RunbookContent.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-FileExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw ('{0} does not exist or is not a file: {1}' -f $Label, $Path)
  }
}

function Assert-RequiredColumns {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [object]$Row
  )

  foreach ($name in @('SubscriptionId', 'ResourceGroupName')) {
    if (-not ($Row.PSObject.Properties.Name -contains $name) -or [string]::IsNullOrWhiteSpace([string]$Row.$name)) {
      throw ("CSV row is missing required column '{0}' or it is empty." -f $name)
    }
  }
}

function Get-OptionalColumnValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][object]$Row,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ColumnName
  )

  if ($Row.PSObject.Properties.Name -contains $ColumnName) {
    $value = [string]$Row.$ColumnName
    if (-not [string]::IsNullOrWhiteSpace($value)) {
      return $value
    }
  }

  return $null
}

Assert-FileExists -Path $UpdateScriptPath -Label 'UpdateScriptPath'
Assert-FileExists -Path $CsvPath -Label 'CsvPath'

# LocalFilePath may be overridden per-row by a CSV column, but the param should still be valid.
Assert-FileExists -Path $LocalFilePath -Label 'LocalFilePath'

$targets = Import-Csv -LiteralPath $CsvPath -ErrorAction Stop
if (-not $targets -or $targets.Count -eq 0) {
  throw "CSV contains no rows: $CsvPath"
}

$results = New-Object System.Collections.Generic.List[object]

$index = 0
foreach ($row in $targets) {
  $index++
  Assert-RequiredColumns -Row $row

  $rowAutomationAccountName = Get-OptionalColumnValue -Row $row -ColumnName 'AutomationAccountName'
  if ([string]::IsNullOrWhiteSpace($rowAutomationAccountName)) {
    $rowAutomationAccountName = $AutomationAccountName
  }
  if ([string]::IsNullOrWhiteSpace($rowAutomationAccountName)) {
    throw "Row $index is missing AutomationAccountName (provide a CSV column or pass -AutomationAccountName)."
  }

  $rowRunbookName = Get-OptionalColumnValue -Row $row -ColumnName 'RunbookName'
  if ([string]::IsNullOrWhiteSpace($rowRunbookName)) {
    $rowRunbookName = $RunbookName
  }
  if ([string]::IsNullOrWhiteSpace($rowRunbookName)) {
    throw "Row $index is missing RunbookName (provide a CSV column or pass -RunbookName)."
  }

  $rowLocalFile = $LocalFilePath
  if ($row.PSObject.Properties.Name -contains 'LocalFilePath') {
    if (-not [string]::IsNullOrWhiteSpace([string]$row.LocalFilePath)) {
      $rowLocalFile = [string]$row.LocalFilePath
      Assert-FileExists -Path $rowLocalFile -Label "Row $index LocalFilePath"
    }
  }

  $desc = "Row ${index}: Subscription='$($row.SubscriptionId)' RG='$($row.ResourceGroupName)' AA='$rowAutomationAccountName' Runbook='$rowRunbookName'"
  if (-not $PSCmdlet.ShouldProcess($desc, "Update runbook content from '$rowLocalFile'")) {
    continue
  }

  try {
    $invokeParams = @{
      AutomationAccountName = [string]$rowAutomationAccountName
      SubscriptionId        = [string]$row.SubscriptionId
      ResourceGroupName     = [string]$row.ResourceGroupName
      RunbookName           = [string]$rowRunbookName
      LocalFilePath         = [string]$rowLocalFile
    }

    if ($Publish.IsPresent) { $invokeParams['Publish'] = $true }
    if ($RecreateAsPowerShell.IsPresent) { $invokeParams['RecreateAsPowerShell'] = $true }
    if ($PSBoundParameters.ContainsKey('RunAfter')) { $invokeParams['RunAfter'] = $RunAfter }

    # Forward common parameters (only when explicitly set).
    if ($VerbosePreference -ne 'SilentlyContinue') { $invokeParams['Verbose'] = $true }
    if ($WhatIfPreference) { $invokeParams['WhatIf'] = $true }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $invokeParams['Confirm'] = [bool]$PSBoundParameters['Confirm'] }

    $result = & $UpdateScriptPath @invokeParams
    $results.Add($result) | Out-Null
  }
  catch {
    $results.Add([pscustomobject]@{
        Row                   = $index
        SubscriptionId        = [string]$row.SubscriptionId
        ResourceGroupName     = [string]$row.ResourceGroupName
        AutomationAccountName = [string]$rowAutomationAccountName
        RunbookName           = [string]$rowRunbookName
        LocalFilePath         = [string]$rowLocalFile
        Succeeded             = $false
        Error                 = $_.Exception.Message
      }) | Out-Null

    Write-Error ('{0} failed: {1}' -f $desc, $_.Exception.Message)
  }
}

$results
