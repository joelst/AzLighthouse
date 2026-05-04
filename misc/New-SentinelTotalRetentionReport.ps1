#requires -Version 7.0
<#
.SYNOPSIS
    Generates a retention report for all tables in one or more Microsoft Sentinel (Log Analytics) workspaces.
.DESCRIPTION
    Retrieves per-table retention settings (interactive, archive, and total retention) from Azure Monitor
    Log Analytics workspaces using Get-AzOperationalInsightsTable. Supports multiple workspaces,
    configurable output formats (console table, CSV, JSON), and both interactive and managed-identity
    authentication.

    This script is intended for ad-hoc compliance auditing of retention policies. It can also be
    scheduled in Azure Automation for periodic reporting.
.PARAMETER WorkspaceName
    One or more Log Analytics workspace names to report on.
.PARAMETER ResourceGroupName
    The resource group containing the workspace(s).
.PARAMETER SubscriptionId
    Azure subscription ID. If omitted, the current Az context subscription is used.
.PARAMETER TenantId
    Azure tenant ID. Required only when no existing Az context is available.
.PARAMETER UseManagedIdentity
    Authenticate using a managed identity (system-assigned or user-assigned).
.PARAMETER ManagedIdentityClientId
    Client ID for a user-assigned managed identity. Ignored if UseManagedIdentity is not set.
.PARAMETER OutputFormat
    Output format: Table (default, returns PSCustomObjects to pipeline), CSV, or JSON.
.PARAMETER OutputPath
    File path for CSV or JSON output. Required when OutputFormat is CSV or JSON.
.PARAMETER IncludeZeroRetention
    Include tables that report zero-day retention. These are typically system tables with
    retention managed by the platform.
.PARAMETER IncludeAllTables
    Include search result (_SRCH), restored log (_RST), and non-active tables in the output.
    By default these are filtered out to match the Azure Portal table list.
.PARAMETER CompareRetention
    Enable compliance comparison against expected retention defaults. Tables not ending in
    _SRCH that fall below the expected thresholds are flagged as non-compliant.
.PARAMETER ExpectedRetentionInDays
    Expected minimum interactive (hot) retention in days. Default: 90.
.PARAMETER ExpectedTotalRetentionInDays
    Expected minimum total retention in days (interactive + archive). Default: 365.
.EXAMPLE
    .\New-SentinelTotalRetentionReport.ps1 -WorkspaceName 'sentinel-ws-prod' -ResourceGroupName 'rg-sentinel'

    Retrieves retention data for all tables in the specified workspace and outputs to the console.
.EXAMPLE
    .\New-SentinelTotalRetentionReport.ps1 -WorkspaceName 'ws-prod','ws-dev' -ResourceGroupName 'rg-sentinel' -OutputFormat CSV -OutputPath 'C:\Reports\retention.csv'

    Reports on two workspaces and exports results to a CSV file.
.EXAMPLE
    .\New-SentinelTotalRetentionReport.ps1 -WorkspaceName 'sentinel-ws-prod' -ResourceGroupName 'rg-sentinel' -CompareRetention

    Flags tables (excluding _SRCH) below the default 90-day retention / 365-day total thresholds.
.EXAMPLE
    .\New-SentinelTotalRetentionReport.ps1 -WorkspaceName 'sentinel-ws-prod' -ResourceGroupName 'rg-sentinel' -CompareRetention -ExpectedRetentionInDays 30 -ExpectedTotalRetentionInDays 180

    Compares against custom thresholds of 30 days interactive and 180 days total retention.
.EXAMPLE
    .\New-SentinelTotalRetentionReport.ps1 -WorkspaceName 'sentinel-ws' -ResourceGroupName 'rg-sentinel' -UseManagedIdentity -ManagedIdentityClientId '00000000-0000-0000-0000-000000000000'

    Authenticates via a user-assigned managed identity and outputs retention data to the console.
.NOTES
    Requires Az.OperationalInsights and Az.Accounts modules.
    This script is a work in progress. Review and test in a safe environment before production use.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Log Analytics workspace name(s).')]
    [ValidateNotNullOrEmpty()]
    [string[]]$WorkspaceName,

    [Parameter(Mandatory = $true, HelpMessage = 'Resource group containing the workspace(s).')]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false, HelpMessage = 'Azure subscription ID.')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false, HelpMessage = 'Azure tenant ID.')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$UseManagedIdentity,

    [Parameter(Mandatory = $false, HelpMessage = 'Client ID for user-assigned managed identity.')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ManagedIdentityClientId,

    [Parameter(Mandatory = $false, HelpMessage = 'Output format: Table, CSV, or JSON.')]
    [ValidateSet('Table', 'CSV', 'JSON')]
    [string]$OutputFormat = 'Table',

    [Parameter(Mandatory = $false, HelpMessage = 'File path for CSV or JSON output.')]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeZeroRetention,

    [Parameter(Mandatory = $false, HelpMessage = 'Include _SRCH, _RST, and non-active tables.')]
    [switch]$IncludeAllTables,

    [Parameter(Mandatory = $false, HelpMessage = 'Compare tables against expected retention defaults.')]
    [switch]$CompareRetention,

    [Parameter(Mandatory = $false, HelpMessage = 'Expected minimum interactive retention in days.')]
    [ValidateRange(1, 3650)]
    [int]$ExpectedRetentionInDays = 90,

    [Parameter(Mandatory = $false, HelpMessage = 'Expected minimum total retention in days.')]
    [ValidateRange(1, 3650)]
    [int]$ExpectedTotalRetentionInDays = 365
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Connect-AzAccountIfNeeded {
    <#
    .SYNOPSIS
        Ensures an authenticated Az context is available.
    .DESCRIPTION
        Checks for an existing Az context. If none exists, connects via managed
        identity or interactive login depending on parameters.
    .PARAMETER TenantId
        Azure tenant ID for interactive auth.
    .PARAMETER SubscriptionId
        Azure subscription ID to set context to.
    .PARAMETER UseManagedIdentity
        Use managed identity authentication.
    .PARAMETER ManagedIdentityClientId
        Client ID for user-assigned managed identity.
    #>
    [CmdletBinding()]
    param (
        [string]$TenantId,
        [string]$SubscriptionId,
        [switch]$UseManagedIdentity,
        [string]$ManagedIdentityClientId
    )

    $existingContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($existingContext) {
        Write-Verbose "Using existing Az context: $($existingContext.Account.Id) on subscription $($existingContext.Subscription.Id)"

        # Switch subscription if a different one was requested
        if ($SubscriptionId -and $existingContext.Subscription.Id -ne $SubscriptionId) {
            Write-Verbose "Switching to subscription $SubscriptionId"
            $null = Set-AzContext -SubscriptionId $SubscriptionId
        }
        return
    }

    Write-Verbose 'No existing Az context found. Authenticating...'

    if ($UseManagedIdentity) {
        $connectParams = @{ Identity = $true }
        if ($ManagedIdentityClientId) {
            $connectParams['AccountId'] = $ManagedIdentityClientId
        }
        $null = Connect-AzAccount @connectParams
        Write-Verbose 'Authenticated via managed identity.'
    }
    else {
        $connectParams = @{}
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        if ($SubscriptionId) {
            $connectParams['Subscription'] = $SubscriptionId
        }
        $null = Connect-AzAccount @connectParams
        Write-Verbose 'Authenticated via interactive login.'
    }

    if ($SubscriptionId) {
        $null = Set-AzContext -SubscriptionId $SubscriptionId
    }
}

function Get-WorkspaceRetentionData {
    <#
    .SYNOPSIS
        Retrieves per-table retention data for a single Log Analytics workspace.
    .DESCRIPTION
        Uses Get-AzOperationalInsightsTable and filters via Schema properties to return
        only tables visible in the Azure Portal (Sentinel-connected, custom, and DCR-based).
    .PARAMETER WorkspaceName
        The workspace name.
    .PARAMETER ResourceGroupName
        The resource group containing the workspace.
    .PARAMETER IncludeZeroRetention
        Include tables with zero-day total retention.
    .PARAMETER IncludeAllTables
        Include all table definitions, not just portal-visible tables.
    .OUTPUTS
        Array of PSCustomObjects with retention properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [switch]$IncludeZeroRetention,

        [switch]$IncludeAllTables
    )

    Write-Verbose "Retrieving tables for workspace '$WorkspaceName' in resource group '$ResourceGroupName'..."

    # Get workspace default retention for comparison
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
    $workspaceDefaultRetention = if ($null -ne $workspace.RetentionInDays) { [int]$workspace.RetentionInDays } else { 90 }
    Write-Verbose "Workspace default retention: $workspaceDefaultRetention days."

    $tableParams = @{
        ResourceGroupName = $ResourceGroupName
        WorkspaceName     = $WorkspaceName
    }
    $allTables = Get-AzOperationalInsightsTable @tableParams

    if (-not $allTables) {
        Write-Warning "No tables returned for workspace '$WorkspaceName'."
        return @()
    }

    Write-Verbose "Retrieved $($allTables.Count) total table definitions for workspace '$WorkspaceName'."

    # Filter to match portal view using Schema properties
    if (-not $IncludeAllTables) {
        $preFilterCount = $allTables.Count
        $allTables = @($allTables | Where-Object {
            $schema = $_.Schema
            $schema.Solutions -contains 'SecurityInsights' -or
            $schema.Solutions -eq 'BehaviorAnalyticsInsights' -or
            $schema.TableType -eq 'CustomLog' -or
            $_.Name -eq 'Usage' -or
            $_.Name -eq 'Alert' -or
            $_.Name -eq 'AppCenterError' -or
            $_.Name -eq 'AADManagedIdentitySignInLogs' -or
            $_.Name -eq 'AADNonInteractiveUserSignInLogs' -or
            $_.Name -eq 'AADProvisioningLogs' -or
            $_.Name -eq 'AADRiskyUsers' -or
            $_.Name -eq 'AADServicePrincipalSignInLogs' -or
            $_.Name -eq 'AADUserRiskEvents' -or
            $_.Name -eq 'AuditLogs' -or
            $_.Name -eq 'SigninLogs' -or
            $_.Name -eq 'InsightsMetrics' -or
            $_.Name -eq 'ComputerGroup' -or
            ($schema.TableSubType -eq 'DataCollectionRuleBased' -and $schema.TableType -ne 'SearchResults')
        })
        Write-Verbose "Filtered $preFilterCount to $($allTables.Count) portal-visible tables."
    }

    $results = foreach ($table in $allTables) {
        $retentionInDays  = if ($null -ne $table.RetentionInDays) { [int]$table.RetentionInDays } else { 0 }
        $totalRetention   = if ($null -ne $table.TotalRetentionInDays) { [int]$table.TotalRetentionInDays } else { 0 }
        $archiveRetention = [Math]::Max(0, $totalRetention - $retentionInDays)
        $plan             = if ($null -ne $table.Plan) { [string]$table.Plan } else { 'Unknown' }

        # Determine retention source by comparing to workspace default
        # Per docs: RetentionInDays of -1 means "use workspace default"
        # The cmdlet resolves -1 to the actual value, so we compare to workspace default
        if ($retentionInDays -eq $workspaceDefaultRetention) {
            $retentionSource = 'Workspace Default'
        }
        else {
            $retentionSource = 'Table Override'
        }

        if (-not $IncludeZeroRetention -and $totalRetention -eq 0) {
            Write-Verbose "Skipping table '$($table.Name)' (zero total retention)."
            continue
        }

        [PSCustomObject]@{
            WorkspaceName          = $WorkspaceName
            TableName              = $table.Name
            RetentionInDays        = [int]$retentionInDays
            ArchiveRetentionInDays = [int]$archiveRetention
            TotalRetentionInDays   = [int]$totalRetention
            Plan                   = [string]$plan
            RetentionSource        = [string]$retentionSource
        }
    }

    return $results
}

function Compare-RetentionCompliance {
    <#
    .SYNOPSIS
        Adds compliance status to retention data by comparing against expected thresholds.
    .DESCRIPTION
        Evaluates each table against the expected interactive retention and total retention
        values. Tables whose names end in _SRCH (search result tables) are excluded from
        compliance checks and marked as 'Excluded'. All other tables are marked 'Compliant'
        or 'Non-Compliant' based on whether they meet the expected minimums.
    .PARAMETER Data
        Array of retention report objects from Get-WorkspaceRetentionData.
    .PARAMETER ExpectedRetentionInDays
        Minimum expected interactive (hot) retention in days.
    .PARAMETER ExpectedTotalRetentionInDays
        Minimum expected total retention in days (interactive + archive).
    .OUTPUTS
        Array of PSCustomObjects with added MeetsRetention and ComplianceDetail properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedRetentionInDays,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedTotalRetentionInDays
    )

    foreach ($row in $Data) {
        $tableName = $row.TableName

        # Search result tables (_SRCH suffix) are excluded from compliance checks
        if ($tableName -like '*_SRCH') {
            $row | Add-Member -NotePropertyName 'MeetsRetention' -NotePropertyValue 'Excluded' -Force
            $row | Add-Member -NotePropertyName 'ComplianceDetail' -NotePropertyValue 'Search result table — excluded from compliance check' -Force
            continue
        }

        $issues = [System.Collections.Generic.List[string]]::new()

        if ($row.RetentionInDays -lt $ExpectedRetentionInDays) {
            $issues.Add("RetentionInDays $($row.RetentionInDays) < expected $ExpectedRetentionInDays")
        }
        if ($row.TotalRetentionInDays -lt $ExpectedTotalRetentionInDays) {
            $issues.Add("TotalRetentionInDays $($row.TotalRetentionInDays) < expected $ExpectedTotalRetentionInDays")
        }

        if ($issues.Count -eq 0) {
            $row | Add-Member -NotePropertyName 'MeetsRetention' -NotePropertyValue 'Compliant' -Force
            $row | Add-Member -NotePropertyName 'ComplianceDetail' -NotePropertyValue '' -Force
        }
        else {
            $row | Add-Member -NotePropertyName 'MeetsRetention' -NotePropertyValue 'Non-Compliant' -Force
            $row | Add-Member -NotePropertyName 'ComplianceDetail' -NotePropertyValue ($issues -join '; ') -Force
        }
    }

    return $Data
}

function Export-RetentionReport {
    <#
    .SYNOPSIS
        Formats and outputs the retention report data.
    .PARAMETER Data
        Array of retention report objects.
    .PARAMETER OutputFormat
        Output format: Table, CSV, or JSON.
    .PARAMETER OutputPath
        File path for CSV or JSON output.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Table', 'CSV', 'JSON')]
        [string]$OutputFormat,

        [string]$OutputPath
    )

    if ($Data.Count -eq 0) {
        Write-Warning 'No retention data to export.'
        return
    }

    switch ($OutputFormat) {
        'Table' {
            $Data
        }
        'CSV' {
            if (-not $OutputPath) {
                Write-Error 'OutputPath is required when OutputFormat is CSV.' -ErrorAction Stop
            }
            $parentDir = Split-Path -Path $OutputPath -Parent
            if ($parentDir -and -not (Test-Path $parentDir)) {
                $null = New-Item -ItemType Directory -Path $parentDir -Force
            }
            $Data | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Verbose "CSV report written to '$OutputPath' ($($Data.Count) rows)."
        }
        'JSON' {
            if (-not $OutputPath) {
                Write-Error 'OutputPath is required when OutputFormat is JSON.' -ErrorAction Stop
            }
            $parentDir = Split-Path -Path $OutputPath -Parent
            if ($parentDir -and -not (Test-Path $parentDir)) {
                $null = New-Item -ItemType Directory -Path $parentDir -Force
            }
            $Data | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Force
            Write-Verbose "JSON report written to '$OutputPath' ($($Data.Count) rows)."
        }
    }
}

# ============================================================================
# MAIN LOGIC
# ============================================================================

# Skip main execution when dot-sourcing for tests
if ($env:RETENTION_REPORT_SKIP_MAIN -eq '1') {
    Write-Verbose 'RETENTION_REPORT_SKIP_MAIN=1 detected; skipping main execution.'
    return
}

# Validate OutputPath is provided for file-based formats
if ($OutputFormat -in @('CSV', 'JSON') -and -not $OutputPath) {
    Write-Error "OutputPath is required when OutputFormat is '$OutputFormat'." -ErrorAction Stop
}

# Authenticate
$authParams = @{
    UseManagedIdentity = $UseManagedIdentity
}
if ($TenantId) { $authParams['TenantId'] = $TenantId }
if ($SubscriptionId) { $authParams['SubscriptionId'] = $SubscriptionId }
if ($ManagedIdentityClientId) { $authParams['ManagedIdentityClientId'] = $ManagedIdentityClientId }

Connect-AzAccountIfNeeded @authParams

# Collect retention data across all workspaces
$allRetentionData = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($workspace in $WorkspaceName) {
    try {
        Write-Verbose "Processing workspace: $workspace"
        $retentionParams = @{
            WorkspaceName        = $workspace
            ResourceGroupName    = $ResourceGroupName
            IncludeZeroRetention = $IncludeZeroRetention
            IncludeAllTables     = $IncludeAllTables
        }
        $workspaceData = Get-WorkspaceRetentionData @retentionParams

        if ($workspaceData) {
            foreach ($item in $workspaceData) {
                $allRetentionData.Add($item)
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve retention data for workspace '$workspace': $_"
    }
}

# Apply compliance comparison if requested
if ($CompareRetention) {
    $complianceParams = @{
        Data                          = $allRetentionData.ToArray()
        ExpectedRetentionInDays       = $ExpectedRetentionInDays
        ExpectedTotalRetentionInDays  = $ExpectedTotalRetentionInDays
    }
    $allResults = Compare-RetentionCompliance @complianceParams

    # Sort: Non-Compliant first, then Excluded, then Compliant; alphabetical within each group
    $sortOrder = @{ 'Non-Compliant' = 0; 'Excluded' = 1; 'Compliant' = 2 }
    $allResults = $allResults | Sort-Object { $sortOrder[$_.MeetsRetention] }, TableName

    $nonCompliant = @($allResults | Where-Object { $_.MeetsRetention -eq 'Non-Compliant' })
    if ($nonCompliant.Count -gt 0) {
        Write-Warning "$($nonCompliant.Count) table(s) do not meet the expected retention policy (Retention: $ExpectedRetentionInDays days, Total: $ExpectedTotalRetentionInDays days)."
    }
    else {
        Write-Verbose 'All applicable tables meet the expected retention policy.'
    }
}
else {
    # Default: alphabetical by table name
    $allResults = $allRetentionData.ToArray() | Sort-Object TableName
}

# Output results
$exportParams = @{
    Data         = $allResults
    OutputFormat = $OutputFormat
}
if ($OutputPath) { $exportParams['OutputPath'] = $OutputPath }

Export-RetentionReport @exportParams