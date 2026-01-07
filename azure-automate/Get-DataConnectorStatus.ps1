#requires -Version 7.0
#requires -Modules Az.Accounts, Az.Resources, Az.Monitor, Az.SecurityInsights

<#

Disclaimer: This script is provided "as-is" without any warranties.

# Version: 2026.01.06.05

.SYNOPSIS
  Microsoft Sentinel Data Connectors management & health runbook.

.DESCRIPTION
  Enumerates Sentinel data connectors with enhanced metadata, optionally assigns the 'Microsoft Sentinel Reader' role to the runbook's
  User Assigned Managed Identity (UAMI), derives connector status & ingestion metrics (KQL).

    Enhanced Output Fields:
    - Standard ingestion metrics: LastLogTime, LogsLastHour, TotalLogs24h, QueryStatus, HoursSinceLastLog
    - Enhanced metadata from AllDataConnectorDefinitions.json: Id, Title, Publisher, ConnectivityCriteria
    - Status classification and diagnostic information

    Status priority:
    ActivelyIngesting   (last log <=1h)
    RecentlyActive      (last log <=24h)
    Stale               (logs exist but last >24h)
    ConfiguredButNoLogs (enabled/connected yet no logs observed)
    NoLogs              (not connected and no logs observed)
    NoKqlAndNoLogs      (no mapping available and no log evidence)
    Disabled
    Error
    Unknown

    Expected custom KQL columns: LastLogTime, LogsLastHour (else TimeGenerated is attempted; QueryStatus may be 'SuccessNoStandardColumns').
    Additional QueryStatus values: NoKql, MetricsUnavailable (query infra issue), QueryFailed (final failure).

  Enhanced connector mappings include hardcoded metadata (Id, Title, Publisher, ConnectivityCriteria) and custom KQL queries.

.PARAMETER SubscriptionId
     (Local execution only) Target subscription ID containing the Log Analytics workspace.

 .PARAMETER VerboseLogging
     Accepts boolean-like values (true/false, yes/no, 1/0). Enables DEBUG level log output when true.
 .PARAMETER WhatIf
     Prevents destructive/privileged changes (e.g., role assignment).
 .PARAMETER FailOnQueryErrors
     Accepts boolean-like values (true/false, yes/no, 1/0). When true, exits with code 2 if any connector KQL query fails after retries.
 .PARAMETER KindFilter
     One or more connector kinds to include (post-resolution). If supplied, only these kinds are processed.
 .PARAMETER NameFilter
     One or more connector names to include. Applied before kind filtering.
 .PARAMETER ExcludeStatus
     One or more final status values to exclude from emitted collection (e.g. Disabled,ConfiguredButNoLogs).
 .PARAMETER Parallel
     Accepts boolean-like values (true/false, yes/no, 1/0). When true, processes connectors concurrently using ForEach-Object -Parallel.
 .PARAMETER ThrottleLimit
     Maximum number of concurrent connector queries when -Parallel is used. Default 4.
.NOTES
  Managed identity requires Log Analytics Data Reader for KQL. MappingFound columns assist diagnostics.
  
  Logic App Posting (optional):
    Set -PostToLogicApp -LogicAppUri 'https://prod-00.../triggers/manual/paths/invoke?...sig=...'
    Payload shape (array of connector status objects). Use this sample schema in Logic App HTTP trigger:
        {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Name": { "type": "string" },
                    "Kind": { "type": "string" },
                    "Status": { "type": "string" },
                    "LastLogTime": { "type": ["string","null"], "format": "date-time" },
                    "LogsLastHour": { "type": "integer" },
                    "TotalLogs24h": { "type": "integer" },
                    "QueryStatus": { "type": "string" },
                    "HoursSinceLastLog": { "type": ["number","null"] },
                    "StatusDetails": { "type": "string" },
                    "Workspace": { "type": "string" },
                    "Subscription": { "type": "string" },
                    "Tenant": { "type": ["string","null"] },
                    "NoLastLog": { "type": ["boolean","null"] },
                    "Id": { "type": ["string","null"] },
                    "Title": { "type": ["string","null"] },
                    "Publisher": { "type": ["string","null"] },
                    "IsConnected": { "type": "boolean" }
                },
                "required": ["Name","Kind","Status","LogsLastHour","TotalLogs24h","QueryStatus","Workspace","Subscription"]
            }
        }
    The Logic App parses JSON then iterate over each item for downstream actions.
.NOTES
 Use at your own risk. No warranty or support is provided.

#>
# Requires Az.Accounts, Az.Resources, Az.Monitor, Az.SecurityInsights modules.
# Tested in Azure Automation with PowerShell 7.4 runtime.
# Can also be run locally by providing SubscriptionId, ResourceGroupName, and WorkspaceName parameters.
[CmdletBinding()]
param(
    [object] $VerboseLogging = 'false',
    [switch] $WhatIf,
    [Alias('FailOnQueryFailures')]
    [object] $FailOnQueryErrors = 'false',
    [string[]] $KindFilter,
    [string[]] $NameFilter,
    [string[]] $ExcludeStatus,
    [object] $Parallel = 'false',
    [int] $ThrottleLimit = 4,
    
    # Local execution parameters (override automation variables)
    [string] $SubscriptionId,
    [string] $ResourceGroupName,
    [string] $WorkspaceName,
    [string] $LogicAppUri,
    [switch] $AllowModuleInstall,
    [switch] $AllowCrossTenantScope
)

$script:SecurityInsightsDataConnectorApiVersion = '2025-09-01'
$script:SecurityInsightsDefinitionApiVersion   = '2025-09-01'
$script:DataConnectorDefinitionCache           = @{}
$script:IsArmScopeValidated                    = $false
$script:AllowModuleAutoInstall                 = $false

# This provides a way to collect all logs for a single run via the RunId correlation id.
# Correlation Run Id (32 hex chars) for this execution. Appended to all log lines.
$script:RunId = [guid]::NewGuid().ToString('N')
$TenantId = $null

if ($PSBoundParameters.ContainsKey('Verbose') -and -not $PSBoundParameters.ContainsKey('VerboseLogging')) {
    $VerboseLogging = 'true'
}
elseif (-not $PSBoundParameters.ContainsKey('VerboseLogging') -and $VerbosePreference -eq 'Continue') {
    $VerboseLogging = 'true'
}

if ($AllowModuleInstall.IsPresent) {
    $script:AllowModuleAutoInstall = $true
}

# Record run start timestamp (UTC) early for later duration computatio
if (-not $RunStartUtc) { $RunStartUtc = (Get-Date).ToUniversalTime() }

# Each entry includes: Id, Title, Publisher, ConnectivityCriteria, and Kql for 24h usage metrics
$ConnectorInfo = @(
    # Lookup order when resolving a mapping:
    #   1. Exact match on resolved Kind
    #   2. If no Kind match, exact match on connector Name (fallback)
    @{
        Id              = 'AbnormalSecurity'
        Title           = 'Abnormal Security '
        Publisher       = 'Abnormal Security'
        ConnectivityKql = @(
            'ABNORMAL_THREAT_MESSAGES_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'ABNORMAL_CASES_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union ABNORMAL_THREAT_MESSAGES_CL, ABNORMAL_CASES_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AwsS3'
        Title           = 'Amazon Web Services S3'
        Publisher       = 'Amazon'
        ConnectivityKql = 'AWSCloudTrail | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'AWSCloudTrail | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
@{
        Id              = 'AWS'
        Title           = 'Amazon Web Services'
        Publisher       = 'Amazon'
        ConnectivityKql = @(
            'AWSCloudTrail | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'AWSGuardDuty | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true AWSGuardDuty, AWSCloudTrail | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AmazonWebServicesS3'
        Title           = 'Amazon Web Services S3'
        Publisher       = 'Amazon'
        ConnectivityKql = @(
            'AWSCloudTrail | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'AWSGuardDuty | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true AWSGuardDuty, AWSCloudTrail | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AzureActiveDirectory'
        Title           = 'Microsoft Entra ID'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'SigninLogs | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'AuditLogs | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'AzureActiveDirectoryIdentityProtection'
        Title           = 'Microsoft Entra ID Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Azure Active Directory Identity Protection" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'

        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(7d) | where ProductName == "Azure Active Directory Identity Protection" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'AzureActivity'
        Title           = 'Azure Activity'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'AzureActivity | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'AzureActivity | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AzureAdvancedThreatProtection'
        Title           = 'Microsoft Defender for Identity'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Azure Advanced Threat Protection" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(7d) | where ProductName == "Azure Advanced Threat Protection" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'AzureSecurityCenter'
        Title           = 'Subscription-based Microsoft Defender for Cloud (Legacy)'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'SecurityAlert | where ProductName == "Azure Security Center" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
            #,
            #'SecurityRecommendation | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(7d) | where ProductName == "Azure Security Center" | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
        @{
        Id              = 'Barracuda'
        Title           = 'Barracuda'
        Publisher       = 'Barracuda'
        ConnectivityKql = @('CommonSecurityLog​ | where DeviceVendor == "Barracuda" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)')
        ActivityKql     = 'BarracudaEvents_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'BoxDataConnector'
        Title           = 'Box'
        Publisher       = 'Box'
        ConnectivityKql = @('BoxEvents_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)')
        ActivityKql     = 'BoxEvents_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'CEF'
        Title           = 'Common Event Format'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'CommonSecurityLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'CefAma'
        Title           = 'Common Event Format (AMA)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'CommonSecurityLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'CommonSecurityLog'
        Title           = 'Common Security Log'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'CommonSecurityLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'DDOS'
        Title           = 'Azure DDoS Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'AzureDiagnostics | where ResourceType == "PUBLICIPADDRESSES" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'AzureDiagnostics | where TimeGenerated >= ago(7d) | where ResourceType == "PUBLICIPADDRESSES" | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'DNS'
        Title           = 'DNS'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'DnsEvents | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'DnsEvents | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
        @{
        Id              = 'ESI-ExchangeAdminAuditLogEvents'
        Title           = '[Deprecated] Microsoft Exchange Logs and Events'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Event | where EventLog == "MSExchange Management" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Event | where TimeGenerated >= ago(7d) | where EventLog == "MSExchange Management" | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ESI-ExchangeOnlineCollector'
        Title           = '[Deprecated] Microsoft Exchange Online Collector'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ESIExchangeOnlineConfig_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ESIExchangeOnlineConfig_CL | where TimeGenerated >= ago(7d)  | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-ExchangeOnPremisesCollector'
        Title           = 'Exchange Security Insights On-Premises Collector'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ESIExchangeConfig_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ESIExchangeConfig_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-Opt1ExchangeAdminAuditLogsByEventLogs'
        Title           = 'Microsoft Exchange Admin Audit Logs by Event Logs'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Event | where EventLog == "MSExchange Management" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Event | where EventLog == "MSExchange Management" | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-Opt2ExchangeServersEventLogs'
        Title           = 'Microsoft Exchange Logs and Events'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Event | where EventLog == "Application" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Event | where EventLog == "Application" | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-Opt34DomainControllersSecurityEventLogs'
        Title           = 'Microsoft Active-Directory Domain Controllers Security Event Logs'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityEvent | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityEvent | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-Opt5ExchangeIISLogs'
        Title           = 'IIS Logs of Microsoft Exchange Servers'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'W3CIISLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'W3CIISLog | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-Opt6ExchangeMessageTrackingLogs'
        Title           = 'Microsoft Exchange Message Tracking Logs'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'MessageTrackingLog_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'MessageTrackingLog_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'ESI-Opt7ExchangeHTTPProxyLogs'
        Title           = 'Microsoft Exchange HTTP Proxy Logs'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ExchangeHttpProxy_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ExchangeHttpProxy_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'F5'
        Title           = '[Deprecated] F5 Networks via Legacy Agent'
        Publisher       = 'F5 Networks'
        ConnectivityKql = 'CommonSecurityLog | where DeviceVendor == "F5" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where DeviceVendor == "F5" | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'F5Ama'
        Title           = '[Deprecated] F5 Networks via AMA'
        Publisher       = 'F5 Networks'
        ConnectivityKql = 'CommonSecurityLog | where DeviceVendor =~ "F5" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where DeviceVendor =~ "F5" | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'GCPIAMDataConnector'
        Title           = 'Google Cloud Platform IAM'
        Publisher       = 'Google'
        ConnectivityKql = 'GCP_IAM_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'GCP_IAM_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'GoogleWorkspaceCCPDefinition'
        Title           = 'Google Workspace Activities (via Codeless Connector Framework)'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'GoogleWorkspaceActivities_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql = 'GoogleWorkspaceActivities_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'MicrosoftCloudAppSecurity'
        Title           = 'Microsoft Defender for Cloud Apps'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'McasShadowItReporting | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'McasShadowItReporting | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftDefenderAdvancedThreatProtection'
        Title           = 'Microsoft Defender for Endpoint'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'DeviceEvents | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'DeviceFileEvents | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftDefenderForCloudTenantBased'
        Title           = 'Microsoft Defender for Cloud (Tenant-based)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Azure Security Center" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where ProductName == "Azure Security Center" | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftDefenderThreatIntelligence'
        Title           = 'Microsoft Defender Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftPurviewInformationProtection'
        Title           = 'Microsoft Purview Information Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'MicrosoftPurviewInformationProtection | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'MicrosoftPurviewInformationProtection | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'MicrosoftThreatIntelligence'
        Title           = 'Microsoft Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftThreatProtection'
        Title           = 'Microsoft Defender XDR'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'union isfuzzy=true DeviceEvents, DeviceFileEvents, DeviceLogonEvents, DeviceInfo, EmailEvents, EmailUrlInfo, EmailAttachmentInfo, CloudAppEvents, IdentityLogonEvents, AlertEvidence| summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'  
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(7d) | where ProductName in("Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Microsoft Cloud App Security", "Microsoft 365 Defender", "Azure Active Directory Identity Protection") | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'Office365'
        Title           = 'Microsoft 365 (formerly, Office 365)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'OfficeActivity | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'OfficeActivity | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'OfficeATP'
        Title           = 'Office Advanced Threat Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProviderName == "OATP" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(7d) | where ProviderName == "OATP" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'OfficeIRM'
        Title           = 'Microsoft 365 Insider Risk Management'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Microsoft 365 Insider Risk Management" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(7d) | where ProductName == "Microsoft 365 Insider Risk Management" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'OktaSSO'
        Title           = 'Okta Single Sign-On'
        Publisher       = 'Okta'
        ConnectivityKql = 'OktaV2_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'OktaV2_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'PremiumMicrosoftDefenderForThreatIntelligence'
        Title           = 'Premium Microsoft Defender Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | where SourceSystem == "Premium Microsoft Defender Threat Intelligence" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
        @{
        Id              = 'SAP'
        Title           = 'SAP'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SAPConnectorOverview() | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SAPConnectorOverview() | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'SecurityEvents'
        Title           = 'Security Events'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityEvent | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityEvent | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'SentinelOne'
        Title           = 'SentinelOne'
        Publisher       = 'SentinelOne'
        ConnectivityKql = 'SentinelOne_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SentinelOne_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'SentinelOneCCP'
        Title           = 'SentinelOne'
        Publisher       = 'SentinelOne'
        ConnectivityKql = @('SentinelOneActivities_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)','SentinelOneAgents_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)','SentinelOneThreats_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)','SentinelOneGroups_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)','SentinelOneAlerts_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)')
        ActivityKql     = 'SentinelOne | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'SlackAuditLogsCCPDefinition'
        Title           = 'SlackAudit (via Codeless Connector Framework)'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'SlackAuditV2_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(30d)',
            'SlackAuditV2_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(30d)'
        )
        ActivityKql     = 'union isfuzzy=true SlackAuditV2_CL, SlackAuditV2_CL | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'Syslog'
        Title           = 'Syslog'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Syslog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Syslog | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'SyslogAma'
        Title           = 'Syslog (AMA)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Syslog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Syslog | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ThreatIntelligence'
        Title           = 'Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ThreatIntelligenceTaxii'
        Title           = 'Threat Intelligence TAXII'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ThreatIntelligenceUploadIndicatorsAPI'
        Title           = 'Threat Intelligence Upload Indicators API'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'WindowsFirewall'
        Title           = 'Windows Firewall'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'WindowsFirewall | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'WindowsFirewall | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'WindowsForwardedEvents'
        Title           = 'Windows Forwarded Events'
        Publisher       = 'Microsoft'
        ConnectivityKql = ''
        ActivityKql     = 'WindowsEvent | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'WindowsSecurityEvents'
        Title           = 'Windows Security Events via AMA'
        Publisher       = 'Microsoft'
        ConnectivityKql = ''
        ActivityKql     = 'SecurityEvent | where TimeGenerated >= ago(7d) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }
)

function Write-Log {
    <#
  .SYNOPSIS
  Writes a structured log line with timestamp and level.
  .DESCRIPTION
    Outputs a log entry formatted as [ISO8601][LEVEL] with optional correlation id. DEBUG messages are suppressed unless VerboseLogging is true. WARN levels emit via Write-Warning and ERROR via Write-Error so Azure Automation surfaces them clearly.
  .PARAMETER Level
  Log severity: INFO, WARN, ERROR, DEBUG.
  .PARAMETER Message
  Text to write.
  .PARAMETER CorrelationId
  Optional correlation identifier appended as 'corr=...'.
  .OUTPUTS
  System.String (written to pipeline)
  .EXAMPLE
  Write-Log -Level INFO -Message 'Starting run.'
  #>
    param(
        [Parameter(Mandatory)][ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$CorrelationId
    )
    if (-not $CorrelationId -and $script:RunId) { $CorrelationId = $script:RunId }
    $ts = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    $cid = if ($CorrelationId) { " corr=$CorrelationId" } else { '' }
    if ($Level -eq 'DEBUG' -and -not $VerboseLogging) { return }
    $formatted = "[$ts][$Level]$cid $Message"
    switch ($Level) {
        'ERROR' { Write-Error -Message $formatted -ErrorAction Continue }
        'WARN'  { Write-Warning $formatted }
        default { Write-Information $formatted }
    }
}

function Get-MaskedIdentifier {
    param(
        [string]$Value,
        [int]$VisibleCount = 4
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '<null>'
    }

    $trimmed = $Value.Trim()
    if ($trimmed.Length -le $VisibleCount) {
        return "****$trimmed"
    }

    $suffix = $trimmed.Substring($trimmed.Length - $VisibleCount)
    return "****$suffix"
}

function Get-UriHostForLog {
    param(
        [string]$UriString
    )

    if ([string]::IsNullOrWhiteSpace($UriString)) {
        return '<null>'
    }

    try {
        $uri = [Uri]$UriString
        if (-not $uri.Host) {
            return '<invalid-uri>'
        }
        return $uri.Host
    }
    catch {
        return '<invalid-uri>'
    }
}

function Confirm-SubscriptionScope {
    param(
        [string]$SubscriptionId,
        [string]$TenantId,
        [switch]$AllowCrossTenantScope
    )

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { return $false }
    try {
        $subscription = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop
    }
    catch {
        throw "Unable to read subscription '$SubscriptionId': $($_.Exception.Message)"
    }

    if (-not $AllowCrossTenantScope -and $TenantId -and $subscription.TenantId -and ($subscription.TenantId.ToString() -ne $TenantId)) {
        $maskedSubTenant = Get-MaskedIdentifier -Value $subscription.TenantId
        $maskedActiveTenant = Get-MaskedIdentifier -Value $TenantId
        throw "Subscription tenant ($maskedSubTenant) differs from active tenant ($maskedActiveTenant). Use -AllowCrossTenantScope to override."
    }
    return $true
}

function Confirm-WorkspaceScope {
    param(
        [string]$WorkspaceResourceId,
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName
    )

    if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId)) { return $false }
    $expected = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WorkspaceName"
    if ($WorkspaceResourceId.ToLowerInvariant() -ne $expected.ToLowerInvariant()) {
        Write-Log -Level WARN -Message "Workspace scope mismatch. Expected '$expected' but resolved '$WorkspaceResourceId'."
        return $false
    }
    return $true
}

function ConvertTo-NullableBool {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [int] -or $Value -is [long]) {
        if ($Value -eq 1) { return $true }
        if ($Value -eq 0) { return $false }
    }
    $text = $Value.ToString()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    switch ($text.Trim().ToLower()) {
        'true' { return $true }
        '1' { return $true }
        'yes' { return $true }
        'false' { return $false }
        '0' { return $false }
        'no' { return $false }
    }
    return $null
}

function Get-IsConnectedStateFromResult {
    param([object]$QueryResult)

    $state = [pscustomobject]@{
        Observed    = $false
        IsConnected = $false
    }
    if (-not $QueryResult) { return $state }

    if ($QueryResult.Tables -and $QueryResult.Tables.Count -gt 0) {
        foreach ($tableObj in $QueryResult.Tables) {
            $idxIsConnected = [Array]::IndexOf($tableObj.Columns.Name, 'IsConnected')
            if ($idxIsConnected -lt 0 -or $tableObj.Rows.Count -eq 0) { continue }
            foreach ($row in $tableObj.Rows) {
                $parsedValue = ConvertTo-NullableBool -Value $row[$idxIsConnected]
                if ($null -eq $parsedValue) { continue }
                $state.Observed = $true
                if ($parsedValue) {
                    $state.IsConnected = $true
                    return $state
                }
            }
        }
    }

    if ($QueryResult.Results -and $QueryResult.Results.Count -gt 0) {
        foreach ($record in $QueryResult.Results) {
            $candidate = $null
            if ($record.PSObject.Properties.Name -contains 'IsConnected') { $candidate = $record.IsConnected }
            elseif ($record -is [System.Collections.IDictionary] -and $record.Contains('IsConnected')) { $candidate = $record['IsConnected'] }
            if ($null -eq $candidate) { continue }
            $parsedValue = ConvertTo-NullableBool -Value $candidate
            if ($null -eq $parsedValue) { continue }
            $state.Observed = $true
            if ($parsedValue) {
                $state.IsConnected = $true
                return $state
            }
        }
    }

    return $state
}

function Get-HttpStatusCode {
    param([object]$Response)

    if (-not $Response) { return $null }
    $statusProperty = $Response.PSObject.Properties['StatusCode']
    if (-not $statusProperty) { return $null }
    $value = $statusProperty.Value
    if ($null -eq $value) { return $null }
    if ($value -is [int]) { return $value }
    if ($value -is [System.Net.HttpStatusCode]) { return [int]$value }
    $stringValue = $value.ToString()
    [int]$parsedValue = 0
    if ([int]::TryParse($stringValue, [ref]$parsedValue)) { return $parsedValue }
    return $stringValue
}

function Get-HttpHeaderValue {
    param(
        [object]$Response,
        [string]$HeaderName
    )

    if (-not $Response -or [string]::IsNullOrWhiteSpace($HeaderName)) {
        return $null
    }

    $headers = $null
    if ($Response.PSObject.Properties.Name -contains 'Headers') { $headers = $Response.Headers }
    elseif ($Response.PSObject.Properties.Name -contains 'headers') { $headers = $Response.headers }
    if (-not $headers) { return $null }

    if ($headers -is [System.Collections.IDictionary]) {
        foreach ($key in $headers.Keys) {
            if ([string]::Equals($key, $HeaderName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $value = $headers[$key]
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                    return ($value | Select-Object -First 1)
                }
                return $value
            }
        }
    }
    else {
        foreach ($prop in $headers.PSObject.Properties) {
            if ([string]::Equals($prop.Name, $HeaderName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $value = $prop.Value
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                    return ($value | Select-Object -First 1)
                }
                return $value
            }
        }
    }
    return $null
}

function Get-ExceptionHttpResponse {
    param([System.Exception]$Exception)

    $current = $Exception
    while ($current) {
        if ($current.PSObject.Properties.Name -contains 'Response' -and $current.Response) {
            return $current.Response
        }
        $current = $current.InnerException
    }
    return $null
}

function Get-ResponseBodySnippet {
    param(
        [object]$Response,
        [int]$MaxLength = 512
    )

    if (-not $Response) { return $null }
    $rawContent = $null
    if ($Response -is [string]) {
        $rawContent = $Response
    }
    elseif ($Response.PSObject.Properties.Name -contains 'Content') {
        $contentValue = $Response.Content
        if ($contentValue -is [string]) {
            $rawContent = $contentValue
        }
        elseif ($contentValue -is [System.Net.Http.HttpContent]) {
            try { $rawContent = $contentValue.ReadAsStringAsync().GetAwaiter().GetResult() }
            catch { $rawContent = $null }
        }
        elseif ($contentValue) {
            $rawContent = $contentValue.ToString()
        }
    }

    if ([string]::IsNullOrWhiteSpace($rawContent)) { return $null }
    $trimmed = $rawContent.Trim()
    if ($trimmed.Length -gt $MaxLength) {
        return $trimmed.Substring(0, $MaxLength) + '...'
    }
    return $trimmed
}

function Get-RestErrorDiagnostics {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    if (-not $ErrorRecord) { return $null }
    $response = Get-ExceptionHttpResponse -Exception $ErrorRecord.Exception
    if (-not $response) {
        return [pscustomobject]@{}
    }

    return [pscustomobject]@{
        StatusCode = Get-HttpStatusCode -Response $response
        ActivityId = Get-HttpHeaderValue -Response $response -HeaderName 'x-ms-activity-id'
        RequestId  = Get-HttpHeaderValue -Response $response -HeaderName 'x-ms-request-id'
        Body       = Get-ResponseBodySnippet -Response $response -MaxLength 512
    }
}

function Submit-LogicAppResult {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$LogicAppUri,
        [Parameter(Mandatory)][object]$Payload,
        [int]$ConnectorCount = 0
    )

    if ([string]::IsNullOrWhiteSpace($LogicAppUri)) {
        Write-Log -Level WARN -Message 'Logic App URI is empty; skipping submission.'
        return $false
    }

    try { $parsedUri = [Uri]$LogicAppUri }
    catch {
        Write-Log -Level ERROR -Message "Logic App URI is invalid: $($_.Exception.Message)"
        return $false
    }

    if ($parsedUri.Scheme -ne 'https') {
        Write-Log -Level ERROR -Message 'Logic App URI must use HTTPS. Submission aborted.'
        return $false
    }

    $logicAppHost = $parsedUri.Host
    if (-not $ConnectorCount -and ($Payload -is [System.Collections.ICollection])) {
        $ConnectorCount = $Payload.Count
    }
    if (-not $ConnectorCount -and ($Payload -is [array])) {
        $ConnectorCount = $Payload.Length
    }

    $actionDescription = "POST $ConnectorCount record(s)"
    $actionTarget = "Logic App host '$logicAppHost'"
    if (-not $PSCmdlet.ShouldProcess($actionTarget, $actionDescription)) {
        Write-Log -Level INFO -Message "WhatIf: Would $actionDescription to $actionTarget."
        return $true
    }

    $payloadJson = $Payload
    if ($Payload -isnot [string]) {
        $payloadJson = $Payload | ConvertTo-Json -Depth 6
    }

    try {
        Write-Log -Level INFO -Message "Posting $ConnectorCount record(s) to Logic App host '$logicAppHost'."
        Invoke-RestMethod -Method Post -Uri $parsedUri.AbsoluteUri -Body $payloadJson -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Log -Level INFO -Message 'Logic App post succeeded.'
        return $true
    }
    catch {
        $diag = Get-RestErrorDiagnostics -ErrorRecord $_
        $statusLabel = if ($diag.StatusCode) { $diag.StatusCode } else { 'unknown' }
        $activityLabel = if ($diag.ActivityId) { $diag.ActivityId }
        elseif ($diag.RequestId) { $diag.RequestId } else { 'n/a' }
        $errorSummary = "Logic App post failed (host='{0}') status={1} activityId={2}: {3}" -f $logicAppHost, $statusLabel, $activityLabel, $_.Exception.Message
        Write-Log -Level ERROR -Message $errorSummary
        if ($diag.Body) {
            Write-Log -Level DEBUG -Message "Logic App diagnostics snippet: $($diag.Body)"
        }
        return $false
    }
}

function Resolve-BoolInput {
    <#
  .SYNOPSIS
  Converts flexible inputs (string, numeric, switch) to a boolean value.
  .DESCRIPTION
  Allows Azure Automation string parameters ("true", "1", "yes") to map to boolean flags. Throws when input cannot be parsed.
  .PARAMETER Value
  The incoming value to convert.
  .PARAMETER Default
  Boolean fallback when Value is null/empty.
  .PARAMETER ParameterName
  Name of the parameter being converted (for error messaging).
  #>
    param(
        [Parameter()][AllowNull()][object]$Value,
        [bool]$Default = $false,
        [string]$ParameterName = 'Parameter'
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    if ($Value -is [System.Management.Automation.SwitchParameter]) {
        return [bool]$Value
    }

    if ($Value -is [int] -or $Value -is [long]) {
        return ($Value -ne 0)
    }

    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $Default
        }
        switch ($text.ToLower()) {
            'true' { return $true }
            'false' { return $false }
            '1' { return $true }
            '0' { return $false }
            'yes' { return $true }
            'no' { return $false }
            'on' { return $true }
            'off' { return $false }
        }
        throw "Unable to parse '$Value' for $ParameterName. Use true/false, yes/no, on/off, or 1/0."
    }

    throw "Unsupported value '$Value' for $ParameterName. Provide a boolean, number, switch, or string (true/false)."
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
    Simple exponential backoff retry helper (for transient KQL failures, etc.)
    .DESCRIPTION
    Executes the provided script block, retrying on failure with exponential backoff delays.
    .PARAMETER ScriptBlock
    The script block to execute.
    .PARAMETER OperationName
    Friendly name of the operation for logging purposes. Default 'Operation'.
    .PARAMETER MaxAttempts
    Maximum number of attempts. Default 3.
    .PARAMETER InitialDelaySeconds
    Initial delay in seconds before first retry. Default 2.
    .OUTPUTS
    The result of the script block if successful.
    .EXAMPLE
    Invoke-WithRetry -ScriptBlock { Get-SomeResource } -OperationName 'Get Resource' -MaxAttempts 5 -InitialDelaySeconds 3
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [string]$OperationName = 'Operation',
        [int]$MaxAttempts = 3,
        [int]$InitialDelaySeconds = 2
    )
    $attempt = 0
    $delay = $InitialDelaySeconds
    $lastError = $null
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            if ($attempt -gt 1) { Write-Log -Level WARN -Message "$OperationName retry attempt $attempt of $MaxAttempts (delay=$delay s)" }
            return & $ScriptBlock
        }
        catch {
            $lastError = $_
            Write-Log -Level WARN -Message "$OperationName failed attempt $($attempt): $($_.Exception.Message)"
            if ($attempt -ge $MaxAttempts) { break }
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 30)
        }
    }
    if ($lastError) {
        Write-Log -Level ERROR -Message "${OperationName} failed after $MaxAttempts attempts: $($lastError.Exception.Message)"
        throw $lastError
    }
}

function Get-ConnectorLookupKeys {
    <#
      .SYNOPSIS
      Produces case-insensitive lookup keys for a connector object.
      .DESCRIPTION
      Generates keys based on Id and Name so we can detect duplicates between
      cmdlet and REST responses even when one of the fields is missing.
      .PARAMETER Connector
      Connector object from either Get-AzSentinelDataConnector or the REST API.
      .OUTPUTS
      String array containing zero or more key tokens.
    #>
    param([Parameter(Mandatory)][object]$Connector)

    $keys = @()
    $idValue = $null
    if ($Connector.PSObject.Properties.Name -contains 'Id') { $idValue = $Connector.Id }
    elseif ($Connector.PSObject.Properties.Name -contains 'id') { $idValue = $Connector.id }
    if ($idValue) {
        try {
            $idString = [string]$idValue
            if (-not [string]::IsNullOrWhiteSpace($idString)) {
                $normalizedId = $idString.ToLowerInvariant()
                $keys += "id::$normalizedId"
            }
        }
        catch {}
    }
    $nameValue = $null
    if ($Connector.PSObject.Properties.Name -contains 'Name') { $nameValue = $Connector.Name }
    elseif ($Connector.PSObject.Properties.Name -contains 'name') { $nameValue = $Connector.name }
    if ($nameValue) {
        try {
            $nameString = [string]$nameValue
            if (-not [string]::IsNullOrWhiteSpace($nameString)) {
                $normalizedName = $nameString.ToLowerInvariant()
                $keys += "name::$normalizedName"
            }
        }
        catch {}
    }
    return $keys | Where-Object { $_ }
}

function New-DataConnectorApiUri {
    <#
      .SYNOPSIS
      Builds a properly encoded Azure Resource Manager URI for Sentinel data connectors.
      .DESCRIPTION
      Uses System.UriBuilder to ensure workspace, resource group, and connector ids are safely encoded.
      .PARAMETER SubscriptionId
      Azure subscription id hosting the workspace.
      .PARAMETER ResourceGroupName
      Resource group containing the Log Analytics workspace.
      .PARAMETER WorkspaceName
      Name of the Log Analytics workspace.
      .PARAMETER ConnectorId
      Optional connector id for detail calls; omit for list calls.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [string]$ConnectorId
    )

    $segments = @(
        'subscriptions', $SubscriptionId,
        'resourceGroups', $ResourceGroupName,
        'providers', 'Microsoft.OperationalInsights',
        'workspaces', $WorkspaceName,
        'providers', 'Microsoft.SecurityInsights',
        'dataConnectors'
    )
    if ($ConnectorId) { $segments += $ConnectorId }

    $encodedSegments = $segments | ForEach-Object { [System.Uri]::EscapeDataString([string]$_) }
    $builder = [System.UriBuilder]'https://management.azure.com/'
    $builder.Path = ($encodedSegments -join '/')
    $builder.Query = "api-version=$script:SecurityInsightsDataConnectorApiVersion"
    return $builder.Uri.AbsoluteUri
}

function New-DataConnectorDefinitionApiUri {
    <#
      .SYNOPSIS
      Builds the ARM URI for Sentinel data connector definitions.
      .DESCRIPTION
      Mirrors New-DataConnectorApiUri but targets the dataConnectorDefinitions collection so we can hydrate metadata.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [string]$DefinitionName
    )

    $segments = @(
        'subscriptions', $SubscriptionId,
        'resourceGroups', $ResourceGroupName,
        'providers', 'Microsoft.OperationalInsights',
        'workspaces', $WorkspaceName,
        'providers', 'Microsoft.SecurityInsights',
        'dataConnectorDefinitions'
    )
    if ($DefinitionName) { $segments += $DefinitionName }

    $encodedSegments = $segments | ForEach-Object { [System.Uri]::EscapeDataString([string]$_) }
    $builder = [System.UriBuilder]'https://management.azure.com/'
    $builder.Path = ($encodedSegments -join '/')
    $builder.Query = "api-version=$script:SecurityInsightsDefinitionApiVersion"
    return $builder.Uri.AbsoluteUri
}

function Get-RestDataConnectors {
    <#
      .SYNOPSIS
      Retrieves Sentinel data connectors via the ARM REST API.
      .DESCRIPTION
      Enumerates all connectors for the specified workspace, following nextLink pagination.
      .PARAMETER SubscriptionId
      Azure subscription id hosting the workspace.
      .PARAMETER ResourceGroupName
      Resource group containing the workspace.
      .PARAMETER WorkspaceName
      Name of the Log Analytics workspace.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName
    )

    if ([string]::IsNullOrWhiteSpace($SubscriptionId) -or [string]::IsNullOrWhiteSpace($ResourceGroupName) -or [string]::IsNullOrWhiteSpace($WorkspaceName)) {
        Write-Log -Level WARN -Message 'Get-RestDataConnectors: Missing SubscriptionId/ResourceGroupName/WorkspaceName; skipping REST fallback.'
        return @()
    }

    if (-not $script:IsArmScopeValidated) {
        Write-Log -Level WARN -Message 'Get-RestDataConnectors: ARM scope not validated; skipping REST fallback.'
        return @()
    }

    $uri = New-DataConnectorApiUri -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
    $results = @()
    $page = 1

    while ($uri) {
        $pageUri = $uri
        $pageHost = Get-UriHostForLog -UriString $pageUri
        Write-Log -Level DEBUG -Message "Calling REST data connectors API (Page $page) Host='$pageHost'"
        $callTimer = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $response = Invoke-WithRetry -OperationName "REST-DataConnectors-Page$page" -MaxAttempts 3 -InitialDelaySeconds 2 -ScriptBlock {
                Invoke-AzRestMethod -Method Get -Uri $pageUri -ErrorAction Stop
            }
            $callTimer.Stop()
            $statusCode = Get-HttpStatusCode -Response $response
            $activityId = Get-HttpHeaderValue -Response $response -HeaderName 'x-ms-activity-id'
            if (-not $activityId) { $activityId = Get-HttpHeaderValue -Response $response -HeaderName 'x-ms-request-id' }
            $statusLabel = if ($statusCode) { $statusCode } else { 'unknown' }
            $activityLabel = if ($activityId) { $activityId } else { 'n/a' }
            Write-Log -Level DEBUG -Message "REST data connectors page $page completed with status=$statusLabel activityId=$activityLabel duration=$($callTimer.ElapsedMilliseconds)ms"
        }
        catch {
            $errMsg = $_.Exception.Message
            $callTimer.Stop()
            $diag = Get-RestErrorDiagnostics -ErrorRecord $_
            $statusLabel = if ($diag.StatusCode) { $diag.StatusCode } else { 'unknown' }
            $activityLabel = if ($diag.ActivityId) { $diag.ActivityId }
            elseif ($diag.RequestId) { $diag.RequestId } else { 'n/a' }
            Write-Log -Level WARN -Message "Get-RestDataConnectors: REST call failed on page $page (host='$pageHost') status=$statusLabel activityId=$activityLabel duration=$($callTimer.ElapsedMilliseconds)ms: $errMsg"
            if ($diag.Body) {
                Write-Log -Level DEBUG -Message "Get-RestDataConnectors diagnostics snippet: $($diag.Body)"
            }
            if ($errMsg -match '401' -or $errMsg -match 'Unauthorized') {
                Write-Log -Level WARN -Message 'REST fallback is unauthorized. Ensure the managed identity or account has Microsoft Sentinel Reader (or higher) on the workspace.'
            }
            break
        }

        $payload = $response
        if ($response -and ($response.PSObject.Properties.Name -contains 'Content')) {
            $content = $response.Content
            if ($content) {
                try {
                    $payload = $content | ConvertFrom-Json -Depth 32
                }
                catch {
                    Write-Log -Level WARN -Message "Get-RestDataConnectors: Failed to parse response content on page ${page}. Error: $($_.Exception.Message)"
                    $payload = $null
                }
            }
            else {
                $payload = $null
            }
        }

        if ($payload -and $payload.value) {
            $results += $payload.value
        }

        if ($payload -and $payload.nextLink) {
            $uri = $payload.nextLink
            $page++
        }
        else {
            $uri = $null
        }
    }

    Write-Log -Level INFO -Message "Get-RestDataConnectors: Retrieved $($results.Count) connector(s) via REST."
    return $results
}

function Get-RestDataConnectorDefinition {
    <#
      .SYNOPSIS
      Retrieves a specific data connector definition to enrich connector metadata.
      .DESCRIPTION
      Caches results per workspace to avoid redundant REST calls when multiple connectors share the same definition.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [Parameter(Mandatory)][string]$DefinitionName
    )

    if ([string]::IsNullOrWhiteSpace($DefinitionName)) {
        return $null
    }

    if (-not $script:IsArmScopeValidated) {
        Write-Log -Level WARN -Message 'Get-RestDataConnectorDefinition: ARM scope not validated; skipping.'
        return $null
    }

    if (-not $script:DataConnectorDefinitionCache) {
        $script:DataConnectorDefinitionCache = @{}
    }

    $definitionToken = $DefinitionName
    if ($DefinitionName -like '*/dataConnectorDefinitions/*') {
        $definitionToken = ($DefinitionName -split '/')[-1]
    }

    $cacheKey = "${SubscriptionId}/${ResourceGroupName}/${WorkspaceName}/${definitionToken}"
    if ($script:DataConnectorDefinitionCache.ContainsKey($cacheKey)) {
        return $script:DataConnectorDefinitionCache[$cacheKey]
    }

    $definitionUri = New-DataConnectorDefinitionApiUri -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DefinitionName $definitionToken
    try {
        $response = Invoke-AzRestMethod -Method Get -Uri $definitionUri -ErrorAction Stop
    }
    catch {
        Write-Log -Level WARN -Message "Get-RestDataConnectorDefinition: Failed for '$definitionToken': $($_.Exception.Message)"
        return $null
    }

    $payload = $response
    if ($response -and ($response.PSObject.Properties.Name -contains 'Content')) {
        $content = $response.Content
        if ($content) {
            try { $payload = $content | ConvertFrom-Json -Depth 64 }
            catch {
                Write-Log -Level WARN -Message "Get-RestDataConnectorDefinition: Unable to parse JSON for '$definitionToken': $($_.Exception.Message)"
                $payload = $null
            }
        }
        else {
            $payload = $null
        }
    }

    if ($payload) {
        $script:DataConnectorDefinitionCache[$cacheKey] = $payload
    }
    return $payload
}

function Get-RestDataConnectorDetail {
    <#
      .SYNOPSIS
      Retrieves a single data connector via REST for richer metadata.
      .DESCRIPTION
      Used to hydrate REST-only connectors so downstream logic has Properties, UI config, etc.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [Parameter(Mandatory)][string]$ConnectorName
    )

    if (-not $script:IsArmScopeValidated) {
        Write-Log -Level WARN -Message 'Get-RestDataConnectorDetail: ARM scope not validated; skipping.'
        return $null
    }

    $detailUri = New-DataConnectorApiUri -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ConnectorId $ConnectorName
    try {
        $response = Invoke-AzRestMethod -Method Get -Uri $detailUri -ErrorAction Stop
    }
    catch {
        Write-Log -Level WARN -Message "Get-RestDataConnectorDetail: Failed for '$ConnectorName': $($_.Exception.Message)"
        return $null
    }

    $payload = $response
    if ($response -and ($response.PSObject.Properties.Name -contains 'Content')) {
        $content = $response.Content
        if ($content) {
            try { $payload = $content | ConvertFrom-Json -Depth 32 }
            catch {
                Write-Log -Level WARN -Message "Get-RestDataConnectorDetail: Unable to parse detail JSON for '$ConnectorName': $($_.Exception.Message)"
                $payload = $null
            }
        }
        else {
            $payload = $null
        }
    }
    return $payload
}

function ConvertTo-ConnectorObject {
    <#
      .SYNOPSIS
      Aligns REST payload field names with cmdlet output expectations.
      .DESCRIPTION
      Ensures downstream logic can access Name/Id/Kind/Properties/ConnectorUiConfig* regardless of source casing.
    #>
    param(
        [Parameter(Mandatory)][object]$Connector,
        [string]$SourceTag
    )

    $copy = $Connector.PSObject.Copy()
    $propertyMap = @{
        Name = 'name'
        Id   = 'id'
        Type = 'type'
        Kind = 'kind'
        Etag = 'etag'
    }
    foreach ($pair in $propertyMap.GetEnumerator()) {
        if (-not ($copy.PSObject.Properties.Name -contains $pair.Key)) {
            if ($Connector.PSObject.Properties.Name -contains $pair.Value) {
                Add-Member -InputObject $copy -NotePropertyName $pair.Key -NotePropertyValue $Connector.($pair.Value) -Force
            }
        }
    }
    if (-not ($copy.PSObject.Properties.Name -contains 'Properties')) {
        if ($Connector.PSObject.Properties.Name -contains 'properties') {
            Add-Member -InputObject $copy -NotePropertyName 'Properties' -NotePropertyValue $Connector.properties -Force
        }
    }

    $props = $null
    if ($copy.PSObject.Properties.Name -contains 'Properties') { $props = $copy.Properties }
    if (-not $copy.Kind -and $props -and $props.PSObject.Properties.Name -contains 'kind') {
        Add-Member -InputObject $copy -NotePropertyName 'Kind' -NotePropertyValue $props.kind -Force
    }
    if ($props -and $props.PSObject.Properties.Name -contains 'connectorUiConfig') {
        $ui = $props.connectorUiConfig
        if ($ui) {
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigTitle') -and $ui.PSObject.Properties.Name -contains 'title') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigTitle' -NotePropertyValue $ui.title -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigPublisher') -and $ui.PSObject.Properties.Name -contains 'publisher') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigPublisher' -NotePropertyValue $ui.publisher -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigConnectivityCriterion') -and $ui.PSObject.Properties.Name -contains 'connectivityCriteria') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigConnectivityCriterion' -NotePropertyValue $ui.connectivityCriteria -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigActivityCriterion') -and $ui.PSObject.Properties.Name -contains 'activityCriteria') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigActivityCriterion' -NotePropertyValue $ui.activityCriteria -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigDescriptionMarkdown') -and $ui.PSObject.Properties.Name -contains 'descriptionMarkdown') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigDescriptionMarkdown' -NotePropertyValue $ui.descriptionMarkdown -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigGraphQueries') -and $ui.PSObject.Properties.Name -contains 'graphQueries') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigGraphQueries' -NotePropertyValue $ui.graphQueries -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigDataTypes') -and $ui.PSObject.Properties.Name -contains 'dataTypes') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigDataTypes' -NotePropertyValue $ui.dataTypes -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigPermissions') -and $ui.PSObject.Properties.Name -contains 'permissions') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigPermissions' -NotePropertyValue $ui.permissions -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigAvailability') -and $ui.PSObject.Properties.Name -contains 'availability') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigAvailability' -NotePropertyValue $ui.availability -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigLogo') -and $ui.PSObject.Properties.Name -contains 'logo') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigLogo' -NotePropertyValue $ui.logo -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigInstructionSteps') -and $ui.PSObject.Properties.Name -contains 'instructionSteps') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigInstructionSteps' -NotePropertyValue $ui.instructionSteps -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigSampleQueries') -and $ui.PSObject.Properties.Name -contains 'sampleQueries') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigSampleQueries' -NotePropertyValue $ui.sampleQueries -Force
            }
            if (-not ($copy.PSObject.Properties.Name -contains 'ConnectorUiConfigIsConnectivityMatchSome') -and $ui.PSObject.Properties.Name -contains 'isConnectivityCriteriasMatchSome') {
                Add-Member -InputObject $copy -NotePropertyName 'ConnectorUiConfigIsConnectivityMatchSome' -NotePropertyValue $ui.isConnectivityCriteriasMatchSome -Force
            }
        }
    }

    if ($props -and $props.PSObject.Properties.Name -contains 'connectorDefinitionDetail') {
        Add-Member -InputObject $copy -NotePropertyName 'ConnectorDefinitionDetail' -NotePropertyValue $props.connectorDefinitionDetail -Force
    }
    if ($props -and $props.PSObject.Properties.Name -contains 'connectorDefinitionName') {
        Add-Member -InputObject $copy -NotePropertyName 'ConnectorDefinitionName' -NotePropertyValue $props.connectorDefinitionName -Force
    }

    if ($SourceTag) {
        Add-Member -InputObject $copy -NotePropertyName 'Source' -NotePropertyValue $SourceTag -Force
    }
    return $copy
}

function Convert-RestConnectorRecord {
    <#
      .SYNOPSIS
      Converts a REST list payload (optionally hydrated with detail) into the expected connector shape.
    #>
    param(
        [Parameter(Mandatory)][object]$ListRecord,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName
    )

    $payload = $ListRecord
    $needsDetail = $true
    if ($payload) {
        if ($payload.PSObject.Properties.Name -contains 'properties' -and $payload.properties) {
            $needsDetail = $false
            $ui = $payload.properties.connectorUiConfig
            if (-not $ui) { $needsDetail = $true }
        }
    }

    if ($needsDetail) {
        $connectorName = if ($payload -and $payload.name) { $payload.name } elseif ($payload -and $payload.id) { ($payload.id -split '/')[-1] } else { $null }
        if ($connectorName) {
            $detail = Get-RestDataConnectorDetail -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ConnectorName $connectorName
            if ($detail) {
                $payload = $detail
            }
        }
    }

    if ($payload -and $payload.PSObject.Properties.Name -contains 'properties') {
        $props = $payload.properties
        if (-not ($props.PSObject.Properties.Name -contains 'connectorDefinitionName') -and $ListRecord -and $ListRecord.PSObject.Properties.Name -contains 'properties') {
            $listProps = $ListRecord.properties
            if ($listProps -and $listProps.PSObject.Properties.Name -contains 'connectorDefinitionName' -and $listProps.connectorDefinitionName) {
                Add-Member -InputObject $props -NotePropertyName 'connectorDefinitionName' -NotePropertyValue $listProps.connectorDefinitionName -Force
            }
        }

        $definitionName = $null
        if ($props.PSObject.Properties.Name -contains 'connectorDefinitionName') {
            $definitionName = $props.connectorDefinitionName
        }

        if ($definitionName) {
            $definitionDetail = Get-RestDataConnectorDefinition -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DefinitionName $definitionName
            if ($definitionDetail -and $definitionDetail.PSObject.Properties.Name -contains 'properties') {
                $definitionProps = $definitionDetail.properties

                if (-not ($props.PSObject.Properties.Name -contains 'connectorDefinitionDetail')) {
                    Add-Member -InputObject $props -NotePropertyName 'connectorDefinitionDetail' -NotePropertyValue $definitionDetail -Force
                }
                else {
                    $props.connectorDefinitionDetail = $definitionDetail
                }

                $definitionUi = $definitionProps.connectorUiConfig
                if ($definitionUi) {
                    if (-not ($props.PSObject.Properties.Name -contains 'connectorUiConfig') -or -not $props.connectorUiConfig) {
                        Add-Member -InputObject $props -NotePropertyName 'connectorUiConfig' -NotePropertyValue $definitionUi -Force
                    }
                    else {
                        $targetUi = $props.connectorUiConfig
                        foreach ($uiProp in $definitionUi.PSObject.Properties) {
                            $hasProperty = $targetUi.PSObject.Properties.Name -contains $uiProp.Name
                            $existingValue = if ($hasProperty) { $targetUi.($uiProp.Name) } else { $null }
                            $shouldReplace = $false

                            if (-not $hasProperty) {
                                $shouldReplace = $true
                            }
                            elseif ($existingValue -is [string]) {
                                $shouldReplace = [string]::IsNullOrWhiteSpace($existingValue)
                            }
                            elseif (-not $existingValue) {
                                $shouldReplace = $true
                            }

                            if ($shouldReplace) {
                                Add-Member -InputObject $targetUi -NotePropertyName $uiProp.Name -NotePropertyValue $uiProp.Value -Force
                            }
                        }
                    }
                }
            }
        }
    }

    $normalized = $null
    if ($payload) {
        $normalized = ConvertTo-ConnectorObject -Connector $payload -SourceTag 'RESTFallback'
    }
    else {
        Write-Log -Level WARN -Message "Convert-RestConnectorRecord: No payload available for REST connector."
    }
    return $normalized
}

function New-ConnectorFallbackRecord {
    <#
      .SYNOPSIS
      Generates a minimal summary record when full status processing fails.
    #>
    param(
        [Parameter(Mandatory)][object]$Connector,
        [string]$Reason,
        [string]$Workspace,
        [string]$Subscription,
        [string]$Tenant
    )

    $name = $null
    if ($Connector.PSObject.Properties.Name -contains 'Name' -and $Connector.Name) { $name = $Connector.Name }
    elseif ($Connector.PSObject.Properties.Name -contains 'name' -and $Connector.name) { $name = $Connector.name }
    elseif ($Connector.Id) { $name = ($Connector.Id -split '/')[-1] }
    elseif ($Connector.PSObject.Properties.Name -contains 'Id') { $name = $Connector.Id }
    else { $name = 'UnknownConnector' }

    $kind = $Connector.Kind
    if (-not $kind -and $Connector.PSObject.Properties.Name -contains 'DataConnectorKind') { $kind = $Connector.DataConnectorKind }
    if (-not $kind -and $Connector.PSObject.Properties.Name -contains 'properties' -and $Connector.properties.kind) { $kind = $Connector.properties.kind }
    if (-not $kind) { $kind = 'UnknownKind' }

    $source = if ($Connector.PSObject.Properties.Name -contains 'Source') { $Connector.Source } else { 'Unknown' }

    return [pscustomobject]@{
        Name              = $name
        Kind              = $kind
        Id                = if ($Connector.Id) { $Connector.Id } elseif ($Connector.PSObject.Properties.Name -contains 'id') { $Connector.id } else { $null }
        Title             = if ($Connector.ConnectorUiConfigTitle) { $Connector.ConnectorUiConfigTitle } else { $name }
        Publisher         = $Connector.ConnectorUiConfigPublisher
        Status            = 'NotProcessed'
        QueryStatus       = 'NotProcessed'
        LastLogTime       = $null
        LogsLastHour      = $null
        TotalLogs24h      = $null
        HoursSinceLastLog = $null
        IsConnected       = $null
        NoLastLog         = $null
        StatusDetails     = $Reason
        Workspace         = $Workspace
        Subscription      = $Subscription
        Tenant            = $Tenant
        Source            = $source
    }
}

function Resolve-Connector {
<#
  .SYNOPSIS
  Resolves the appropriate Id value for a connector based on Kind, DataConnectorKind, or Name.
  .DESCRIPTION
  Analyzes connector properties (Kind, DataConnectorKind) and Name to determine the best Id value
  for Logic App payload and $ConnectorInfo lookups. Returns Name and Kind as-is from the connector,
  plus the resolved Id that will be used for matching against $ConnectorInfo entries.
  Priority: 1) Kind if meaningful (not GenericUI/StaticUI), 2) Name if not a GUID, 3) Name as fallback.
  .PARAMETER Connector
  The raw connector object.
  .OUTPUTS
  PSCustomObject with Name, Kind, Id, Source, Title, Publisher.
  .EXAMPLE
  Resolve-Connector -Connector $c
  #>
    param([Parameter(Mandatory)][object]$Connector)
    $candidates = @()
    if ([string]::IsNullOrWhiteSpace($Connector.Kind) -eq $false ) {
        # Direct top-level Kind property
        [void]($candidates += [pscustomobject]@{Kind = $Connector.Kind; Title = $Connector.ConnectorUiConfigTitle; Publisher = $Connector.ConnectorUiConfigPublisher; })
    }
    if ([string]::IsNullOrWhiteSpace($Connector.DataConnectorKind) -eq $false ) {
        [void]($candidates += [pscustomobject]@{Kind = $Connector.DataConnectorKind; Title = $Connector.ConnectorUiConfigTitle; Publisher = $Connector.ConnectorUiConfigPublisher; })
    }

    $chosen = $null
    if ($candidates.Count -gt 0) {
        $chosen = $candidates | Where-Object { $_.Kind -and $_.Kind -ne 'DataConnector' } | Select-Object -First 1
        if (-not $chosen) {
            $chosen = $candidates | Select-Object -First 1 
        }
    }
    
    $kindString = $null
    if ($chosen -and $chosen.Kind) {
        switch -Regex ($chosen.Kind.GetType().FullName) {
            'System.String' {
                $kindString = $chosen.Kind.Trim() 
            }
            'System\.String\[\]' {
                $kindString = ($chosen.Kind | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ',' 
            }
            default {
                if ($chosen.Kind -is [System.Collections.IEnumerable] -and ($chosen.Kind -isnot [string])) {
                    $kindString = ($chosen.Kind | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) -join ','
                }
                else {
                    $kindString = $chosen.Kind.ToString().Trim() 
                }
            }
        }
    }
    
    $isRestApiPoller = $false
    foreach ($candidateKind in @($kindString, $Connector.Kind, $Connector.DataConnectorKind)) {
        if (-not $candidateKind) { continue }
        $candidateParts = @()
        if ($candidateKind -is [string]) {
            $candidateParts = $candidateKind.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
        }
        elseif ($candidateKind -is [System.Collections.IEnumerable] -and ($candidateKind -isnot [string])) {
            foreach ($part in $candidateKind) {
                if ($part) { $candidateParts += $part.ToString() }
            }
        }
        else {
            $candidateParts = @($candidateKind.ToString())
        }
        foreach ($candidatePart in $candidateParts) {
            if ([string]::IsNullOrWhiteSpace($candidatePart)) { continue }
            if ([string]::Equals($candidatePart.Trim(), 'RestApiPoller', [System.StringComparison]::OrdinalIgnoreCase)) {
                $isRestApiPoller = $true
                break
            }
        }
        if ($isRestApiPoller) { break }
    }

    # Determine best Id value for lookup in $ConnectorInfo
    # Priority: 1) Kind if meaningful, 2) Name if not a GUID
    $idValue = $null
    $idSource = 'None'
    
    if ($kindString -and $kindString -notin @('StaticUI', 'GenericUI', 'DataConnector', 'UnknownKind')) {
        # Use Kind as Id if it's a meaningful value
        $idValue = $kindString
        $idSource = if ($chosen) { $chosen.Source } else { 'KindString' }
    }
    
    # Fallback to Name if Kind is not useful or missing
    if (-not $idValue) {
        $name = $Connector.Name
        $isGuid = ($name -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')
        if (-not $isGuid -and -not [string]::IsNullOrWhiteSpace($name)) {
            $idValue = $name
            $idSource = 'ConnectorName'
        }
    }
    
    # Final fallback: use Name even if it's a GUID
    if (-not $idValue) {
        $idValue = $Connector.Name
        $idSource = 'ConnectorNameFallback'
    }

    $infoMatch = $null
    if ($idValue) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
    }

    if (-not $infoMatch -and $isRestApiPoller) {
        $definitionCandidates = @()
        if ($Connector.PSObject.Properties.Name -contains 'ConnectorDefinitionName' -and $Connector.ConnectorDefinitionName) {
            $definitionCandidates += $Connector.ConnectorDefinitionName
        }
        if ($Connector.PSObject.Properties.Name -contains 'connectorDefinitionName' -and $Connector.connectorDefinitionName) {
            $definitionCandidates += $Connector.connectorDefinitionName
        }
        foreach ($definitionCandidate in $definitionCandidates) {
            if ([string]::IsNullOrWhiteSpace($definitionCandidate)) { continue }
            $definitionKey = $definitionCandidate
            if ($definitionKey -like '*/dataConnectorDefinitions/*') {
                $definitionKey = ($definitionKey -split '/')[-1]
            }
            $match = $ConnectorInfo | Where-Object { $_.Id -ieq $definitionKey } | Select-Object -First 1
            if ($match) {
                $infoMatch = $match
                $idValue = $match.Id
                $idSource = 'DefinitionName'
                break
            }
        }
    }

    if (-not $infoMatch -and $isRestApiPoller -and $Connector.Name) {
        $nameLower = $Connector.Name.ToLowerInvariant()
        $prefixMatch = $ConnectorInfo | Where-Object {
            if (-not $_.Id) { $false }
            else {
                $candidateLower = $_.Id.ToLowerInvariant()
                $nameLower.StartsWith($candidateLower)
            }
        } | Select-Object -First 1
        if ($prefixMatch) {
            $infoMatch = $prefixMatch
            $idValue = $prefixMatch.Id
            $idSource = 'ConnectorNamePrefix'
        }
    }

    if (-not $infoMatch -and $idValue) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
    }
    
    # If $Connector.ConnectorUiConfigTitle and/or $Connector.ConnectorUiConfigPublisher is null or whitespace, try to match $idValue with $ConnectorInfo Title and Publisher values.
    $resolvedTitle = $Connector.ConnectorUiConfigTitle
    $resolvedPublisher = $Connector.ConnectorUiConfigPublisher
    if ([string]::IsNullOrWhiteSpace($resolvedTitle) -or [string]::IsNullOrWhiteSpace($resolvedPublisher)) {
        if ($infoMatch) {
            if ([string]::IsNullOrWhiteSpace($resolvedTitle)) {
                $resolvedTitle = $infoMatch.Title
            }
            if ([string]::IsNullOrWhiteSpace($resolvedPublisher)) {
                $resolvedPublisher = $infoMatch.Publisher
            }
        }
    }

    # If $Connector.ConnectorUiConfigConnectivityCriterion has one or more property of type = "IsConnectedQuery", collect their values as an array and assign to ConnectivityCriteria; otherwise, fallback to $ConnectorInfo lookup.
    $resolvedConnectivityKQL = $null
    $resolvedConnectivityCriteria = $null
    if ($Connector.PSObject.Properties.Name -contains 'ConnectorUiConfigConnectivityCriterion' -and $Connector.ConnectorUiConfigConnectivityCriterion) {
        $criteria = $Connector.ConnectorUiConfigConnectivityCriterion
        $isConnectedQueries = @()
        foreach ($item in $criteria) {
            if ($item.type -eq 'IsConnectedQuery' -and $item.value) {
                [void]($isConnectedQueries += $item.value)
            }
        }
        if ($isConnectedQueries.Count -gt 0) {
            $resolvedConnectivityCriteria = $isConnectedQueries
        }
    }
    if (-not $resolvedConnectivityCriteria -and $infoMatch -and $infoMatch.ConnectivityCriteria) {
        $resolvedConnectivityCriteria = $infoMatch.ConnectivityCriteria
    }
    $resolvedConnectivityKQL = $null
    if ($Connector.ConnectorUiConfigConnectivityCriterion) {
        $isConnectedKqls = @()
        foreach ($crit in $Connector.ConnectorUiConfigConnectivityCriterion) {
            if ($crit.type -eq "IsConnectedQuery" -and $crit.value) {
                [void]($isConnectedKqls += $crit.value)
            }
        }
        if ($isConnectedKqls.Count -gt 0) {
            $resolvedConnectivityKQL = $isConnectedKqls
        }
    }
    if (-not $resolvedConnectivityKQL -and $infoMatch -and $infoMatch.ConnectivityKql) {
        $resolvedConnectivityKQL = $infoMatch.ConnectivityKql
    }

    # If $Connector.ConnectorUiConfigConnectivityCriterion has one or more property of type = "IsConnectedQuery", collect their values as an array and assign to ConnectivityCriteria; otherwise, fallback to $ConnectorInfo lookup.
    $resolvedActivityKQL = $null
    $resolvedActivityCriteria = $null
    if (-not $resolvedActivityCriteria -and $infoMatch -and $infoMatch.ActivityKql) {
        $resolvedConnectivityCriteria = $infoMatch.ConnectivityCriteria
    }
    $resolvedActivityKQL = $null
    if ($Connector.ConnectorUiConfigConnectivityCriterion) {
        $isActivityKqls = @()
        foreach ($crit in $Connector.ConnectorUiConfigActivityCriterion) {
            if ($crit.type -eq "IsConnectedQuery" -and $crit.value) {
                [void]($isActivityKqls += $crit.value)
            }
        }
        if ($isActivityKqls.Count -gt 0) {
            $resolvedActivityKQL = $isActivityKqls
        }
    }
    if (-not $resolvedActivityKQL -and $infoMatch -and $infoMatch.ActivityKql) {
        $resolvedActivityKQL = $infoMatch.ActivityKql
    }

    # Return object with Name and Kind preserved as-is from connector
    return [pscustomobject]@{
        Name            = $Connector.Name
        Kind            = if ($kindString) { $kindString } else { 'UnknownKind' }
        Id              = $idValue
        Source          = $idSource
        Title           = $resolvedTitle
        Publisher       = $resolvedPublisher
        ConnectivityKQL = $resolvedConnectivityKql
        ActivityKQL     = $resolvedActivityKql      
    }
}

function Test-SubscriptionIdFormat {
    <#
.SYNOPSIS
Validates a subscription id string.
.DESCRIPTION
Returns $true if the provided string matches a GUID pattern; otherwise $false.
.PARAMETER Value
Subscription id candidate.
.OUTPUTS
System.Boolean
.EXAMPLE
Test-SubscriptionIdFormat '11111111-1111-1111-1111-111111111111'
#>
    param([string]$Value) 
    if ([string]::IsNullOrWhiteSpace($Value)) { 
        return $false 
    }
    return $Value -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' 
}

function Test-ResourceGroupName {

    <#
.SYNOPSIS
Validates an Azure resource group name.
.DESCRIPTION
Ensures name length and allowed characters per Azure constraints.
.PARAMETER Value
Resource group name to test.
.OUTPUTS
System.Boolean
.EXAMPLE
Test-ResourceGroupName 'rg-security-prod'
#>
    param([string]$Value) 

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false 
    }
    if ($Value.Length -gt 90) {
        return $false 
    }
    return $Value -match '^[A-Za-z0-9_.()\-]+$' 
}

function Test-WorkspaceName {
    <#
.SYNOPSIS
Validates a Log Analytics workspace name.
.DESCRIPTION
Checks length (4-63) and allowed start/end characters and dashes rules.
.PARAMETER Value
Workspace name.
.OUTPUTS
System.Boolean
.EXAMPLE
Test-WorkspaceName 'law-prod-eus'
#>
    param([string]$Value) 
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false 
    }
    if ($Value.Length -lt 4 -or $Value.Length -gt 63) {
        return $false 
    }
    return $Value -match '^[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?$' 
}

function Resolve-ManagedIdentityObjectId {
    <#
  .SYNOPSIS
  Resolves the object id (principal id) for the managed identity.
  .DESCRIPTION
  Uses explicit override, automation variable, or directory lookup via application (client) id.
  .PARAMETER ClientId
  ApplicationId of user-assigned managed identity.
  .OUTPUTS
  System.String ObjectId GUID.
  .EXAMPLE
  Resolve-ManagedIdentityObjectId -ClientId $UmiClientId
  #>
    param([string]$ClientId
    )
    if (-not $ClientId) {
        throw 'Cannot resolve managed identity objectId: no clientId and no overrides provided.' 
    }
    try {
        $sp = Get-AzADServicePrincipal -ApplicationId $ClientId -ErrorAction Stop
        if ($sp -and $sp.Id) {
            Write-Log -Level INFO -Message "Resolved MI objectId $($sp.Id) from clientId $ClientId"; return $sp.Id 
        }
        throw 'Service principal lookup returned no Id'
    }
    catch {
        Write-Log -Level WARN -Message "Directory lookup for MI objectId failed: $($_.Exception.Message). Provide -ManagedIdentityObjectId or set automation variable 'UMI_OBJECT_ID'."
        throw
    }
}

function Test-ModuleLoaded {
    <#
  .SYNOPSIS
  Ensures an Az module is available and imports it.
  .DESCRIPTION
  Attempts to install (CurrentUser scope) if missing, then imports (throws on failure).
  .PARAMETER Name
  Module name.
  .EXAMPLE
  Test-ModuleLoaded -Name 'Az.Accounts'
  #>
    param([string]$Name)

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        if ($IsAzureAutomation) {
            Write-Log -Level WARN -Message "Module '$Name' not found in Automation sandbox; skipping inline install. Ensure the module is pre-imported in the account."
        }
        else {
            if (-not $script:AllowModuleAutoInstall) {
                throw "Module '$Name' is not installed. Install it manually or rerun with -AllowModuleInstall to permit automatic installation."
            }
            Write-Log -Level WARN -Message "Module '$Name' not found locally; attempting install (CurrentUser scope)."
            try {
                Install-Module -Name $Name -Force -Scope CurrentUser -ErrorAction Stop 
            }
            catch {
                Write-Log -Level WARN -Message "Install of $Name failed: $($_.Exception.Message)" 
            }
        }
    }
    Import-Module $Name -ErrorAction Stop
}

function Get-KqlErrorDetails {

    <#
    .SYNOPSIS
    Extracts detailed error message including inner error information from a query result.
    .DESCRIPTION
    Checks for Error.Message and Error.InnerError to provide comprehensive error details.
    Inner errors often contain helpful information like "Failed to resolve table expression named..."
    .PARAMETER QueryResult
    The result object from Invoke-AzOperationalInsightsQuery.
    .OUTPUTS
    String containing detailed error message.
    .EXAMPLE
    Get-KqlErrorDetails -QueryResult $result
    #>
    param([object]$QueryResult)
    
    if (-not $QueryResult -or -not $QueryResult.Error) {
        return $null
    }
    
    $errorParts = @()
    
    # Add main error message
    if ($QueryResult.Error.Message) {
        $errorParts += $QueryResult.Error.Message
    }
    
    # Check for inner error which often has more details
    if ($QueryResult.Error.InnerError) {
        $innerError = $QueryResult.Error.InnerError
        
        # InnerError might be a string or an object
        if ($innerError -is [string]) {
            $errorParts += "InnerError: $innerError"
        }
        elseif ($innerError.Message) {
            $errorParts += "InnerError: $($innerError.Message)"
        }
        elseif ($innerError.ToString() -ne 'System.Object') {
            $errorParts += "InnerError: $($innerError.ToString())"
        }
    }
    
    # Check for Code which might provide additional context
    if ($QueryResult.Error.Code) {
        $errorParts += "Code: $($QueryResult.Error.Code)"
    }
    
    return ($errorParts -join ' | ')
}

function Get-ConnectivityResults {
    <#
    .SYNOPSIS
    Executes connectivity criteria KQL queries and returns overall connectivity status.
    .DESCRIPTION
    Takes an array of KQL queries from ConnectivityCriteria and executes each one,
    returning true if ANY query indicates connectivity, false otherwise.
    .PARAMETER WorkspaceCustomerId
    The GUID (CustomerId) of the Log Analytics workspace.
    .PARAMETER ConnectivityCriteria
    Array of KQL query strings to execute.
    .PARAMETER ConnectorName
    Friendly name for logging context.
    .OUTPUTS
    Boolean indicating overall connectivity status.
    #>
    param(
        [string]$WorkspaceCustomerId,
        [string[]]$ConnectivityCriteria,
        [string]$ConnectorName
    )
    
    if (-not $WorkspaceCustomerId -or -not $ConnectivityCriteria -or $ConnectivityCriteria.Count -eq 0) {
        return $false
    }
    
    $overallConnected = $false
    
    for ($i = 0; $i -lt $ConnectivityCriteria.Count; $i++) {
        $kql = $ConnectivityCriteria[$i]
        if ([string]::IsNullOrWhiteSpace($kql)) { continue }
        
        try {
            Write-Log -Level DEBUG -Message "Executing connectivity criteria $i for '$ConnectorName': $($kql.Substring(0, [Math]::Min(50, $kql.Length)))..."
            
            $queryResult = Invoke-WithRetry -OperationName "ConnectivityKQL-$ConnectorName-$i" -ScriptBlock {
                Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $kql -Wait 60 -ErrorAction Stop
            } -MaxAttempts 2 -InitialDelaySeconds 1
            
            if (-not $queryResult.Error) {
                $connectivityState = Get-IsConnectedStateFromResult -QueryResult $queryResult

                if (-not $connectivityState.Observed) {
                    Write-Log -Level DEBUG -Message "Connectivity criteria $i for '$ConnectorName': no IsConnected column detected in result."
                }
                else {
                    Write-Log -Level DEBUG -Message "Connectivity criteria $i for '$ConnectorName': IsConnected=$($connectivityState.IsConnected)"
                }
                
                # If ANY query returns true, set overall result to true
                if ($connectivityState.IsConnected) {
                    $overallConnected = $true
                    Write-Log -Level DEBUG -Message "Overall connectivity for '$ConnectorName': true (criteria $i passed)"
                    # Continue checking remaining queries for completeness but result is already true
                }
            }
            else {
                $errorDetails = Get-KqlErrorDetails -QueryResult $queryResult
                Write-Log -Level WARN -Message "Connectivity criteria $i for '$ConnectorName' failed: $errorDetails"
            }
        }
        catch {
            Write-Log -Level WARN -Message "Connectivity criteria $i for '$ConnectorName' exception: $($_.Exception.Message)"
        }
    }
    
    Write-Log -Level DEBUG -Message "Final connectivity status for '$ConnectorName': $overallConnected"
    return $overallConnected
}

function Get-LogIngestionMetrics {

    <#
      .SYNOPSIS
  Executes KQL query/queries to derive ingestion metrics.
      .DESCRIPTION
  Accepts KQL as either a single string or array of strings via $ConnectivityKql  parameter.
  When array is provided, executes all queries and aggregates results (max LastLogTime, sum of counts).
  Returns LastLogTime, LogsLastHour, QueryStatus and KqlUsed (for transparency / troubleshooting).
      .PARAMETER WorkspaceCustomerId
      The GUID (CustomerId) of the Log Analytics workspace needed by Invoke-AzOperationalInsightsQuery.
      .PARAMETER ConnectorKind
      Sentinel connector Kind for logging context.
      .PARAMETER ConnectorName
      Friendly name for logging context.
      .PARAMETER ConnectorId
      Connector Id for metadata.
      .PARAMETER ConnectorTitle
      Connector Title for metadata.
      .PARAMETER ConnectorPublisher
      Connector Publisher for metadata.
      .PARAMETER ConnectivityKQL
      KQL query or queries to execute to determine if connector is reporting to be connected. Can be a single string or array of strings.
      .PARAMETER ActivityKQL
      KQL query or queries to execute to see activity for last time period. Can be a single string or array of strings.
      .OUTPUTS
      Hashtable with ingestion metrics fields.
      .EXAMPLE
      Get-LogIngestionMetrics -WorkspaceCustomerId $WorkspaceCustomerId -ConnectorName 'AAD' -ConnectivityKQL $kqlQuery -ActivityKQl $activityKQL
      .NOTES
    QueryStatus values: Success, SuccessNoStandardColumns, PartialError, QueryFailed, NoKql, MetricsUnavailable, Unknown.
      #>
    param(
        [string]$WorkspaceCustomerId,
        [string]$ConnectorKind,
        [string]$ConnectorName,
        [string]$ConnectorId,
        [string]$ConnectorTitle,
        [string]$ConnectorPublisher,
        $ConnectivityKql,
        $ActivityKql
    )
    
    $metrics = @{
        LastLogTime  = $null
        LogsLastHour = 0
        TotalLogs24h = 0
        QueryStatus  = 'Unknown'
        KqlUsed      = @{
            Connectivity = $ConnectivityKql
            Activity     = $ActivityKql
        }
        NoLastLog    = $false
        Id           = $ConnectorId
        Title        = $ConnectorTitle
        Publisher    = $ConnectorPublisher
        IsConnected  = $false
        Name         = $ConnectorName
    }
    
    if (-not $WorkspaceCustomerId) {
        Write-Log -Level WARN -Message 'No WorkspaceCustomerId passed to Get-LogIngestionMetrics'; return $metrics 
    }
    
    # Normalize $ConnectivityKql to array
    [array]$connectivityQueries = @()
    if ($ConnectivityKql) {
        if ($ConnectivityKql -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($ConnectivityKql)) {
                [array]$connectivityQueries = @($ConnectivityKql)
            }
        }
        elseif ($ConnectivityKql -is [array]) {
            [array]$connectivityQueries = $ConnectivityKql | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
    }
    
    # Normalize $ActivityKql to array
    $activityQueries = @()
    if ($ActivityKql) {
        if ($ActivityKql -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($ActivityKql)) {
                $activityQueries = @($ActivityKql)
            }
        }
        elseif ($ActivityKql -is [array]) {
            $activityQueries = $ActivityKql | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
    }
    
    if ($connectivityQueries.Count -eq 0 -and $activityQueries.Count -eq 0) {
        $metrics.QueryStatus = 'NoKql'
        Write-Log -Level WARN -Message "No KQL available for connector '$ConnectorName' (Kind=$ConnectorKind)."
        return $metrics
    }
    
    Write-Log -Level DEBUG -Message "Processing $($connectivityQueries.Count) ConnectivityKql and $($activityQueries.Count) ActivityKql queries for connector '$ConnectorName'"
    
    # ===== PART 1: Execute ConnectivityKql queries to determine IsConnected status =====
    if ($connectivityQueries.Count -gt 0) {
        Write-Log -Level DEBUG -Message "Executing $($connectivityQueries.Count) ConnectivityKql quer(y/ies) for '$ConnectorName'"

        for ($i = 0; $i -lt $connectivityQueries.Count; $i++) {
            $kqlQuery = $connectivityQueries[$i]
            $queryLabel = if ($connectivityQueries.Count -gt 1) { "[Connectivity $($i+1)/$($connectivityQueries.Count)]" } else { "[Connectivity]" }
            $queryPreview = ($kqlQuery -split "`n" | Select-Object -First 2) -join ' | '
            
            Write-Log -Level DEBUG -Message "KQL start $queryLabel Connector='$ConnectorName' Preview='$queryPreview'"
            
            try {
                $result = Invoke-WithRetry -OperationName "ConnectivityKQL-$ConnectorName-$i" -ScriptBlock { 
                    Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $kqlQuery -Wait 60 -ErrorAction Stop 
                } -MaxAttempts 2 -InitialDelaySeconds 1
                
                if ($result -and -not $result.Error) {
                    $connectivityState = Get-IsConnectedStateFromResult -QueryResult $result

                    if (-not $connectivityState.Observed) {
                        Write-Log -Level DEBUG -Message "$queryLabel for '$ConnectorName': no IsConnected column detected in result."
                    }
                    else {
                        Write-Log -Level DEBUG -Message "$queryLabel for '$ConnectorName': IsConnected=$($connectivityState.IsConnected)"
                    }

                    if ($connectivityState.IsConnected) {
                        $metrics.IsConnected = $true
                        Write-Log -Level DEBUG -Message "Connectivity established for '$ConnectorName' via query $($i+1)"
                    }
                }
                else {
                    $errorDetails = Get-KqlErrorDetails -QueryResult $result
                    Write-Log -Level WARN -Message "$queryLabel for '$ConnectorName' returned error: $errorDetails"
                }
            }
            catch {
                Write-Log -Level WARN -Message "$queryLabel for '$ConnectorName' exception: $($_.Exception.Message)"
            }
        }
    }
    
    # ===== PART 2: Execute ActivityKql queries to get activity metrics =====
    if ($activityQueries.Count -gt 0) {
        try {
            Write-Log -Level DEBUG -Message "Executing $($activityQueries.Count) ActivityKql queries for '$ConnectorName'"
            
            $allExtracted = $false
            $anySuccess = $false
            $anyFailure = $false
            $totalRowsAll = 0
            
            for ($i = 0; $i -lt $activityQueries.Count; $i++) {
                $kqlQuery = $activityQueries[$i]
                $queryPreview = ($kqlQuery -split "`n" | Select-Object -First 3) -join ' | '
                $queryLabel = if ($activityQueries.Count -gt 1) { "[Activity $($i+1)/$($activityQueries.Count)]" } else { "[Activity]" }
                
                Write-Log -Level INFO -Message "KQL start $queryLabel Connector='$ConnectorName' Preview='$queryPreview'"
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $result = $null
            
                try {
                    $result = Invoke-WithRetry -OperationName "KQL-$ConnectorName-$i" -ScriptBlock { 
                        Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $kqlQuery -Wait 60 -ErrorAction Stop 
                    } -MaxAttempts 3 -InitialDelaySeconds 2
                }
                catch {
                    Write-Log -Level WARN -Message "KQL final failure $($queryLabel) for '${ConnectorName}': $($_.Exception.Message)"
                    $anyFailure = $true
                    $sw.Stop()
                    continue
                }
            
                $sw.Stop()
            
                if ($null -eq $result) {
                    Write-Log -Level WARN -Message "KQL returned null result $($queryLabel) for '$ConnectorName' (DurationMs=$($sw.ElapsedMilliseconds))"
                    $anyFailure = $true
                    continue
                }
            
                if ($result.Error) {
                    $errorDetails = Get-KqlErrorDetails -QueryResult $result
                    Write-Log -Level WARN -Message "KQL error $queryLabel for '${ConnectorName}' (DurationMs=$($sw.ElapsedMilliseconds)): $errorDetails"
                    $anyFailure = $true
                    continue
                }
            
                # Process successful result
                $extracted = $false
                $totalRows = 0
            
                if ($result.Tables -and $result.Tables.Count -gt 0) {
                    # Newer SDK shape: multiple tables collection
                    foreach ($tableObj in $result.Tables) {
                        $totalRows += $tableObj.Rows.Count 
                        if ($tableObj.Rows.Count -eq 0) { continue }

                        $cols = $tableObj.Columns.Name
                        $idxLast = [Array]::IndexOf($cols, 'LastLogTime')
                        if ($idxLast -lt 0) {
                            $idxLast = [Array]::IndexOf($cols, 'TimeGenerated') 
                        }
                        $idxHour = [Array]::IndexOf($cols, 'LogsLastHour')
                        $idxTotal = [Array]::IndexOf($cols, 'TotalLogs24h')

                        foreach ($row in $tableObj.Rows) {
                            if ($idxLast -ge 0 -and $row[$idxLast]) {
                                $currentLastLog = [DateTime]$row[$idxLast]
                                # Keep the most recent LastLogTime across all queries
                                if (-not $metrics.LastLogTime -or $currentLastLog -gt $metrics.LastLogTime) {
                                    $metrics.LastLogTime = $currentLastLog
                                }
                                $extracted = $true 
                            }
                            if ($idxHour -ge 0 -and $row[$idxHour]) {
                                # Sum LogsLastHour across all queries
                                $metrics.LogsLastHour += [int]$row[$idxHour]
                                $extracted = $true 
                            }
                            if ($idxTotal -ge 0 -and $row[$idxTotal]) {
                                # Sum TotalLogs24h across all queries
                                $metrics.TotalLogs24h += [int]$row[$idxTotal]
                                $extracted = $true 
                            }
                        }
                    }
                }
                elseif ($result.Results) {
                    # Legacy shape: .Results array
                    $totalRows = $result.Results.Count
                    foreach ($data in $result.Results) {
                        if ($data.LastLogTime) {
                            $currentLastLog = [DateTime]$data.LastLogTime
                            if (-not $metrics.LastLogTime -or $currentLastLog -gt $metrics.LastLogTime) {
                                $metrics.LastLogTime = $currentLastLog
                            }
                            $extracted = $true 
                        }
                        elseif ($data.TimeGenerated) {
                            $currentLastLog = [DateTime]$data.TimeGenerated
                            if (-not $metrics.LastLogTime -or $currentLastLog -gt $metrics.LastLogTime) {
                                $metrics.LastLogTime = $currentLastLog
                            }
                            $extracted = $true 
                        }
                        if ($data.LogsLastHour) {
                            $metrics.LogsLastHour += [int]$data.LogsLastHour
                            $extracted = $true 
                        }
                        if ($data.TotalLogs24h) {
                            $metrics.TotalLogs24h += [int]$data.TotalLogs24h
                            $extracted = $true 
                        }
                    }
                }
            
                $totalRowsAll += $totalRows
                
                if ($extracted) {
                    $allExtracted = $true
                    $anySuccess = $true
                }
                
                if ($totalRows -eq 0) {
                    Write-Log -Level WARN -Message "KQL returned zero rows $queryLabel for '$ConnectorName' DurationMs=$($sw.ElapsedMilliseconds)" 
                }
                else {
                    Write-Log -Level INFO -Message "KQL done $queryLabel Connector='$ConnectorName' Rows=$totalRows DurationMs=$($sw.ElapsedMilliseconds) Status=$(if ($extracted) { 'Success' } else { 'NoStandardColumns' })" 
                }
                
                if ($VerboseLogging -and $result.Tables -and $result.Tables.Count -gt 0) {
                    $firstTbl = $result.Tables[0]
                    if ($firstTbl.Rows.Count -gt 0) {
                        Write-Log -Level DEBUG -Message "FirstRow $queryLabel (${ConnectorName}): $([string]::Join(';', ($firstTbl.Columns.Name | ForEach-Object { \"$($_)=$($firstTbl.Rows[0][[Array]::IndexOf($firstTbl.Columns.Name, $_)])\" })))" 
                    }
                }
            }
            
            # Determine overall query status for Activity queries
            if ($anySuccess -and -not $anyFailure) {
                $metrics.QueryStatus = if ($allExtracted) { 'Success' } else { 'SuccessNoStandardColumns' }
            }
            elseif ($anySuccess -and $anyFailure) {
                $metrics.QueryStatus = 'PartialError'
            }
            elseif ($anyFailure) {
                $metrics.QueryStatus = 'QueryFailed'
            }
            
            Write-Log -Level INFO -Message "Activity KQL summary: Connector='$ConnectorName' TotalQueries=$($activityQueries.Count) TotalRows=$totalRowsAll LastLogTime=$($metrics.LastLogTime) LogsLastHour=$($metrics.LogsLastHour) TotalLogs24h=$($metrics.TotalLogs24h) Status=$($metrics.QueryStatus)"
        }
        catch {
            Write-Log -Level WARN -Message "Activity KQL exception for connector '$ConnectorName': $($_.Exception.Message)"
            $metrics.QueryStatus = 'QueryFailed'
        }
    }
    else {
        # No activity queries provided
        $metrics.QueryStatus = 'NoActivityKql'
        Write-Log -Level DEBUG -Message "No ActivityKql provided for connector '$ConnectorName'"
    }
      
    return $metrics
}

function Get-IngestionStatus {
    <#
    .SYNOPSIS
        Classifies ingestion freshness based on last log timestamp.
    .DESCRIPTION
        Returns a PSCustomObject with Status (ActivelyIngesting, RecentlyActive, Stale or $null when LastLogTime not provided)
        and HoursSinceLastLog (rounded 2 decimals) for a given LastLogTime.
    .PARAMETER LastLogTime
        DateTime (any kind) representing most recent log. If null -> Status=$null, HoursSinceLastLog=$null.
    .PARAMETER ActiveThresholdHours
        Upper bound (inclusive) in hours for ActivelyIngesting. Default 1.
    .PARAMETER RecentThresholdHours
        Upper bound (inclusive) for RecentlyActive (after Active threshold). Default 24.
    .OUTPUTS
        PSCustomObject (Status, HoursSinceLastLog)
    .EXAMPLE
        Get-IngestionStatus -LastLogTime (Get-Date).AddMinutes(-20)
    #>
    param(
        [Nullable[DateTime]] $LastLogTime,
        [int] $ActiveThresholdHours = 1,
        [int] $RecentThresholdHours = 24
    )
    if (-not $LastLogTime) {
        return [pscustomobject]@{ Status = $null; HoursSinceLastLog = $null }
    }
    $utc = $LastLogTime.ToUniversalTime()
    $hours = ((Get-Date).ToUniversalTime() - $utc).TotalHours
    $rounded = [Math]::Round($hours, 2)
    $status = if ($hours -le $ActiveThresholdHours) { 'ActivelyIngesting' }
    elseif ($hours -le $RecentThresholdHours) { 'RecentlyActive' }
    else { 'Stale' }
    return [pscustomobject]@{ Status = $status; HoursSinceLastLog = $rounded }
}

function Get-ConnectorStatus {
    # PURPOSE: Merge configuration state & ingestion metrics into a final status classification.
    <#
      .SYNOPSIS
      Produces a composite status object for a Sentinel data connector.
      .DESCRIPTION
      Aggregates raw status/state/enabled properties (top-level, nested Properties,
      and dataTypes.*.state) and combines them with live ingestion metrics from
      Get-LogIngestionMetrics to determine an OverallStatus classification.
      .PARAMETER Connector
      The raw connector object returned by Get-AzSentinelDataConnector.
      .OUTPUTS
      Hashtable containing OverallStatus, StateDetails (name/value map), RawProperties (string array), LogMetrics (hashtable).
      .EXAMPLE
      Get-ConnectorStatus -Connector $c -WorkspaceId $WorkspaceCustomerId
      .NOTES
      OverallStatus precedence prioritizes ingestion recency (ActivelyIngesting, RecentlyActive,
      Stale) before fallback configuration states (ConfiguredButNoLogs, Disabled, Error, Unknown).
      #>
    param(
        [object]$Connector,
        [Parameter(Mandatory)][string]$WorkspaceCustomerId
    )

    try {
        $resolved = Resolve-Connector -Connector $Connector
    }
    catch {
        Write-Log -Level ERROR -Message "Resolve-Connector failed for connector '$($Connector.Name)': $($_.Exception.Message)"
        return $null
    }
  
    $resourceId = $null
    if ($Connector.PSObject.Properties.Name -contains 'Id' -and $Connector.Id) {
        $resourceId = $Connector.Id
    }
    elseif ($Connector.PSObject.Properties.Name -contains 'id' -and $Connector.id) {
        $resourceId = $Connector.id
    }

    $statusInfo = @{
        OverallStatus     = 'Unknown'
        StateDetails      = @{}
        RawProperties     = @()
        LogMetrics        = $null
        HoursSinceLastLog = $null
        Title             = $resolved.Title
        Publisher         = $resolved.Publisher
        Id                = $resolved.Id
        Name              = $resolved.Name
        IsConnected       = $false
        Kind              = $resolved.Kind
        Source            = if ($Connector.PSObject.Properties.Name -contains 'Source') { $Connector.Source } else { 'Cmdlet' }
        ResourceId        = $resourceId
    }
      
    # Check top-level status/state/enabled properties
    $statusProps = $Connector.PSObject.Properties | Where-Object { $_.Name -imatch '(status|state|enabled)' }
    # Top-level connector flags (shape varies per connector kind/provider)
    foreach ($prop in $statusProps) {
        $statusInfo.StateDetails[$prop.Name] = $prop.Value
        [void]($statusInfo.RawProperties += "$($prop.Name)=$($prop.Value)")
    }
      
    # Check Properties bag for status/state
    if ($Connector.Properties) {
        $props = $Connector.Properties
        $nestedStatusProps = $props.PSObject.Properties | Where-Object { $_.Name -imatch '(status|state|enabled)' }
        foreach ($prop in $nestedStatusProps) {
            $statusInfo.StateDetails["Properties.$($prop.Name)"] = $prop.Value
            [void]($statusInfo.RawProperties += "Properties.$($prop.Name)=$($prop.Value)")
        }
        
        # Check dataTypes (common in Sentinel connectors)
        if ($props.dataTypes) {
            # Enumerate nested dataTypes.*.state entries
            foreach ($dtProp in $props.dataTypes.PSObject.Properties) {
                $dataType = $dtProp.Value
                if ($dataType -and $dataType.state) {
                    $statusInfo.StateDetails["dataTypes.$($dtProp.Name).state"] = $dataType.state
                    [void]($statusInfo.RawProperties += "dataTypes.$($dtProp.Name).state=$($dataType.state)")
                }
            }
        }
    }
    
    # Get log ingestion metrics (defensive try/catch to avoid null property errors)
    try {
        $statusInfo.LogMetrics = Get-LogIngestionMetrics -WorkspaceCustomerId $WorkspaceCustomerId -ConnectorKind $Connector.Kind -ConnectorName $Connector.Name -ConnectorId $resolved.Id -ConnectorTitle $resolved.Title -ConnectorPublisher $resolved.Publisher -ConnectivityKQL $resolved.ConnectivityKQL -ActivityKql $resolved.ActivityKQL
        if (-not $statusInfo.LogMetrics) {
            $statusInfo.LogMetrics = @{ QueryStatus = 'MetricsUnavailable'; NoLastLog = $true }
        }
    }
    catch {
        Write-Log -Level WARN -Message "Get-LogIngestionMetrics threw for connector '$($Connector.Name)': $($_.Exception.Message)"
        $statusInfo.LogMetrics = @{ QueryStatus = 'MetricsUnavailable'; NoLastLog = $true }
    }

    # Gather state values for fallback decisions (stringified values)
    $allValues = @()
    foreach ($v in $statusInfo.StateDetails.Values) {
        if ($null -eq $v) { continue }
        try { $s = $v.ToString(); if ($s) { [void]($allValues += $s.ToLower()) } } catch {}
    }
    # Derive virtual tokens from boolean / numeric flags whose KEY names imply enablement state
    $derivedTokens = @()
    foreach ($kv in $statusInfo.StateDetails.GetEnumerator()) {
        $keyName = $kv.Key.ToLower()
        $valueRaw = $kv.Value
        # Normalize boolean-ish value
        $boolVal = $null
        if ($valueRaw -is [bool]) { $boolVal = [bool]$valueRaw }
        elseif ($valueRaw -is [int] -or $valueRaw -is [long]) {
            if ($valueRaw -eq 1) { $boolVal = $true }
            elseif ($valueRaw -eq 0) { $boolVal = $false }
        }
        elseif ($valueRaw -is [string]) {
            switch ($valueRaw.ToLower()) {
                'true' { $boolVal = $true }
                'false' { $boolVal = $false }
                'enabled' { [void]($derivedTokens += 'enabled') }
                'disabled' { [void]($derivedTokens += 'disabled') }
            }
        }
        if ($null -ne $boolVal) {
            if ($keyName -match '(enabled|connected|active)') {
                [void]($derivedTokens += if ($boolVal) { 'enabled' } else { 'disabled' })
            }
            elseif ($keyName -match '(disabled|inactive|disconnected)') {
                # If key contains a negative state indicator and flag is true, treat as disabled
                if ($boolVal) { [void]($derivedTokens += 'disabled') }
            }
        }
    }
    if ($derivedTokens.Count -gt 0) {
        [void]($allValues += $derivedTokens)
    }

    $statusInfo.IsConnected = $statusInfo.LogMetrics.IsConnected

    # Ingestion classification (pure function) with null-safe LastLogTime extraction
    $lastLogTimeValue = $null
    if ($statusInfo.LogMetrics -is [System.Collections.IDictionary] -and $statusInfo.LogMetrics.Contains('LastLogTime')) {
        $lastLogTimeValue = $statusInfo.LogMetrics['LastLogTime']
    }
    $ingestion = Get-IngestionStatus -LastLogTime $lastLogTimeValue
    if ($ingestion.Status) {
        $statusInfo.OverallStatus = $ingestion.Status
        $statusInfo.HoursSinceLastLog = $ingestion.HoursSinceLastLog

        # Normalize LastLogTime => UTC once (only if value exists & is DateTime)
        if ($lastLogTimeValue -is [DateTime]) {
            $utcVal = $lastLogTimeValue.ToUniversalTime()
            if ($statusInfo.LogMetrics -is [System.Collections.IDictionary]) { $statusInfo.LogMetrics['LastLogTime'] = $utcVal }
        }
    }
    else {
        if (-not $lastLogTimeValue) { if ($statusInfo.LogMetrics -is [System.Collections.IDictionary]) { $statusInfo.LogMetrics['NoLastLog'] = $true } }
        # Special case: no mapping (NoKql/NoActivityKql) and no logs -> distinct status
        # NoKql = both ConnectivityKql and ActivityKql missing
        # NoActivityKql = only ActivityKql missing (ConnectivityKql may or may not exist)
        # Without ActivityKql, we cannot determine log ingestion status, so treat as NoKqlAndNoLogs
        if (($statusInfo.LogMetrics.QueryStatus -eq 'NoKql' -or $statusInfo.LogMetrics.QueryStatus -eq 'NoActivityKql') -and -not $lastLogTimeValue) {
            # No KQL mapping available (or ActivityKql missing) and no logs
            $statusInfo.OverallStatus = 'NoKqlAndNoLogs'
        }
        else {
            # Fallback to configuration-based classification
            # Check IsConnected boolean (from ConnectivityKql queries) first, then check text-based state values
            if ($statusInfo.IsConnected -eq $true -or $allValues -contains 'enabled' -or $allValues -contains 'connected' -or $allValues -contains 'active') {
                $statusInfo.OverallStatus = 'ConfiguredButNoLogs'
            }
            elseif ($statusInfo.IsConnected -eq $false -and -not $lastLogTimeValue) {
                # Connector reports not connected (via ConnectivityKql) and has no logs
                $statusInfo.OverallStatus = 'NoLogs'
            }
            elseif ($allValues -contains 'disabled' -or $allValues -contains 'disconnected' -or $allValues -contains 'inactive') {
                $statusInfo.OverallStatus = 'Disabled'
            }
            elseif ($allValues -contains 'error' -or $allValues -contains 'failed') {
                $statusInfo.OverallStatus = 'Error'
            }
        }
    }

    if ($statusInfo.OverallStatus -eq 'Unknown') {
        try {
            $sdump = ($statusInfo.StateDetails.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
            Write-Log -Level DEBUG -Message "Status remained 'Unknown' for connector '$($Connector.Name)'. QueryStatus=$($statusInfo.LogMetrics.QueryStatus) LastLogTime=$($statusInfo.LogMetrics.LastLogTime) DerivedTokens=$([string]::Join(',', $derivedTokens)) StateDetails=$sdump"
        }
        catch {}
    }
    return $statusInfo
}

function Resolve-Workspace {
    param([string]$RG, [string]$Name)
    <#
  .SYNOPSIS
  Resolves a Log Analytics workspace via multiple strategies.
  .DESCRIPTION
  Attempts exact cmdlet, generic resource, and case-insensitive lookup; returns the first successful workspace resource object.
  .PARAMETER RG
  Resource group name.
  .PARAMETER Name
  Workspace name.
  .OUTPUTS
  Workspace resource object or $null.
  .EXAMPLE
  Resolve-Workspace -RG 'rg-sec' -Name 'law-sec'
  #>
    $strategies = @(
        @{Kind = 'CmdletExact'; Op = { Get-AzOperationalInsightsWorkspace -ResourceGroupName $RG -Name $Name -ErrorAction Stop } },
        @{Kind = 'GenericExact'; Op = { Get-AzResource -ResourceGroupName $RG -ResourceType 'Microsoft.OperationalInsights/workspaces' -ErrorAction Stop | Where-Object Name -EQ $Name } },
        @{Kind = 'CaseInsensitive'; Op = { Get-AzResource -ResourceGroupName $RG -ResourceType 'Microsoft.OperationalInsights/workspaces' -ErrorAction Stop | Where-Object { $_.Name.ToLower() -eq $Name.ToLower() } } }
    )
    foreach ($s in $strategies) {
        # Iterate lookup strategies until one returns a workspace
        try {
            Write-Log -Level DEBUG -Message "Workspace lookup attempt via $($s.Kind)"
            $w = & $s.Op
            if ($w) {
                return ($w | Select-Object -First 1) 
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "Strategy $($s.Kind) failed: $($_.Exception.Message)"
        }
    }
    return $null
}

function Get-Var {

    <#
  .SYNOPSIS
  Retrieves an Azure Automation variable.
  .DESCRIPTION
  Returns the variable value or throws unless -Optional specified. In strict
  mode referencing an uninitialized variable throws, so we always pre-initialize.
  .PARAMETER Name
  Automation variable name.
  .PARAMETER Optional
  Switch to suppress throwing if variable missing.
  .OUTPUTS
  System.Object
  .EXAMPLE
  Get-Var -Name 'SUBSCRIPTION_ID'
  #>
    param([string]$Name, [switch]$Optional)

    $v = $null
    try {
        $v = Get-AutomationVariable -Name $Name -ErrorAction Stop
    }
    catch {
        if ($Optional) {
            if ($VerboseLogging) {
                Write-Log -Level DEBUG -Message "Optional automation variable '$Name' not found." 
            }
            return $null
        }
        else {
            Write-Log ERROR "Required automation variable '$Name' not found."
            throw "Automation variable '$Name' is missing."
        }
    }

    if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrWhiteSpace($v))) {
        if ($Optional) {
            if ($VerboseLogging) {
                Write-Log -Level DEBUG -Message "Optional automation variable '$Name' is empty." 
            }
            return $null
        }
        else {
            Write-Log ERROR "Required automation variable '$Name' is empty."
            throw "Automation variable '$Name' is empty."
        }
    }
    return $v
}

function Get-StringDiagnostics {
    <#
  .SYNOPSIS
  Emits debug diagnostics for a string value including length and raw byte hex.
  .DESCRIPTION
  Useful for spotting hidden / non-printable characters and leading / trailing
  whitespace that can break Azure resource lookups. Logs WARN if leading or
  trailing whitespace is detected.
  .PARAMETER Value
  The string to examine.
  .PARAMETER Label
  Friendly identifier for log output (e.g. 'WorkspaceName').
  .EXAMPLE
  Get-StringDiagnostics -Value $WorkspaceName -Label 'WorkspaceName'
  .OUTPUTS
  None (logging side effects only).
  .NOTES
  Skips processing if Value is $null.
  #>
    param([string]$Value, [string]$Label)
    if ($null -eq $Value) {
        return 
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value) | ForEach-Object { $_.ToString('X2') }
    Write-Log -Level DEBUG -Message "$Label length=$($Value.Length) bytes=[$( ($bytes -join ' ') )]"
    if ($Value -match '\s$') {
        Write-Log -Level WARN -Message "$Label has trailing whitespace." 
    }
    if ($Value -match '^\s') {
        Write-Log -Level WARN -Message "$Label has leading whitespace." 
    }
}

function Invoke-AutomaticReaderRoleAssignment {
    <#
    .SYNOPSIS
        Attempts to assign 'Microsoft Sentinel Reader' role to the UAMI at the specified scope.
    .DESCRIPTION
        Used to automatically remediate access failures by granting read permissions
        to the User-Assigned Managed Identity (UAMI) executing this runbook.
    .PARAMETER Scope
        The scope (resourceId) at which to assign the Reader role.
    .EXAMPLE
        Invoke-AutomaticReaderRoleAssignment -Scope '/subscriptions/xxxx/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/law-sec'
    #>
    param([string]$Scope)
    $roleName = 'Microsoft Sentinel Reader'
    $miObjectId = Resolve-ManagedIdentityObjectId -ClientId $UmiClientId
    $maskedObjectId = Get-MaskedIdentifier -Value $miObjectId
    $scopeLogValue = if ($Scope) { ($Scope -split '/')[-1] } else { '<null>' }
    Write-Log -Level WARN -Message "Attempting automatic role assignment due to access failure. Role='$roleName' ObjectId=$maskedObjectId Scope=$scopeLogValue"
    if ($WhatIf) {
        Write-Log -Level INFO -Message "WhatIf: Would assign role '$roleName' to ObjectId $maskedObjectId at scope segment '$scopeLogValue'"
        return
    }
    try {
        $existing = Get-AzRoleAssignment -ObjectId $miObjectId -Scope $Scope -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq $roleName }
        if ($existing) {
            Write-Log -Level INFO -Message 'Reader role already present.'
            return
        }
        New-AzRoleAssignment -ObjectId $miObjectId -RoleDefinitionName $roleName -Scope $Scope -ErrorAction Stop | Out-Null
        Write-Log INFO 'Reader role assignment created.'
    }
    catch {
        Write-Log ERROR "Automatic role assignment failed: $($_.Exception.Message)"
    }
}

$VerboseLogging = Resolve-BoolInput -Value $VerboseLogging -Default:$false -ParameterName 'VerboseLogging'
$FailOnQueryErrors = Resolve-BoolInput -Value $FailOnQueryErrors -Default:$false -ParameterName 'FailOnQueryErrors'
$Parallel = Resolve-BoolInput -Value $Parallel -Default:$false -ParameterName 'Parallel'

$throttleFloor = 1
$throttleCeiling = 32
if ($ThrottleLimit -lt $throttleFloor -or $ThrottleLimit -gt $throttleCeiling) {
    $requestedThrottle = $ThrottleLimit
    $ThrottleLimit = [Math]::Min([Math]::Max($ThrottleLimit, $throttleFloor), $throttleCeiling)
    Write-Log -Level WARN -Message "ThrottleLimit value $requestedThrottle is outside the supported range ($throttleFloor-$throttleCeiling). Clamped to $ThrottleLimit."
}

if ($env:MSP_SKIP_CONNECTOR_RUN -eq '1') {
    $script:IsArmScopeValidated = $true
    Write-Log -Level INFO -Message 'MSP_SKIP_CONNECTOR_RUN=1 detected; skipping main execution (test harness mode).'
    return
}

Write-Log -Level INFO -Message 'Starting Sentinel Data Connectors management runbook.'
Write-Log -Level INFO -Message "RunId=$script:RunId"


$IsAzureAutomation = $env:AUTOMATION_ASSET_ACCOUNTID -or (Test-Path Variable:\AutomationAccountId)
Write-Log -Level INFO -Message "Execution environment: $(if ($IsAzureAutomation) { 'Azure Automation' } else { 'Local/Manual' })"

# --- Retrieve configuration ---
# In Azure Automation: Use automation variables
# In Local execution: Use provided parameters
if ($IsAzureAutomation) {
    Write-Log -Level INFO -Message 'Loading configuration from Azure Automation variables...'
    # UMI_ID (preferred) should be the CLIENT ID (ApplicationId) of the User-Assigned Managed Identity.
    $UmiClientId = Get-Var -Name 'UMI_ID'                            # UAMI (client) id
    
    # Override with parameters if explicitly provided (allows testing in automation)
    if (-not $SubscriptionId) { $SubscriptionId = Get-Var -Name 'SUBSCRIPTION_ID' }
    if (-not $ResourceGroupName) { $ResourceGroupName = Get-Var -Name 'RESOURCE_GROUP_NAME' }
    if (-not $WorkspaceName) { $WorkspaceName = Get-Var -Name 'WORKSPACE_NAME' }
    if (-not $LogicAppUri) { $LogicAppUri = Get-Var -Name 'DATACONNECTOR_API' -Optional }
    
    $logicAppHostForLog = Get-UriHostForLog -UriString $LogicAppUri
    $maskedUmiClientId = Get-MaskedIdentifier -Value $UmiClientId
    Write-Log -Level INFO -Message "Variables loaded: RG=$ResourceGroupName Workspace=$WorkspaceName LogicAppHost=$logicAppHostForLog UmiClientId=$maskedUmiClientId"
}
else {
    Write-Log -Level INFO -Message 'Using parameters provided for local execution...'
    $UmiClientId = $null  # Not used in local execution
    
    # Validate required parameters for local execution
    if (-not $SubscriptionId) { throw 'SubscriptionId parameter is required for local execution' }
    if (-not $ResourceGroupName) { throw 'ResourceGroupName parameter is required for local execution' }
    if (-not $WorkspaceName) { throw 'WorkspaceName parameter is required for local execution' }
    
    $maskedSubscriptionId = Get-MaskedIdentifier -Value $SubscriptionId
    Write-Log -Level INFO -Message "Parameters: RG=$ResourceGroupName Workspace=$WorkspaceName SubscriptionId=$maskedSubscriptionId"
}

# Post-resolution validation
foreach ($pair in @([pscustomobject]@{N = 'ResourceGroupName'; V = $ResourceGroupName }, [pscustomobject]@{N = 'WorkspaceName'; V = $WorkspaceName })) {
    # Ensure mandatory resolved values exist before continuing
    if ([string]::IsNullOrWhiteSpace($pair.V)) {
        throw "Required value '$($pair.N)' is null/empty after resolution. Check automation variables or parameter overrides." 
    }
}

# Strict format validation (throw early for malformed inputs) on resolved values
if (-not (Test-SubscriptionIdFormat $SubscriptionId)) {
    # Fail fast on invalid subscription GUID
    throw "SubscriptionId is not a valid GUID: $SubscriptionId" 
}
if (-not (Test-ResourceGroupName $ResourceGroupName)) {
    throw "ResourceGroupName fails validation rules: $ResourceGroupName" 
}
if (-not (Test-WorkspaceName $WorkspaceName)) {
    throw "WorkspaceName fails validation rules: $WorkspaceName" 
}

$ResourceGroupName = $ResourceGroupName.Trim()
$WorkspaceName = $WorkspaceName.Trim()
Get-StringDiagnostics -Value $ResourceGroupName -Label 'ResourceGroupName'
Get-StringDiagnostics -Value $WorkspaceName -Label 'WorkspaceName'

if ($WorkspaceName.Contains('/')) {
    # Support passing full resourceId; extract final segment
    Write-Log -Level INFO -Message 'Workspace value looks like a resourceId; extracting terminal segment.'
    $parts = $WorkspaceName -split '/'
    $WorkspaceName = $parts[$parts.Length - 1]
    Write-Log -Level DEBUG -Message "Parsed workspace name segment: $WorkspaceName"
}

if (-not $SubscriptionId) {
    Write-Log -Level WARN -Message 'No subscription id variable provided; will rely on current context after connect.' 
}

# --- Authenticate to Azure ---
if ($IsAzureAutomation) {
    # Azure Automation: Use Managed Identity
    if (-not $UmiClientId) {
        # Fall back to system-assigned or default identity
        Write-Log -Level WARN -Message 'UMI_ID variable not supplied; attempting system-assigned or default identity login (Connect-AzAccount -Identity).'
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null 
        }
        catch {
            throw "Managed identity login failed (no clientId provided): $($_.Exception.Message)" 
        }
    }
    else {
        $maskedUmiClientId = Get-MaskedIdentifier -Value $UmiClientId
        Write-Log -Level INFO -Message "Connecting with User-Assigned Managed Identity (ClientId=$maskedUmiClientId)"
        try {
            Connect-AzAccount -Identity -AccountId $UmiClientId -ErrorAction Stop | Out-Null 
        }
        catch {
            throw "Failed to authenticate with managed identity clientId=$maskedUmiClientId : $($_.Exception.Message)" 
        }
    }
}
else {
    # Local execution: Use existing context or prompt for interactive login
    Write-Log -Level INFO -Message 'Local execution: Checking for existing Azure authentication...'
    try {
        $context = Get-AzContext -ErrorAction Stop
        if ($context -and $context.Account) {
            $maskedAccount = Get-MaskedIdentifier -Value $context.Account.Id
            $maskedTenant = if ($context.Tenant -and $context.Tenant.Id) { Get-MaskedIdentifier -Value $context.Tenant.Id } else { '<unknown>' }
            Write-Log -Level INFO -Message "Using existing authentication: Account=$maskedAccount Tenant=$maskedTenant"
        }
        else {
            Write-Log -Level INFO -Message 'No existing context found. Initiating interactive login...'
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $context = Get-AzContext
            $maskedAccountAfterLogin = Get-MaskedIdentifier -Value $context.Account.Id
            Write-Log -Level INFO -Message "Authenticated interactively: Account=$maskedAccountAfterLogin"
        }
    }
    catch {
        Write-Log -Level WARN -Message 'No existing context found. Initiating interactive login...'
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $context = Get-AzContext
            $maskedAccountAfterLogin = Get-MaskedIdentifier -Value $context.Account.Id
            Write-Log -Level INFO -Message "Authenticated interactively: Account=$maskedAccountAfterLogin"
        }
        catch {
            throw "Failed to authenticate: $($_.Exception.Message)" 
        }
    }
}

if ($SubscriptionId) {
    try {
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        $maskedSubscriptionId = Get-MaskedIdentifier -Value $SubscriptionId
        Write-Log -Level INFO -Message "Context set to subscription $maskedSubscriptionId"
    }
    catch {
        throw "Failed setting subscription context: $($_.Exception.Message)" 
    }
}
else {
    $SubscriptionId = (Get-AzContext).Subscription.Id
    $maskedSubscriptionId = Get-MaskedIdentifier -Value $SubscriptionId
    Write-Log -Level INFO -Message "Derived subscription id from context: $maskedSubscriptionId"
}

try {
    $currentContext = Get-AzContext -ErrorAction Stop
    if ($currentContext -and $currentContext.Tenant -and $currentContext.Tenant.Id) {
        $TenantId = $currentContext.Tenant.Id
        $maskedTenantId = Get-MaskedIdentifier -Value $TenantId
        Write-Log -Level INFO -Message "Active tenant context: $maskedTenantId"
    }
    else {
        Write-Log -Level WARN -Message 'Unable to determine tenant id from current context.'
    }
}
catch {
    Write-Log -Level WARN -Message "Unable to read tenant context: $($_.Exception.Message)"
}

try {
    Confirm-SubscriptionScope -SubscriptionId $SubscriptionId -TenantId $TenantId -AllowCrossTenantScope:$AllowCrossTenantScope | Out-Null
    Write-Log -Level DEBUG -Message 'Subscription scope validated.'
}
catch {
    throw
}

# --- Load required modules ---
foreach ($m in 'Az.Accounts', 'Az.Resources', 'Az.OperationalInsights', 'Az.SecurityInsights', 'Az.MonitoringSolutions') {
    # Import each required module (idempotent if already loaded)
    Test-ModuleLoaded -Name $m 
}
Write-Log -Level DEBUG -Message 'All required modules imported.'
if ($VerboseLogging) {
    $modVersions = Get-Module Az.* | Sort-Object Name | Select-Object Name, Version | ForEach-Object { "$($_.Name)=$($_.Version)" }
    Write-Log -Level DEBUG -Message "ModuleVersions: $([string]::Join(',', $modVersions))"
}

$workspace = Resolve-Workspace -RG $ResourceGroupName -Name $WorkspaceName
if (-not $workspace) {
    # Workspace lookup failed -> gather diagnostics to aid troubleshooting then abort
    Write-Log ERROR 'Workspace unresolved. Collecting diagnostics.' 
    try {
        $rgObj = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        Write-Log -Level INFO -Message "RG exists: Name=$($rgObj.ResourceGroupName) Location=$($rgObj.Location)"
    }
    catch {
        Write-Log -Level WARN -Message "RG lookup failed: $($_.Exception.Message)" 
    }
    try {
        $wsNames = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.OperationalInsights/workspaces' -ErrorAction Stop | Select-Object -ExpandProperty Name
        Write-Log -Level INFO -Message "Workspaces found in RG: $([string]::Join(',', $wsNames))"
    }
    catch {
        Write-Log -Level WARN -Message "Workspace enumeration failed: $($_.Exception.Message)" 
    }
    # Attempt REST call for extra context
    try {
        $restId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName?api-version=2022-10-01"
        $rest = Invoke-AzRestMethod -Path $restId -Method GET -ErrorAction Stop
        Write-Log -Level INFO -Message "REST call succeeded unexpectedly during diagnostics (status $($rest.StatusCode))."
    }
    catch {
        Write-Log -Level WARN -Message "REST diagnostic call failed: $($_.Exception.Message)" 
    }
    throw "Workspace lookup failed RG=$ResourceGroupName Name=$WorkspaceName"
}

$workspaceId = if ($workspace.Id) {
    $workspace.Id 
}
else {
    $workspace.ResourceId 
}
Write-Log -Level INFO -Message "Workspace resolved: Name=$WorkspaceName ResourceGroup=$ResourceGroupName"

if (-not (Confirm-WorkspaceScope -WorkspaceResourceId $workspaceId -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName)) {
    throw "Workspace scope validation failed for RG=$ResourceGroupName Workspace=$WorkspaceName"
}
$script:IsArmScopeValidated = $true

# Split the workspace ID
if ([string]::IsNullOrWhiteSpace($workspace.CustomerId) -eq $false) {
    $WorkspaceCustomerId = $workspace.CustomerId.ToString()
    $maskedWorkspaceCustomerId = Get-MaskedIdentifier -Value $WorkspaceCustomerId
    Write-Log -Level INFO -Message "Workspace CustomerId (GUID for KQL): $maskedWorkspaceCustomerId"
}
else {
    Write-Log -Level WARN -Message 'Workspace CustomerId not present; KQL queries may not function.'
    $WorkspaceCustomerId = $null
}

#  Retrieve Data Connectors 
# --- Retrieve data connectors ---
Write-Log INFO 'Retrieving Sentinel Data Connectors for workspace...'
try {
    # Primary attempt to enumerate all data connectors
    $connectors = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop | Sort-Object Name
}
catch {
    Write-Log -Level WARN -Message "Initial connector retrieval failed: $($_.Exception.Message)"
    $canAttemptAutoAssignment = $IsAzureAutomation -and (-not [string]::IsNullOrWhiteSpace($UmiClientId))
    if ($canAttemptAutoAssignment) {
        Invoke-AutomaticReaderRoleAssignment -Scope $workspaceId
        Start-Sleep -Seconds 5
    }
    else {
        Write-Log -Level INFO -Message 'Skipping automatic role assignment (not running with a User-Assigned Managed Identity in Azure Automation).'
    }
    try {
        Write-Log INFO 'Retrying connector retrieval after role assignment attempt.'
        $connectors = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop | Sort-Object Name
    }
    catch {
        Write-Log ERROR "Retry failed: $($_.Exception.Message)"
        throw
    }
}

$connectors = if ($connectors) { @($connectors) } else { @() }
foreach ($conn in $connectors) {
    if ($conn -and -not ($conn.PSObject.Properties.Name -contains 'Source')) {
        Add-Member -InputObject $conn -NotePropertyName 'Source' -NotePropertyValue 'Cmdlet' -Force -ErrorAction SilentlyContinue
    }
}

# Supplement cmdlet response with REST-only connectors
$restFallbackConnectors = @()
try {
    $restFallbackConnectors = Get-RestDataConnectors -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
}
catch {
    Write-Log -Level WARN -Message "REST fallback retrieval threw: $($_.Exception.Message)"
    $restFallbackConnectors = @()
}

if ($restFallbackConnectors.Count -eq 0) {
    Write-Log -Level WARN -Message 'REST fallback: 0 connectors returned. Verify Sentinel Reader permission for the run identity if connectors are missing.'
}

if ($restFallbackConnectors.Count -gt 0) {
    $restCandidateNames = $restFallbackConnectors | ForEach-Object {
        if ($_.name) { $_.name }
        elseif ($_.Name) { $_.Name }
        elseif ($_.id) { ($_.id -split '/')[-1] }
        else { 'UnknownRestConnector' }
    }
    Write-Log -Level WARN -Message "REST fallback: API returned $($restFallbackConnectors.Count) connector(s): $([string]::Join(', ', $restCandidateNames))"
    $existingKeys = New-Object System.Collections.Generic.HashSet[string]
    foreach ($conn in $connectors) {
        if (-not $conn) { continue }
        foreach ($key in (Get-ConnectorLookupKeys -Connector $conn)) {
            if ($null -ne $key) { [void]$existingKeys.Add($key) }
        }
    }

    $restOnly = @()
    $restSkipped = @()
    foreach ($restConnector in $restFallbackConnectors) {
        if (-not $restConnector) { continue }
        $keys = Get-ConnectorLookupKeys -Connector $restConnector
        $hasMatch = $false
        $matchedKey = $null
        foreach ($key in $keys) {
            if ($existingKeys.Contains($key)) { $hasMatch = $true; $matchedKey = $key; break }
        }
        if ($hasMatch) {
            $restSkipped += [pscustomobject]@{ Name = if ($restConnector.name) { $restConnector.name } else { $restConnector.Name }; Reason = "Matched existing key '$matchedKey'" }
            continue
        }

        if (-not $hasMatch) {
            $converted = Convert-RestConnectorRecord -ListRecord $restConnector -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
            if ($converted) {
                $restOnly += $converted
                foreach ($key in (Get-ConnectorLookupKeys -Connector $converted)) {
                    if ($null -ne $key) { [void]$existingKeys.Add($key) }
                }
            }
        }
    }

    if ($restSkipped.Count -gt 0) {
        $skipDetails = $restSkipped | ForEach-Object { "$($_.Name): $($_.Reason)" }
        Write-Log -Level WARN -Message "REST fallback: candidates skipped (already returned by cmdlet): $([string]::Join(', ', $skipDetails))"
    }

    if ($restOnly.Count -gt 0) {
        $restNames = $restOnly | ForEach-Object { $_.Name } | Sort-Object
        Write-Log -Level WARN -Message "REST fallback: $($restOnly.Count) connector(s) missing from cmdlet output; merging: $([string]::Join(', ', $restNames))"
        $connectors = @($connectors + $restOnly) | Sort-Object Name
    }
    else {
        Write-Log -Level INFO -Message "REST API returned $($restFallbackConnectors.Count) connector(s); all represented in cmdlet output."
    }
}

if (-not $connectors) {
    Write-Log -Level WARN -Message 'No data connectors returned.' 
}
else {

    $connectTxt = $connectors | Format-List * | Out-String
    Write-Log -Level DEBUG -Message "Connectors: $connectTxt"
    if ($VerboseLogging -and $connectors.Count -gt 0) {
        Write-Log -Level DEBUG -Message "Raw output from Get-AzSentinelDataConnector ($($connectors.Count) item(s)) follows."
        foreach ($connector in $connectors) {
            $raw = $null
            try {
                $raw = $connector | ConvertTo-Json -Depth 10 -Compress
            }
            catch {
                $raw = ($connector | Format-List * | Out-String).Trim()
            }
            Write-Log -Level DEBUG -Message "ConnectorRaw: $raw"
        }
    }
    
    # Summarize connectors with accurate status including log ingestion
    # Apply NameFilter and KindFilter early if provided
    $filteredConnectors = $connectors
    if ($NameFilter) { $nameSet = $NameFilter | ForEach-Object { $_.ToLower() }; $filteredConnectors = $filteredConnectors | Where-Object { $nameSet -contains $_.Name.ToLower() } }
    if ($KindFilter) {
        # We have to resolve kinds first to filter correctly
        $filteredConnectors = $filteredConnectors | ForEach-Object {
            $kres = Resolve-Connector -Connector $_
            $_ | Add-Member -NotePropertyName _ResolvedKindPreFilter -NotePropertyValue $kres.Kind -Force
            $_
        } | Where-Object { $KindFilter -contains $_._ResolvedKindPreFilter }
    }

    if ($Parallel) {
        Write-Log INFO "Parallel mode enabled (ThrottleLimit=$ThrottleLimit)"
        $summary = $filteredConnectors | ForEach-Object -Parallel {
            # Build a normalized record enriched with ingestion metrics
            $statusInfo = Get-ConnectorStatus -Connector $_ -WorkspaceCustomerId $using:WorkspaceCustomerId
            
            # Check if Get-ConnectorStatus returned null
            if (-not $statusInfo) {
                $connectorDetails = @(
                    "Name='$($_.Name)'"
                    "Kind='$($_.Kind)'"
                    "DataConnectorKind='$($_.DataConnectorKind)'"
                    "Id='$($_.Id)'"
                    "Type='$($_.Type)'"
                    "Etag='$($_.Etag)'"
                )
                $detailsStr = $connectorDetails -join ' '
                Write-Warning "Get-ConnectorStatus returned null - Skipping connector: $detailsStr"
                return (New-ConnectorFallbackRecord -Connector $_ -Reason 'Get-ConnectorStatus failed' -Workspace $using:WorkspaceName -Subscription $using:SubscriptionId -Tenant $using:TenantId)
            }
            
            $logMetrics = if ($statusInfo.LogMetrics -is [System.Collections.IDictionary]) { $statusInfo.LogMetrics } else { @{} }
            $trimmedName = if ($statusInfo.Name -is [string]) { $statusInfo.Name.Trim() } else { $statusInfo.Name }
            $trimmedId = if ($statusInfo.Id -is [string]) { $statusInfo.Id.Trim() } else { $statusInfo.Id }
            $trimmedTitle = if ($statusInfo.Title -is [string]) { $statusInfo.Title.Trim() } else { $statusInfo.Title }
            $trimmedPublisher = if ($statusInfo.Publisher -is [string]) { $statusInfo.Publisher.Trim() } else { $statusInfo.Publisher }
            $trimmedKind = if ($statusInfo.Kind -is [string]) { $statusInfo.Kind.Trim() } else { $statusInfo.Kind }
            if ([string]::IsNullOrWhiteSpace([string]$trimmedTitle)) {
                $fallbackId = if ([string]::IsNullOrWhiteSpace([string]$trimmedId) -and ($statusInfo.Id -is [string])) { $statusInfo.Id.Trim() } elseif ([string]::IsNullOrWhiteSpace([string]$trimmedId)) { $statusInfo.Id } else { $trimmedId }
                if ([string]::IsNullOrWhiteSpace([string]$fallbackId) -and ($trimmedName -is [string])) {
                    $fallbackId = $trimmedName
                }
                $trimmedTitle = $fallbackId
                $trimmedPublisher = 'No Match'
            }
            [pscustomobject]@{
                Name              = $trimmedName
                Id                = $trimmedId
                ResourceId        = $statusInfo.ResourceId
                Title             = $trimmedTitle
                Publisher         = $trimmedPublisher
                Kind              = $trimmedKind
                Status            = $statusInfo.OverallStatus
                LastLogTime       = if ($logMetrics.ContainsKey('LastLogTime')) { $logMetrics['LastLogTime'] } else { $null }
                LogsLastHour      = if ($logMetrics.ContainsKey('LogsLastHour')) { $logMetrics['LogsLastHour'] } else { $null }
                TotalLogs24h      = if ($logMetrics.ContainsKey('TotalLogs24h')) { $logMetrics['TotalLogs24h'] } else { $null }
                QueryStatus       = if ($logMetrics.ContainsKey('QueryStatus')) { $logMetrics['QueryStatus'] } else { $null }
                HoursSinceLastLog = $statusInfo.HoursSinceLastLog
                IsConnected       = if ($logMetrics.ContainsKey('IsConnected')) { $logMetrics['IsConnected'] } else { $null }
                StatusDetails     = if ($statusInfo.RawProperties) { ($statusInfo.RawProperties -join ';') } else { $null }
                Workspace         = $using:WorkspaceName
                Subscription      = $using:SubscriptionId
                Source            = $statusInfo.Source
            }
        } -ThrottleLimit $ThrottleLimit
    }
    else {
        Write-Log -Level INFO -Message "Processing $($filteredConnectors.Count) filtered connectors (non-parallel mode)"
        $emissionCount = 0
        $summary = $filteredConnectors | ForEach-Object {
            # Iterate each connector and build a normalized record enriched with ingestion metrics
            $connector = $_
            Write-Log -Level DEBUG -Message "Processing connector: Name='$($connector.Name)' Kind='$($connector.Kind)'"

            $statusInfo = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $WorkspaceCustomerId
            
            # Check if Get-ConnectorStatus returned null
            if (-not $statusInfo) {
                # Log comprehensive details about the skipped connector for diagnostics
                $connectorDetails = [ordered]@{
                    Name                = $connector.Name
                    Kind                = $connector.Kind
                    DataConnectorKind   = $connector.DataConnectorKind
                    Id                  = $connector.Id
                    Type                = $connector.Type
                    Etag                = $connector.Etag
                }
                
                # Add Properties if present
                if ($connector.Properties) {
                    $propsStr = ($connector.Properties.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                    $connectorDetails['Properties'] = $propsStr
                }
                
                # Convert to readable string for logging
                $detailsStr = ($connectorDetails.GetEnumerator() | ForEach-Object { "$($_.Key)='$($_.Value)'" }) -join ' '
                Write-Log -Level ERROR -Message "Get-ConnectorStatus returned null - Skipping connector: $detailsStr"
                return (New-ConnectorFallbackRecord -Connector $connector -Reason 'Get-ConnectorStatus failed' -Workspace $WorkspaceName -Subscription $SubscriptionId -Tenant $TenantId)
            }
            
            $logMetrics = if ($statusInfo.LogMetrics -is [System.Collections.IDictionary]) { $statusInfo.LogMetrics } else { @{} }
            $trimmedName = if ($statusInfo.Name -is [string]) { $statusInfo.Name.Trim() } else { $statusInfo.Name }
            $trimmedKind = if ($statusInfo.Kind -is [string]) { $statusInfo.Kind.Trim() } else { $statusInfo.Kind }
            $trimmedId = if ($statusInfo.Id -is [string]) { $statusInfo.Id.Trim() } else { $statusInfo.Id }
            $trimmedTitle = if ($statusInfo.Title -is [string]) { $statusInfo.Title.Trim() } else { $statusInfo.Title }
            $trimmedPublisher = if ($statusInfo.Publisher -is [string]) { $statusInfo.Publisher.Trim() } else { $statusInfo.Publisher }
            if ([string]::IsNullOrWhiteSpace([string]$trimmedTitle)) {
                $fallbackId = if ([string]::IsNullOrWhiteSpace([string]$trimmedId) -and ($statusInfo.Id -is [string])) { $statusInfo.Id.Trim() } elseif ([string]::IsNullOrWhiteSpace([string]$trimmedId)) { $statusInfo.Id } else { $trimmedId }
                if ([string]::IsNullOrWhiteSpace([string]$fallbackId) -and ($trimmedName -is [string])) {
                    $fallbackId = $trimmedName
                }
                $trimmedTitle = $fallbackId
                $trimmedPublisher = 'No Match'
            }
            $record = [ordered]@{
                Name              = $trimmedName
                Kind              = $trimmedKind
                Id                = $trimmedId
                ResourceId        = $statusInfo.ResourceId
                Title             = $trimmedTitle
                Publisher         = $trimmedPublisher
                Status            = $statusInfo.OverallStatus
                LastLogTime       = if ($logMetrics.ContainsKey('LastLogTime')) { $logMetrics['LastLogTime'] } else { $null }
                LogsLastHour      = if ($logMetrics.ContainsKey('LogsLastHour')) { $logMetrics['LogsLastHour'] } else { $null }
                TotalLogs24h      = if ($logMetrics.ContainsKey('TotalLogs24h')) { $logMetrics['TotalLogs24h'] } else { $null }
                QueryStatus       = if ($logMetrics.ContainsKey('QueryStatus')) { $logMetrics['QueryStatus'] } else { $null }
                HoursSinceLastLog = $statusInfo.HoursSinceLastLog
                IsConnected       = if ($logMetrics.ContainsKey('IsConnected')) { $logMetrics['IsConnected'] } else { $null }
                NoLastLog         = if ($logMetrics.ContainsKey('NoLastLog')) { $logMetrics['NoLastLog'] } else { $null }
                DataTypeStatus    = @()
                StatusDetails     = if ($statusInfo.RawProperties) { ($statusInfo.RawProperties -join '; ') } else { $null }
                Workspace         = $WorkspaceName
                Subscription      = $SubscriptionId
                Tenant            = $TenantId
                Source            = $statusInfo.Source
            }
            $stateDetails = if ($statusInfo.StateDetails -is [System.Collections.IDictionary]) { $statusInfo.StateDetails } else { $null }
            if ($record -is [System.Collections.IDictionary] -and $stateDetails) {
                foreach ($key in $stateDetails.Keys) {
                    # Add any additional state detail properties (dynamic set per connector)
                    if ($null -eq $key) { continue }
                    if (-not $record.Contains($key)) {
                        $record[$key] = $stateDetails[$key]
                    }
                }
            }
            elseif (-not ($record -is [System.Collections.IDictionary])) {
                Write-Log -Level WARN -Message "Connector record initialization failed (non-dictionary) for Name='$trimmedName' Id='$trimmedId'"
            }
            $emissionCount++
            Write-Log -Level DEBUG -Message "Emitting record #$emissionCount for connector: Name='$($record.Name)' Kind='$($record.Kind)' Id='$($record.Id)'"
            # Emit the record ONCE per connector (outside the StateDetails loop)
            [PSCustomObject]$record
        }
        Write-Log -Level INFO -Message "ForEach-Object completed. Emitted $emissionCount records. Summary contains $($summary.Count) items"
    }

    # --- Prepare connector collection ---
    # Requirement: Output an object collection with specific fields
    # Fields: Name, Kind, Status, LastLogTime, LogsLastHour,
    #         QueryStatus, MappingFound, StatusDetails
    # Produce a clean collection prior to consolidated object.
    $ConnectorCollection = $summary 

    # Ensure every record has a Name value (fallback to Id/Title) for downstream grouping/logging
    $nameInjected = 0
    foreach ($rec in $ConnectorCollection) {
        if (-not $rec) { continue }
        $hasNameProp = $rec.PSObject.Properties.Name -contains 'Name'
        $nameValue = if ($hasNameProp) { $rec.Name } else { $null }
        if ([string]::IsNullOrWhiteSpace([string]$nameValue)) {
            $fallback = $null
            if ($rec.Id) { $fallback = $rec.Id }
            elseif ($rec.Title) { $fallback = $rec.Title }
            else { $fallback = "UnknownConnector_$($nameInjected + 1)" }
            if ($hasNameProp) {
                $rec.Name = $fallback
            }
            else {
                Add-Member -InputObject $rec -NotePropertyName Name -NotePropertyValue $fallback -Force
            }
            $nameInjected++
        }
    }
    if ($nameInjected -gt 0) {
        Write-Log -Level WARN -Message "Injected fallback Name value for $nameInjected connector record(s)."
    }

    Write-Log -Level INFO -Message "After Select-Object: ConnectorCollection contains $($ConnectorCollection.Count) items"
    $uniqueNames = New-Object System.Collections.Generic.HashSet[string]
    foreach ($rec in $ConnectorCollection) {
        if (-not $rec) { continue }
        if (-not ($rec.PSObject.Properties.Name -contains 'Name')) { continue }
        $nameValue = [string]$rec.Name
        if ([string]::IsNullOrWhiteSpace($nameValue)) { continue }
        [void]$uniqueNames.Add($nameValue)
    }
    Write-Log -Level DEBUG -Message "ConnectorCollection unique names: $($uniqueNames.Count)"

    # --- Merge duplicate connector records ---
    # Deduplication/Merge: Connectors with the same Id represent the same underlying integration.

    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $mergedRecords = @()
    $merged = @()
    
    # Group by Id (case-insensitive, handling nulls)
    $groupsById = $ConnectorCollection | Where-Object { $_.Id } | Group-Object -Property { $_.Id.ToLower() }
    
    # Track which records have been processed
    $processedNames = New-Object System.Collections.Generic.HashSet[string]
    
    foreach ($g in $groupsById) {
        $records = $g.Group
        
        if ($records.Count -eq 1) {
            # Single record with this Id - keep as-is
            [void]($processedNames.Add($records[0].Name))
            $mergedRecords += $records[0]
            continue
        }
        
        # Multiple records with same Id - merge them
        Write-Log -Level DEBUG -Message "Merging $($records.Count) records with Id='$($g.Name)'"
        
        # Prefer non-GUID Name for display (more user-friendly)
        $nonGuidRecords = $records | Where-Object { $_.Name -notmatch $guidPattern }
        $target = if ($nonGuidRecords) { 
            $nonGuidRecords | Select-Object -First 1 
        }
        else { 
            $records | Select-Object -First 1 
        }
        
        # Clone the target to avoid modifying original
        $mergedRecord = $target.PSObject.Copy()
        
        # Merge StatusDetails - combine all unique tokens
        $allStatusDetailsTokens = ($records | ForEach-Object { 
                if ($_.StatusDetails) { ($_.StatusDetails -split ';') } 
            }) | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique
        $mergedRecord.StatusDetails = ($allStatusDetailsTokens -join '; ')
        
        # Use latest LastLogTime and associated metrics
        $latest = $records | Where-Object { $_.LastLogTime } | Sort-Object LastLogTime -Descending | Select-Object -First 1
        if ($latest -and $latest.LastLogTime) {
            $mergedRecord.LastLogTime = $latest.LastLogTime
            $mergedRecord.LogsLastHour = $latest.LogsLastHour
            $mergedRecord.TotalLogs24h = $latest.TotalLogs24h
            $mergedRecord.HoursSinceLastLog = $latest.HoursSinceLastLog
        }
        
        # Use best Status based on priority
        $priority = @('ActivelyIngesting', 'RecentlyActive', 'Stale', 'ConfiguredButNoLogs', 'Disabled', 'Error', 'NoKqlAndNoLogs', 'Unknown')
        $bestStatusRecord = $records | Sort-Object { 
            $idx = [Array]::IndexOf($priority, $_.Status)
            if ($idx -eq -1) { 999 } else { $idx }
        } | Select-Object -First 1
        $mergedRecord.Status = $bestStatusRecord.Status
        
        # Use best QueryStatus (Success > SuccessNoStandardColumns > PartialError > NoKql > QueryFailed > MetricsUnavailable)
        $qsPriority = @('Success', 'SuccessNoStandardColumns', 'PartialError', 'NoKql', 'QueryFailed', 'MetricsUnavailable', 'Unknown')
        $bestQsRecord = $records | Sort-Object { 
            $idx = [Array]::IndexOf($qsPriority, $_.QueryStatus)
            if ($idx -eq -1) { 999 } else { $idx }
        } | Select-Object -First 1
        $mergedRecord.QueryStatus = $bestQsRecord.QueryStatus
        
        # IsConnected: true if ANY record is connected
        $mergedRecord.IsConnected = ($records | Where-Object { $_.IsConnected -eq $true }).Count -gt 0
        
        # NoLastLog: false if ANY record has logs
        $mergedRecord.NoLastLog = ($records | Where-Object { $_.NoLastLog -ne $true }).Count -eq 0
        
        # Use first non-null Title and Publisher
        if (-not $mergedRecord.Title) {
            $withTitle = $records | Where-Object { $_.Title } | Select-Object -First 1
            if ($withTitle) { $mergedRecord.Title = $withTitle.Title }
        }
        if (-not $mergedRecord.Publisher) {
            $withPublisher = $records | Where-Object { $_.Publisher } | Select-Object -First 1
            if ($withPublisher) { $mergedRecord.Publisher = $withPublisher.Publisher }
        }
        
        # Track processed records
        foreach ($r in $records) { [void]($processedNames.Add($r.Name)) }
        
        # Log merge details
        $allNames = ($records | Select-Object -ExpandProperty Name) -join ', '
        [void]($merged += [pscustomobject]@{ 
                Id           = $g.Name
                KeptName     = $mergedRecord.Name
                AllNames     = $allNames
                RecordCount  = $records.Count
                MergedStatus = $mergedRecord.Status 
            })
        
        $mergedRecords += $mergedRecord
    }
    
    # Add records that don't have an Id (shouldn't happen, but handle defensively)
    $noIdRecords = $ConnectorCollection | Where-Object { -not $_.Id -or -not $processedNames.Contains($_.Name) }
    foreach ($rec in $noIdRecords) {
        if (-not $processedNames.Contains($rec.Name)) {
            $mergedRecords += $rec
            [void]($processedNames.Add($rec.Name))
        }
    }
    
    # Update ConnectorCollection with merged results
    $ConnectorCollection = $mergedRecords
    
    if ($merged.Count -gt 0) {
        Write-Log -Level INFO -Message "Merged $($merged.Count) connector groups (reduced from $(($merged | Measure-Object -Property RecordCount -Sum).Sum) to $($merged.Count) records)"
        foreach ($m in $merged) { 
            Write-Log -Level DEBUG -Message "MergeDetail Id=$($m.Id) KeptName=$($m.KeptName) MergedFrom=[$($m.AllNames)] Count=$($m.RecordCount) Status=$($m.MergedStatus)" 
        }
    }

    if ($ExcludeStatus) {
        $ConnectorCollection = $ConnectorCollection | Where-Object { $ExcludeStatus -notcontains $_.Status }
    }

    # Remediation Pass: HoursSinceLastLog is unexpectedly null for records with a non-null LastLogTime.
    # Root cause could be prior classification path not executed; recompute defensively here.
    # Also (optionally) upgrade Status if it is a configuration placeholder but ingestion recency indicates activity.
    $recomputed = 0
    $upgraded = 0
    foreach ($rec in $ConnectorCollection) {
        if ($rec.LastLogTime -and $null -eq $rec.HoursSinceLastLog) {
            try {
                $hrs = ((Get-Date).ToUniversalTime() - ([DateTime]$rec.LastLogTime).ToUniversalTime()).TotalHours
                $rounded = [Math]::Round($hrs, 2)
                $rec.HoursSinceLastLog = $rounded
                $recomputed++
                if ($rec.Status -in @('ConfiguredButNoLogs', 'Unknown', 'NoKqlAndNoLogs')) {
                    $newStatus = if ($hrs -le 1) { 'ActivelyIngesting' } elseif ($hrs -le 24) { 'RecentlyActive' } else { $rec.Status }
                    if ($newStatus -ne $rec.Status) { $rec.Status = $newStatus; $upgraded++ }
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "RemediationHours calc failed for Name='$($rec.Name)': $($_.Exception.Message)" 
            }
        }
    }
    if ($recomputed -gt 0) { Write-Log -Level INFO -Message "Remediation: Recomputed HoursSinceLastLog for $recomputed record(s). UpgradedStatus=$upgraded" }

    # Guarantee 'Kind' property presence & value (fallback to 'UnknownKind' if null/empty)
    $missingKindCount = 0
    foreach ($c in $ConnectorCollection) {
        # Ensure Kind always exists and is a simple string for downstream consumers
        if (-not ($c.PSObject.Properties.Name -contains 'Kind')) {
            $missingKindCount++
            Add-Member -InputObject $c -NotePropertyName Kind -NotePropertyValue 'UnknownKind' -Force
            continue
        }
        # Coerce non-string Kind values (e.g., hashtable renders as {})
        if ($c.Kind -and ($c.Kind -isnot [string])) {
            try {
                if ($c.Kind -is [System.Collections.IDictionary]) {
                    $c.Kind = ($c.Kind.GetEnumerator() | ForEach-Object { "${($_.Key)}=${($_.Value)}" }) -join ';'
                }
                elseif ($c.Kind -is [System.Collections.IEnumerable]) {
                    $c.Kind = ($c.Kind | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) -join ','
                }
                else {
                    $c.Kind = $c.Kind.ToString().Trim()
                }
                if ($VerboseLogging) {
                    Write-Log -Level DEBUG -Message "Coerced non-string Kind to '$($c.Kind)' for connector Name='$($c.Name)'" 
                }
            }
            catch {
                Write-Log WARN "Failed coercing Kind value for Name='$($c.Name)': $($_.Exception.Message)" 
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$c.Kind)) {
            $missingKindCount++
            $c.Kind = 'UnknownKind'
        }
    }
    if ($missingKindCount -gt 0) {
        Write-Log WARN "Injected fallback Kind for $missingKindCount connector record(s)." 
    }

    # Emit raw objects so all columns appear in Automation output (Format-Table would stringify & can drop columns)
    # Status distribution
    $statusGroups = $ConnectorCollection | Group-Object -Property Status | Sort-Object Name
    foreach ($g in $statusGroups) { Write-Log INFO "StatusSummary: $($g.Name)=$($g.Count)" }
    $noKql = $ConnectorCollection | Where-Object { $_.QueryStatus -eq 'NoKql' }
    if ($noKql.Count -gt 0) { Write-Log WARN "UnmappedKqlCount=$($noKql.Count) Names=$([string]::Join(',', ($noKql | Select-Object -First 10 -ExpandProperty Name)))" }
    $failed = $ConnectorCollection | Where-Object { $_.QueryStatus -eq 'QueryFailed' }
    if ($failed.Count -gt 0) { Write-Log WARN "QueryFailedCount=$($failed.Count) Names=$([string]::Join(',', ($failed | Select-Object -First 10 -ExpandProperty Name)))" }
    $metricsUnavailable = $ConnectorCollection | Where-Object { $_.QueryStatus -eq 'MetricsUnavailable' }
    if ($metricsUnavailable.Count -gt 0) { Write-Log WARN "MetricsUnavailableCount=$($metricsUnavailable.Count) Names=$([string]::Join(',', ($metricsUnavailable | Select-Object -First 10 -ExpandProperty Name)))" }
    Write-Log INFO "Emitting per-connector collection ($($ConnectorCollection.Count) items) as raw objects."

    # Emit main collection
    $ConnectorCollection | Sort-Object Id | Format-Table Name, Id, Title, Publisher, Status, LastLogTime, LogsLastHour, TotalLogs24h, QueryStatus, IsConnected -AutoSize

    # Emit run summary object (second JSON line) for downstream automation if desired
    $runEnd = (Get-Date).ToUniversalTime()
    $statusCounts = @{}
    foreach ($g in $statusGroups) { $statusCounts[$g.Name] = $g.Count }
    $maxHours = ($ConnectorCollection | Where-Object { $null -ne $_.HoursSinceLastLog } | Measure-Object -Property HoursSinceLastLog -Maximum).Maximum
    $noKqlAndNoLogs = ($ConnectorCollection | Where-Object { $_.Status -eq 'NoKqlAndNoLogs' })
    if ($noKqlAndNoLogs.Count -gt 0) {
        $ratio = [math]::Round( (100.0 * $noKqlAndNoLogs.Count / [math]::Max(1, $ConnectorCollection.Count)), 2)
        Write-Log WARN "NoKqlAndNoLogsCount=$($noKqlAndNoLogs.Count) Ratio=${ratio}% (no mapping + no logs)."
        if ($ratio -ge 20) {
            Write-Log WARN 'RemediationHint: High proportion of NoKqlAndNoLogs connectors; consider extending $ConnectorInfo mappings or validating connector enablement.'
        }
    }

    $durationSec = $null
    if ($RunStartUtc -is [datetime]) {
        try { $durationSec = [Math]::Round(($runEnd - $RunStartUtc).TotalSeconds, 2) } catch { $durationSec = $null }
    }
    else {
        Write-Log -Level WARN -Message 'RunStartUtc not a DateTime; DurationSec omitted.'
    }

    $summaryObj = [pscustomobject]@{
        RunId                   = $script:RunId
        RunStartUtc             = $RunStartUtc
        RunEndUtc               = $runEnd
        DurationSec             = $durationSec
        TotalConnectorsOut      = $ConnectorCollection.Count
        StatusCounts            = $statusCounts
        QueryFailedCount        = ($ConnectorCollection | Where-Object { $_.QueryStatus -eq 'QueryFailed' }).Count
        UnmappedCount           = ($ConnectorCollection | Where-Object { $_.QueryStatus -eq 'NoKql' }).Count
        MaxHoursSinceLastLog    = $maxHours
        MetricsUnavailableCount = $metricsUnavailable.Count
        NoKqlAndNoLogsCount     = $noKqlAndNoLogs.Count
    }
    $summaryObj | ConvertTo-Json -Depth 5 | Write-Information
}

if ($LogicAppUri) {
    $connectorCountForPost = 0
    if ($ConnectorCollection -is [System.Collections.ICollection]) { $connectorCountForPost = $ConnectorCollection.Count }
    elseif ($ConnectorCollection -is [array]) { $connectorCountForPost = $ConnectorCollection.Length }

    $postSuccess = Submit-LogicAppResult -LogicAppUri $LogicAppUri -Payload $ConnectorCollection -ConnectorCount $connectorCountForPost -WhatIf:$WhatIf
    if (-not $postSuccess) {
        Write-Log -Level WARN -Message 'Logic App submission failed; continuing without halting the run.'
    }
}
else {
    Write-Log INFO 'No Logic App URI detected; skipping Logic App post.' 
}

if ($FailOnQueryErrors -and $ConnectorCollection -and ($ConnectorCollection | Where-Object { $_.QueryStatus -eq 'QueryFailed' })) {
    Write-Log ERROR 'One or more connectors experienced KQL query failures. Exiting with code 2 due to -FailOnQueryErrors.'
    exit 2
}

Write-Log INFO 'Runbook completed successfully.' 
Write-Log -Level INFO -Message "Total execution time: $([Math]::Round((Get-Date).ToUniversalTime().Subtract($RunStartUtc).TotalSeconds, 2)) seconds."