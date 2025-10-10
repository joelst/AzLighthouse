<#
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
    NoKqlAndNoLogs      (no mapping available and no log evidence)
    Disabled
    Error
    Unknown

    Expected custom KQL columns: LastLogTime, LogsLastHour (else TimeGenerated is attempted; QueryStatus may be 'SuccessNoStandardColumns').
    Additional QueryStatus values: NoKql, MetricsUnavailable (query infra issue), QueryFailed (final failure).

  Enhanced connector mappings include hardcoded metadata (Id, Title, Publisher, ConnectivityCriteria) and custom KQL queries.

 .PARAMETER VerboseLogging
     Enables DEBUG level log output.
 .PARAMETER WhatIf
     Prevents destructive/privileged changes (e.g., role assignment).
 .PARAMETER FailOnQueryErrors
     Exit with code 2 if any connector KQL query fails after retries.
 .PARAMETER KindFilter
     One or more connector kinds to include (post-resolution). If supplied, only these kinds are processed.
 .PARAMETER NameFilter
     One or more connector names to include. Applied before kind filtering.
 .PARAMETER ExcludeStatus
     One or more final status values to exclude from emitted collection (e.g. Disabled,ConfiguredButNoLogs).
 .PARAMETER Parallel
     When specified, process connectors concurrently using ForEach-Object -Parallel.
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
    In the Logic App you can parse JSON then iterate over each item for downstream actions.
#>
# Requires Az.Accounts, Az.Resources, Az.Monitor, Az.SecurityInsights modules (latest versions recommended).
# Tested in Azure Automation with PowerShell 7.4 runtime.
# Can also be run locally by providing SubscriptionId, ResourceGroupName, and WorkspaceName parameters.
param(
    [switch] $VerboseLogging,
    [switch] $WhatIf,
    [switch] $FailOnQueryErrors,
    [string[]] $KindFilter,
    [string[]] $NameFilter,
    [string[]] $ExcludeStatus,
    [switch] $Parallel,
    [int] $ThrottleLimit = 4,
    
    # Local execution parameters (override automation variables)
    [string] $SubscriptionId,
    [string] $ResourceGroupName,
    [string] $WorkspaceName,
    [string] $LogicAppUri
)

# This provides a way to collect all logs for a single run via the RunId correlation id.
# Correlation Run Id (32 hex chars) for this execution. Appended to all log lines.
$script:RunId = [guid]::NewGuid().ToString('N')

# Record run start timestamp (UTC) early for later duration computatio
if (-not $RunStartUtc) { $RunStartUtc = (Get-Date).ToUniversalTime() }

# Enhanced Per-connector KQL mappings with hardcoded metadata from AllDataConnectorDefinitions.json
# Each entry includes: Id, Title, Publisher, ConnectivityCriteria, and Kql for 24h usage metrics
$ConnectorInfo = @(
    # Each key = connector Kind/ID; value = hashtable with enhanced metadata and KQL
    # Alphabetical order maintained for readability & merge clarity.
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
        ActivityKql     = 'union ABNORMAL_THREAT_MESSAGES_CL, ABNORMAL_CASES_CL | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AwsS3'
        Title           = 'Amazon Web Services S3'
        Publisher       = 'Amazon'
        ConnectivityKql = 'AWSCloudTrail | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'AWSCloudTrail | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AWS'
        Title           = 'Amazon Web Services'
        Publisher       = 'Amazon'
        ConnectivityKql = @(
            'AWSCloudTrail | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'AWSGuardDuty | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true AWSGuardDuty, AWSCloudTrail | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AzureActiveDirectory'
        Title           = 'Azure Active Directory'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'SigninLogs | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'AuditLogs | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'AzureActiveDirectoryIdentityProtection'
        Title           = 'Azure Active Directory Identity Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Azure Active Directory Identity Protection" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'

        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(24h) | where ProductName == "Azure Active Directory Identity Protection" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'AzureActivity'
        Title           = 'Azure Activity'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'AzureActivity | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'AzureActivity | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'AzureAdvancedThreatProtection'
        Title           = 'Azure Advanced Threat Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Azure Advanced Threat Protection" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(24h) | where ProductName == "Azure Advanced Threat Protection" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'AzureSecurityCenter'
        Title           = 'Subscription-based Microsoft Defender for Cloud (Legacy)'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'SecurityAlert | where ProductName == "Azure Security Center" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'SecurityRecommendation | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(24h) | where ProductName == "Azure Security Center" | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'CEF'
        Title           = 'Common Event Format'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'CommonSecurityLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'CefAma'
        Title           = 'Common Event Format (AMA)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'CommonSecurityLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'CommonSecurityLog'
        Title           = 'Common Security Log'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'CommonSecurityLog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'CommonSecurityLog | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'DDOS'
        Title           = 'Azure DDoS Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'AzureDiagnostics | where ResourceType == "PUBLICIPADDRESSES" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'AzureDiagnostics | where TimeGenerated >= ago(24h) | where ResourceType == "PUBLICIPADDRESSES" | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'DNS'
        Title           = 'DNS'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'DnsEvents | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'DnsEvents | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'GCPIAMDataConnector'
        Title           = 'Google Cloud Platform IAM'
        Publisher       = 'Google'
        ConnectivityKql = 'GCP_IAM_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'GCP_IAM_CL | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftCloudAppSecurity'
        Title           = 'Microsoft Cloud App Security'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'McasShadowItReporting | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'McasShadowItReporting | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftDefenderAdvancedThreatProtection'
        Title           = 'Microsoft Defender Advanced Threat Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = @(
            'DeviceEvents | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)',
            'DeviceFileEvents | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        )
        ActivityKql     = 'union isfuzzy=true DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftDefenderForCloudTenantBased'
        Title           = 'Microsoft Defender for Cloud (Tenant-based)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Azure Security Center" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where ProductName == "Azure Security Center" | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftDefenderThreatIntelligence'
        Title           = 'Microsoft Defender Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftPurviewInformationProtection'
        Title           = 'Microsoft Purview Information Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'MicrosoftPurviewInformationProtection | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'MicrosoftPurviewInformationProtection | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'MicrosoftThreatIntelligence'
        Title           = 'Microsoft Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'MicrosoftThreatProtection'
        Title           = 'Microsoft Threat Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName in("Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Microsoft Cloud App Security", "Microsoft 365 Defender", "Azure Active Directory Identity Protection") | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'        
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(24h) | where ProductName in("Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", "Microsoft Cloud App Security", "Microsoft 365 Defender", "Azure Active Directory Identity Protection") | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'Office365'
        Title           = 'Office 365'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'OfficeActivity | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'OfficeActivity | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'OfficeATP'
        Title           = 'Office Advanced Threat Protection'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProviderName == "OATP" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(24h) | where ProviderName == "OATP" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerted), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'OfficeIRM'
        Title           = 'Office Insider Risk Management'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityAlert | where ProductName == "Microsoft 365 Insider Risk Management" | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityAlert | where TimeGenerated >= ago(24h) | where ProductName == "Microsoft 365 Insider Risk Management" | extend alertWasCustomized = bag_has_key(todynamic(ExtendedProperties), "OriginalProductName") | where alertWasCustomized == false | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'OktaSSO'
        Title           = 'Okta Single Sign-On'
        Publisher       = 'Okta'
        ConnectivityKql = 'OktaV2_CL | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'OktaV2_CL | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'PremiumMicrosoftDefenderForThreatIntelligence'
        Title           = 'PremiumMicrosoftDefenderForThreatIntelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'SecurityEvents'
        Title           = 'Security Events'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'SecurityEvent | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'SecurityEvent | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'Syslog'
        Title           = 'Syslog'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Syslog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Syslog | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'SyslogAma'
        Title           = 'Syslog (AMA)'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'Syslog | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'Syslog | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ThreatIntelligence'
        Title           = 'Threat Intelligence'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ThreatIntelligenceTaxii'
        Title           = 'Threat Intelligence TAXII'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'ThreatIntelligenceUploadIndicatorsAPI'
        Title           = 'Threat Intelligence Upload Indicators API'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'ThreatIntelligenceIndicator | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'ThreatIntelligenceIndicator | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'WindowsFirewall'
        Title           = 'Windows Firewall'
        Publisher       = 'Microsoft'
        ConnectivityKql = 'WindowsFirewall | summarize LastLogReceived = max(TimeGenerated) | project IsConnected = LastLogReceived > ago(7d)'
        ActivityKql     = 'WindowsFirewall | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }, 
    @{
        Id              = 'WindowsForwardedEvents'
        Title           = 'Windows Forwarded Events'
        Publisher       = 'Microsoft'
        ConnectivityKql = ''
        ActivityKql     = 'WindowsEvent | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    },
    @{
        Id              = 'WindowsSecurityEvents'
        Title           = 'Windows Security Events via AMA'
        Publisher       = 'Microsoft'
        ConnectivityKql = ''
        ActivityKql     = 'SecurityEvent | where TimeGenerated >= ago(24h) | summarize LastLogTime=max(TimeGenerated), LogsLastHour=countif(TimeGenerated >= ago(1h)), TotalLogs24h=count() | project LastLogTime, LogsLastHour, TotalLogs24h'
    }
)

function Write-Log {
    # PURPOSE: Centralized logging helper with level filtering.
    <#
  .SYNOPSIS
  Writes a structured log line with timestamp and level.
  .DESCRIPTION
  Outputs a log entry formatted as [ISO8601][LEVEL] with optional correlation id. DEBUG messages suppressed unless -VerboseLogging switch is set.
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
    Write-Information "[$ts][$Level]$cid $Message"
}

# Simple exponential backoff retry helper (for transient KQL failures, etc.)
function Invoke-WithRetry {
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
            # Use interpolated string with subexpressions for clarity & safe colon delimiter
            Write-Log -Level WARN -Message "$OperationName failed attempt $($attempt): $($_.Exception.Message)"
            if ($attempt -ge $MaxAttempts) { break }
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 30)
        }
    }
    if ($lastError) { throw "${OperationName} failed after $MaxAttempts attempts: $($lastError.Exception.Message)" }
}

# Helper to robustly resolve connector Kind with source tracking
function Resolve-Connector {
    # PURPOSE: Determine the best Id value for a connector to use in Logic App payload and $ConnectorInfo lookups.
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
    # foreach ($p in $Connector.PSObject.Properties) {
    #     # Generic scan of any property whose name includes 'kind'
    #     if ($p.Name -match 'kind' -and $p.Value -and -not ($candidates.Kind -contains $p.Value)) {
    #         $candidates += [pscustomobject]@{Kind = $p.Value; Source = $p.Name; Title = $p.Title; Publisher = $p.Publisher } 
    #     }
        
    # }
    $chosen = $null
    if ($candidates.Count -gt 0) {
        $chosen = $candidates | Where-Object { $_.Kind -and $_.Kind -ne 'DataConnector' } | Select-Object -First 1
        if (-not $chosen) {
            $chosen = $candidates | Select-Object -First 1 
        }
    }
    
    # Normalize Kind to string for processing
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
    
    # If $Connector.ConnectorUiConfigTitle and/or $Connector.ConnectorUiConfigPublisher is null or whitespace, try to match $idValue with $ConnectorInfo Title and Publisher values.
    $resolvedTitle = $Connector.ConnectorUiConfigTitle
    $resolvedPublisher = $Connector.ConnectorUiConfigPublisher
    if ([string]::IsNullOrWhiteSpace($resolvedTitle) -or [string]::IsNullOrWhiteSpace($resolvedPublisher)) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
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
    if (-not $resolvedConnectivityCriteria) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
        if ($infoMatch -and $infoMatch.ConnectivityCriteria) {
            $resolvedConnectivityCriteria = $infoMatch.ConnectivityCriteria
        }
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
    if (-not $resolvedConnectivityKQL) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
        if ($infoMatch -and $infoMatch.ConnectivityKql) {
            $resolvedConnectivityKQL = $infoMatch.ConnectivityKql
        }
    }

    # If $Connector.ConnectorUiConfigConnectivityCriterion has one or more property of type = "IsConnectedQuery", collect their values as an array and assign to ConnectivityCriteria; otherwise, fallback to $ConnectorInfo lookup.
    $resolvedActivityKQL = $null
    $resolvedActivityCriteria = $null
    if (-not $resolvedActivityCriteria) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
        if ($infoMatch -and $infoMatch.ActivityKql) {
            $resolvedConnectivityCriteria = $infoMatch.ConnectivityCriteria
        }
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
    if (-not $resolvedActivityKQL) {
        $infoMatch = $ConnectorInfo | Where-Object { $_.Id -ieq $idValue } | Select-Object -First 1
        if ($infoMatch -and $infoMatch.ActivityKql) {
            $resolvedActivityKQL = $infoMatch.ActivityKql
        }
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
    # PURPOSE: Simple GUID pattern validation (no ARM lookup performed).
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
    # PURPOSE: Validate RG name locally to fail fast before API calls.
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
    # PURPOSE: Validate Log Analytics workspace naming rules.
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
    # PURPOSE: Obtain principal ObjectId for UAMI (order: parameter > variable > directory lookup).
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
    # PURPOSE: Ensure required Az.* module is available (tries install when missing - may be blocked in sandbox).
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
        Write-Log -Level WARN -Message "Module '$Name' not found in environment; attempting install (may fail in Automation sandbox)."
        try {
            Install-Module -Name $Name -Force -Scope CurrentUser -ErrorAction Stop 
        }
        catch {
            Write-Log -Level WARN -Message "Install of $Name failed: $($_.Exception.Message)" 
        }
    }
    Import-Module $Name -ErrorAction Stop
}

function Get-ConnectivityResults {
    # PURPOSE: Execute connectivity criteria KQL queries and return overall connectivity status
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
                # Parse the result to determine connectivity
                $isConnected = $false
                if ($queryResult.Tables -and $queryResult.Tables.Count -gt 0) {
                    foreach ($table in $queryResult.Tables) {
                        if ($table.Rows.Count -gt 0) {
                            $row = $table.Rows[0]
                            $cols = $table.Columns.Name
                            $isConnectedIdx = [Array]::IndexOf($cols, 'IsConnected')
                            if ($isConnectedIdx -ge 0 -and $row[$isConnectedIdx] -is [bool]) {
                                $isConnected = [bool]$row[$isConnectedIdx]
                            }
                            elseif ($isConnectedIdx -ge 0) {
                                # Try to parse as string boolean
                                $val = $row[$isConnectedIdx].ToString().ToLower()
                                $isConnected = $val -eq 'true' -or $val -eq '1'
                            }
                        }
                    }
                }
                
                Write-Log -Level DEBUG -Message "Connectivity criteria $i for '$ConnectorName': IsConnected=$isConnected"
                
                # If ANY query returns true, set overall result to true
                if ($isConnected) {
                    $overallConnected = $true
                    Write-Log -Level DEBUG -Message "Overall connectivity for '$ConnectorName': true (criteria $i passed)"
                    # Continue checking remaining queries for completeness but result is already true
                }
            }
            else {
                Write-Log -Level WARN -Message "Connectivity criteria $i for '$ConnectorName' failed: $($queryResult.Error.Message)"
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
    # PURPOSE: Execute KQL queries for a connector and extract ingestion timestamps/counts.
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
    $connectivityQueries = @()
    if ($ConnectivityKql) {
        if ($ConnectivityKql -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($ConnectivityKql)) {
                $connectivityQueries = @($ConnectivityKql)
            }
        }
        elseif ($ConnectivityKql -is [array]) {
            $connectivityQueries = $ConnectivityKql | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
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
    
    try {
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
                        # Parse IsConnected column
                        $isConnected = $false
                        if ($result.Results -and $result.Results.Count -gt 0) {
                            foreach ($table in $result.Results) {
                                if ($table.IsConnected) {
                                    $isConnected = $true
                                }
                                else {
                                    $isConnected = $false
                                }
                            }
                        }
                        
                        Write-Log -Level DEBUG -Message "$queryLabel for '$ConnectorName': IsConnected=$isConnected"
                        
                        # If ANY connectivity query returns true, set IsConnected to true
                        if ($isConnected) {
                            $metrics.IsConnected = $true
                            Write-Log -Level DEBUG -Message "Connectivity established for '$ConnectorName' via query $($i+1)"
                        }
                    }
                    else {
                        Write-Log -Level WARN -Message "$queryLabel for '$ConnectorName' returned error: $($result.Error.Message)"
                    }
                }
                catch {
                    Write-Log -Level WARN -Message "$queryLabel for '$ConnectorName' exception: $($_.Exception.Message)"
                }
            }
        }
        
        # ===== PART 2: Execute ActivityKql queries to get activity metrics =====
        if ($activityQueries.Count -gt 0) {
            Write-Log -Level DEBUG -Message "Executing $($activityQueries.Count) ActivityKql quer(y/ies) for '$ConnectorName'"
            
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
                    Write-Log -Level WARN -Message "KQL error $($queryLabel) for '${ConnectorName}' (DurationMs=$($sw.ElapsedMilliseconds)): $($result.Error.Message)"
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
                    }
                
                    foreach ($tableObj in $result.Tables) {
                        if ($tableObj.Rows.Count -gt 0) {
                            $row = $tableObj.Rows[0]
                            $cols = $tableObj.Columns.Name
                            $idxLast = [Array]::IndexOf($cols, 'LastLogTime')
                            if ($idxLast -lt 0) {
                                $idxLast = [Array]::IndexOf($cols, 'TimeGenerated') 
                            }
                            $idxHour = [Array]::IndexOf($cols, 'LogsLastHour')
                            $idxTotal = [Array]::IndexOf($cols, 'TotalLogs24h')
                        
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
                    if ($totalRows -gt 0) {
                        $data = $result.Results[0]
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
        else {
            # No activity queries provided
            $metrics.QueryStatus = 'NoActivityKql'
            Write-Log -Level DEBUG -Message "No ActivityKql provided for connector '$ConnectorName'"
        }
    }
    catch {
        Write-Log -Level WARN -Message "KQL exception for connector '$ConnectorName': $($_.Exception.Message)"; $metrics.QueryStatus = 'QueryFailed'
    }
      
    return $metrics
}

# Pure ingestion classification helper (supports unit testing)
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
        [int] $ActiveThresholdHours = 12,
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


    $resolved = Resolve-Connector -Connector $Connector
  
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
        # Special case: no mapping (NoKql) and no logs -> distinct status
        if ($statusInfo.LogMetrics.QueryStatus -eq 'NoKql' -and -not $lastLogTimeValue) {
            $statusInfo.OverallStatus = 'NoKqlAndNoLogs'
        }
        else {
            # Fallback to configuration-based classification
            if ($allValues -contains 'enabled' -or $allValues -contains 'connected' -or $allValues -contains 'active') {
                $statusInfo.OverallStatus = 'ConfiguredButNoLogs'
            }
            elseif ($allValues -contains 'disabled' -or $allValues -contains 'disconnected' -or $allValues -contains 'inactive') {
                $statusInfo.OverallStatus = 'Disabled'
            }
            elseif ($allValues -contains 'error' -or $allValues -contains 'failed') {
                $statusInfo.OverallStatus = 'Error'
            }
        }
        $statusInfo.IsConnected = $ingestion.IsConnected
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

# ---------- Resolve Workspace Resource (multi-strategy) ----------
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
    # PURPOSE: Safely fetch Automation variables (with optional requirement enforcement).
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

# Normalize & diagnose possible hidden characters in names
function Get-StringDiagnostics {
    # PURPOSE: Help detect invisible characters in resource names (common source of lookup failures).
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

# ---------- Automatic Role Assignment Helper ----------
function Invoke-AutomaticReaderRoleAssignment {
    # PURPOSE: If connector retrieval fails (likely RBAC), attempt to grant Sentinel Reader to MI.
    param([string]$Scope)
    $roleName = 'Microsoft Sentinel Reader'
    $miObjectId = Resolve-ManagedIdentityObjectId -ClientId $UmiClientId
    Write-Log -Level WARN -Message "Attempting automatic role assignment due to access failure. Role='$roleName' ObjectId=$miObjectId Scope=$Scope"
    if ($WhatIf) {
        Write-Log -Level INFO -Message "WhatIf: Would assign role '$roleName' to ObjectId $miObjectId at $Scope"
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

if ($env:MSP_SKIP_CONNECTOR_RUN -eq '1') {
    Write-Log -Level INFO -Message 'MSP_SKIP_CONNECTOR_RUN=1 detected; skipping main execution (test harness mode).'
    return
}

Write-Log -Level INFO -Message 'Starting Sentinel Data Connectors management runbook.'
Write-Log -Level INFO -Message "RunId=$script:RunId"

# ---------- Detect Execution Environment ----------
$IsAzureAutomation = $env:AUTOMATION_ASSET_ACCOUNTID -or (Test-Path Variable:\AutomationAccountId)
Write-Log -Level INFO -Message "Execution environment: $(if ($IsAzureAutomation) { 'Azure Automation' } else { 'Local/Manual' })"

# ---------- Retrieve Configuration (Automation Variables or Parameters) ----------
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
    if (-not $LogicAppUri) { $LogicAppUri = Get-Var -Name 'DATACONNECTOR_LA_URI' -Optional }
    
    Write-Log -Level INFO -Message "Variables loaded: RG=$ResourceGroupName Workspace=$WorkspaceName LogicAppUri=$LogicAppUri UmiClientId=$UmiClientId"
}
else {
    Write-Log -Level INFO -Message 'Using parameters provided for local execution...'
    $UmiClientId = $null  # Not used in local execution
    
    # Validate required parameters for local execution
    if (-not $SubscriptionId) { throw 'SubscriptionId parameter is required for local execution' }
    if (-not $ResourceGroupName) { throw 'ResourceGroupName parameter is required for local execution' }
    if (-not $WorkspaceName) { throw 'WorkspaceName parameter is required for local execution' }
    
    Write-Log -Level INFO -Message "Parameters: RG=$ResourceGroupName Workspace=$WorkspaceName SubscriptionId=$SubscriptionId"
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

# ---------- Authenticate ----------
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
        Write-Log -Level INFO -Message "Connecting with User-Assigned Managed Identity (ClientId=$UmiClientId)"
        try {
            Connect-AzAccount -Identity -AccountId $UmiClientId -ErrorAction Stop | Out-Null 
        }
        catch {
            throw "Failed to authenticate with managed identity clientId=$UmiClientId : $($_.Exception.Message)" 
        }
    }
}
else {
    # Local execution: Use existing context or prompt for interactive login
    Write-Log -Level INFO -Message 'Local execution: Checking for existing Azure authentication...'
    try {
        $context = Get-AzContext -ErrorAction Stop
        if ($context -and $context.Account) {
            Write-Log -Level INFO -Message "Using existing authentication: Account=$($context.Account.Id) Tenant=$($context.Tenant.Id)"
        }
        else {
            Write-Log -Level INFO -Message 'No existing context found. Initiating interactive login...'
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $context = Get-AzContext
            Write-Log -Level INFO -Message "Authenticated interactively: Account=$($context.Account.Id)"
        }
    }
    catch {
        Write-Log -Level WARN -Message 'No existing context found. Initiating interactive login...'
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $context = Get-AzContext
            Write-Log -Level INFO -Message "Authenticated interactively: Account=$($context.Account.Id)"
        }
        catch {
            throw "Failed to authenticate: $($_.Exception.Message)" 
        }
    }
}

if ($SubscriptionId) {
    try {
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        Write-Log -Level INFO -Message "Context set to subscription $SubscriptionId"
    }
    catch {
        throw "Failed setting subscription context: $($_.Exception.Message)" 
    }
}
else {
    $SubscriptionId = (Get-AzContext).Subscription.Id
    Write-Log -Level INFO -Message "Derived subscription id from context: $SubscriptionId"
}

# ---------- Load Required Modules ----------
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
Write-Log -Level INFO -Message "Workspace resolved (resourceId): $workspaceId"
# Split the workspace ID
if ([string]::IsNullOrWhiteSpace($workspace.CustomerId) -eq $false) {
    $WorkspaceCustomerId = $workspace.CustomerId.ToString()
    Write-Log -Level INFO -Message "Workspace CustomerId (GUID for KQL): $WorkspaceCustomerId"
}
else {
    Write-Log -Level WARN -Message 'Workspace CustomerId not present; KQL queries may not function.'
    $WorkspaceCustomerId = $null
}

# ---------- Retrieve Data Connectors ----------
Write-Log INFO 'Retrieving Sentinel Data Connectors for workspace...'
try {
    # Primary attempt to enumerate all data connectors
    $connectors = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop | Sort-Object Name
}
catch {
    Write-Log -Level WARN -Message "Initial connector retrieval failed: $($_.Exception.Message)"
    Invoke-AutomaticReaderRoleAssignment -Scope $workspaceId
    Start-Sleep -Seconds 5
    try {
        Write-Log INFO 'Retrying connector retrieval after role assignment attempt.'
        $connectors = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop | Sort-Object Name
    }
    catch {
        Write-Log ERROR "Retry failed: $($_.Exception.Message)"
        throw
    }
}

if (-not $connectors) {
    Write-Log -Level WARN -Message 'No data connectors returned.' 
}
else {

    $connectTxt = $connectors | Format-List * | Out-String
    Write-Log -Level DEBUG -Message "Connectors: $connectTxt"
    
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
            #$resolved = Resolve-Connector -Connector $_
            # Ensure the resolved Kind is applied back to object prior to metrics call
            try {
                if ($_.PSObject.Properties.Name -contains 'Kind') { $_.Kind = $resolved.Kind } else { $_ | Add-Member -NotePropertyName Kind -NotePropertyValue $resolved.Kind -Force }
            }
            catch {}
            $statusInfo = Get-ConnectorStatus -Connector $_ -WorkspaceCustomerId $using:WorkspaceCustomerId
            $lastLogUtc = $statusInfo.LogMetrics.LastLogTime
            $hoursSince = $statusInfo.HoursSinceLastLog
            [pscustomobject]@{
                Name              = $statusInfo.Name.Trim()
                Id                = $statusInfo.Id.Trim()
                Title             = $statusInfo.Title.Trim()
                Publisher         = $statusInfo.Publisher.Trim()
                Kind              = $statusInfo.Kind.Trim()
                Status            = $statusInfo.OverallStatus
                LastLogTime       = $lastLogUtc
                LogsLastHour      = $statusInfo.LogMetrics.LogsLastHour
                TotalLogs24h      = $statusInfo.LogMetrics.TotalLogs24h
                QueryStatus       = $statusInfo.LogMetrics.QueryStatus
                HoursSinceLastLog = $hoursSince
                IsConnected       = $statusInfo.LogMetrics.IsConnected
                StatusDetails     = ($statusInfo.RawProperties -join ';')
                Workspace         = $using:WorkspaceName
                Subscription      = $using:SubscriptionId
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
            #$kindResolution = Resolve-Connector -Connector $connector

            $statusInfo = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $WorkspaceCustomerId
            
            $record = [ordered]@{
                Name              = $statusInfo.Name.Trim()
                Kind              = $statusInfo.Kind.Trim()
                Id                = $statusInfo.Id.Trim()
                Title             = $statusInfo.Title.Trim()
                Publisher         = $statusInfo.Publisher.Trim()
                Status            = $statusInfo.OverallStatus
                LastLogTime       = $statusInfo.LogMetrics.LastLogTime
                LogsLastHour      = $statusInfo.LogMetrics.LogsLastHour
                TotalLogs24h      = $statusInfo.LogMetrics.TotalLogs24h
                QueryStatus       = $statusInfo.LogMetrics.QueryStatus
                HoursSinceLastLog = $statusInfo.LogMetrics.HoursSinceLastLog
                IsConnected       = $statusInfo.LogMetrics.IsConnected
                NoLastLog         = $statusInfo.LogMetrics.NoLastLog
                DataTypeStatus    = @()
                StatusDetails     = ($statusInfo.RawProperties -join '; ')
                Workspace         = $WorkspaceName
                Subscription      = $SubscriptionId
                Tenant            = $TenantId
            }
            [void]$(foreach ($key in $statusInfo.StateDetails.Keys) {
                    # Add any additional state detail properties (dynamic set per connector)
                    if (-not $record.Contains($key)) {
                        $record[$key] = $statusInfo.StateDetails[$key]
                    } 
                })
            $emissionCount++
            Write-Log -Level DEBUG -Message "Emitting record #$emissionCount for connector: Name='$($record.Name)' Kind='$($record.Kind)' Id='$($record.Id)'"
            # Emit the record ONCE per connector (outside the StateDetails loop)
            [PSCustomObject]$record
        }
        Write-Log -Level INFO -Message "ForEach-Object completed. Emitted $emissionCount records. Summary contains $($summary.Count) items"
    }

    # ------------------------------------------------------------------
    # Requirement: Output an object collection with specific fields
    # Fields: Name, Kind, Status, LastLogTime, LogsLastHour,
    #         QueryStatus, MappingFound, StatusDetails
    # Produce a clean collection prior to consolidated object.
    $ConnectorCollection = $summary #| Select-Object Id, Name, Kind, Status, LastLogTime, LogsLastHour, TotalLogs24h, QueryStatus, HoursSinceLastLog, StatusDetails, Workspace, Subscription, Title, Publisher, IsConnected, NoLastLog

    Write-Log -Level INFO -Message "After Select-Object: ConnectorCollection contains $($ConnectorCollection.Count) items"
    Write-Log -Level DEBUG -Message "ConnectorCollection unique names: $(($ConnectorCollection | Select-Object -ExpandProperty Name -Unique | Measure-Object).Count)"

    # ------------------------------------------------------------------
    # Deduplication/Merge: Connectors with the same Id represent the same underlying integration.
    # Group by Id and merge records for each unique connector.
    #
    # Merge approach:
    #   Group by Id (case-insensitive)
    #   If group count > 1:
    #       Prefer non-GUID Name over GUID Name for display
    #       Merge StatusDetails (semicolon joining unique tokens)
    #       Use latest LastLogTime and associated metrics
    #       Prefer best Status (ActivelyIngesting > RecentlyActive > Stale > ConfiguredButNoLogs > Disabled > Error > Unknown)
    #       Combine all unique property values
    # Logging: emit INFO with merge summary for transparency.
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

    # ------------------------------------------------------------------
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
                # Status upgrade logic mirrors Get-IngestionStatus thresholds (1h / 24h) if current status is placeholder
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
    # $ConnectorCollection | ConvertTo-Json -Depth 6 | Write-Information
    $ConnectorCollection | Sort-Object Id | Format-Table Name, Id, Title, Publisher, Status, LastLogTime, LogsLastHour, TotalLogs24h, QueryStatus, IsConnected -AutoSize

    # Emit run summary object (second JSON line) for downstream automation if desired
    $runEnd = (Get-Date).ToUniversalTime()
    $statusCounts = @{}
    foreach ($g in $statusGroups) { $statusCounts[$g.Name] = $g.Count }
    $maxHours = ($ConnectorCollection | Where-Object { $_.HoursSinceLastLog -ne $null } | Measure-Object -Property HoursSinceLastLog -Maximum).Maximum
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
    #$summaryObj | ConvertTo-Json -Depth 5 | Write-Information
}

# Logic App posting: already resolved from automation variable earlier (DATACONNECTOR_LA_URI)
if ($LogicAppUri) {
    # Optional outbound push of results to Logic App (if uri provided)
    try {
        $payload = $ConnectorCollection | ConvertTo-Json -Depth 6
        Write-Log INFO "Posting $($ConnectorCollection.Count) records to Logic App." 
        Invoke-RestMethod -Method Post -Uri $LogicAppUri -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Log INFO 'Logic App post succeeded.'
    }
    catch {
        Write-Log ERROR "Logic App post failed: $($_.Exception.Message)" 
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