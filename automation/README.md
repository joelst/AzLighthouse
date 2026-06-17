# MSSP SOC Azure Onboarding

## Overview

This solution deploys an Azure Automation account with runbooks to manage Microsoft Sentinel data connectors and service principal
credentials for MSSP (Managed Security Service Provider) environments. The automation enables centralized monitoring of Sentinel
data connector health and automated credential rotation.

> **I did not develop the Logic Apps so they are not included in this repo.**

## Architecture

The deployment includes:

1. **Azure Automation Account** - Hosts PowerShell 7.4 runbooks with scheduled execution
2. **User-Assigned Managed Identity (UAMI)** - Provides secure authentication to Azure resources
3. **Runbooks**:
  - `Get-DataConnectorStatus` - Monitors Sentinel data connector health and ingestion metrics
  - `Update-AppRegistrationCredential` - Rotates service principal credentials automatically
  - `Get-SentinelPricing` - Retrieves pricing tier information for Sentinel workspaces
  - `Invoke-AzSentinelSearchJob` - Creates Sentinel search jobs in Log Analytics
  - `Get-AzurePolicies` - Collects Azure Policy assignment and definition inventory
4. **Logic App Integration** - Sends connector status, credential updates, pricing data, and policy inventory to the MSSP tenant

## Prerequisites

Before deploying, ensure you have:

- **Azure Subscription** with Contributor access
- **Microsoft Sentinel workspace** deployed
- **User-Assigned Managed Identity (UAMI)** created with appropriate permissions:
  - `Microsoft Sentinel Reader` role on Sentinel workspace
  - `Log Analytics Reader` role on Log Analytics workspace
  - `Reader` role on subscription (for enumerating resources)
- **Logic App endpoint URI** in MSSP tenant for receiving status updates
- **PowerShell 7.4 runtime** configured in Automation Account

### Required Permissions for UAMI

The managed identity needs the following role assignments:

```powershell
# Sentinel Reader role
New-AzRoleAssignment -ObjectId <UAMI-ObjectId> -RoleDefinitionName "Microsoft Sentinel Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

# Log Analytics Reader role
New-AzRoleAssignment -ObjectId <UAMI-ObjectId> -RoleDefinitionName "Log Analytics Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"
```

## Deployment Options

### Option 1: Deploy via Azure Portal

Click the button below to deploy directly to your Azure subscription:

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Fautomation%2FautomationAccount.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

Customized UI
<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Fautomation%2FautomationAccount.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Fautomation%2FcreateUiDefinition.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

**Deployment Parameters:**

| Parameter                               | Description                                                                | Required |
| --------------------------------------- | -------------------------------------------------------------------------- | -------- |
| `automationAccountName`                 | Automation Account name                                                    | Yes      |
| `userAssignedIdentityName`              | Existing UAMI name (same resource group as deployment)                     | Yes      |
| `userAssignedIdentityClientId`          | UAMI client ID (GUID)                                                      | Yes      |
| `sentinelWorkspaceResourceId`           | Full workspace resource ID or workspace name (same RG/sub as deployment)   | Yes      |
| `servicePrincipalCredentialLogicAppUri` | Logic App callback URL for credential updates (secure string)              | Yes      |
| `dataConnectorLogicAppUri`              | Logic App callback URL for connector status updates (secure string)        | Yes      |
| `pricingTierLogicAppUri`                | Pricing tier API callback URL (secure string)                              | Yes      |
| `policyMonitoringLogicAppUri`           | Logic App callback URL for policy inventory updates (secure string)        | Yes      |
| `servicePrincipalCredentialAppReg`      | App registration display name managed by credential runbook                | Yes      |
| `runtimeEnvironmentName`                | Automation runtime environment name (2-64 chars, alphanumeric + `_` / `-`) | Yes      |
| `runtimeVersion`                        | Runtime version (`7.2` or `7.4`)                                           | Yes      |
| `*RunbookName` / `*RunbookContentUri`   | Runbook names and runbook content URIs                                     | Optional |

### Option 2: Clone repo and deploy with PowerShell

This option avoids the portal deployment blade and allows repeatable deployment from source control.

```powershell
# 1) Clone and open the repo
git clone https://github.com/joelst/AzLighthouse.git
Set-Location .\AzLighthouse\automation

# 2) Sign in and set target subscription
Connect-AzAccount
Set-AzContext -Subscription '<subscription-id>'

# 3) Create deployment resource group if needed
$resourceGroupName = 'SOC-Automation-RG'
$location = 'eastus'
New-AzResourceGroup -Name $resourceGroupName -Location $location -Force
```

Create a secure parameter file (recommended) so signed Logic App URLs are not echoed in terminal history.

`automation.parameters.json`

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "automationAccountName": { "value": "SOC-Automation" },
    "userAssignedIdentityName": { "value": "SOC-Sentinel-Ingestion-UMI" },
    "userAssignedIdentityClientId": { "value": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
    "sentinelWorkspaceResourceId": { "value": "/subscriptions/<sub-id>/resourceGroups/<workspace-rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" },
    "servicePrincipalCredentialLogicAppUri": { "value": "https://prod-00.<region>.logic.azure.com/workflows/...&sig=..." },
    "dataConnectorLogicAppUri": { "value": "https://prod-00.<region>.logic.azure.com/workflows/...&sig=..." },
    "pricingTierLogicAppUri": { "value": "https://prod-00.<region>.logic.azure.com/workflows/...&sig=..." },
    "policyMonitoringLogicAppUri": { "value": "https://prod-00.<region>.logic.azure.com/workflows/...&sig=..." },
    "servicePrincipalCredentialAppReg": { "value": "SOC-Sentinel-Ingestion" },
    "runtimeEnvironmentName": { "value": "PowerShell_74_SOC" },
    "runtimeVersion": { "value": "7.4" }
  }
}
```

Deploy:

```powershell
New-AzResourceGroupDeployment `
  -Name "automation-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -ResourceGroupName $resourceGroupName `
  -TemplateFile .\automationAccount.json -TemplateParameterFile .\automation.parameters.json `
  -Verbose
```

### Option 3: Clone repo and deploy with Azure CLI

```bash
# 1) Clone and open the repo
git clone https://github.com/joelst/AzLighthouse.git
cd AzLighthouse/automation

# 2) Sign in and set target subscription
az login
az account set --subscription <subscription-id>

# 3) Create resource group
RESOURCE_GROUP="SOC-Automation-RG"
LOCATION="eastus"
az group create --name $RESOURCE_GROUP --location $LOCATION

# 4) Deploy with a parameter file
az deployment group create \
  --name automation-$(date +%Y%m%d-%H%M%S) \
  --resource-group $RESOURCE_GROUP \
  --template-file ./automationAccount.json \
  --parameters @automation.parameters.json \
  --verbose
```

### Option 4: Use the end-to-end deployment script

Use `Deploy-AutomationTemplate.ps1` to run prerequisite checks, validate required inputs (including `automation.parameters.json`), deploy the template, optionally upload local runbook files, and validate deployment success.

```powershell
Set-Location .\automation

./Deploy-AutomationTemplate.ps1 `
  -subscriptionId '<subscription-id>' `
  -resourceGroupName 'SOC-Automation-RG' `
  -location 'eastus' `
  -createResourceGroup
```

With local runbook upload after deployment:

```powershell
./Deploy-AutomationTemplate.ps1 `
  -subscriptionId '<subscription-id>' `
  -resourceGroupName 'SOC-Automation-RG' `
  -location 'eastus' `
  -uploadLocalRunbooks `
  -runbookSourcePath .
```

## Required Inputs Checklist

Collect these before deployment:

1. Subscription ID where the Automation Account will be deployed.
2. Resource group name and region for the Automation Account.
3. Existing UAMI name and UAMI client ID.
4. Sentinel workspace identifier (workspace name or full resource ID).
5. Logic App callback URL for each workflow:
   - credential updates
   - data connector status
   - pricing tier
   - policy monitoring
6. Automation account name.
7. App registration display name for credential management.
8. Runtime environment name and version (`7.2` or `7.4`).

## Runbook Content: URL-based vs Local Upload

The ARM template deploys runbooks using `publishContentLink.uri`, so by default it expects reachable URIs for runbook scripts.

### Option A: Keep URL-based runbook deployment (default)

Use raw GitHub URLs (or any HTTPS location reachable by Azure Automation) in these parameters:

1. `servicePrincipalCredentialRunbookContentUri`
2. `connectorRunbookContentUri`
3. `pricingRunbookContentUri`
4. `searchJobRunbookContentUri`
5. `policyRunbookContentUri`

### Option B: Upload runbooks from local files after template deployment

Yes, runbooks can be uploaded from local files instead of UI-provided URLs. In this approach, deploy infrastructure first and then import/publish scripts directly.

```powershell
$rg = 'SOC-Automation-RG'
$aa = 'SOC-Automation'

Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Type PowerShell -Name 'Update-AppRegistrationCredential' -Path .\Update-AppRegistrationCredential.ps1 -Force
Publish-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Name 'Update-AppRegistrationCredential'

Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Type PowerShell -Name 'Get-DataConnectorStatus' -Path .\Get-DataConnectorStatus.ps1 -Force
Publish-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Name 'Get-DataConnectorStatus'

Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Type PowerShell -Name 'Get-SentinelPricing' -Path .\Get-SentinelPricing.ps1 -Force
Publish-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Name 'Get-SentinelPricing'

Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Type PowerShell -Name 'Invoke-AzSentinelSearchJob' -Path .\Invoke-AzSentinelSearchJob.ps1 -Force
Publish-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Name 'Invoke-AzSentinelSearchJob'

Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Type PowerShell -Name 'Get-AzurePolicies' -Path .\Get-AzurePolicies.ps1 -Force
Publish-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa -Name 'Get-AzurePolicies'
```

Tip: if your organization disallows public script hosting, Option B is usually preferred.

## Post-Deployment Configuration

### 1. Configure Automation Variables

After deployment, add the following automation variables in the Azure Portal:

Navigate to: **Automation Account → Shared Resources → Variables**

| Variable Name           | Type   | Value                          | Used By                                 | Description                                  |
| ----------------------- | ------ | ------------------------------ | --------------------------------------- | -------------------------------------------- |
| `UMI_CLIENT_ID`         | String | UAMI Client ID (GUID)          | All runbooks                            | Application ID of the managed identity       |
| `UMI_OBJECT_ID`         | String | UAMI Object ID (GUID)          | All runbooks                            | Principal ID of the managed identity         |
| `SUBSCRIPTION_ID`       | String | Azure Subscription ID          | All runbooks                            | Target subscription containing Sentinel      |
| `RESOURCE_GROUP_NAME`   | String | Resource group name            | All runbooks                            | Where Sentinel workspace is located          |
| `WORKSPACE_NAME`        | String | Workspace name                 | All runbooks                            | Sentinel Log Analytics workspace name        |
| `DATACONNECTOR_API`     | String | Logic App endpoint             | `Get-DataConnectorStatus`               | MSSP tenant Logic App URI for status updates |
| `SEARCH_TABLE_NAME`     | String | Output table name              | `Invoke-AzSentinelSearchJob`            | Destination table for search results         |
| `SEARCH_QUERY`          | String | KQL query string               | `Invoke-AzSentinelSearchJob`            | KQL query to run as a search job             |
| `SEARCH_START_TIME_UTC` | String | ISO 8601 datetime (UTC)        | `Invoke-AzSentinelSearchJob`            | Start of search time range                   |
| `SEARCH_END_TIME_UTC`   | String | ISO 8601 datetime (UTC)        | `Invoke-AzSentinelSearchJob`            | End of search time range                     |
| `SEARCH_RETENTION_DAYS` | Int    | Number of days (e.g. `14`)     | `Invoke-AzSentinelSearchJob` (optional) | Retention period for search result table     |
| `SEARCH_LIMIT`          | Int    | Row limit (e.g. `100000`)      | `Invoke-AzSentinelSearchJob` (optional) | Maximum rows returned by search job          |
| `POLICYMONITORING_API`  | String | Logic App endpoint (encrypted) | `Get-AzurePolicies`                     | Logic App URI for policy inventory updates   |

### 2. Verify Deployment

Test the runbooks manually before relying on automated schedules:

1. Navigate to **Automation Account → Process Automation → Runbooks**
2. Select `Get-DataConnectorStatus`
3. Click **Start** and provide test parameters
4. Monitor job output in the **Output** tab
5. Verify data is sent to Logic App endpoint

## Runbook Details

### Get-DataConnectorStatus

**Purpose:** Monitors Microsoft Sentinel data connector health and ingestion metrics.

**Key Features:**

- Enumerates all Sentinel data connectors
- Executes KQL queries to determine connectivity status
- Calculates ingestion metrics (LastLogTime, LogsLastHour, TotalLogs24h)
- Classifies connector status (ActivelyIngesting, RecentlyActive, Stale, Disabled, etc.)
- Sends status updates to MSSP Logic App

**Status Classifications:**

- `ActivelyIngesting` - Logs received within last hour
- `RecentlyActive` - Logs received within last 24 hours
- `Stale` - Logs exist but last received >24h ago
- `ConfiguredButNoLogs` - Connector enabled but no logs observed
- `Disabled` - Connector is disabled
- `Error` - Query or processing error occurred

**Common Parameters:**

- `-VerboseLogging` - Enable detailed DEBUG logging
- `-WhatIf` - Preview changes without executing
- `-KindFilter` - Filter by connector kind (e.g., 'AzureActiveDirectory')
- `-NameFilter` - Filter by connector name
- `-ExcludeStatus` - Exclude specific statuses from output

### Update-AppRegistrationCredential

**Purpose:** Automates service principal credential rotation for enhanced security.

**Key Features:**

- Monitors app registration credential expiration (configurable threshold)
- Creates new client secrets with configurable validity periods
- Automatically removes expired credentials
- Sends credential notifications to MSSP Logic App endpoint
- Provides comprehensive execution summary with statistics
- Handles both existing app registrations and creates new ones when needed

**Recent Updates (2024-10-24):**

- Fixed Write-AppGroupSummary parameter type issue for better object handling
- Enhanced error handling for role assignment conflicts
- Improved summary reporting with detailed application status

**Parameters:**

- `-UMIId` - User Managed Identity Client ID for authentication
- `-DaysBeforeExpiration` - Days before expiration to trigger rotation (default: 30)
- `-CredentialValidDays` - How long new credentials remain valid (default: 180)
- `-SecretLAUri` - Logic App endpoint for credential notifications
- `-AppRegName` - Application registration name pattern to manage
- `-CreateNewAppReg` - Force creation of new app registration

### Invoke-AzSentinelSearchJob

**Purpose:** Creates a Sentinel search job table in Log Analytics using Azure Automation.

**Production behavior:**

- Resolves inputs from runbook parameters first, then environment/Automation variables
- Validates all required inputs before any Azure API call
- Authenticates with **user-assigned managed identity only** (`Connect-AzAccount -Identity -AccountId <UAMI ClientId>`)
- Creates search table via `New-AzOperationalInsightsSearchTable`
- Normalizes output table name with `_SRCH` suffix when missing
- Emits structured output for downstream automation

**Parameters and fallback variables:**

| Parameter           | Variable Fallback           | Required |
| ------------------- | --------------------------- | -------- |
| `UmiClientId`       | `UMI_ID` or `UMI_CLIENT_ID` | Yes      |
| `SubscriptionId`    | `SUBSCRIPTION_ID`           | Yes      |
| `ResourceGroupName` | `RESOURCE_GROUP_NAME`       | Yes      |
| `WorkspaceName`     | `WORKSPACE_NAME`            | Yes      |
| `OutputTableName`   | `SEARCH_TABLE_NAME`         | Yes      |
| `SearchQuery`       | `SEARCH_QUERY`              | Yes      |
| `StartSearchTime`   | `SEARCH_START_TIME_UTC`     | Yes      |
| `EndSearchTime`     | `SEARCH_END_TIME_UTC`       | Yes      |
| `RetentionInDays`   | `SEARCH_RETENTION_DAYS`     | No       |
| `Limit`             | `SEARCH_LIMIT`              | No       |

**UAMI role requirements (minimum):**

- `Log Analytics Contributor` on the target workspace scope (or equivalent custom role that allows search table creation)
- `Reader` on the workspace resource group/subscription for context and lookup operations

**Example runbook execution:**

```powershell
Invoke-AzSentinelSearchJob.ps1 `
  -UmiClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
  -SubscriptionId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
  -ResourceGroupName "rg-sentinel-prod" `
  -WorkspaceName "law-prod" `
  -OutputTableName "HeartbeatByIp" `
  -SearchQuery "Heartbeat | where TimeGenerated > ago(1d)" `
  -StartSearchTime "2026-02-20T00:00:00Z" `
  -EndSearchTime "2026-02-21T00:00:00Z" `
  -RetentionInDays 14 `
  -Limit 100000
```

### Get-AzurePolicies

**Purpose:** Collects Azure Policy assignments and definitions for a subscription and posts the inventory to a Logic App endpoint for MSSP visibility.

**Production behavior:**

- Resolves inputs from runbook parameters first, then environment variables, then Automation variables
- Validates all required inputs (GUIDs, HTTPS URI) before any Azure API call
- Authenticates with **user-assigned managed identity only** (`Connect-AzAccount -Identity -AccountId <UAMI ClientId>`)
- Enumerates policy assignments at subscription scope
- Resolves both policy definitions and policy set definitions (initiatives)
- Posts a slim JSON inventory payload to a Logic App endpoint with retry and backoff
- Emits a structured summary object for downstream automation and auditing
- Supports `-WhatIf` to preview without posting
- Never logs the full Logic App URI (SAS-protected webhook); only the host is logged

**Parameters and fallback variables:**

| Parameter                                    | Variable Fallback           | Required |
| -------------------------------------------- | --------------------------- | -------- |
| `LogicAppUri` (alias: `policyMonitoringApi`) | `POLICYMONITORING_API`      | Yes      |
| `UmiClientId` (alias: `UMIId`)               | `UMI_ID` or `UMI_CLIENT_ID` | Yes      |
| `SubscriptionId`                             | `SUBSCRIPTION_ID`           | Yes      |
| `WorkspaceName`                              | `WORKSPACE_NAME`            | Yes      |
| `IncludePolicyRule`                          | —                           | No       |
| `VerboseLogging`                             | `AZLH_VERBOSE_LOGGING`      | No       |

**UAMI role requirements (minimum):**

- `Reader` at subscription scope (covers `Microsoft.Authorization/policyAssignments/read`, `policyDefinitions/read`, and `policySetDefinitions/read`)

**Example runbook execution:**

```powershell
.\Get-AzurePolicies.ps1 `
  -UmiClientId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
  -SubscriptionId 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' `
  -WorkspaceName 'law-sentinel-eastus' `
  -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/.../triggers/manual/paths/invoke?...&sig=...'
```

**With full policy rules:**

```powershell
.\Get-AzurePolicies.ps1 `
  -UmiClientId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' `
  -SubscriptionId 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' `
  -WorkspaceName 'law-sentinel-eastus' `
  -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/...' `
  -IncludePolicyRule
```

## Troubleshooting

### Common Issues

**Issue: Runbook fails with "UnauthorizedAccess"**

```
Solution: Verify UAMI has required role assignments (Sentinel Reader, Log Analytics Reader)
```

**Issue: KQL queries return "Failed to resolve table expression"**

```
Solution: Check that connector KQL mappings match your Sentinel workspace tables
Review InnerError details in runbook output logs
```

**Issue: Logic App not receiving data**

```
Solution: Verify Logic App URI is correct and includes SAS token
Test URI with manual HTTP POST using tools like Postman
Check Network Security Group rules if using private endpoints
```

**Issue: Runbook job hangs or times out**

```
Solution: Reduce query timeout values in runbook parameters
Consider using -Parallel parameter for faster execution
Check workspace query throttling limits
```

### Enable Diagnostic Logging

```powershell
# Enable diagnostic logs for Automation Account
$automationAccount = Get-AzAutomationAccount -ResourceGroupName "SOC-Automation-RG" -Name "SOC-Automation"
$workspaceId = "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>"

Set-AzDiagnosticSetting `
  -ResourceId $automationAccount.ResourceId `
  -WorkspaceId $workspaceId `
  -Enabled $true `
  -Category "JobLogs","JobStreams"
```

## Maintenance

### Updating Runbooks

Runbooks are automatically imported from GitHub during deployment. To update:

1. **Manual Update:**
   - Navigate to Automation Account → Runbooks
   - Select runbook → Edit → Replace content
   - Test → Publish

2. **Redeploy from Template:**
   - Run deployment again with updated parameters
   - Existing resources are updated in-place

### Monitoring Runbook Execution

View job history and logs:

```powershell
# Get recent job history
Get-AzAutomationJob `
  -ResourceGroupName "SOC-Automation-RG" `
  -AutomationAccountName "SOC-Automation" `
  -RunbookName "Get-DataConnectorStatus" |
  Select-Object -First 10

# Get job output
$job = Get-AzAutomationJob -ResourceGroupName "SOC-Automation-RG" `
  -AutomationAccountName "SOC-Automation" -Id <job-id>
Get-AzAutomationJobOutput -ResourceGroupName "SOC-Automation-RG" `
  -AutomationAccountName "SOC-Automation" -Id $job.JobId -Stream Output
```

## Security Best Practices

1. **Limit RBAC Permissions** - Grant minimum required roles to UAMI
2. **Secure Logic App Endpoints** - Use SAS tokens with expiration dates
3. **Protect Logic App URIs at runtime** - Logic App webhook URIs contain SAS tokens in the query string and are bearer secrets. The `POLICYMONITORING_API` and `PRICINGTIER_API` Automation variables store these URIs (the policy variable is encrypted at rest). At runtime, the `Get-AzurePolicies` and `Get-SentinelPricing` runbooks use `Get-UriHostForLog` to log only the host portion — the full URI (including SAS token) never appears in job output, warning, verbose, or error streams.
4. **Enable Diagnostic Logging** - Monitor all automation account activities
5. **Review Job Outputs** - Regularly audit runbook execution logs
6. **Use Private Endpoints** - Consider private connectivity for sensitive environments

## Support & Documentation

- **Testing Guide:** See [TESTS-README.md](./Tests/TESTS-README.md) for Pester test information
- **Sample Payloads:** See [Sample-LogicAppPayload.ps1](./Sample-LogicAppPayload.ps1) for Logic App schema
- **Additional Scripts:** See [Verify-LogicAppPermissions.ps1](./Verify-LogicAppPermissions.ps1) for permission validation

## Additional Resources

- [Azure Automation Documentation](https://learn.microsoft.com/azure/automation/)
- [Microsoft Sentinel Data Connectors](https://learn.microsoft.com/azure/sentinel/connect-data-sources)
- [Managed Identities for Azure Resources](https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/)
- [KQL Query Language Reference](https://learn.microsoft.com/azure/data-explorer/kusto/query/)

