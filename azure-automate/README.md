# MSSP SOC Azure Onboarding

## Overview

This solution deploys an Azure Automation account with runbooks to manage Microsoft Sentinel data connectors and service principal credentials for MSSP (Managed Security Service Provider) environments. The automation enables centralized monitoring of Sentinel data connector health and automated credential rotation.

## Architecture

The deployment includes:

1. **Azure Automation Account** - Hosts PowerShell 7.4 runbooks with scheduled execution
2. **User-Assigned Managed Identity (UAMI)** - Provides secure authentication to Azure resources
3. **Two Primary Runbooks**:
   - `Get-MsspDataConnectorStatus` - Monitors Sentinel data connector health and ingestion metrics
   - `Update-MsspAppRegistrationCredential` - Rotates service principal credentials automatically
4. **Logic App Integration** - Sends connector status and credential updates to MSSP tenant

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
New-AzRoleAssignment -ObjectId <UAMI-ObjectId> `
  -RoleDefinitionName "Microsoft Sentinel Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

# Log Analytics Reader role
New-AzRoleAssignment -ObjectId <UAMI-ObjectId> `
  -RoleDefinitionName "Log Analytics Reader" `
  -Scope "/subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"
```

## Deployment Options

### Option 1: Deploy via Azure Portal (Recommended)

Click the button below to deploy directly to your Azure subscription:

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Fazure-automate%2FautomationAccount.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/></a>

**Deployment Parameters:**

| Parameter | Description | Default Value | Required |
|-----------|-------------|---------------|----------|
| `automationAccountName` | Name of the automation account | `MSSP-Automation` | Yes |
| `userAssignedIdentityName` | Name of the existing UAMI | `MSSP-Sentinel-Ingestion-UMI` | Yes |
| `userAssignedIdentityClientId` | Client ID (GUID) of the UAMI | - | Yes |
| `userAssignedIdentityResourceGroupName` | Resource group containing the UAMI | `Sentinel-Prod` | Yes |
| `sentinelResourceGroupName` | Resource group containing Sentinel workspace | - | Yes |
| `sentinelWorkspaceName` | Name of the Sentinel workspace | - | Yes |
| `dataConnectorLogicAppUri` | Logic App URI for connector status updates | - | Yes |
| `servicePrincipalCredentialLogicAppUri` | Logic App URI for credential updates | - | Optional |
| `servicePrincipalCredentialAppReg` | App registration name for credential rotation | - | Optional |

### Option 2: Deploy via PowerShell

```powershell
# Set variables
$resourceGroupName = "MSSP-Automation-RG"
$location = "eastus"
$templateFile = ".\automationAccount.json"

# Create resource group if it doesn't exist
New-AzResourceGroup -Name $resourceGroupName -Location $location -Force

# Deploy the template
New-AzResourceGroupDeployment `
  -ResourceGroupName $resourceGroupName `
  -TemplateFile $templateFile `
  -automationAccountName "MSSP-Automation" `
  -userAssignedIdentityName "MSSP-Sentinel-Ingestion-UMI" `
  -userAssignedIdentityClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
  -userAssignedIdentityResourceGroupName "Sentinel-Prod" `
  -sentinelResourceGroupName "Sentinel-Prod" `
  -sentinelWorkspaceName "MyWorkspace" `
  -dataConnectorLogicAppUri "https://prod-00.region.logic.azure.com/workflows/.../triggers/manual/paths/invoke?...&sig=..." `
  -Verbose
```

### Option 3: Deploy via Azure CLI

```bash
# Set variables
RESOURCE_GROUP="MSSP-Automation-RG"
LOCATION="eastus"
TEMPLATE_FILE="./automationAccount.json"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Deploy the template
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file $TEMPLATE_FILE \
  --parameters \
    automationAccountName="MSSP-Automation" \
    userAssignedIdentityName="MSSP-Sentinel-Ingestion-UMI" \
    userAssignedIdentityClientId="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    userAssignedIdentityResourceGroupName="Sentinel-Prod" \
    sentinelResourceGroupName="Sentinel-Prod" \
    sentinelWorkspaceName="MyWorkspace" \
    dataConnectorLogicAppUri="https://prod-00.region.logic.azure.com/..." \
  --verbose
```

## Post-Deployment Configuration

### 1. Configure Automation Variables

After deployment, add the following automation variables in the Azure Portal:

Navigate to: **Automation Account → Shared Resources → Variables**

| Variable Name | Type | Value | Description |
|---------------|------|-------|-------------|
| `UMI_CLIENT_ID` | String | UAMI Client ID (GUID) | Application ID of the managed identity |
| `UMI_OBJECT_ID` | String | UAMI Object ID (GUID) | Principal ID of the managed identity |
| `SUBSCRIPTION_ID` | String | Azure Subscription ID | Target subscription containing Sentinel |
| `RESOURCE_GROUP_NAME` | String | Resource group name | Where Sentinel workspace is located |
| `WORKSPACE_NAME` | String | Workspace name | Sentinel Log Analytics workspace name |
| `LOGIC_APP_URI` | String | Logic App endpoint | MSSP tenant Logic App URI |



### 2. Verify Deployment

Test the runbooks manually before relying on automated schedules:

1. Navigate to **Automation Account → Process Automation → Runbooks**
2. Select `Get-MsspDataConnectorStatus`
3. Click **Start** and provide test parameters
4. Monitor job output in the **Output** tab
5. Verify data is sent to Logic App endpoint

## Runbook Details

### Get-MsspDataConnectorStatus

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

### Update-MsspAppRegistrationCredential

**Purpose:** Automates service principal credential rotation for enhanced security.

**Key Features:**
- Creates new client secret for app registration
- Updates secrets in Key Vault
- Sends notification to MSSP Logic App
- Removes expired credentials automatically

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
$automationAccount = Get-AzAutomationAccount -ResourceGroupName "MSSP-Automation-RG" -Name "MSSP-Automation"
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
  -ResourceGroupName "MSSP-Automation-RG" `
  -AutomationAccountName "MSSP-Automation" `
  -RunbookName "Get-MsspDataConnectorStatus" | 
  Select-Object -First 10

# Get job output
$job = Get-AzAutomationJob -ResourceGroupName "MSSP-Automation-RG" `
  -AutomationAccountName "MSSP-Automation" -Id <job-id>
Get-AzAutomationJobOutput -ResourceGroupName "MSSP-Automation-RG" `
  -AutomationAccountName "MSSP-Automation" -Id $job.JobId -Stream Output
```

## Security Best Practices

1. **Limit RBAC Permissions** - Grant minimum required roles to UAMI
2. **Secure Logic App Endpoints** - Use SAS tokens with expiration dates
3. **Enable Diagnostic Logging** - Monitor all automation account activities
4. **Review Job Outputs** - Regularly audit runbook execution logs
5. **Use Private Endpoints** - Consider private connectivity for sensitive environments

## Support & Documentation

- **Testing Guide:** See [Testing-README.md](./Testing-README.md) for Pester test information
- **Sample Payloads:** See [Sample-LogicAppPayload.ps1](./Sample-LogicAppPayload.ps1) for Logic App schema
- **Additional Scripts:** See [Verify-LogicAppPermissions.ps1](./Verify-LogicAppPermissions.ps1) for permission validation

## Additional Resources

- [Azure Automation Documentation](https://learn.microsoft.com/azure/automation/)
- [Microsoft Sentinel Data Connectors](https://learn.microsoft.com/azure/sentinel/connect-data-sources)
- [Managed Identities for Azure Resources](https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/)
- [KQL Query Language Reference](https://learn.microsoft.com/azure/data-explorer/kusto/query/)

