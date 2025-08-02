# MSSP SOC Azure Lighthouse Onboarding

Managing Microsoft Sentinel at scale with Lighthouse for distributed IT teams. This process is specifically meant for organizations that are using Lighthouse to manage tenants where different IT organizations control each tenant. It is also for when the SOC will have a separate subscription for its services that will be billed back to them.

## 1. Create SOC subscription in tenant

Follow the steps to create a subscription in the customer tenant.

## 2. Onboard customer tenant into Lighthouse

A user in the customer tenant with the correct permissions can use the following link to onboard:

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FLighthouse-Offers%2Flighthouse-offer1.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FLighthouse-Offers%2FcreateUiDefinition.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/>

## 3. Customer creates user assigned identity

The following steps will require the customer to create identities to allow SOC to perform automation tasks.

### Create User Managed Identity and assigns permissions

These tasks can be completed in the Azure Portal using Cloud Shell. Open the Cloud Shell verify that PowerShell (not Bash) is the selected shell type.

 - Download [UMI Deployment script](/deploy-umi/deploy-umi.ps1) (Right-click and click *Save link as*).
  - In the Azure Portal, open Cloud Shell.
    - Select PowerShell as the shell type.
    - You do not need to create a resource group or storage account.
  - Upload the file to the Cloud Shell using the **Manage Files > Upload** button in the Cloud Shell toolbar.
  - Run the script with the command `./deploy-umi.ps1`.
  - Follow the prompts to complete the deployment.
  - You may need to grant your account access to use the Microsoft Graph API.


## 4. MSSP creates Service Principal / App Registration and assigns permissions

The customer should complete the following tasks from their tenant.

### Automated Process (Preferred)

Click the button below to automatically create the service principal using the UMI created earlier.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FDeploy-ServicePrincipal%2Fdeployment.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/>

### Manual process (If the automated process doesn't work)

#### Manual Option 1: Using the Azure portal

Sign in to the Azure portal and complete these high-level steps.

1. Create a Service Principal in customer tenant
2. Assign the Service Principal the Monitoring Metrics Publisher role (3913510d-42f4-4e42-8a64-420c390055eb) for entire subscription.
3. Create credentials for the SP and securely supply to MSSP.

#### Manual Option 2: Using the Azure Cloud Shell

These tasks can also be completed in the Azure Portal using Cloud Shell. Open the Cloud Shell, and verify that PowerShell (not Bash) is selected. Then run the following script:

```PowerShell
# Name of the service principal
$servicePrincipalName = "MsspNameSOC-Sentinel-LogIngest"
$subscriptionId = (Get-AzContext).Subscription.Id
$sp = New-AzAdServicePrincipal -DisplayName $servicePrincipalName
$scope = "/subscriptions/$($subscriptionId)"
New-AzRoleAssignment -RoleDefinitionId "3913510d-42f4-4e42-8a64-420c390055eb" -ObjectId $sp.Id -Scope $scope
New-AzADServicePrincipalCredential -ObjectId $sp.Id
```

## 5. Azure Automation

This rotates the service principal secrets.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Fazure-automate%2FautomationAccount.json)

> **IMPORTANT**: After a successful deployment, you must manually set the runbook to use the customized runtime environment.

## 6. Deploy Sentinel using template

If you would like the standard connectors to be connected, the customer must be signed in with Global Admin. Otherwise the SOC can complete the basic deployment and the work with the customer to complete the configuration steps.

### Customized Sentinel-All-In-One v2

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FDeploy-Sentinel%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FDeploy-Sentinel%2FcreateUiDefinition.json)

### Work-In-Progress Customize Sentinel-All-In-One v2

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FDeploy-Sentinel-Dev%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FDeploy-Sentinel-Dev%2FcreateUiDefinition.json)

### ORIGINAL Sentinel-All-In-One v2

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FSentinel-All-In-One%2Fv2%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2FSentinel-All-In-One%2Fv2%2FcreateUiDefinition.json)
