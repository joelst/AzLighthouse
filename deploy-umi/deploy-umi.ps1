<#
.SYNOPSIS
  Deploys a User Managed Identity (UMI) for Sentinel ingestion.
.DESCRIPTION
  This script deploys a User Managed Identity (UMI) for Sentinel ingestion. It creates a resource group,
  registers the required Azure Resource Providers, installs the required PowerShell modules, and assigns
  permissions to the UMI. It also creates a service principal and assigns the required permissions for
  the UMI to manage the service principal.
.PARAMETER CustomerPrefix
  The customer prefix name. This is used to create the resource group name.
.PARAMETER SubscriptionId
  The subscription ID where the UMI will be deployed.
.PARAMETER AzRegion
  The Azure region where the UMI will be deployed. Default is 'eastus'.

#>
[CmdletBinding()]
param (
  [Parameter()]
  [string] $CustomerPrefix,
  [Parameter()]
  [string] $Subscription,
  [Parameter()]
  [string] $AzRegion = 'eastus'
)

# Install the required PowerShell modules
Install-Module Az.Resources -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense
Install-Module Microsoft.Graph.Applications -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense

# Add required Azure Resource Providers
Register-AzResourceProvider -ProviderNamespace Microsoft.Insights
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedServices
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity

do {
  $customerPrefix = Read-Host 'Enter customer prefix name: '
} while ($customerPrefix.Length -lt 3)

do {
  $Subscription = Read-Host 'Enter the subscription id: '
} while ($Subscription.Length -lt 36)

$umiName = 'MSSP-Sentinel-Ingestion-UMI'
$rg = "$($customerPrefix.ToUpper())-Sentinel-Prod-rg"

# If running locally, instead of cloud shell, you will need to authenticate to Azure.
# Connect-AzAccount
Set-AzContext -SubscriptionId $Subscription

# Get the context of the current subscription
$subscriptionId = (Get-AzContext).Subscription.Id
$scope = "/subscriptions/$($subscriptionId)"

# Azure RBAC role IDs needed
$azureOwnerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' # This is Owner.
$azureKVAdminRoleId = '00482a5a-887f-4fb3-b363-3b7fe8e74483' # This is Key Vault Administrator.
$azureKVUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6' # This is Key Vault Secrets User.
$metricsPubRoleId = '3913510d-42f4-4e42-8a64-420c390055eb' # This is Monitoring Metrics Publisher.

# Create resource group if needed.
if ([string]::IsNullOrEmpty((Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue))) {
  New-AzResourceGroup -Name $rg -Location $azRegion
}

# Create user managed identity
$null = New-AzUserAssignedIdentity -Name $umiName -ResourceGroupName $rg -Location $AzRegion
$umi = Get-AzADServicePrincipal -DisplayName $umiName

# Wait for the UMI to be created
Start-Sleep 10

# Assign User Assigned Identity Owner permissions to the subscription
New-AzRoleAssignment -RoleDefinitionId $azureOwnerRoleId -ObjectId $umi.Id -Scope $scope

# Assign Key Vault permissions to the UMI
# The UMI needs to be able to manage Key Vaults, so we assign it the
New-AzRoleAssignment -RoleDefinitionId $azureKVAdminRoleId -ObjectId $umi.Id -Scope $scope

# Assign Key Vault Secrets User permissions to the UMI
# The UMI needs to be able to read secrets from Key Vaults, so we assign it the Key Vault Secrets User role.
# This role allows the UMI to read secrets from Key Vaults, which is necessary for its operation.
New-AzRoleAssignment -RoleDefinitionId $azureKVUserRoleId -ObjectId $umi.Id -Scope $scope

# Wait for the role assignments to propagate
Start-Sleep 15

# Create the service principal/app registration
$appName = "MSSP-Sentinel-Ingestion"
New-AzADServicePrincipal -DisplayName $appName
Start-Sleep 20
$adsp = Get-AzADServicePrincipal -DisplayName $appName

# Assign the UMI Monitoring Metrics Publisher role to the subscription.
# This role is required to allow the UMI to publish data to Azure Sentinel/Azure Monitor.
New-AzRoleAssignment -RoleDefinitionId $metricsPubRoleId -ObjectId $adsp.Id -Scope $subscriptionId

# The UMI needs to be granted permissions to the Microsoft Graph API
# to allow it to view and manage its owned resources in the tenant.

# Connect to Microsoft Graph. You will need to complete the authentication outside the shell.
Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Directory.Read.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome

# Get the Service Principal for Microsoft Graph
$graphSP = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

# Graph API permissions to assign to the UMI
# This allows the UMI to manage its service principal
$addPermissions = @(
  'Application.ReadWrite.OwnedBy',
  'Application.Read.All'
)

$appRoles = $graphSP.AppRoles |
  Where-Object { ($_.Value -in $addPermissions) -and ($_.AllowedMemberTypes -contains 'Application') }

$appRoles | ForEach-Object {
  New-MgServicePrincipalAppRoleAssignment -ResourceId $graphSP.Id -PrincipalId $umi.Id -AppRoleId $_.Id -ServicePrincipalId $umi.Id
}

# Make sure the UMI is set as the owner of the application. This is required to allow
# the UMI to manage the app registration.
$newOwner = @{
  '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($umi.Id)"
}

# This adds the UMI as an owner to application
New-MgApplicationOwnerByRef -ApplicationId $adsp.Id -BodyParameter $newOwner

