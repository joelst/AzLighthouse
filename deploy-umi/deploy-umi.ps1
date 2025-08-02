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
.PARAMETER Subscription
  The subscription ID where the UMI will be deployed.
.PARAMETER AzRegion
  The Azure region where the UMI will be deployed. Default is 'eastus'.
.PARAMETER SkipModuleInstall
  Skip module installation (useful in Azure Cloud Shell where modules may already be available).

#>
[CmdletBinding()]
param (
  [Parameter(Mandatory = $false)]
  [string] $CustomerPrefix,

  [Parameter(Mandatory = $false)]
  [string] $Subscription,

  [Parameter(Mandatory = $false)]
  [string] $AzRegion = 'eastus',

  [Parameter(Mandatory = $false)]
  [switch] $SkipModuleInstall
)

# Set maximum retry attempts for Azure operations
$maxRetries = 10

# Check if running in Azure Cloud Shell by examining environment variables
# ACC_CLOUD=PROD indicates Azure Cloud Shell environment
# AZUREPS_HOST_ENVIRONMENT=cloud-shell indicates PowerShell in Cloud Shell
$isCloudShell = $env:ACC_CLOUD -eq 'PROD' -or $env:AZUREPS_HOST_ENVIRONMENT -eq 'cloud-shell'

# Install the required PowerShell modules (skip in Cloud Shell if requested)
# Cloud Shell has most modules pre-installed, so installation can be skipped for performance
if (-not $SkipModuleInstall -and -not $isCloudShell) {
  Write-Information 'Installing required PowerShell modules' -InformationAction Continue
  # Az.Resources: Required for Azure resource management (RG, UMI, role assignments)
  Install-Module Az.Resources -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense
  # Microsoft.Graph.Authentication: Required for Microsoft Graph authentication
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense
  # Microsoft.Graph.Applications: Required for application registration management
  Install-Module Microsoft.Graph.Applications -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense
  # Microsoft.Graph.Identity.DirectoryManagement: Required for service principal operations
  Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -SkipPublisherCheck -Force -AllowClobber -AcceptLicense
}
elseif ($isCloudShell) {
  Write-Information 'Running in Azure Cloud Shell - using pre-installed modules' -InformationAction Continue
}
else {
  Write-Information 'Skipping module installation as requested' -InformationAction Continue
}

# Register required Azure Resource Providers
# These providers must be registered in the subscription before creating the resources
Register-AzResourceProvider -ProviderNamespace Microsoft.Insights      # For monitoring and metrics
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedServices # For Azure Lighthouse
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity  # For User Managed Identities

# Get user input if not provided as parameters
# Validate customer prefix - must be at least 3 characters for resource naming
if (-not $CustomerPrefix) {
  do {
    $CustomerPrefix = Read-Host 'Enter customer prefix name'
  } while ($CustomerPrefix.Length -lt 3)
}

# Get subscription ID - auto-detect if "sentinel" is in the name, otherwise prompt user
if (-not $Subscription) {
  # Try to find subscriptions with "sentinel" in the name for convenience
  $subscriptions = Get-AzSubscription | Where-Object { $_.Name -like '*sentinel*' }
  if ($subscriptions.Count -eq 1) {
    # Single sentinel subscription found - use it automatically
    $Subscription = $subscriptions[0].Id
  }
  elseif ($subscriptions.Count -eq 0) {
    # No sentinel subscriptions found - show all and prompt
    Write-Information 'No sentinel subscriptions found - please enter one.' -InformationAction Continue
    Get-AzSubscription | Format-Table -Property Name, Id
    do {
      $Subscription = Read-Host 'Enter the subscription id'
    } while ($Subscription.Length -lt 36)
  }
  elseif ($subscriptions.Count -gt 1) {
    # Multiple sentinel subscriptions found - show them and prompt for selection
    Write-Information 'Multiple subscriptions found - please select one.' -InformationAction Continue
    $subscriptions | Format-Table -Property Name, Id
    do {
      $Subscription = Read-Host 'Enter the subscription id'
    } while ($Subscription.Length -lt 36)
  }
}

# Define standard resource names for consistent deployment
$umiName = 'MSSP-Sentinel-Ingestion-UMI'  # User Managed Identity name
$rg = "$($CustomerPrefix.ToUpper())-Sentinel-Prod-rg"  # Resource group name with customer prefix

# Handle authentication based on environment
# Authentication check - in Cloud Shell, user is already authenticated
if ($isCloudShell) {
  Write-Information 'Running in Azure Cloud Shell - using existing authentication' -InformationAction Continue
}
else {
  Write-Information 'If running locally, ensure you are authenticated with Connect-AzAccount' -InformationAction Continue
  Connect-AzAccount  # Uncomment if needed for local execution
}

# Set the subscription context for all subsequent operations
Set-AzContext -SubscriptionId $Subscription

# Get Azure subscription context and set up RBAC scope
# Get the context of the current subscription for role assignments
$subscriptionId = (Get-AzContext).Subscription.Id
$scope = "/subscriptions/$($subscriptionId)"  # Subscription-level scope for role assignments

# Define Azure RBAC role IDs (these are constant GUIDs across all Azure tenants)
# These role definitions provide the UMI with necessary permissions
$azureOwnerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'   # Owner role for full subscription access
$azureKVAdminRoleId = '00482a5a-887f-4fb3-b363-3b7fe8e74483' # Key Vault Administrator for KV management
$azureKVUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'  # Key Vault Secrets User for reading secrets
$metricsPubRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'   # Monitoring Metrics Publisher for telemetry


# RESOURCE GROUP AND USER MANAGED IDENTITY CREATION

# Create resource group if it doesn't exist
# Resource group serves as a logical container for all related Azure resources
if ([string]::IsNullOrEmpty((Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue))) {
  Write-Information "Creating resource group: $rg" -InformationAction Continue
  New-AzResourceGroup -Name $rg -Location $AzRegion
}
else {
  Write-Information "Resource group $rg already exists" -InformationAction Continue
}

# Connect to Microsoft Graph early for all directory operations
# This connection is required for application registration and service principal management
Write-Information 'Connecting to Microsoft Graph' -InformationAction Continue
Write-Information 'You will need to open a new tab and authenticate' -InformationAction Continue
Write-Information ' ' -InformationAction Continue

# Use Microsoft Graph PowerShell to connect with required scopes
# Scopes are permissions required for the operations we will perform
Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Directory.Read.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome

# Check if User Managed Identity already exists to avoid duplication
# UMI provides a managed identity that can be assigned to Azure resources
Write-Information 'Checking if User Managed Identity already exists' -InformationAction Continue
$existingUmi = Get-AzUserAssignedIdentity -Name $umiName -ResourceGroupName $rg -ErrorAction SilentlyContinue

if ($existingUmi) {
  Write-Information "User Managed Identity '$umiName' exists - skipping creation" -InformationAction Continue
  $umi = $existingUmi
}
else {
  Write-Information "Creating User Managed Identity '$umiName'" -InformationAction Continue
  $null = New-AzUserAssignedIdentity -Name $umiName -ResourceGroupName $rg -Location $AzRegion

  # Wait for the UMI to be created and available in Azure AD
  $retryCount = 0
  $umi = $null

  do {
    Start-Sleep 10
    $retryCount++
    Write-Information "Attempt $retryCount of $maxRetries - Checking if UMI is available." -InformationAction Continue

    try {
      # Use Graph to lookup the UMI service principal for consistency with other Graph operations
      # UMI automatically creates a service principal in Azure AD
      $umi = Get-MgServicePrincipal -Filter "DisplayName eq '$umiName'" -ErrorAction SilentlyContinue
      if ($umi) {
        Write-Information 'User Managed Identity found and ready!' -InformationAction Continue
        break
      }
    }
    catch {
      Write-Warning "Error checking UMI: $($_.Exception.Message)"
    }

    if ($retryCount -ge $maxRetries) {
      throw "Timeout waiting for User Managed Identity '$umiName' to be created after $($maxRetries * 10) seconds"
    }
  } while (-not $umi)
}


# RBAC ROLE ASSIGNMENTS FOR USER MANAGED IDENTITY


# Assign required RBAC roles to the UMI for Sentinel operations
# These permissions allow the UMI to manage Azure resources and access Key Vaults
Write-Information 'Assigning RBAC roles to the UMI' -InformationAction Continue

# Owner role: Provides full access to manage all resources in the subscription
New-AzRoleAssignment -RoleDefinitionId $azureOwnerRoleId -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue

# Monitoring Metrics Publisher: Allows publishing custom metrics to Azure Monitor
New-AzRoleAssignment -RoleDefinitionId $metricsPubRoleId -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue

# Key Vault Administrator: Allows full management of Key Vault resources
New-AzRoleAssignment -RoleDefinitionId $azureKVAdminRoleId -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue

# Key Vault Secrets User: Provides read access to Key Vault secrets
# This role allows the UMI to read secrets from Key Vaults, necessary for accessing credentials
New-AzRoleAssignment -RoleDefinitionId $azureKVUserRoleId -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue

# Wait for the role assignments to propagate across Azure AD
# Role assignments can take time to become effective across all Azure services
Write-Information 'Waiting for role assignments to propagate' -InformationAction Continue
Start-Sleep 15

# APPLICATION REGISTRATION AND SERVICE PRINCIPAL CREATION

# Create the service principal/app registration using Microsoft Graph
$appName = 'MSSP-Sentinel-Ingestion'

# Check if application registration exists to avoid conflicts
# This allows the script to be re-run safely without creating duplicates
Write-Information 'Checking if application registration exists' -InformationAction Continue
$existingApplication = Get-MgApplication -Filter "DisplayName eq '$appName'" -ErrorAction SilentlyContinue

if ($existingApplication) {
  Write-Information "Application registration '$appName' exists - using existing" -InformationAction Continue
  $application = $existingApplication

  # Check if service principal exists for this application
  $existingServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$($application.AppId)'" -ErrorAction SilentlyContinue

  if ($existingServicePrincipal) {
    Write-Information "Service Principal for '$appName' exists - using existing" -InformationAction Continue
    $adsp = $existingServicePrincipal
  }
  else {
    Write-Information "Creating Service Principal for existing application '$appName'" -InformationAction Continue
    $spParams = @{
      AppId       = $application.AppId
      DisplayName = $appName
    }
    $null = New-MgServicePrincipal @spParams

    # Wait for service principal to be available
    $retryCount = 0
    $adsp = $null
    do {
      Start-Sleep 10
      $retryCount++
      Write-Information "Attempt $retryCount of $maxRetries - Checking for Service Principal" `
        -InformationAction Continue
      try {
        $adsp = Get-MgServicePrincipal -Filter "AppId eq '$($application.AppId)'" -ErrorAction SilentlyContinue
        if ($adsp) {
          Write-Information 'Service Principal found and ready!' -InformationAction Continue
          break
        }
      }
      catch {
        Write-Warning "Error checking Service Principal: $($_.Exception.Message)"
      }
      if ($retryCount -ge $maxRetries) {
        throw "Timeout waiting for Service Principal '$appName' to be created after $($maxRetries * 10) seconds"
      }
    } while (-not $adsp)
  }
}
else {
  Write-Information "Creating new application registration '$appName'" -InformationAction Continue

  # Create the application with retry logic
  $appParams = @{
    DisplayName    = $appName
    SignInAudience = 'AzureADMyOrg'
  }

  Write-Information 'Attempting to create application registration' -InformationAction Continue
  $retryCount = 0
  $application = $null

  do {
    $retryCount++
    Write-Information "Attempt $retryCount of $maxRetries - Creating application" -InformationAction Continue

    try {
      $application = New-MgApplication @appParams

      # Verify the application was created successfully
      if ($application -and $application.Id) {
        Write-Information "Application '$appName' created successfully with ID: $($application.Id)" -InformationAction Continue
        break
      }
      else {
        Write-Warning "Application creation returned null or missing ID on attempt $retryCount"
      }
    }
    catch {
      Write-Warning "Error creating application on attempt ${retryCount}: $($_.Exception.Message)"
    }

    if ($retryCount -ge $maxRetries) {
      throw "Failed to create application registration '$appName' after $maxRetries attempts"
    }

    Start-Sleep 5
  } while (-not $application -or -not $application.Id)

  # Create the service principal from the application
  Write-Information "Creating Service Principal for new application '$appName'" -InformationAction Continue
  $spParams = @{
    AppId       = $application.AppId
    DisplayName = $appName
  }

  $null = New-MgServicePrincipal @spParams

  # Wait for the service principal to be created and available
  Write-Information 'Waiting for Service Principal to be created' -InformationAction Continue
  $retryCount = 0
  $adsp = $null

  do {
    Start-Sleep 10
    $retryCount++
    Write-Information "Attempt $retryCount of $maxRetries - Checking if Service Principal is available" `
      -InformationAction Continue

    try {
      # Use Graph to lookup the service principal for consistency
      $adsp = Get-MgServicePrincipal -Filter "AppId eq '$($application.AppId)'" -ErrorAction SilentlyContinue
      if ($adsp) {
        Write-Information 'Service Principal found and ready!' -InformationAction Continue
        break
      }
    }
    catch {
      Write-Warning "Error checking Service Principal: $($_.Exception.Message)"
    }

    if ($retryCount -ge $maxRetries) {
      throw "Timeout waiting for Service Principal '$appName' to be created after $($maxRetries * 10) seconds"
    }
  } while (-not $adsp)
}

# CLIENT SECRET CREATION AND MICROSOFT GRAPH PERMISSIONS

# Create a client secret with 1-day expiration (always create new secret for security)
# Even for existing applications, we create a new secret to ensure fresh credentials
Write-Information 'Creating new application secret with 1-day expiration' -InformationAction Continue
$secretParams = @{
  PasswordCredential = @{
    DisplayName = 'Auto-generated secret (1 day expiry)'
    EndDateTime = (Get-Date).AddDays(1)
  }
}

$appSecret = Add-MgApplicationPassword -ApplicationId $application.Id -BodyParameter $secretParams
Write-Information "Application secret created with 1-day expiration: $($appSecret.SecretText)" -InformationAction Continue

# MICROSOFT GRAPH API PERMISSIONS FOR UMI

# The UMI needs to be granted permissions to the Microsoft Graph API
# to allow it to view and manage its owned resources in the tenant.

# Get the Service Principal for Microsoft Graph (well-known AppId)
$graphSP = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

# Define Graph API permissions to assign to the UMI
# These permissions allow the UMI to manage its service principal and applications
$addPermissions = @(
  'Application.ReadWrite.OwnedBy',  # Allows managing applications owned by this service principal
  'Application.Read.All'            # Allows reading all application registrations
)

# Find the specific app roles (permissions) in Microsoft Graph
$appRoles = $graphSP.AppRoles |
  Where-Object { ($_.Value -in $addPermissions) -and ($_.AllowedMemberTypes -contains 'Application') }

# Assign each permission to the UMI service principal
$appRoles | ForEach-Object {
  New-MgServicePrincipalAppRoleAssignment -ResourceId $graphSP.Id -PrincipalId $umi.Id -AppRoleId $_.Id -ServicePrincipalId $umi.Id
}

# APPLICATION OWNERSHIP AND DEPLOYMENT SUMMARY

# Make sure the UMI is set as the owner of the application. This is required to allow
# the UMI to manage the app registration and its credentials programmatically.
$newOwner = @{
  '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($umi.Id)"
}

# Add the UMI as an owner to the application (using the application object, not service principal)
# This enables the UMI to manage the application registration autonomously
New-MgApplicationOwnerByRef -ApplicationId $application.Id -BodyParameter $newOwner

# DEPLOYMENT COMPLETION SUMMARY

# Display comprehensive deployment summary with all important identifiers
# These values are essential for configuring Sentinel and other dependent services
Write-Information '=== DEPLOYMENT COMPLETED SUCCESSFULLY ===' -InformationAction Continue
Write-Information "Resource Group: $rg" -InformationAction Continue
Write-Information "User Managed Identity: $umiName" -InformationAction Continue
Write-Information "  UMI Object ID: $($umi.Id)" -InformationAction Continue
Write-Information "Application Registration: $appName" -InformationAction Continue
Write-Information "  Application ID: $($application.AppId)" -InformationAction Continue
Write-Information "  Service Principal Object ID: $($adsp.Id)" -InformationAction Continue
