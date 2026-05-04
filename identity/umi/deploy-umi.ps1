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

# Initialize change tracking variables to summarize actions taken
$changesSummary = @{
  ResourceGroupCreated    = $false
  UmiCreated              = $false
  UmiFound                = $false
  ApplicationCreated      = $false
  ApplicationFound        = $false
  ServicePrincipalCreated = $false
  ServicePrincipalFound   = $false
  SecretCreated           = $false
  RoleAssignments         = @()
  GraphPermissions        = @()
  OwnershipAdded          = $false
  GraphConnectionMade     = $false
  ModulesInstalled        = @()
}

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
    Write-Information ' ' -InformationAction Continue
    Write-Information 'No Sentinel subscriptions found - please enter one.' -InformationAction Continue
    Write-Information ' ' -InformationAction Continue
    Get-AzSubscription | Format-Table -Property Name, Id
    Write-Information ' ' -InformationAction Continue
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
  Connect-AzAccount
}

# Set the subscription context for all subsequent operations
Set-AzContext -SubscriptionId $Subscription

# Get Azure subscription context and set up RBAC scope
# Get the context of the current subscription for role assignments
$subscriptionId = (Get-AzContext).Subscription.Id
$scope = "/subscriptions/$($subscriptionId)"  # Subscription-level scope for role assignments

# Register required Azure Resource Providers
# These providers must be registered in the subscription before creating the resources
Register-AzResourceProvider -ProviderNamespace Microsoft.Insights      # For monitoring and metrics
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedServices # For Azure Lighthouse
Register-AzResourceProvider -ProviderNamespace Microsoft.ManagedIdentity  # For User Managed Identities

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
  $changesSummary.ResourceGroupCreated = $true
}
else {
  Write-Information "Resource group $rg already exists" -InformationAction Continue
}

# Connect to Microsoft Graph early for all directory operations
# This connection is required for application registration and service principal management

# Check if already connected to Microsoft Graph with the required scopes
$requiredScopes = @('Application.ReadWrite.All', 'Directory.Read.All', 'AppRoleAssignment.ReadWrite.All')
$currentContext = Get-MgContext -ErrorAction SilentlyContinue

# Determine if we need to connect or reconnect
$needsConnection = $false
if (-not $currentContext) {
  Write-Information 'Not connected to Microsoft Graph - connecting now' -InformationAction Continue
  $needsConnection = $true
}
else {
  # Check if we have all required scopes
  $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentContext.Scopes }
  if ($missingScopes) {
    Write-Information "Connected to Microsoft Graph but missing required scopes: $($missingScopes -join ', ')" -InformationAction Continue
    Write-Information 'Reconnecting with all required scopes...' -InformationAction Continue
    $needsConnection = $true
  }
  else {
    Write-Information 'Already connected to Microsoft Graph with required scopes' -InformationAction Continue
  }
}

# Connect only if needed
if ($needsConnection) {
  if (-not $isCloudShell) {
    Write-Information 'You will need to open a new tab and authenticate' -InformationAction Continue
    Write-Information ' ' -InformationAction Continue
  }

  # Use Microsoft Graph PowerShell to connect with required scopes
  # Scopes are permissions required for the operations we will perform
  Connect-MgGraph -Scopes $requiredScopes -NoWelcome
  $changesSummary.GraphConnectionMade = $true
}# Check if User Managed Identity already exists to avoid duplication
# UMI provides a managed identity that can be assigned to Azure resources
Write-Information 'Checking if User Managed Identity already exists' -InformationAction Continue
$existingUmi = Get-AzUserAssignedIdentity -Name $umiName -ResourceGroupName $rg -ErrorAction SilentlyContinue

if ($existingUmi) {
  Write-Information "User Managed Identity '$umiName' exists - skipping creation" -InformationAction Continue
  $changesSummary.UmiFound = $true

  # Get the associated service principal for the existing UMI
  # UMI creates a service principal in Azure AD with the same name
  Write-Information 'Getting associated service principal for existing UMI' -InformationAction Continue
  $umi = Get-MgServicePrincipal -Filter "DisplayName eq '$umiName'" -ErrorAction SilentlyContinue

  if (-not $umi) {
    throw "Could not find service principal for existing UMI '$umiName'. This may indicate a permissions issue or the UMI may not be fully provisioned."
  }
}
else {
  Write-Information "Creating User Managed Identity '$umiName'" -InformationAction Continue
  $null = New-AzUserAssignedIdentity -Name $umiName -ResourceGroupName $rg -Location $AzRegion
  $changesSummary.UmiCreated = $true

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
Write-Information 'Checking and assigning RBAC roles to the UMI...' -InformationAction Continue
Write-Information "Using UMI Service Principal ID: $($umi.Id)" -InformationAction Continue

# Get existing role assignments for the UMI to avoid duplicates
Write-Information 'Retrieving existing role assignments for UMI...' -InformationAction Continue
$existingRoleAssignments = Get-AzRoleAssignment -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue

if ($existingRoleAssignments) {
  Write-Information "Found $($existingRoleAssignments.Count) existing role assignment(s) for this UMI" -InformationAction Continue
  foreach ($existing in $existingRoleAssignments) {
    Write-Information "  - Existing role: $($existing.RoleDefinitionName) (ID: $($existing.RoleDefinitionId))" -InformationAction Continue
  }
}
else {
  Write-Information 'No existing role assignments found for this UMI' -InformationAction Continue
}

# Define role assignments to check and create
$roleAssignments = @(
  @{ RoleId = $azureOwnerRoleId; Name = 'Owner'; Description = 'Provides full access to manage all resources in the subscription' },
  @{ RoleId = $metricsPubRoleId; Name = 'Monitoring Metrics Publisher'; Description = 'Allows publishing custom metrics to Azure Monitor' },
  @{ RoleId = $azureKVAdminRoleId; Name = 'Key Vault Administrator'; Description = 'Allows full management of Key Vault resources' },
  @{ RoleId = $azureKVUserRoleId; Name = 'Key Vault Secrets User'; Description = 'Provides read access to Key Vault secrets' }
)

# Check and assign each role
foreach ($role in $roleAssignments) {
  # Check if this role is already assigned (match by RoleDefinitionId)
  $existingAssignment = $existingRoleAssignments | Where-Object {
    $_.RoleDefinitionId -eq $role.RoleId -and $_.ObjectId -eq $umi.Id -and $_.Scope -eq $scope
  }

  if ($existingAssignment) {
    Write-Information "RBAC role '$($role.Name)' already assigned to UMI at scope '$scope' - skipping" -InformationAction Continue
  }
  else {
    Write-Information "Assigning RBAC role '$($role.Name)' to UMI..." -InformationAction Continue
    Write-Information "  Role ID: $($role.RoleId)" -InformationAction Continue
    Write-Information "  Object ID: $($umi.Id)" -InformationAction Continue
    Write-Information "  Scope: $scope" -InformationAction Continue

    $attempt = 0
    $maxRoleAssignAttempts = 3  # Initial try + up to 2 retries
    $assigned = $false

    while (-not $assigned -and $attempt -lt $maxRoleAssignAttempts) {
      $attempt++
      try {
        $null = New-AzRoleAssignment -RoleDefinitionId $role.RoleId -ObjectId $umi.Id -Scope $scope -ErrorAction Stop
        Write-Information "Successfully assigned '$($role.Name)' role (attempt $attempt)" -InformationAction Continue
        $changesSummary.RoleAssignments += $role.Name
        $assigned = $true
        break
      }
      catch {
        # Check if assignment actually exists despite error (eventual consistency)
        $postCheck = Get-AzRoleAssignment -RoleDefinitionId $role.RoleId -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue

        if ($postCheck) {
          Write-Information "Role '$($role.Name)' appears assigned after error (attempt $attempt) - treating as success" -InformationAction Continue
          if ($role.Name -notin $changesSummary.RoleAssignments) { $changesSummary.RoleAssignments += $role.Name }
          $assigned = $true
          break
        }

        if ($_.Exception.Message -like '*already exists*' -or $_.Exception.Message -like '*conflict*' -or $_.Exception.Message -like '*RoleAssignmentExists*') {
          Write-Information "RBAC role '$($role.Name)' already exists (error indicated duplicate)" -InformationAction Continue
          $assigned = $true
          break
        }
        elseif ($attempt -lt $maxRoleAssignAttempts) {
          Write-Warning "Attempt $attempt to assign '$($role.Name)' failed: $($_.Exception.Message)"
          Write-Information 'Waiting 10 seconds before rechecking and retrying...' -InformationAction Continue
          Start-Sleep -Seconds 10

          # Re-verify before retrying
          $existingAssignmentRecheck = Get-AzRoleAssignment -RoleDefinitionId $role.RoleId -ObjectId $umi.Id -Scope $scope -ErrorAction SilentlyContinue
          if ($existingAssignmentRecheck) {
            Write-Information "Role '$($role.Name)' detected after wait - no further retry needed" -InformationAction Continue
            if ($role.Name -notin $changesSummary.RoleAssignments) { $changesSummary.RoleAssignments += $role.Name }
            $assigned = $true
            break
          }
          else {
            Write-Information "Retrying assignment for role '$($role.Name)' (attempt $(($attempt)+1))" -InformationAction Continue
          }
        }
        else {
          Write-Warning "Final attempt $attempt failed for role '$($role.Name)': $($_.Exception.Message)"
          Write-Warning 'Continuing without this role assignment.'
        }
      }
    }
  }
}

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
  $changesSummary.ApplicationFound = $true

  # Check if service principal exists for this application
  $existingServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$($application.AppId)'" -ErrorAction SilentlyContinue

  if ($existingServicePrincipal) {
    Write-Information "Service Principal for '$appName' exists - using existing" -InformationAction Continue
    $adsp = $existingServicePrincipal
    $changesSummary.ServicePrincipalFound = $true
  }
  else {
    Write-Information "Creating Service Principal for existing application '$appName'" -InformationAction Continue
    $spParams = @{
      AppId       = $application.AppId
      DisplayName = $appName
    }
    $null = New-MgServicePrincipal @spParams
    $changesSummary.ServicePrincipalCreated = $true

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
$changesSummary.SecretCreated = $true

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

# Check existing app role assignments to avoid duplicates
Write-Information 'Checking existing Microsoft Graph permissions for UMI...' -InformationAction Continue
$existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $umi.Id -ErrorAction SilentlyContinue

# Assign each permission to the UMI service principal (only if not already assigned)
$appRoles | ForEach-Object {
  $roleId = $_.Id
  $roleName = $_.Value

  # Check if this specific app role is already assigned
  $existingAssignment = $existingAssignments | Where-Object { $_.AppRoleId -eq $roleId -and $_.ResourceId -eq $graphSP.Id }

  if ($existingAssignment) {
    Write-Information "Microsoft Graph permission '$roleName' already assigned to UMI - skipping" -InformationAction Continue
  }
  else {
    $attempt = 0
    $maxGraphAssignAttempts = 3 # initial + 2 retries
    $assigned = $false
    while (-not $assigned -and $attempt -lt $maxGraphAssignAttempts) {
      $attempt++
      Write-Information "Assigning Microsoft Graph permission '$roleName' to UMI (attempt $attempt)..." -InformationAction Continue
      try {
        New-MgServicePrincipalAppRoleAssignment -ResourceId $graphSP.Id -PrincipalId $umi.Id -AppRoleId $_.Id -ServicePrincipalId $umi.Id -ErrorAction Stop
        # Re-check to confirm assignment (eventual consistency)
        $verify = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $umi.Id -ErrorAction SilentlyContinue | Where-Object { $_.AppRoleId -eq $roleId -and $_.ResourceId -eq $graphSP.Id }
        if ($verify) {
          Write-Information "Successfully assigned '$roleName' permission (attempt $attempt)" -InformationAction Continue
          if ($roleName -notin $changesSummary.GraphPermissions) { $changesSummary.GraphPermissions += $roleName }
          $assigned = $true
          break
        }
        else {
          Write-Warning "Permission '$roleName' not visible yet after assignment attempt $attempt - will re-check/ retry if attempts remain"
        }
      }
      catch {
        # Check if assignment exists despite error
        $postErrorCheck = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $umi.Id -ErrorAction SilentlyContinue | Where-Object { $_.AppRoleId -eq $roleId -and $_.ResourceId -eq $graphSP.Id }
        if ($postErrorCheck) {
          Write-Information "Permission '$roleName' appears assigned after error (attempt $attempt) - treating as success" -InformationAction Continue
          if ($roleName -notin $changesSummary.GraphPermissions) { $changesSummary.GraphPermissions += $roleName }
          $assigned = $true
          break
        }
        elseif ($_.Exception.Message -like '*already*' -or $_.Exception.Message -like '*conflict*') {
          Write-Information "Permission '$roleName' error indicated it already exists - treating as success" -InformationAction Continue
          if ($roleName -notin $changesSummary.GraphPermissions) { $changesSummary.GraphPermissions += $roleName }
          $assigned = $true
          break
        }
        elseif ($attempt -lt $maxGraphAssignAttempts) {
          Write-Warning "Attempt $attempt failed assigning Graph permission '$roleName': $($_.Exception.Message)"
          Write-Information 'Waiting 10 seconds before retrying permission assignment...' -InformationAction Continue
          Start-Sleep -Seconds 10
          # Re-evaluate if assignment appeared during wait
          $recheck = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $umi.Id -ErrorAction SilentlyContinue | Where-Object { $_.AppRoleId -eq $roleId -and $_.ResourceId -eq $graphSP.Id }
          if ($recheck) {
            Write-Information "Permission '$roleName' detected after wait - no further retry needed" -InformationAction Continue
            if ($roleName -notin $changesSummary.GraphPermissions) { $changesSummary.GraphPermissions += $roleName }
            $assigned = $true
            break
          }
        }
        else {
          Write-Warning "Final attempt $attempt failed for Graph permission '$roleName': $($_.Exception.Message)"
          Write-Warning 'Continuing without this Graph permission.'
        }
      }
      if (-not $assigned -and $attempt -lt $maxGraphAssignAttempts) {
        # Delay before next loop iteration if not already delayed due to catch
        if (-not $postErrorCheck -and -not $recheck -and -not $verify) {
          Start-Sleep -Seconds 10
        }
      }
    }
  }
}

# APPLICATION OWNERSHIP AND DEPLOYMENT SUMMARY

# Make sure the UMI is set as the owner of the application. This is required to allow
# the UMI to manage the app registration and its credentials programmatically.

# Check if UMI is already an owner of the application to avoid duplicate attempts
Write-Information 'Checking application ownership...' -InformationAction Continue
$existingOwners = Get-MgApplicationOwner -ApplicationId $application.Id -ErrorAction SilentlyContinue

# Check if the UMI is already an owner
$umiIsOwner = $existingOwners | Where-Object { $_.Id -eq $umi.Id }

if ($umiIsOwner) {
  Write-Information "UMI is already an owner of application '$appName' - skipping ownership assignment" -InformationAction Continue
}
else {
  $ownerAttempts = 0
  $maxOwnerAttempts = 3
  $ownershipAdded = $false
  while (-not $ownershipAdded -and $ownerAttempts -lt $maxOwnerAttempts) {
    $ownerAttempts++
    Write-Information "Adding UMI as owner of application '$appName' (attempt $ownerAttempts)..." -InformationAction Continue
    $newOwner = @{
      '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($umi.Id)"
    }
    try {
      New-MgApplicationOwnerByRef -ApplicationId $application.Id -BodyParameter $newOwner -ErrorAction Stop
      # Verify ownership
      $ownerVerify = Get-MgApplicationOwner -ApplicationId $application.Id -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $umi.Id }
      if ($ownerVerify) {
        Write-Information 'Successfully added UMI as application owner' -InformationAction Continue
        $changesSummary.OwnershipAdded = $true
        $ownershipAdded = $true
        break
      }
      else {
        Write-Warning 'Ownership addition not visible yet after attempt - will retry if attempts remain'
      }
    }
    catch {
      $ownerPostCheck = Get-MgApplicationOwner -ApplicationId $application.Id -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $umi.Id }
      if ($ownerPostCheck) {
        Write-Information 'UMI ownership appears present after error - treating as success' -InformationAction Continue
        $changesSummary.OwnershipAdded = $true
        $ownershipAdded = $true
        break
      }
      elseif ($_.Exception.Message -like '*already exists*' -or $_.Exception.Message -like '*conflict*') {
        Write-Information 'UMI ownership already exists (error indicated duplicate)' -InformationAction Continue
        $changesSummary.OwnershipAdded = $true
        $ownershipAdded = $true
        break
      }
      elseif ($ownerAttempts -lt $maxOwnerAttempts) {
        Write-Warning "Attempt $ownerAttempts failed adding ownership: $($_.Exception.Message)"
      }
      else {
        Write-Warning "Final attempt $ownerAttempts failed adding ownership: $($_.Exception.Message)"
        Write-Warning 'Continuing without setting ownership.'
      }
    }
    if (-not $ownershipAdded -and $ownerAttempts -lt $maxOwnerAttempts) {
      Write-Information 'Waiting 10 seconds before retrying ownership assignment...' -InformationAction Continue
      Start-Sleep -Seconds 10
      # Re-check before next attempt
      $preNextAttemptCheck = Get-MgApplicationOwner -ApplicationId $application.Id -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $umi.Id }
      if ($preNextAttemptCheck) {
        Write-Information 'Ownership detected during wait - stopping retries' -InformationAction Continue
        $changesSummary.OwnershipAdded = $true
        $ownershipAdded = $true
        break
      }
    }
  }
}


# COMPREHENSIVE CHANGES SUMMARY

Write-Information ' ' -InformationAction Continue
Write-Information ' === CHANGES MADE DURING THIS EXECUTION ===' -InformationAction Continue

# Azure Authentication and Setup
if ($changesSummary.GraphConnectionMade) {
  Write-Information '  Connected to Microsoft Graph with required permissions' -InformationAction Continue
}
else {
  Write-Information '  Used existing Microsoft Graph connection' -InformationAction Continue
}

# Resource Group
if ($changesSummary.ResourceGroupCreated) {
  Write-Information "  Created new resource group: $rg" -InformationAction Continue
}
else {
  Write-Information "  Used existing resource group: $rg" -InformationAction Continue
}

# User Managed Identity
if ($changesSummary.UmiCreated) {
  Write-Information "  Created new User Managed Identity: $umiName" -InformationAction Continue
}
elseif ($changesSummary.UmiFound) {
  Write-Information "  Found and used existing User Managed Identity: $umiName" -InformationAction Continue
}

# RBAC Role Assignments
if ($changesSummary.RoleAssignments.Count -gt 0) {
  Write-Information "  Assigned $($changesSummary.RoleAssignments.Count) RBAC role(s):" -InformationAction Continue
  foreach ($role in $changesSummary.RoleAssignments) {
    Write-Information "  - $role" -InformationAction Continue
  }
}
else {
  Write-Information '  All required RBAC roles were already assigned' -InformationAction Continue
}

# Application Registration
if ($changesSummary.ApplicationCreated) {
  Write-Information "  Created new application registration: $appName" -InformationAction Continue
}
elseif ($changesSummary.ApplicationFound) {
  Write-Information "  Found and used existing application registration: $appName" -InformationAction Continue
}

# Service Principal
if ($changesSummary.ServicePrincipalCreated) {
  Write-Information "  Created new service principal for application: $appName" -InformationAction Continue
}
elseif ($changesSummary.ServicePrincipalFound) {
  Write-Information "  Found and used existing service principal for: $appName" -InformationAction Continue
}

# Client Secret
if ($changesSummary.SecretCreated) {
  Write-Information '  Created new application secret (1-day expiration)' -InformationAction Continue
}

# Microsoft Graph Permissions
if ($changesSummary.GraphPermissions.Count -gt 0) {
  Write-Information "  Assigned $($changesSummary.GraphPermissions.Count) Microsoft Graph permission(s):" -InformationAction Continue
  foreach ($permission in $changesSummary.GraphPermissions) {
    Write-Information "  - $permission" -InformationAction Continue
  }
}
else {
  Write-Information '  All required Microsoft Graph permissions were already assigned' -InformationAction Continue
}

# Application Ownership
if ($changesSummary.OwnershipAdded) {
  Write-Information '  Added UMI as owner of the application registration' -InformationAction Continue
}
else {
  Write-Information '  UMI was already an owner of the application registration' -InformationAction Continue
}

Write-Information ' ' -InformationAction Continue


# DEPLOYMENT COMPLETION SUMMARY

# Display comprehensive deployment summary with all important identifiers
# These values are essential for configuring Sentinel and other dependent services
Write-Information '=== DEPLOYMENT COMPLETED SUCCESSFULLY ===' -InformationAction Continue
Write-Information ' ' -InformationAction Continue
Write-Information "  Resource Group: $rg" -InformationAction Continue
Write-Information "  User Managed Identity: $umiName" -InformationAction Continue
Write-Information "    UMI Object ID: $($umi.Id)" -InformationAction Continue
Write-Information "  Application Registration: $appName" -InformationAction Continue
Write-Information "    Application ID: $($application.AppId)" -InformationAction Continue
Write-Information "    Service Principal Object ID: $($adsp.Id)" -InformationAction Continue
