#requires -module Microsoft.Graph.Authentication, Microsoft.Graph.Application, Microsoft.Graph.Users.Actions, Microsoft.Graph.DirectoryObjects, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding()]
param (
    [Parameter()]
    [String]
    # The User Managed Identity Client ID. This is the ID of the user-assigned managed identity that will be used to authenticate to Azure.
    $UMIId,
    [Parameter()]
    [int]
    # Number of days before the credential expires to create a new one.
    $DaysBeforeExpiration = 30,
    [Parameter()]
    [int]
    # Number of days the new credential will be valid.
    $CredentialValidDays = 180,
    [Parameter()]
    [string]
    # URI to post credential notifications.
    $SecretApiUri,
    [Parameter()]
    [string]
    # String to find existing/legacy application registrations
    # Set this to an improbable to find app registration and it will create a new one with the name $NewAppRegName
    $AppSearchString,
    [Parameter()]
    [string]
    # Name for newly created application registrations.
    $NewAppRegName

)

# Set variables from automation account variables if not already set.
if ([string]::IsNullOrWhiteSpace($UMIId)) {
    $UMIId = Get-AutomationVariable -Name 'UMI_ID'
}
if ([string]::IsNullOrWhiteSpace($SecretApiUri)) {  
    $SecretApiUri = Get-AutomationVariable -Name 'SECRET_API_URI'
}
if ([string]::IsNullOrWhiteSpace($AppSearchString)) {
    $AppSearchString = Get-AutomationVariable -Name 'APP_SEARCH_STRING'
}
if ([string]::IsNullOrWhiteSpace($NewAppRegName)) {
    $NewAppRegName = Get-AutomationVariable -Name 'NEW_APP_REG_NAME'
}

# Check if all required parameters are set.
if ($null -eq $UMIId) {
    Write-Error "No UMI Id specified"
    exit
}
if ($null -eq $SecretApiUri) {
    Write-Error "No Secret API URI specified"
    exit
}

if ($null -eq $AppSearchString) {
    Write-Error "No App Search String specified"
    exit
}

if ($null -eq $NewAppRegName) {
    Write-Error "No New App Reg Name specified"
    exit
}

function New-SecretNotification {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $URI,
        [Parameter()]
        [string]
        $ApplicationId,
        [Parameter()]
        [string]
        $SecretName,
        [Parameter()]
        [string]
        $PublisherDomain,
        [Parameter()]
        [string]
        $TenantDomain,
        [Parameter()]
        [string]
        $TenantName,
        [Parameter()]
        [string]
        $TenantId,
        [Parameter()]
        [string]
        $CreateDate,
        [Parameter()]
        [string]
        $EndDate,
        [Parameter()]
        [string]
        $KeyId,
        [Parameter()]
        [string]
        $SecretText,
        [Parameter()]
        [string]
        $Action
    )

    <#
    .SYNOPSIS
    Posts a secret notification to provided URI.

    .DESCRIPTION
    Posts a secret notification to provided URI.

    .PARAMETER URI
    The URI to post the secret notification to.

    .PARAMETER SecretName
    The name of the secret.

    .PARAMETER PublisherDomain
    The domain of the publisher.

    .PARAMETER CreateDate
    The date the secret was created.

    .PARAMETER EndDate
    The date the secret will expire.

    .PARAMETER KeyId
    The key ID of the secret.

    .PARAMETER SecretText
    The secret text.

    .PARAMETER Action
    The action taken. Default is "Create". It could also be "Delete".

    .PARAMETER ApplicationId
    The application ID of the secret.

    .PARAMETER TenantId

    .PARAMETER TenantName

    .PARAMETER TenantDomain

    #>

    # Make sure all parameters are set to valid values.
    if ([string]::IsNullOrWhiteSpace($UMIId)) {
        Write-Error "No UMI Id specified"
        exit
    }

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        $SecretName = "NONE"
    }

    if ([string]::IsNullOrWhiteSpace($SecretText)) {
        $SecretText = "NONE"
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "Create"
    }
    if ([string]::IsNullOrWhiteSpace($ApplicationId)) {
        $ApplicationId = "NONE"
    }
    if ([string]::IsNullOrWhiteSpace($PublisherDomain)) {
        $PublisherDomain = "NONE"
    }
    if ([string]::IsNullOrWhiteSpace($CreateDate)) {
        $CreateDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    if ([string]::IsNullOrWhiteSpace($EndDate)) {
        $EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    if ([string]::IsNullOrWhiteSpace($KeyId)) {
        $KeyId = "NONE"
    }
    if ([string]::IsNullOrWhiteSpace($TenantDomain)) {
        $TenantDomain = "$($env.TENANT_DOMAIN)"
    }
    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = "$($env.TENANT_ID)"
    }
    if ([string]::IsNullOrWhiteSpace($TenantName)) {
        $TenantName = "$($env:TENANT_NAME)"
    }
    $jsonBody = @{
        applicationId   = $ApplicationId
        secretName      = $SecretName
        publisherDomain = $PublisherDomain
        createDate      = $CreateDate
        endDate         = $EndDate
        keyId           = $KeyId
        action          = $Action
        secretText      = $SecretText
        tenantId        = $TenantId
        tenantName      = $TenantName
        tenantDomain    = $TenantDomain

    } | ConvertTo-Json

    try {
        
        $null = Invoke-RestMethod -Uri $URI -Method Post -Body $jsonBody -ContentType "application/json"

    }
    catch {
        Write-Error "Failed to post to $URI"
        Write-Error $_.Exception.Message
    }
    return $true
}

function New-AppRegCredential {
    [CmdletBinding()]
    param (
    
        [Parameter()]
        [string]
        $appId,
        [Parameter()]
        [string]
        $SecretApiUri,
        [Parameter()]
        [int]
        $CredentialValidDays = 180,
        [Parameter()]
        [string]
        $AppPublisherDomain,
        [Parameter()]
        [string]
        $AppDisplayName
    )

    # Set the name and expiration date of the new credential based on CredentialValidDays
    $passwordCred = @{
        DisplayName = "Created by MSSP RSOC Automation on $(Get-Date)"
        EndDateTime = (Get-Date).AddDays($CredentialValidDays)
    }
    try {
        # Try to create the new credential
        $secret = Add-MgApplicationPassword -ApplicationId $AppId -PasswordCredential $passwordCred
    }
    catch {
        Write-Error "Failed to create a new secret."
        Write-Error $_.Exception.Message
        continue
    }
    
    # if the valid application password was created, post it to the main tenant.
    if ([string]::IsNullOrWhiteSpace($secret.KeyId) -eq $false) {        
        # Post the secret info to a API/Azure Function/Azure Logic App/etc to save this in the main tenant.
        $null = New-SecretNotification -URI $SecretApiUri -ApplicationId $AppId -SecretName $secret.DisplayName -PublisherDomain $appPublisherDomain -CreateDate $secret.StartDateTime -EndDate $secret.EndDateTime -KeyId $secret.KeyId -Action "Create" -SecretText $secret.SecretText -TenantDomain $env:TENANT_DOMAIN -TenantId $env:TENANT_ID -TenantName $env:TENANT_NAME
        $Script:ValidAppRegExists = $true
    }
    else {
        # If a new credential was needed, but it was not created.
        # This may not be a catostrophic problem if another AppRegistration has a valid credential
        # We will check at the end to see if this is a real problem.
        Write-Warning "New secret was required for $($appDisplayName), however a new secret could not be created"
        $Script:ValidAppRegExists = $false
    }
}
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null

# Connect to Azure with user-assigned managed identity running the script
$azureAutomationContext = Connect-AzAccount -Identity -AccountId $UMIId
$azureAutomationContext = $azureAutomationContext.context

# Set and store Azure context
$azureContext = Set-AzContext -SubscriptionName $azureAutomationContext.Subscription -DefaultProfile $azureAutomationContext
$accessToken = Get-AzAccessToken -ResourceTypeName MSGraph -AsSecureString | Select-Object -ExpandProperty Token

# Connect to Microsoft Graph
Connect-MgGraph -AccessToken $accessToken -NoWelcome | Out-Null

$azureTenant = Get-AzTenant
$env:TENANT_ID = $azureTenant.Id
$env:TENANT_NAME = $azureTenant.Name
$env:TENANT_DOMAIN = $azureTenant.DefaultDomain

if ($null -eq $env:TENANT_NAME) {
    $mgOrg = Get-MgOrganization
    $env:TENANT_NAME = $mgOrg.DisplayName 
    $env:TENANT_DOMAIN = (Get-MgDomain | Where-Object { $_.IsInitial -eq $true }).Id
}

# track that at least one credential is valid
$validAppRegExists = $false

# Get all the apps from graph and then filter out only those that have "-Sentinel-Ingestion" in the name.
$allApps = Get-MgApplication

# find all legacy app registrations
$apps = $allApps | Where-Object { $_.DisplayName -like $AppSearchString -or $_.DisplayName -like $NewAppRegName }

# if no proper application registrations are found, create a new one.
if ($apps.Count -eq 0) {

    Write-Warning "No applications found with the search string $AppSearchString or named $NewAppRegName"
    
    # Create a new service principal with the name $NewAppRegName
    Write-Output "Creating a new service principal $NewAppRegName with role Owner on subscription $subscriptionId"
    $subscriptionId = (Get-AzContext).Subscription.Id
    
    # Create a new service principal with the name $NewAppRegName
    $sp = New-AzAdServicePrincipal -DisplayName $NewAppRegName -Description "Created by MSSP RSOC Automation on $(Get-Date)" -EndDate (Get-Date).AddDays($CredentialValidDays)
    $scope = "/subscriptions/$($subscriptionId)"
    
    # Assign the service principal the Owner role on the subscription
    New-AzRoleAssignment -RoleDefinitionId "3913510d-42f4-4e42-8a64-420c390055eb" -ObjectId $sp.Id -Scope $scope
    $appCred = $sp | Select-Object -ExpandProperty PasswordCredentials | Select-Object -First 1
    
    # Just in case it takes a bit longer to return the data, wait before querying.
    Start-Sleep -seconds 20
    
    # Refresh the list to include the new one
    $app = Get-MgApplication | Where-Object { $_.DisplayName -like $NewAppRegName }
    if ($null -eq $app) {
        Write-Error "Failed to create a new application registration."
        exit
    }
    else {
        if ($app.Count -gt 1) {
            $app = $app[0]
        }

        Write-Output "Posting new secret to main tenant."
        # Post the secret info to a API/Azure Function/Azure Logic App/etc to save this in the main tenant.
        $null = New-SecretNotification -URI $SecretApiUri -ApplicationId $app.Id -SecretName $appCred.Hint -PublisherDomain $app.PublisherDomain -CreateDate $appCred.StartDateTime -EndDate $appCred.EndDateTime -KeyId $appCred.KeyId -Action "Create" -SecretText $appCred.SecretText -TenantId $env:TENANT_ID -TenantName $env:TENANT_NAME -TenantDomain $env:TENANT_DOMAIN
        $validCredentialExists = $true
        $validAppRegExists = $true

    }

}

# Go through each of the apps and check credentials expiration.
foreach ($app in $apps) {

    # Keep track to see if we need to create a new cred.
    # There is probably a better way to do this, but this is working.
    $need = 0
    # This is set to $true if there is at least one valid credential. 
    [bool]$validCredentialExists = $false

    # Check each credential.
    foreach ($cred in $app.PasswordCredentials) {
        # Difference between now and the expiration of the credential
        $dateDifference = New-TimeSpan -Start (Get-Date) -End $cred.EndDateTime
        # Output the details for logging and troubleshooting.
        Write-Output "`n--------------------------------------------------"
        Write-Output "Tenant ID: $($env:TENANT_ID)"
        Write-Output "Tenant Name: $($azureTenant.Name)"
        Write-Output "Tenant Domain: $($azureTenant.DefaultDomain)"
        Write-Output "Application: $($app.DisplayName)"
        Write-Output "Credential count: $($app.PasswordCredentials.Count)"
        Write-Output "Checking credential: $($cred.DisplayName)"
        Write-Output "Created: $($cred.StartDateTime)"
        Write-Output "Expires: $($cred.EndDateTime)"
        Write-Output "Current Time: $(Get-Date)"
        Write-Output "Expired: $($dateDifference -le 0)"   
        Write-Output "Date difference in days: $($dateDifference.days)"

        # If the credential is expired or will expire within the next $DaysBeforeExpiration days, we need to create a new one.
        # If the date differences is less than or equal to 0 that means it has expired.
        if ($dateDifference.days -le 0) {
            
            Write-Output "Credential expired! $($cred.EndDateTime)" 
        
            # It is possible there are more than one credential and if one is valid we don't need to create a new one
            # This Keep track whether we need to create a new credential
            $need++
        
            Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $cred.KeyId

            # Post that this secret is being removed to a API/Azure Function/Azure Logic App/etc to save this in the main tenant.
            $null = New-SecretNotification -URI $SecretApiUri -ApplicationId $app.Id -SecretName $cred.DisplayName -PublisherDomain $app.PublisherDomain -CreateDate $cred.StartDateTime -EndDate $cred.EndDateTime -KeyId $cred.KeyId -Action "Delete" -TenantId $env:TENANT_ID -TenantName $env:TENANT_NAME -TenantDomain $env:TENANT_DOMAIN

        } 
        elseif ($dateDifference.days -le $DaysBeforeExpiration) {
            Write-Output "Expires within $DaysBeforeExpiration days! $((Get-Date).AddDays(- $DaysBeforeExpiration) - $cred.EndDateTime)"           
            # Yes if this is the only cred we need to create one
            $need++
        }
        else {
            Write-Output "Credential Valid - Expires: $($cred.EndDateTime)"
            # We have a working cred so no matter what don't create one.
            $validCredentialExists = $true
            $validAppRegExists = $true
        }

    }

    # If there are expired/expiring credential(s) and no valid credentials
    if ($need -gt 0 -and $validCredentialExists -eq $false) {

        New-AppRegCredential -appId $app.Id -SecretApiUri $SecretApiUri -CredentialValidDays $CredentialValidDays -AppPublisherDomain $app.PublisherDomain -AppDisplayName $app.DisplayName
    }
    else {
        Write-Information "  At least one valid key is present for $($app.DisplayName)."
    }
}

# If there is no valid credential after all this then we need to raise an issue
if ($validAppRegExists -eq $false) {
    Write-Error "Found $($apps.Count) apps; however the credentials have expired or are expiring."
    Write-Error "Error creating new credentials. Please review logs."

    $null = New-SecretNotification -URI $SecretApiUri -ApplicationId "NONE" -SecretName "No valid credentials" -PublisherDomain "NONE" -Action "ERROR" -TenantDomain $env:TENANT_DOMAIN -TenantId $env:TENANT_ID -TenantName $env:TENANT_NAME
    $validAppRegExists = $true
}