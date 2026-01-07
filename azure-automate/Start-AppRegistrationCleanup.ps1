#requires -module Microsoft.Graph.Authentication, Microsoft.Graph.Application, Microsoft.Graph.Users.Actions, Microsoft.Graph.DirectoryObjects, Microsoft.Graph.Identity.DirectoryManagement

<#

Disclaimer: This script is provided "as-is" without any warranties.

Updated: 2025.12.22.01

.SYNOPSIS
    Clean up extra app registrations.

.DESCRIPTION
    This script checks for duplicate App Registrations. It will remove any extra App Registrations.

.PARAMETER UMIId
    The User Managed Identity Client ID. This is the ID of the user-assigned managed identity that will
    be used to authenticate to Azure.
.PARAMETER AppRegName
    Name for application registrations.

.PARAMETER ProductionAppId
    One or more Application (client) IDs that should never be deleted.
    Any matching AppIds in this list are excluded from the delete-command output.

.PARAMETER MaxRemovalCount
  When greater than 0, the runbook will attempt to DELETE this many non-production app registrations.
  It always prints the destructive commands first; deletion is limited to the first N candidate AppIds.

.NOTES
    There is no warranty or support for this script. Use at your own risk.
    This script is provided as-is and may not work in all environments.
    It is recommended to test this script in a non-production environment before using it in production.

    This script is designed to be run in an Azure Automation account with a user-assigned managed identity.
    It requires the Microsoft.Graph.Authentication, Microsoft.Graph.Application, Microsoft.Graph.Users.Actions,
     Microsoft.Graph.DirectoryObjects, Microsoft.Graph.Identity.DirectoryManagement PowerShell modules.
    The script uses the Az module to interact with Azure resources and the Microsoft Graph API to manage
    application registrations and credentials.
#>

[CmdletBinding()]
param (
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$UMIId,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$AppRegName,

  [Parameter(Mandatory = $false)]
  [ValidateRange(0, 100)]
  [int]$MaxRemovalCount = 10,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string[]]$ProductionAppId = @('413b3e92-d152-4822-b2e6-85bb39f12e12','4922c1a8-d8e3-4bdd-9991-d3f7f9cbc659','7bce22f6-97c3-48f8-88f3-6b3c515f153c', '8f18eb80-259a-48d6-b6bd-f7157baf450e', 'fab40239-760b-47a2-830d-2f2dff55c8b1', 'bd873061-0b33-4480-90a0-4c7866a57d78', '54c60856-170c-42c9-b048-86fd3c826960', '89aee9ec-786d-40c7-96cc-ebc634399c9b', 'e06ac95a-afb9-462e-ac17-f0430447b9e0', '4e6222b5-49f0-4243-abe8-472f9da6a872', '9dad0201-bc7a-4a78-8d93-72396066a696', 'e62cfe8b-24a2-4760-97bc-f2a823124df4', '8c688eb6-44d6-47ac-a2ed-0b5f30eedca1', '818c337d-ea3b-44dc-bda0-e76928a102d8', '975f1bd6-d14c-4725-9ace-b6ce0dd9a402', 'b16add06-4423-4762-9d48-5414f91e2ce3', '52b21035-1cc7-40bd-8b55-e0e42dd15f3c', '128b6f61-fe1b-4c9b-8ad9-fbf3041749a9', '09df675e-16f9-4c79-a8fa-92bcd05b57b9', '6889aa1a-6f6b-4164-90d5-4d28884599e3', 'cf622d95-b510-4d59-b7e6-9251a672932a', '351e8da0-989d-4077-81a8-b973e091a137', '4a2509b5-dea7-480d-8a7a-5a4b86c914d2', 'd9328c94-ebed-473e-bd1e-4c2d2a7103f4', 'acca56c4-6c2d-4083-a276-49b71e859675', 'a45b3a2e-41af-4ca8-b908-2c931b13627a', '6e69739c-a611-4ae9-b660-8d0f92b5a5ce', '42fcd586-6c54-4305-b655-25a7b6b343d0', '3ae5542d-b0ee-4dae-90a8-4f2604e483fa', '8f8baf34-f123-4f83-b90e-eed18d740157', 'b9db6031-9942-437d-b78c-6b4db95cd71d', 'a45b3a2e-41af-4ca8-b908-2c931b13627a', 'e1179ef0-c835-429b-b978-2b4ecb2b2cf2', 'dc104ad6-8581-44f3-9cb4-b60e14daa223', '36423bce-2909-4365-b5ca-3badd560cb55', '53b1f8cf-df72-4d34-8edc-f00a4dc91713', '343efb83-502f-44be-a57b-50e41a440b9a', 'b1859c85-5a70-4230-a345-6cb343b9b148', '992261a8-861a-4786-9703-e1cd944c813f', '86ebf91f-8af5-4a41-aa72-a19cbb8eb4ac',
  'b4280fa2-c536-415c-b8b3-6b9117df9e78')
)

function ConvertTo-ODataQuotedString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Value
  )

  # OData uses single quotes; to escape a single quote inside a value, double it.
  return ($Value -replace "'", "''")
}

# Set variables from automation account variables if not already set.
if ([string]::IsNullOrWhiteSpace($UMIId)) {
  $UMIId = Get-AutomationVariable -Name 'UMI_ID'
}

if ([string]::IsNullOrWhiteSpace($AppRegName)) {
  $AppRegName = Get-AutomationVariable -Name 'APP_REG_NAME'
  # fallback to old name for compatibility
  if ([string]::IsNullOrWhiteSpace($AppRegName)) {
    $AppRegName = Get-AutomationVariable -Name 'NEW_APP_REG_NAME'
  }
}

# Check if all required parameters are set.
if ($null -eq $UMIId) {
  throw 'No UMI Id specified'
}

if ($null -eq $AppRegName) {
  throw 'No New App Reg Name specified'
}


try {
  Connect-MgGraph -Identity -ClientId $UMIId -NoWelcome
} catch {
  Write-Error "Failed to authenticate to Microsoft Graph: $($_.Exception.Message)"
  throw 'Authentication failed. Cannot continue.'
}

function Get-DestructiveRemovalCommandsForAppId {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AppId
  )

  # Non-destructive: resolve the object ids, then output ONLY the destructive commands.
  $escapedAppId = ConvertTo-ODataQuotedString -Value $AppId
  $filter = "appId eq '$escapedAppId'"

  $servicePrincipals = @()
  $applications = @()

  try {
    $servicePrincipals = @(Get-MgServicePrincipal -Filter $filter -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
  } catch {
    Write-Verbose "Failed to query service principals for appId '$AppId': $($_.Exception.Message)"
  }

  try {
    $applications = @(Get-MgApplication -Filter $filter -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
  } catch {
    Write-Verbose "Failed to query applications for appId '$AppId': $($_.Exception.Message)"
  }

  foreach ($sp in $servicePrincipals) {
    if ($sp -and -not [string]::IsNullOrWhiteSpace($sp.Id)) {
      Write-Output " Remove-MgServicePrincipal -ServicePrincipalId $($sp.Id)"
    }
  }

  foreach ($app in $applications) {
    if ($app -and -not [string]::IsNullOrWhiteSpace($app.Id)) {
      Write-Output " Remove-MgApplication -ApplicationId $($app.Id)"
    }
  }
}

function Invoke-DeleteAppRegistrationByAppId {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AppId
  )

  # Destructive: resolves object IDs then deletes service principals first, then applications.
  # Note: We intentionally do not rely on -WhatIf/ShouldProcess semantics in Azure Automation.
  $escapedAppId = ConvertTo-ODataQuotedString -Value $AppId
  $filter = "appId eq '$escapedAppId'"

  $servicePrincipals = @()
  $applications = @()

  $servicePrincipals = @(Get-MgServicePrincipal -Filter $filter -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
  $applications = @(Get-MgApplication -Filter $filter -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)

  foreach ($sp in $servicePrincipals) {
    if ($sp -and -not [string]::IsNullOrWhiteSpace($sp.Id)) {
      Remove-MgServicePrincipal -ServicePrincipalId $sp.Id -ErrorAction Stop
    }
  }

  foreach ($app in $applications) {
    if ($app -and -not [string]::IsNullOrWhiteSpace($app.Id)) {
      Remove-MgApplication -ApplicationId $app.Id -ErrorAction Stop
    }
  }
}

function Test-AppRegistrationExistsByAppId {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AppId
  )

  $escapedAppId = ConvertTo-ODataQuotedString -Value $AppId
  $filter = "appId eq '$escapedAppId'"

  $spExists = $false
  $appExists = $false

  try {
    $sp = @(Get-MgServicePrincipal -Filter $filter -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
    $spExists = ($sp.Count -gt 0)
  } catch {
    Write-Verbose "Failed to query service principal existence for appId '$AppId': $($_.Exception.Message)"
  }

  try {
    $app = @(Get-MgApplication -Filter $filter -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
    $appExists = ($app.Count -gt 0)
  } catch {
    Write-Verbose "Failed to query application existence for appId '$AppId': $($_.Exception.Message)"
  }

  return ($spExists -or $appExists)
}

function Wait-AppRegistrationDeletionByAppId {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AppId,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$MaxAttempts = 12,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$InitialDelaySeconds = 8
  )

  $delaySeconds = $InitialDelaySeconds
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    $exists = Test-AppRegistrationExistsByAppId -AppId $AppId
    if (-not $exists) {
      return $true
    }

    Write-Verbose "AppId '$AppId' still exists after deletion attempt. Waiting $delaySeconds second(s) (attempt $attempt/$MaxAttempts)."
    Start-Sleep -Seconds $delaySeconds

    # Simple backoff (caps at 30s)
    $delaySeconds = [Math]::Min(($delaySeconds * 2), 30)
  }

  return $false
}

# Fetch applications.
# Best practice: use server-side filtering for exact match; fall back to client-side matching if wildcards are used.
$apps = @()
try {
  if ($AppRegName -match '[\*\?]') {
    $allApps = Get-MgApplication -All -ErrorAction Stop
    Write-Output "Found $($allApps.Count) applications in the tenant."
    $apps = $allApps | Where-Object { $_.DisplayName -like $AppRegName }
  } else {
    $escapedName = ConvertTo-ODataQuotedString -Value $AppRegName
    $apps = @(Get-MgApplication -Filter "displayName eq '$escapedName'" -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
  }
} catch {
  Write-Error "Failed to enumerate applications from Microsoft Graph. Ensure the managed identity has sufficient Graph permissions. Error: $($_.Exception.Message)"
  throw
}

# ------------------------------------------------------------
# App Registration Cleanup Output
# ------------------------------------------------------------
# Return a list of all Application (client) IDs that match AppRegName.
# Output a list of all AppIds that do not match ProductionAppId.
# For each of those AppIds output ONLY the destructive commands that would be executed (NOT executed by this runbook):
#   Remove-MgServicePrincipal -ServicePrincipalId <id>
#   Remove-MgApplication -ApplicationId <id>

$apps = $apps | Sort-Object -Property CreatedDateTime

$matchingAppIds = @($apps | Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppId) } | Select-Object -ExpandProperty AppId)
$matchingAppIds = @($matchingAppIds | Sort-Object -Unique)

Write-Output "Matching applications found: $($apps.Count)"
Write-Output "Matching AppIds found: $($matchingAppIds.Count)"

$matchedProductionAppIds = @(
  $matchingAppIds |
    Where-Object { $_ -in $ProductionAppId } |
      Sort-Object -Unique
)

if ($matchedProductionAppIds.Count -gt 0) {
  Write-Output "Production AppId matched (safety check passed): $($matchedProductionAppIds -join ', ')"
} else {
  Write-Warning "No ProductionAppId matched among AppIds for AppRegName '$AppRegName'. Safety check FAILED; deletions will be disabled."
}

if (-not $matchingAppIds -or $matchingAppIds.Count -eq 0) {
  Write-Output "No applications matched AppRegName '$AppRegName'."
  return @()
}

$nonProductionAppIds = @(
  $matchingAppIds |
    Where-Object { $_ -notin $ProductionAppId -and $_ -notin $matchedProductionAppIds } |
      Sort-Object -Unique
)

# Safety: re-assert the candidate set used for output/deletion.
# This defends against unexpected data issues and guarantees production AppIds never appear in removal commands.
$candidateRemovalAppIds = @(
  $nonProductionAppIds |
    Where-Object { $_ -notin $ProductionAppId -and $_ -notin $matchedProductionAppIds } |
      Sort-Object -Unique
)


$plannedDeletionAppIds = @()
if ($MaxRemovalCount -gt 0) {
  $plannedDeletionCount = [Math]::Min($MaxRemovalCount, $candidateRemovalAppIds.Count)
  $plannedDeletionAppIds = @($candidateRemovalAppIds | Select-Object -First $plannedDeletionCount)
}


if ($candidateRemovalAppIds.Count -eq 0) {
  Write-Output 'No unneeded AppIds found; nothing to remove.'
  return @()
} else {
  Write-Output "Unneeded AppIds: $($candidateRemovalAppIds.Count)"
  Write-Output 'Unneeded AppIds:'
  foreach ($AppId in $candidateRemovalAppIds) {
    Write-Output " $AppId"
  }
}

if ($candidateRemovalAppIds.Count -gt 0 -and $plannedDeletionAppIds.Count -gt 0) {
  Write-Output ''
  Write-Output "Planned deletions (up to MaxRemovalCount=$MaxRemovalCount): $($plannedDeletionAppIds.Count)"
  Write-Output 'Planned deletion AppIds:'
  foreach ($AppId in $plannedDeletionAppIds) {
    Write-Output " $AppId"
  }
}

foreach ($AppId in $candidateRemovalAppIds) {
  if ($AppId -in $ProductionAppId -or $AppId -in $matchedProductionAppIds) {
    continue
  }
  if ($MaxRemovalCount -gt 0 -and $AppId -in $plannedDeletionAppIds) {
    continue
  }
  Get-DestructiveRemovalCommandsForAppId -AppId $AppId
}

if ($MaxRemovalCount -gt 0 -and $matchedProductionAppIds.Count -gt 0) {
  $deletedAppIds = New-Object System.Collections.ArrayList
  $notVerifiedDeletedAppIds = New-Object System.Collections.ArrayList
  $failedDeleteAppIds = New-Object System.Collections.ArrayList

  $deleteCount = $plannedDeletionAppIds.Count
  Write-Warning "MaxRemovalCount is $MaxRemovalCount; attempting deletion of $deleteCount app registration(s)."

  $targetAppIds = @($plannedDeletionAppIds)
  foreach ($AppId in $targetAppIds) {
    try {
      Write-Warning "Deleting app registration for AppId: $AppId"
      Invoke-DeleteAppRegistrationByAppId -AppId $AppId

      $verified = Wait-AppRegistrationDeletionByAppId -AppId $AppId
      if ($verified) {
        [void]$deletedAppIds.Add($AppId)
        Write-Output "Deleted (verified) app registration for AppId: $AppId"
      } else {
        [void]$notVerifiedDeletedAppIds.Add($AppId)
        Write-Warning "Deletion issued but NOT yet verified for AppId: $AppId"
      }
    } catch {
      [void]$failedDeleteAppIds.Add($AppId)
      Write-Error "Failed to delete app registration for AppId '$AppId': $($_.Exception.Message)"
    }
  }

  Write-Output ''
  Write-Output '===================='
  Write-Output 'DELETION SUMMARY'
  Write-Output '===================='
  Write-Output "Maximum deletions: $MaxRemovalCount"
  Write-Output "Attempted deletions: $deleteCount"
  Write-Output "Verified deleted: $($deletedAppIds.Count)"
  Write-Output "Not yet verified deleted: $($notVerifiedDeletedAppIds.Count)"
  Write-Output "Failed deletions: $($failedDeleteAppIds.Count)"

  if ($deletedAppIds.Count -gt 0) {
    Write-Output ''
    Write-Output 'Deleted AppIds (verified):'
    foreach ($id in $deletedAppIds) {
      Write-Output $id
    }
  }

  if ($notVerifiedDeletedAppIds.Count -gt 0) {
    Write-Output ''
    Write-Output 'AppIds where deletion was issued but not verified yet:'
    foreach ($id in $notVerifiedDeletedAppIds) {
      Write-Output $id
    }
  }

  if ($failedDeleteAppIds.Count -gt 0) {
    Write-Output ''
    Write-Output 'AppIds that failed deletion:'
    foreach ($id in $failedDeleteAppIds) {
      Write-Output $id
    }
  }

  $remainingAppIdsByVerification = @(
    $nonProductionAppIds |
      Where-Object { $_ -notin @($deletedAppIds) } |
        Sort-Object -Unique
  )

  $remainingAppIdsFresh = @()
  try {
    $appsAfter = @()
    if ($AppRegName -match '[\*\?]') {
      $allAppsAfter = Get-MgApplication -All -ErrorAction Stop
      $appsAfter = $allAppsAfter | Where-Object { $_.DisplayName -like $AppRegName }
    } else {
      $escapedNameAfter = ConvertTo-ODataQuotedString -Value $AppRegName
      $appsAfter = @(Get-MgApplication -Filter "displayName eq '$escapedNameAfter'" -All -ConsistencyLevel eventual -CountVariable ignoredCount -ErrorAction Stop)
    }

    $matchingAppIdsAfter = @(
      $appsAfter |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppId) } |
          Select-Object -ExpandProperty AppId |
            Sort-Object -Unique
    )

    $remainingAppIdsFresh = @(
      $matchingAppIdsAfter |
        Where-Object { $_ -notin $ProductionAppId } |
          Sort-Object -Unique
    )
  } catch {
    Write-Warning "Failed to refresh remaining AppIds from Graph; using verification-based list instead. Error: $($_.Exception.Message)"
    $remainingAppIdsFresh = $remainingAppIdsByVerification
  }

  # Safety: ensure production AppIds are never shown as remaining candidates.
  $remainingAppIdsFresh = @(
    $remainingAppIdsFresh |
      Where-Object { $_ -notin $ProductionAppId -and $_ -notin $matchedProductionAppIds } |
        Sort-Object -Unique
  )

  Write-Output ''
  Write-Output "Remaining unneeded AppIds (post-run, fresh Graph query): $($remainingAppIdsFresh.Count)"
  foreach ($id in $remainingAppIdsFresh) {
    Write-Output $id
  }
}

if ($MaxRemovalCount -gt 0 -and $matchedProductionAppIds.Count -eq 0) {
  Write-Warning 'MaxRemovalCount was greater than 0, but no ProductionAppId was matched; therefore no deletions were attempted.'
}

return [pscustomobject]@{
  MatchingAppIds          = $matchingAppIds
  MatchedProductionAppIds = $matchedProductionAppIds
  CandidateRemovalAppIds  = $candidateRemovalAppIds
}