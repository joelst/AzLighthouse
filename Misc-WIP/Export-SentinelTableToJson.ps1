#requires -version 7 -modules Az.OperationalInsights
<#
.SYNOPSIS
    Export data from Azure Monitor (Log Analytics) to JSON files and upload to Azure Storage. There is a 100 second limit on returning data from Log Analytics using the
     Invoke-AzOperationalInsightsQuery cmdlet. This script will export data in 12 hour increments to avoid this limitation. This script provides methods for reducing the 
     scope of the query to return the data within the 100 second limit.
.DESCRIPTION
    This script exports data from Azure Monitor (Log Analytics) to JSON files and uploads the files to Azure Storage. 
    The script requires the Azure Tenant ID, Azure Subscription ID, Log Analytics Workspace ID, Azure Storage Account name, 
    Azure Storage Container name, and Azure Storage Account resource group. 
.PARAMETER TableName
    The table name(s) to export data.
.PARAMETER ExportPath
    The local path to export the data files to.
.PARAMETER StartDate
    The start date to export data from. Should be in the format MM/dd/yyyy.
.PARAMETER EndDate
    The end date to export data to. Should be in the format MM/dd/yyyy.
.PARAMETER TenantId
    The Azure Tenant ID for the Azure Subscription.
.PARAMETER SubscriptionId
    The Azure Subscription ID for the Azure Monitor (Sentinel) workspace and the Azure Storage Account.
.PARAMETER WorkspaceId
    The Log Analytics Workspace ID.
.PARAMETER AzureStorageAccountName
    The name of the Azure Storage Account to upload the data to.
.PARAMETER AzureStorageContainer
    The name of the Azure Storage Container to upload the data to.
.PARAMETER AzureStorageAccountResourceGroup
    The resource group for the Azure Storage Account.
.PARAMETER HourIncrements
    The number of hours to get data for in each iteration. Must evenly divide the value of HourDivisionBase (default 24). Default: 12.
.PARAMETER HourDivisionBase
    The base period (in hours) that HourIncrements must evenly divide. Defaults to 24 (one day). Change only if you want to segment a different total window.
.PARAMETER DoNotUpload
    Set to $true to not upload the data to Azure Storage.
.PARAMETER LogPath
    The path to write the log file. The default is the export path.
.EXAMPLE
    .\Export-AzMonitorTable.ps1 -TableName "DeviceInfo" -ExportPath "C:\ExportTables" -StartDate "1/1/2023" -EndDate "1/11/2023" -TenantId "00000000-0000-0000-0000-000000000000" -SubscriptionId "00000000-0000-0000-0000-000000000000" -WorkspaceId "00000000-0000-0000-0000-000000000000" -AzureStorageAccountName "storageaccountname" -AzureStorageContainer "containername" -AzureStorageAccountResourceGroup "resourcegroupname" -HourIncrements 12 -DoNotUpload $false -LogPath "C:/SentinelTables"

    #>
[CmdletBinding()]
param (
    # The table name(s) to export data. This can be a single table or an array of tables.
    [array]$TableName = "DeviceInfo",
    # The local path to export data files to.
    $ExportPath = (Join-Path "C:/" "ExportedTables"),
    # The start date to export data from, should be in the format MM/dd/yyyy
    [datetime]$StartDate = "1/1/2023",
    # The end date to export data to, should be in the format MM/dd/yyyy
    [datetime]$EndDate = "1/11/2023",
    # The Azure Tenant ID for the Azure Subscription
    $TenantId,
    # The Azure Subscription ID for the Azure Monitor (Sentinel) workspace and the Azure Storage Account
    $SubscriptionId,
    # The Log Analytics Workspace ID
    $WorkspaceId,
    # The name of the Azure Storage Account to upload the data to
    $AzureStorageAccountName,
    # The name of the Azure Storage Container to upload the data to
    $AzureStorageContainer,
    # The resource group for the Azure Storage Account
    $AzureStorageAccountResourceGroup,
    # The number of hours to get data for in each iteration. Must evenly divide HourDivisionBase. Default 12.
    [int]$HourIncrements = 12,
    # Base (in hours) which HourIncrements must evenly divide. Default 24.
    [int]$HourDivisionBase = 24,
    # Set to $true to not upload the data to Azure Storage
    $DoNotUpload = $false,
    # The path to write the log file. The default is the export path.
    $LogPath = $ExportPath
)

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Debug', 'Information', 'Warning', 'Error', 'Test')]
        [string]
        $Severity = "Information",
        $LogFilePath = $Script:LogFilePath
    )
    
    if ([string]::IsNullOrWhiteSpace($LogFilePath)) {    
        $LogFilePath = Join-Path (Get-Location) "$(Get-Date -f yy.MM).log"
    }
    switch ($Severity) {
        Debug { 
            Write-Verbose $Message
        }
        Warning { 
            Write-Warning $Message
            $Script:logContent += "<p>$Message</p>`n"
        }
        Error { 
            Write-Error $Message
            $Script:logContent += "<p>$Message</p>`n"
        }
        Information { 
            Write-Output $Message
            $Script:logContent += "<p>$Message</p>`n"
        }
        Test { 
            Write-Host " [TestOnly] $Message" -ForegroundColor Green
            
        } 
        Default { 
            Write-Host $Message
        }
    }

    $null = [pscustomobject]@{
        Time     = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        Message  = $Message.Replace("`n", '').Replace("`t", '').Replace("``", '').Replace('""', '"_empty"')
        Severity = $Severity
    } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation -Force -ErrorAction SilentlyContinue
} 

function Test-HourIncrementValidity {
    <#
    .SYNOPSIS
        Tests whether the provided HourIncrements value evenly divides the specified base.
    .PARAMETER HourIncrements
        The candidate increment in hours.
    .PARAMETER Base
        The base period (in hours) to divide (default 24).
    .OUTPUTS
        [bool] True if valid; otherwise False.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][int]$HourIncrements,
        [int]$Base = 24
    )
    if ($HourIncrements -le 0) { return $false }
    if ($Base -le 0) { return $false }
    return (($Base % $HourIncrements) -eq 0)
}

function Get-ExportFileNames {
    <#
    .SYNOPSIS
        Builds the JSON and ZIP file names for an export segment.
    .PARAMETER Table
        Table name being exported.
    .PARAMETER CurrentDate
        Segment start timestamp (datetime).
    .PARAMETER NextDate
        Segment end timestamp (datetime).
    .OUTPUTS
        PSCustomObject with Json and Zip properties.
    .NOTES
        File timestamp pattern intentionally preserved (yyyy-MM-dd-mmHHss) for backward compatibility.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][datetime]$CurrentDate,
        [Parameter(Mandatory)][datetime]$NextDate
    )
    $jsonFileName = "$Table-$($CurrentDate.ToString('yyyy-MM-dd-mmHHss'))-$($NextDate.ToString('yyyy-MM-dd-mmHHss')).json"
    [pscustomobject]@{
        Json = $jsonFileName
        Zip  = "$jsonFileName.zip"
    }
}

# This was an attempt to set the maximum idle time for the service point to 10 minutes (600000 milliseconds) instead of the default 1000 milliseconds.
[System.Net.ServicePointManager]::MaxServicePointIdleTime = 600000

# Validate all parameters have been provided, if not prompt for them.
if (-not $TableName) {
    $TableName = Read-Host "Enter the table name:"
}
if (-not $ExportPath) {
    $ExportPath = Read-Host "Enter the local export path:"
}
if (-not $StartDate) {
    $StartDate = Read-Host "Enter the start date (MM/dd/yyyy):"
}
if (-not $EndDate) {
    $EndDate = Read-Host "Enter the end date (MM/dd/yyyy):"
}
if (-not $TenantId) {
    $TenantId = Read-Host "Enter the Azure Tenant ID:"
}
if (-not $SubscriptionId) {
    $SubscriptionId = Read-Host "Enter the Azure Subscription ID:"
}
if (-not $WorkspaceId) {
    $WorkspaceId = Read-Host "Enter the Log Analytics Workspace ID:"
}

# If the DoNotUpload parameter is set to $true, the AzureStorageAccountName, AzureStorageContainer, and AzureStorageAccountResourceGroup parameters are not required.
if ($false -eq $DoNotUpload) {
    if (-not $AzureStorageAccountName) {
        $AzureStorageAccountName = Read-Host "Enter the Azure Storage Account name:"
    }
    if (-not $AzureStorageContainer) {
        $AzureStorageContainer = Read-Host "Enter the Azure Storage Container name:"
    }
    if (-not $AzureStorageAccountResourceGroup) {
        $AzureStorageAccountResourceGroup = Read-Host "Enter the Azure Storage Account resource group:"
    }
}

if (-not $HourIncrements) {
    $HourIncrements = Read-Host "Enter the number of hours to get data for in each iteration (must be divisable by 24):"
}

# Validate hour increment divisibility
if (-not (Test-HourIncrementValidity -HourIncrements $HourIncrements -Base $HourDivisionBase)) {
    throw "HourIncrements ($HourIncrements) must evenly divide HourDivisionBase ($HourDivisionBase)."
}

# Provide a skip mechanism for test harnesses to dot-source without executing main logic
if ($env:EXPORT_TABLES_SKIP_MAIN -eq '1') {
    Write-Log -Message "EXPORT_TABLES_SKIP_MAIN=1 detected; skipping main export loop." -Severity Information
    return
}

# Authenticate to Azure
Write-Log -Message "Authenticating to Azure." -Severity Information
$null = Connect-AzAccount -TenantId $TenantId -Subscription $SubscriptionId | Out-Null

# Get the Azure Storage Account context if the DoNotUpload parameter is set to $false.
if ($false -eq $DoNotUpload) {
    $context = (Get-AzStorageAccount -ResourceGroupName $AzureStorageAccountResourceGroup -Name $AzureStorageAccountName).Context
}
# Create the export path if it does not exist.
if (!(Test-Path $ExportPath)) { 
    $null = New-Item -ItemType Directory -Path $ExportPath
} 

foreach ($table in $TableName) {

    # Set the log file path for the current table.
    $Script:LogFilePath = Join-Path $LogPath "$table-$(Get-Date -f yy.MM).log"
    # Create a loop to get data for one day at a time but for the entire range specified by $StartDate and $EndDate and $EndDate
    $EndDate = $EndDate.AddDays(1)
    # Calculate the number of hours between the start and end dates
    $hours = ($EndDate - $StartDate).TotalHours
        
    # Loop through each timespan in the range
    for ($i = 0; $i -lt $hours; $i = $i + $HourIncrements) {

        # Calculate the current date based on the start date and the loop index
        $currentDate = $StartDate.AddHours($i)
        $nextDate = $currentDate.AddHours($HourIncrements)
        
    # Construct the file names for the current date via helper
    $fileNames = Get-ExportFileNames -Table $table -CurrentDate $currentDate -NextDate $nextDate
    $outputJsonFile = Join-Path $ExportPath $fileNames.Json
    $outputZipFile  = Join-Path $ExportPath $fileNames.Zip
        
        # if the file already exists, skip querying the data
        if (Test-Path $outputZipFile) {
            Write-Log -Message "File $outputZipFile already exists. Skipping." -Severity Information
            continue
        }
        elseif (Test-Path $outputJsonFile) {
            Write-Log -Message "File $outputJsonFile already exists. Skipping." -Severity Information
            continue
        }
        else {
        
            # Construct the query for the current date
            $currentQuery = $table
            $currentTimeSpan = New-TimeSpan -Start $currentDate -End $nextDate
            Write-Log -Message "Getting data from $currentQuery for $currentDate to $nextDate" -Severity Information
            # Get the Table data from Log Analytics for the current date
            $currentTableResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $currentQuery -wait 600 -Timespan $currentTimeSpan | Select-Object Results -ExpandProperty Results -ExcludeProperty Results
            
            if ($? -eq $false) {
                Write-Log -Message "Error: $table from $currentDate to $nextDate $($error.Exception) " -Severity Error
                Write-Log -Message "Debug: EXCEPTION: $($error.Exception) `n CATEGORY: $($error.CategoryInfo) `n ERROR ID: $($error.FullyQualifiedErrorId) `n SCRIPT STACK TRACE: $($error.ScriptStackTrace)" -Severity Debug
                continue
            }

            # Write file for the current date
            if (($currentTableResult | Measure-Object).Count -ge 1) {
                $currentTableResult | ConvertTo-json -Depth 100 -Compress | Out-File $outputJsonFile -Force
            
                if (Test-Path $outputJsonFile) {
                    $outputJsonFile | Compress-Archive -DestinationPath $outputZipFile -Force
                }
            
                if (Test-Path $outputZipFile) {       
                    # Remove the JSON file if the zip file was created.  
                    $null = Remove-Item $outputJsonFile -Force  
                    # upload the zip file to Azure Storage
                    if ($false -eq $DoNotUpload) {
                        $result = Set-AzStorageBlobContent -Context $context -Container $AzureStorageContainer -File $outputZipFile -Blob $fileNames.Zip -Force -ErrorAction SilentlyContinue 
                        if ($result) {
                            Write-Log -Message "File $outputZipFile uploaded to Azure Storage" -Severity Debug
                        }
                        else {
                            Write-Log -Message "Failed to upload $outputZipFile to Azure Storage" -Severity Error
                        }
                    }
                }
                else {
                    Write-Log -Message "Failed to create file $outputZipFile" -Severity Debug
                }       
            }
            else {
                Write-Log -Message "No data returned for $table from $currentDate to $nextDate" -Severity Debug
            }
        }
    }
}
