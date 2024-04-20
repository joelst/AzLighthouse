[CmdletBinding()]
param (
    $TableName = "DeviceInfo",
    $ExportPath = (Join-Path "C:/" "SentinelTables"),
    [datetime]$StartDate = "1/1/2023",
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
    # The number of hours to get data for in each iteration. This should be evenly divisible by 24. The default is 12 hours.
    $HourIncrements = 12,
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

# There was an attempt to set the maximum idle time for the service point to 10 minutes (600000 milliseconds)
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

# Authenticate to Azure
$null = Connect-AzAccount -TenantId $TenantId -Subscription $SubscriptionId | Out-Null
if ($false -eq $DoNotUpload) {
    $context = (Get-AzStorageAccount -ResourceGroupName $AzureStorageAccountResourceGroup -Name $AzureStorageAccountName).Context
}
if (!(Test-Path $ExportPath)) { 
    $null = New-Item -ItemType Directory -Path $ExportPath
} 

foreach ($table in $TableName) {
    
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
            
        # Construct the query for the current date
        $currentQuery = $table
        $currentTimeSpan = New-TimeSpan -Start $currentDate -End $nextDate
        Write-Output "Getting data from $currentQuery for $currentDate to $nextDate"
        # Get the Table data from Log Analytics for the current date
        $currentTableResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $currentQuery -wait 600 -Timespan $currentTimeSpan | Select-Object Results -ExpandProperty Results -ExcludeProperty Results
            
        if ($? -eq $false) {
            Write-Log -Message "Error: $table from $currentDate to $nextDate $($error.Exception) " -Severity Error
            Write-Log -Message "Debug: EXCEPTION: $($error.Exception) `n CATEGORY: $($error.CategoryInfo) `n ERROR ID: $($error.FullyQualifiedErrorId) `n SCRIPT STACK TRACE: $($error.ScriptStackTrace)" -Severity Debug
            continue
        }
        
        $currentTableResultCount = ($currentTableResult | Measure-Object).Count
        $fileName = "$table-$($currentDate.ToString('yyyy-MM-dd-mmHHss'))-$($nextDate.ToString('yyyy-MM-dd-mmHHss')).json"
        $OutputFile = Join-Path $ExportPath $fileName
        
        # Write file for the current date
        if ($currentTableResultCount -ge 1) {
            $currentTableResult | ConvertTo-json -Depth 100 -Compress | Out-File $OutputFile -Force 
            if (Test-Path $OutputFile) {           
                if ($false -eq $DoNotUpload) {
                    $result = Set-AzStorageBlobContent -Context $context -Container $AzureStorageContainer -File $OutputFile -Blob $fileName -Force -ErrorAction SilentlyContinue 
                    if ($result) {
                        #Write-Verbose "File $OutputFile uploaded to Azure Storage"
                    }
                    else {
                        Write-Verbose "Failed to upload file $OutputFile to Azure Storage"
                    }
                }
            }
            else {
                Write-Verbose "Failed to create file $OutputFile"
            }       
        }
        else {
            Write-Log -Message "No data returned for $table from $currentDate to $nextDate" -Severity Debug
        }
    }
}
