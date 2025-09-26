<#
.SYNOPSIS
    Finds JSON files in 'data connectors' subfolders with metadata.kind = "dataConnector".

.DESCRIPTION
    This script recursively searches through a local clone of the Azure Sentinel repository,
    specifically under the 'Solutions' folder, and identifies JSON files that contain
    metadata.kind = "dataConnector". It outputs the results to a text or CSV file.

.PARAMETER BasePath
    The root path of the local Azure Sentinel repo. It expects a 'Solutions' folder within this path.

.PARAMETER OutputFolderPath
    The folder path where the output file will be saved. The filename will be automatically appended as 'AllDataConnectors.json' or 'AllDataConnectors.csv'.

.PARAMETER AsCsv
    Optional switch to output results in CSV format. If not specified, output is JSON format.

.EXAMPLE
    .\Find-DataConnectors.ps1 -BasePath "C:\Repos\Azure-Sentinel\Solutions" -OutputFolderPath "C:\Temp\"

.EXAMPLE
    .\Find-DataConnectors.ps1 -BasePath "C:\Repos\Azure-Sentinel\Solutions" -OutputFolderPath "C:\Temp\" -AsCsv
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$BasePath = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputFolderPath = "",

    [switch]$AsCsv
)

# Prompt for BasePath if not provided or blank
if ([string]::IsNullOrWhiteSpace($BasePath)) {
    $BasePath = Read-Host "Please enter the base path of the Azure Sentinel repository (e.g., C:\git\Azure-Sentinel\)"
    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        Write-Error "BasePath cannot be empty"
        exit 1
    }
}

# Prompt for OutputFolderPath if not provided or blank
if ([string]::IsNullOrWhiteSpace($OutputFolderPath)) {
    $OutputFolderPath = Read-Host "Please enter the output folder path (e.g., C:\output\)"
    if ([string]::IsNullOrWhiteSpace($OutputFolderPath)) {
        Write-Error "OutputFolderPath cannot be empty"
        exit 1
    }
}

# Ensure the base path exists
if (-not (Test-Path $BasePath)) {
    Write-Error "The specified BasePath does not exist: $BasePath"
    exit 1
}

# Construct the full output file path based on the output type
if ($AsCsv) {
    $OutputFilePath = Join-Path $OutputFolderPath "AllDataConnectors.csv"
} else {
    $OutputFilePath = Join-Path $OutputFolderPath "AllDataConnectors.json"
}

# Ensure the output folder exists
if (-not (Test-Path $OutputFolderPath)) {
    New-Item -Path $OutputFolderPath -ItemType Directory -Force | Out-Null
}

# Initialize collection for results
$matchingFiles = @()

# Use -File to avoid directories, and filter early
$jsonFiles = Get-ChildItem -Path $BasePath -Recurse -Filter *.json -File | Where-Object {
    $_.FullName -match "\\Solutions\\.*\\data connectors\\.*\.json$"
}

foreach ($file in $jsonFiles) {
    try {
        $jsonContent = Get-Content $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($jsonContent.metadata.kind -eq "dataConnector") {
            $matchingFiles += [PSCustomObject]@{
                FilePath = $file.FullName
                FileName = $file.Name
            }
        }
    } catch {
        Write-Warning "Skipping invalid JSON file: $($file.FullName)"
    }
}

# Output results
try {
    if ($AsCsv) {
        $matchingFiles | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8
        Write-Host "✅ CSV output saved to: $OutputFilePath"
    } else {
        # Output as JSON format
        $matchingFiles | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputFilePath -Encoding UTF8
        Write-Host "✅ JSON output saved to: $OutputFilePath"
    }
} catch {
    Write-Error "Failed to write output to: $OutputFilePath"
}
