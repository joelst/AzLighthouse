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
    .\Get-DataConnectorDefinitionsFromAzureSentinelrepo.ps1 -BasePath "C:\Repos\Azure-Sentinel\Solutions" -OutputFolderPath "C:\Temp\"

.EXAMPLE
    .\Get-DataConnectorDefinitionsFromAzureSentinelrepo.ps1 -BasePath "C:\Repos\Azure-Sentinel\Solutions" -OutputFolderPath "C:\Temp\" -AsCsv
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$BasePath = '',

    [Parameter(Mandatory = $false)]
    [string]$OutputFolderPath = '',

    [switch]$AsCsv
)

# Prompt for BasePath if not provided or blank

while ([string]::IsNullOrWhiteSpace($BasePath) -or -not (Test-Path $BasePath)) {
    if (-not [string]::IsNullOrWhiteSpace($BasePath)) {
        Write-Warning "The specified path does not exist: $BasePath"
    }
    $BasePath = Read-Host "Please enter a valid base path of the Azure Sentinel repository (e.g., $(Join-Path $env:HOME /git/Azure-Sentinel))"
}

if ([string]::IsNullOrWhiteSpace($OutputFolderPath) -eq $false -and -not (Test-Path $OutputFolderPath)) {
    New-Item -Path $OutputFolderPath -ItemType Directory -Force | Out-Null
}

# Prompt for OutputFolderPath if not provided or blank
while ([string]::IsNullOrWhiteSpace($OutputFolderPath) -or -not (Test-Path $OutputFolderPath)) {

    if (-not [string]::IsNullOrWhiteSpace($OutputFolderPath)) {
        Write-Warning "The specified path does not exist: $OutputFolderPath"
    }
    $OutputFolderPath = Read-Host "Please enter a valid output folder path (e.g., $(Join-Path $HOME output))"
}

# Construct the full output file path based on the output type
if ($AsCsv) {
    $OutputFilePath = Join-Path $OutputFolderPath 'AllDataConnectorDefinitions.csv'
} else {
    $OutputFilePath = Join-Path $OutputFolderPath 'AllDataConnectorDefinitions.json'
}

# Initialize collection for results
$matchingFiles = @()

# Use -File to avoid directories, and filter early
$jsonFiles = Get-ChildItem -Path $BasePath -Recurse -Filter *.json -File | Where-Object {
    $_.FullName -match [regex]::Escape([System.IO.Path]::DirectorySeparatorChar) + 'Solutions' + [regex]::Escape([System.IO.Path]::DirectorySeparatorChar) + '.*' + [regex]::Escape([System.IO.Path]::DirectorySeparatorChar) + 'data connectors' + [regex]::Escape([System.IO.Path]::DirectorySeparatorChar) + '.*\.json$'
}

foreach ($file in $jsonFiles) {
    try {
        $jsonContent = Get-Content $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
        
        # Check if required properties exist at top level
        $hasTopLevelProperties = (-not [string]::IsNullOrWhiteSpace($jsonContent.id) -and 
            -not [string]::IsNullOrWhiteSpace($jsonContent.title) -and 
            -not [string]::IsNullOrWhiteSpace($jsonContent.publisher))
        
        # Check if required properties exist under properties.connectorUiConfig
        $hasConnectorUiConfigProperties = (-not [string]::IsNullOrWhiteSpace($jsonContent.properties.connectorUiConfig.id) -and 
            -not [string]::IsNullOrWhiteSpace($jsonContent.properties.connectorUiConfig.title) -and 
            -not [string]::IsNullOrWhiteSpace($jsonContent.properties.connectorUiConfig.publisher))
        
        if ($hasTopLevelProperties) {
            # Use top-level properties
            $matchingFiles += $jsonContent
        } elseif ($hasConnectorUiConfigProperties) {
            # Use properties.connectorUiConfig and promote to top level for consistent output
            $connectorConfig = $jsonContent.properties.connectorUiConfig
            $normalizedContent = [PSCustomObject]@{
                id                    = $connectorConfig.id
                title                 = $connectorConfig.title
                publisher             = $connectorConfig.publisher
                descriptionMarkdown   = $connectorConfig.descriptionMarkdown
                graphQueries          = $connectorConfig.graphQueries
                sampleQueries         = $connectorConfig.sampleQueries
                dataTypes             = $connectorConfig.dataTypes
                connectivityCriterias = $connectorConfig.connectivityCriterias
                availability          = $connectorConfig.availability
                metadata              = $jsonContent.metadata  # Keep original metadata
            }
            $matchingFiles += $normalizedContent
        }
        # If neither location has the required properties, skip the file (no else clause needed)
        
    } catch {
        Write-Warning "Skipping invalid JSON file: $($file.FullName)"
    }
}

# Output results
try {
    if ($AsCsv) {
        # For CSV output, flatten and JSON-encode complex properties
        $csvOutput = $matchingFiles | Where-Object { 
            # Only include objects that have the essential properties
            $_.id -and $_.title -and $_.publisher
        } | ForEach-Object {
            [PSCustomObject]@{
                Id                    = $_.id
                Title                 = $_.title
                Publisher             = $_.publisher
                DescriptionMarkdown   = $_.descriptionMarkdown
                GraphQueries          = if ($_.graphQueries) {
                    ($_.graphQueries | ConvertTo-Json -Compress) 
                } else {
                    $null 
                }
                SampleQueries         = if ($_.sampleQueries) {
                    ($_.sampleQueries | ConvertTo-Json -Compress) 
                } else {
                    $null 
                }
                DataTypes             = if ($_.dataTypes) {
                    ($_.dataTypes | ConvertTo-Json -Compress) 
                } else {
                    $null 
                }
                ConnectivityCriterias = if ($_.connectivityCriterias) {
                    ($_.connectivityCriterias | ConvertTo-Json -Compress) 
                } else {
                    $null 
                }
                Availability          = if ($_.availability) {
                    ($_.availability | ConvertTo-Json -Compress) 
                } else {
                    $null 
                }
                MetadataId            = $_.metadata.contentId
                MetadataVersion       = $_.metadata.version
                MetadataAuthorName    = $_.metadata.author.name
                MetadataSourceKind    = $_.metadata.source.kind
                MetadataSupportName   = $_.metadata.support.name
                MetadataSupportLink   = $_.metadata.support.link
                MetadataSupportTier   = $_.metadata.support.tier
            }
        }
        $csvOutput | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8
        Write-Host "✅ CSV output saved to: $OutputFilePath"
    } else {
        # Output as JSON format with just content
        $matchingFiles | Sort-Object -Property Id | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutputFilePath -Encoding UTF8
        Write-Host "✅ JSON output saved to: $OutputFilePath"
    }
} catch {
    Write-Error "Failed to write output to: $OutputFilePath"
}
