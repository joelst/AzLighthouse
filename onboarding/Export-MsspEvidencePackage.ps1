#Requires -Version 7.0

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [string]$EvidenceDir        = ".\evidence",
    [string]$OutputDir          = ".\packages",
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = ".\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptName        = "Export-MsspEvidencePackage"
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName

function Write-Evidence {
    param([hashtable]$Data)
    if (-not (Test-Path $EvidenceOutputPath)) {
        New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null
    }
    $ts       = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $filePath = Join-Path $EvidenceOutputPath "$scriptName-$ts.json"
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
    Write-Host "Evidence written: $filePath" -ForegroundColor Cyan
    return $filePath
}

# Keys whose values should be redacted
$sensitiveKeyPatterns = @('secret','password','key','token','credential','pwd','apikey','clientsecret')

function Invoke-RedactSensitive {
    param([object]$InputObj, [int]$Depth = 0)
    if ($Depth -gt 15) { return $InputObj }

    if ($InputObj -is [System.Collections.IDictionary]) {
        $cleaned = [System.Collections.Specialized.OrderedDictionary]::new()
        foreach ($k in $InputObj.Keys) {
            $lower = $k.ToString().ToLower()
            if ($sensitiveKeyPatterns | Where-Object { $lower -like "*$_*" }) {
                $cleaned[$k] = '*** REDACTED ***'
            } else {
                $cleaned[$k] = Invoke-RedactSensitive -InputObj $InputObj[$k] -Depth ($Depth + 1)
            }
        }
        return $cleaned
    }

    if ($InputObj -is [PSCustomObject]) {
        $props = $InputObj.PSObject.Properties
        $cleaned = [PSCustomObject]@{}
        foreach ($prop in $props) {
            $lower = $prop.Name.ToLower()
            if ($sensitiveKeyPatterns | Where-Object { $lower -like "*$_*" }) {
                $cleaned | Add-Member -NotePropertyName $prop.Name -NotePropertyValue '*** REDACTED ***'
            } else {
                $cleaned | Add-Member -NotePropertyName $prop.Name `
                    -NotePropertyValue (Invoke-RedactSensitive -InputObj $prop.Value -Depth ($Depth + 1))
            }
        }
        return $cleaned
    }

    if ($InputObj -is [System.Collections.IEnumerable] -and $InputObj -isnot [string]) {
        return @($InputObj | ForEach-Object { Invoke-RedactSensitive -InputObj $_ -Depth ($Depth + 1) })
    }

    return $InputObj
}

Write-Host "`n=== Export-MsspEvidencePackage ===" -ForegroundColor Cyan
Write-Host "Customer: $customerShortName  |  Evidence dir: $EvidenceDir  |  Output dir: $OutputDir`n"

# Gather evidence files
$evidenceFiles = @()
if (Test-Path $EvidenceDir) {
    $evidenceFiles = Get-ChildItem -Path $EvidenceDir -Filter "*.json" -File | Sort-Object Name
    Write-Host "Found $($evidenceFiles.Count) evidence file(s) in $EvidenceDir"
} else {
    Write-Host "[WARN] Evidence directory not found: $EvidenceDir" -ForegroundColor Yellow
}

# Load and merge evidence
$allEvidence = [System.Collections.Generic.List[object]]::new()
foreach ($file in $evidenceFiles) {
    try {
        $raw  = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $safe = Invoke-RedactSensitive -InputObj $raw
        $allEvidence.Add(@{
            fileName = $file.Name
            data     = $safe
        })
    } catch {
        Write-Host "[WARN] Could not parse $($file.Name): $_" -ForegroundColor Yellow
    }
}

# Sanitise the intake config
$sanitizedConfig = Invoke-RedactSensitive -InputObj $config

# Build summary object
$dateTag = (Get-Date).ToString("yyyyMMdd")
$summary = @{
    packageGeneratedAt  = (Get-Date).ToUniversalTime().ToString("o")
    customerShortName   = $customerShortName
    customerTenantId    = $config.customer.tenantId
    subscriptionId      = $config.deployment.subscriptionId
    evidenceFileCount   = $allEvidence.Count
    generatedBy         = $scriptName
    config              = $sanitizedConfig
    evidenceItems       = $allEvidence.ToArray()
}

# Write summary JSON
if (-not (Test-Path $EvidenceDir)) {
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
}
$summaryPath = Join-Path $EvidenceDir "00-package-summary-$dateTag.json"
$summary | ConvertTo-Json -Depth 15 | Out-File -FilePath $summaryPath -Encoding utf8
Write-Host "Summary written: $summaryPath" -ForegroundColor Green

if ($WhatIfMode) {
    Write-Host "`n[WhatIf] Would create ZIP package at $OutputDir\$customerShortName-evidence-$dateTag.zip" -ForegroundColor Yellow
    $ep = Write-Evidence -Data @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString("o")
        testRequired      = @()
        evidenceFileCount = $allEvidence.Count
        summaryPath       = $summaryPath
    }
    Write-Host "Evidence: $ep"
    exit 0
}

# Create output dir and ZIP
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$zipName = "$customerShortName-evidence-$dateTag.zip"
$zipPath = Join-Path $OutputDir $zipName

if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
    Write-Host "Removed existing ZIP: $zipPath" -ForegroundColor Gray
}

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')

try {
    # Add evidence files
    $filesToAdd = [System.Collections.Generic.List[string]]::new()
    if (Test-Path $EvidenceDir) {
        Get-ChildItem -Path $EvidenceDir -Filter "*.json" -File |
            ForEach-Object { $filesToAdd.Add($_.FullName) }
    }

    # Add intake config (sanitized version written to temp file in evidence dir)
    $sanitizedConfigPath = Join-Path $EvidenceDir "intake-config-sanitized-$dateTag.json"
    $sanitizedConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $sanitizedConfigPath -Encoding utf8
    $filesToAdd.Add($sanitizedConfigPath)

    # Add state file if present
    $stateFile = Join-Path (Split-Path $CustomerConfigPath -Parent) "onboarding-state.json"
    if (Test-Path $stateFile) {
        $filesToAdd.Add($stateFile)
        Write-Host "Including state file: $stateFile"
    }

    foreach ($file in ($filesToAdd | Sort-Object -Unique)) {
        if (Test-Path $file) {
            $entryName = Split-Path $file -Leaf
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file, $entryName) | Out-Null
            Write-Host "  + $entryName" -ForegroundColor Gray
        }
    }
} finally {
    $zip.Dispose()
}

$zipInfo = Get-Item $zipPath
Write-Host "`nPackage created: $zipPath  ($([math]::Round($zipInfo.Length / 1KB, 1)) KB)" -ForegroundColor Green

$ep = Write-Evidence -Data @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = 'succeeded'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString("o")
    testRequired      = @()
    packagePath       = $zipPath
    packageSizeKB     = [math]::Round($zipInfo.Length / 1KB, 1)
    evidenceFileCount = $allEvidence.Count
    summaryPath       = $summaryPath
}
Write-Host "Evidence: $ep`n"
