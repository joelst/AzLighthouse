#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# TEST_REQUIRED: Run before any other scripts; must be run from RSOC tenant

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [Parameter(Mandatory)][string]$ManagedByTenantId,
    # Expected local path to the mssp-management repo clone. Defaults to a sibling of AzLighthouse.
    [string]$MsspManagementRepoPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = ".\evidence"
)

$scriptName = "Test-MsspPrerequisites"
$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName

function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail = "")
    $prefix = if ($Passed) { '[PASS]' } else { '[FAIL]' }
    $color  = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host "$prefix $Name" -ForegroundColor $color
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor Gray }
}

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

$checks = [System.Collections.Generic.List[hashtable]]::new()

function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail = "")
    Write-Check -Name $Name -Passed $Passed -Detail $Detail
    $checks.Add(@{ name = $Name; passed = $Passed; detail = $Detail })
}

Write-Host "`n=== MSSP Prerequisites Check ===" -ForegroundColor Cyan
Write-Host "Customer: $customerShortName  |  ManagedByTenantId: $ManagedByTenantId`n"

 Module checks # 
$requiredModules = @(
    'Az.Resources',
    'Az.Accounts',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.SignIns'
)

foreach ($mod in $requiredModules) {
    $installed = $null -ne (Get-Module -ListAvailable -Name $mod | Select-Object -First 1)
    $detail    = if (-not $installed) { "Install with: Install-Module $mod -Force -AllowClobber" } else { "" }
    Add-Check -Name "Module installed: $mod" -Passed $installed -Detail $detail
}

 Az context tenant check # 
$currentContext = $null
try {
    $currentContext = Get-AzContext -ErrorAction Stop
    $actualTenant   = $currentContext?.Tenant?.Id ?? ''
    $tenantMatch    = $actualTenant -eq $ManagedByTenantId
    Add-Check -Name "Az context tenant matches ManagedByTenantId" -Passed $tenantMatch `
        -Detail "Current: $actualTenant  |  Expected: $ManagedByTenantId"
} catch {
    Add-Check -Name "Az context tenant matches ManagedByTenantId" -Passed $false `
        -Detail "No Az context: $($_.Exception.Message)"
}

 Subscription accessibility # 
$subscriptionId = $config.deployment.subscriptionId
$subAccessible  = $false
try {
    $null = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop
    $subAccessible = $true
    Add-Check -Name "Subscription accessible: $subscriptionId" -Passed $true
} catch {
    Add-Check -Name "Subscription accessible: $subscriptionId" -Passed $false `
        -Detail $_.Exception.Message
}

 Resource provider checks # 
$requiredProviders   = @(
    'Microsoft.OperationsManagement',
    'Microsoft.SecurityInsights',
    'Microsoft.Automation',
    'Microsoft.ManagedServices'
)
$unregisteredProviders = [System.Collections.Generic.List[string]]::new()

if ($subAccessible) {
    foreach ($provider in $requiredProviders) {
        try {
            $rp         = Get-AzResourceProvider -ProviderNamespace $provider -ErrorAction Stop
            $regState   = $rp.RegistrationState
            $registered = $regState -eq 'Registered'
            Add-Check -Name "Resource provider: $provider" -Passed $registered `
                -Detail "RegistrationState: $regState"
            if (-not $registered) { $unregisteredProviders.Add($provider) }
        } catch {
            Add-Check -Name "Resource provider: $provider" -Passed $false `
                -Detail $_.Exception.Message
            $unregisteredProviders.Add($provider)
        }
    }

    if ($unregisteredProviders.Count -gt 0) {
        if ($WhatIfMode) {
            Write-Host "`n[WhatIf] Would register providers: $($unregisteredProviders -join ', ')" -ForegroundColor Yellow
        } else {
            Write-Host "`nUnregistered providers: $($unregisteredProviders -join ', ')" -ForegroundColor Yellow
            $response = Read-Host "Register missing providers now? [y/N]"
            if ($response -match '^[Yy]') {
                foreach ($provider in $unregisteredProviders) {
                    Write-Host "Registering $provider ..." -ForegroundColor Yellow
                    Register-AzResourceProvider -ProviderNamespace $provider | Out-Null
                    Write-Host "  Initiated (may take a few minutes to complete)" -ForegroundColor Gray
                }
            }
        }
    }
} else {
    foreach ($provider in $requiredProviders) {
        Add-Check -Name "Resource provider: $provider" -Passed $false `
            -Detail "Skipped - subscription not accessible"
    }
}

 Local repo checks (mssp-management is private; must be cloned locally) # 
if (-not $MsspManagementRepoPath) {
    $MsspManagementRepoPath = Join-Path $PSScriptRoot '..\..\mssp-management'
}
try { $MsspManagementRepoPath = (Resolve-Path $MsspManagementRepoPath -ErrorAction Stop).Path } catch {}

$repoExists = Test-Path $MsspManagementRepoPath
Add-Check -Name "mssp-management repo cloned: $MsspManagementRepoPath" -Passed $repoExists `
    -Detail $(if (-not $repoExists) { "Clone with: git clone git@github.com:joelst/mssp-management.git" } else { "" })

$requiredRepoFiles = @(
    'tmna-mssp\lighthouse-offer.json',
    'tmna-mssp\createUiDefinition.json'
)
foreach ($rel in $requiredRepoFiles) {
    $full = Join-Path $MsspManagementRepoPath $rel
    $exists = Test-Path $full
    Add-Check -Name "Required repo file exists: $rel" -Passed $exists `
        -Detail $(if (-not $exists) { "Expected at: $full" } else { "" })
}

 Evidence # 
$failCount = ($checks | Where-Object { -not $_.passed } | Measure-Object).Count
$status    = if ($WhatIfMode) { 'whatif-only' } elseif ($failCount -eq 0) { 'passed' } else { 'failed' }

$evidenceData = @{
    scriptName            = $scriptName
    customerShortName     = $customerShortName
    status                = $status
    timestampUtc          = (Get-Date).ToUniversalTime().ToString("o")
    testRequired          = @(
        "Run before any other scripts",
        "Must be run from RSOC tenant"
    )
    managedByTenantId     = $ManagedByTenantId
    subscriptionId        = $subscriptionId
    checks                = $checks.ToArray()
    unregisteredProviders = $unregisteredProviders.ToArray()
    failCount             = $failCount
}

$evidencePath = Write-Evidence -Data $evidenceData

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$passCount = $checks.Count - $failCount
Write-Host "Checks: $($checks.Count)  Pass: $passCount  Fail: $failCount  Status: $status"
Write-Host "Evidence: $evidencePath`n"

if ($failCount -gt 0) { exit 1 }
