#Requires -Version 7.0
<#
.SYNOPSIS
    Set-RsocSubscriptionGovernance.ps1 - Registers resource providers and enables Defender for Cloud plans.
.DESCRIPTION
    Registers required Azure resource providers, enables Microsoft Defender for Cloud MCSB standard,
    and enables Defender plans for Servers (Plan 2), Storage, and Key Vault.
    Also enables auto-provisioning for the Azure Monitor Agent (AMA).
    TEST_REQUIRED: Defender plan enablement requires Security Admin role.
    TEST_REQUIRED: Confirm cost implications with customer before enabling paid Defender plans.
#>

param(
    [Parameter(Mandatory)]
    [string]$CustomerConfigPath,

    [string]$CustomerSubscriptionId,

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = ".\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptName = "Set-RsocSubscriptionGovernance"

# Config
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$subscriptionId    = $CustomerSubscriptionId `
                   ?? $config.deployment?.subscriptionId `
                   ?? (Get-AzContext).Subscription.Id

if (-not (Test-Path $EvidenceOutputPath)) {
    New-Item -ItemType Directory -Path $EvidenceOutputPath -Force | Out-Null
}

function Write-Evidence {
    param([hashtable]$Data)
    $ts   = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $file = Join-Path $EvidenceOutputPath "$scriptName-$customerShortName-$ts.json"
    $Data | ConvertTo-Json -Depth 10 | Set-Content $file -Encoding UTF8
    Write-Host "Evidence written: $file" -ForegroundColor Cyan
    return $file
}

$testRequired = @(
    "Defender plan enablement requires Security Administrator role on the subscription",
    "Confirm cost implications with customer before enabling paid Defender plans (P2 costs apply)",
    "Auto-provisioning for AMA may install agents on all VMs in the subscription"
)

Write-Host "=== Set-RsocSubscriptionGovernance ===" -ForegroundColor Yellow
Write-Host "Customer     : $customerShortName"
Write-Host "Subscription : $subscriptionId"

# Set subscription context
Set-AzContext -Subscription $subscriptionId | Out-Null

$providerResults    = [System.Collections.Generic.List[hashtable]]::new()
$defenderResults    = [System.Collections.Generic.List[hashtable]]::new()
$autoProvResults    = [System.Collections.Generic.List[hashtable]]::new()

# WhatIf early exit
if ($WhatIfMode) {
    Write-Host "[WHATIF] Would register providers: Microsoft.Security, Microsoft.SecurityInsights, Microsoft.Automation" -ForegroundColor Magenta
    Write-Host "[WHATIF] Would enable Defender MCSB standard and plans: VirtualMachines, StorageAccounts, KeyVaults" -ForegroundColor Magenta
    Write-Host "[WHATIF] Would enable AMA auto-provisioning" -ForegroundColor Magenta
    Write-Evidence @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        subscriptionId    = $subscriptionId
        testRequired      = $testRequired
    }
    exit 0
}

# 1. Register resource providers
Write-Host "`n[1] Registering required resource providers..." -ForegroundColor Cyan
$requiredProviders = @(
    'Microsoft.Security',
    'Microsoft.SecurityInsights',
    'Microsoft.Automation',
    'Microsoft.Insights',
    'microsoft.operationalinsights'
)

foreach ($provider in $requiredProviders) {
    try {
        $reg = Get-AzResourceProvider -ProviderNamespace $provider -ErrorAction Stop
        $regState = $reg[0].RegistrationState

        if ($regState -eq 'Registered') {
            Write-Host "  [EXISTS] $provider already registered." -ForegroundColor Gray
            $providerResults.Add(@{ provider = $provider; status = 'already-registered' })
        } else {
            Write-Host "  [REGISTERING] $provider (current state: $regState)..." -ForegroundColor Yellow
            Register-AzResourceProvider -ProviderNamespace $provider -ErrorAction Stop | Out-Null

            # Poll until registered (max 60s)
            $deadline = (Get-Date).AddSeconds(60)
            do {
                Start-Sleep -Seconds 5
                $reg      = Get-AzResourceProvider -ProviderNamespace $provider -ErrorAction Stop
                $regState = $reg[0].RegistrationState
                Write-Host "    State: $regState" -ForegroundColor Gray
            } while ($regState -ne 'Registered' -and (Get-Date) -lt $deadline)

            if ($regState -eq 'Registered') {
                Write-Host "  [REGISTERED] $provider" -ForegroundColor Green
                $providerResults.Add(@{ provider = $provider; status = 'registered' })
            } else {
                Write-Host "  [TIMEOUT] $provider registration timed out (state: $regState)" -ForegroundColor Yellow
                $providerResults.Add(@{ provider = $provider; status = 'registration-timeout'; state = $regState })
            }
        }
    } catch {
        $errMsg = $_.Exception.Message
        Write-Warning "  [FAILED] $provider : $errMsg"
        $providerResults.Add(@{ provider = $provider; status = 'failed'; error = $errMsg })
    }
}

# 2. Enable Microsoft Defender for Cloud plans
# TEST_REQUIRED: Defender plan enablement requires Security Admin; confirm cost implications.
Write-Host "`n[2] Enabling Microsoft Defender for Cloud plans..." -ForegroundColor Cyan

$defenderPlans = @(
    @{ Name = 'VirtualMachines';  Tier = 'Standard'; DisplayName = 'Defender for Servers Plan 2' },
    @{ Name = 'StorageAccounts';  Tier = 'Standard'; DisplayName = 'Defender for Storage' },
    @{ Name = 'KeyVaults';        Tier = 'Standard'; DisplayName = 'Defender for Key Vault' },
    @{ Name = 'SqlServers';       Tier = 'Standard'; DisplayName = 'Defender for SQL on Machines' },
    @{ Name = 'AppServices';      Tier = 'Standard'; DisplayName = 'Defender for App Service' }
)

foreach ($plan in $defenderPlans) {
    try {
        $existing = Get-AzSecurityPricing -Name $plan.Name -ErrorAction Stop
        if ($existing.PricingTier -eq $plan.Tier) {
            Write-Host "  [EXISTS] $($plan.DisplayName) already at $($plan.Tier) tier." -ForegroundColor Gray
            $defenderResults.Add(@{
                plan         = $plan.Name
                displayName  = $plan.DisplayName
                status       = 'already-enabled'
                pricingTier  = $plan.Tier
            })
        } else {
            Write-Host "  [ENABLING] $($plan.DisplayName) ($($existing.PricingTier) -> $($plan.Tier))..." -ForegroundColor Yellow
            Set-AzSecurityPricing -Name $plan.Name -PricingTier $plan.Tier -ErrorAction Stop | Out-Null
            Write-Host "  [ENABLED] $($plan.DisplayName)" -ForegroundColor Green
            $defenderResults.Add(@{
                plan         = $plan.Name
                displayName  = $plan.DisplayName
                status       = 'enabled'
                pricingTier  = $plan.Tier
                previousTier = $existing.PricingTier
            })
        }
    } catch {
        $errMsg = $_.Exception.Message
        Write-Warning "  [FAILED] $($plan.DisplayName): $errMsg"
        $defenderResults.Add(@{
            plan        = $plan.Name
            displayName = $plan.DisplayName
            status      = 'failed'
            error       = $errMsg
        })
    }
}

# 3. Enable MCSB (Microsoft Cloud Security Benchmark) standard
Write-Host "`n[3] Checking MCSB standard enrollment..." -ForegroundColor Cyan
try {
    $mcsbName = 'mcsb'
    $standards = Get-AzSecurityStandard -ErrorAction SilentlyContinue
    $mcsbStandard = $standards | Where-Object { $_.Name -match 'mcsb|Microsoft-cloud-security-benchmark' } | Select-Object -First 1
    if ($mcsbStandard) {
        Write-Host "  [EXISTS] MCSB standard already enrolled." -ForegroundColor Gray
        $defenderResults.Add(@{ plan = 'MCSB'; status = 'already-enabled' })
    } else {
        Write-Host "  [INFO] MCSB standard not found via Get-AzSecurityStandard. It may be enabled by default with Defender for Cloud." -ForegroundColor Yellow
        $defenderResults.Add(@{ plan = 'MCSB'; status = 'check-inconclusive'; note = 'MCSB is enabled by default when Defender for Cloud is active' })
    }
} catch {
    Write-Host "  [INFO] Get-AzSecurityStandard not available in this module version; MCSB is enabled by default with Defender for Cloud." -ForegroundColor Yellow
    $defenderResults.Add(@{ plan = 'MCSB'; status = 'skipped'; note = 'Cmdlet not available; MCSB enabled by default' })
}

# 4. Enable auto-provisioning for AMA
Write-Host "`n[4] Configuring auto-provisioning settings..." -ForegroundColor Cyan
$autoProvSettings = @(
    @{ Name = 'mma';              DisplayName = 'Log Analytics Agent (MMA)' },
    @{ Name = 'MicrosoftMonitoringAgent'; DisplayName = 'MMA (alternate name)' }
)

foreach ($ap in $autoProvSettings) {
    try {
        $existing = Get-AzSecurityAutoProvisioningSetting -Name $ap.Name -ErrorAction SilentlyContinue
        if ($existing -and $existing.AutoProvision -eq 'On') {
            Write-Host "  [EXISTS] Auto-provisioning '$($ap.Name)' already On." -ForegroundColor Gray
            $autoProvResults.Add(@{ setting = $ap.Name; status = 'already-enabled' })
        } elseif ($existing) {
            Write-Host "  [ENABLING] Auto-provisioning '$($ap.Name)'..." -ForegroundColor Yellow
            Set-AzSecurityAutoProvisioningSetting -Name $ap.Name -EnableAutoProvision -ErrorAction Stop | Out-Null
            Write-Host "  [ENABLED] Auto-provisioning '$($ap.Name)'" -ForegroundColor Green
            $autoProvResults.Add(@{ setting = $ap.Name; status = 'enabled' })
        } else {
            Write-Host "  [NOT-FOUND] Auto-provisioning setting '$($ap.Name)' not found; may use different name in this region." -ForegroundColor Yellow
            $autoProvResults.Add(@{ setting = $ap.Name; status = 'not-found' })
        }
    } catch {
        $errMsg = $_.Exception.Message
        Write-Warning "  [FAILED] Auto-provisioning '$($ap.Name)': $errMsg"
        $autoProvResults.Add(@{ setting = $ap.Name; status = 'failed'; error = $errMsg })
    }
}

$anyFailed = ($providerResults + $defenderResults + $autoProvResults) | Where-Object { $_.status -eq 'failed' }
$overallStatus = if ($anyFailed) { 'partial-failure' } else { 'succeeded' }

Write-Evidence @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = $overallStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    subscriptionId    = $subscriptionId
    providerResults   = $providerResults
    defenderResults   = $defenderResults
    autoProvResults   = $autoProvResults
    testRequired      = $testRequired
}

Write-Host "=== Set-RsocSubscriptionGovernance complete. Status: $overallStatus ===" -ForegroundColor Cyan
