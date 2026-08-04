#Requires -Version 7.0
<#
.SYNOPSIS
    Deploy-SentinelContent.ps1 - Connects a GitHub repository to Sentinel and triggers a content sync.
.DESCRIPTION
    Checks if a Sentinel repository connection exists, creates it if missing, then triggers
    a content sync. Supports GitHub repositories via the Sentinel Repositories API.
    MANUAL_ACTION: GitHub PAT or Managed Identity for Sentinel Repositories must be
                   pre-configured in the Azure Portal before this script can create the connection.
                   Maximum 5 repositories per Sentinel workspace.
    TEST_REQUIRED: Sentinel Repositories API requires source control to be set up in portal first.
    TEST_REQUIRED: Validate repository limit (max 5 per workspace) before adding new connection.
#>

param(
    [Parameter(Mandatory)]
    [string]$CustomerConfigPath,

    [Parameter(Mandatory)]
    [string]$ContentRepoUrl,

    [string]$BranchName = 'main',

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = ".\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptName = "Deploy-SentinelContent"

# Config
$config            = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName = $config.customer.shortName
$subscriptionId    = $config.deployment.subscriptionId
$resourceGroupName = $config.deployment.resourceGroupName
$workspaceName     = $config.deployment.sentinelWorkspaceName

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
    "Sentinel Repositories API requires source control (GitHub PAT or Managed Identity) set up in Azure Portal before use",
    "Maximum 5 repositories per Sentinel workspace; validate current count before adding",
    "api-version=2023-04-01 used for repositories endpoint; verify at deployment time",
    "Repository sync may take several minutes; content hub packages may need separate installation"
)

$sentinelBase  = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights"
$repoApiVer    = "api-version=2023-04-01"

Write-Host "=== Deploy-SentinelContent ===" -ForegroundColor Yellow
Write-Host "Customer    : $customerShortName"
Write-Host "Workspace   : $workspaceName"
Write-Host "Repo URL    : $ContentRepoUrl"
Write-Host "Branch      : $BranchName"

# Derive a stable repo name from the URL
$repoName = ($ContentRepoUrl -replace 'https?://[^/]+/', '' -replace '/', '-' -replace '\.git$', '').ToLower()
$repoName = $repoName -replace '[^a-z0-9\-]', '' | Select-Object -First 64
if ($repoName.Length -gt 60) { $repoName = $repoName.Substring(0, 60) }
$repoResourceName = "repo-$repoName"

Write-Host "Repo resource name: $repoResourceName"

# WhatIf early exit
if ($WhatIfMode) {
    Write-Host "[WHATIF] Would check/create Sentinel repository connection for: $ContentRepoUrl ($BranchName)" -ForegroundColor Magenta
    Write-Host "[WHATIF] Repository resource name would be: $repoResourceName" -ForegroundColor Magenta
    Write-Evidence @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = 'whatif-only'
        timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        subscriptionId    = $subscriptionId
        workspaceName     = $workspaceName
        contentRepoUrl    = $ContentRepoUrl
        branchName        = $BranchName
        repoResourceName  = $repoResourceName
        testRequired      = $testRequired
    }
    exit 0
}

# Acquire token
Write-Host "`nAcquiring management API token..." -ForegroundColor Cyan
$tokenResult = Get-AzAccessToken -ResourceUrl 'https://management.azure.com'
$headers = @{
    'Authorization' = "Bearer $($tokenResult.Token)"
    'Content-Type'  = 'application/json'
}

# 1. List existing repository connections
Write-Host "`n[1] Listing existing Sentinel repository connections..." -ForegroundColor Cyan
$reposUri         = "$sentinelBase/repositories?$repoApiVer"
$existingRepos    = @()
$repoExists       = $false
$existingRepoObj  = $null

try {
    $listResp      = Invoke-RestMethod -Method GET -Uri $reposUri -Headers $headers -ErrorAction Stop
    $existingRepos = $listResp.value ?? @()
    Write-Host "  Found $($existingRepos.Count) existing repository connection(s)." -ForegroundColor Cyan

    foreach ($repo in $existingRepos) {
        $repoUrl    = $repo.properties?.url ?? $repo.properties?.repositoryResourceInfo?.url ?? ''
        $repoBranch = $repo.properties?.branch ?? ''
        Write-Host "  - $($repo.name): $repoUrl ($repoBranch)" -ForegroundColor Gray
        if ($repoUrl -eq $ContentRepoUrl -and ($repoBranch -eq $BranchName -or -not $repoBranch)) {
            $repoExists      = $true
            $existingRepoObj = $repo
            Write-Host "  [MATCH] Existing connection found: $($repo.name)" -ForegroundColor Green
        }
    }

    if ($existingRepos.Count -ge 5) {
        Write-Warning "Workspace already has $($existingRepos.Count) repository connections (max is 5). Cannot add more."
        Write-Evidence @{
            scriptName        = $scriptName
            customerShortName = $customerShortName
            status            = 'failed'
            timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
            reason            = "Repository limit reached (5/5)"
            existingRepos     = ($existingRepos | ForEach-Object { $_.name })
            testRequired      = $testRequired
        }
        exit 1
    }
} catch {
    $statusCode = $_.Exception.Response?.StatusCode.value__ ?? 0
    if ($statusCode -eq 404) {
        Write-Host "  Repositories endpoint returned 404 - Sentinel Repositories feature may not be enabled on this workspace." -ForegroundColor Yellow
        Write-Host "  MANUAL_ACTION: Enable Sentinel Repositories in the Azure Portal first." -ForegroundColor Magenta
        Write-Evidence @{
            scriptName        = $scriptName
            customerShortName = $customerShortName
            status            = 'manual-required'
            timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
            reason            = "Sentinel Repositories not enabled (404). Enable in portal first."
            contentRepoUrl    = $ContentRepoUrl
            testRequired      = $testRequired
        }
        exit 1
    }
    Write-Warning "  Could not list repositories (HTTP $statusCode): $($_.Exception.Message)"
}

# 2. Create repository connection if not exists
$createdRepo = $null
if ($repoExists) {
    Write-Host "`n[2] Repository connection already exists. Skipping creation." -ForegroundColor Gray
    $createdRepo = $existingRepoObj
} else {
    Write-Host "`n[2] Creating Sentinel repository connection..." -ForegroundColor Cyan

    # MANUAL_ACTION: GitHub PAT or Managed Identity must be pre-configured in portal.
    Write-Host "  NOTE: GitHub PAT or Managed Identity must already be configured in the Azure Portal." -ForegroundColor Yellow
    Write-Host "  MANUAL_ACTION: If connection fails with auth error, configure credentials at:" -ForegroundColor Magenta
    Write-Host "  https://portal.azure.com > Sentinel > $workspaceName > Content management > Repositories" -ForegroundColor Magenta

    $repoBody = @{
        properties = @{
            url              = $ContentRepoUrl
            branch           = $BranchName
            displayName      = "RSOC Content - $customerShortName"
            repositoryAccess = @{
                # MANUAL_ACTION: Change kind to 'PAT' and retrieve token from Key Vault before automation.
                # 'OAuth' requires interactive browser consent and cannot run unattended.
                # kind = 'PAT'; token = (Get-AzKeyVaultSecret -VaultName $kvName -Name 'github-pat').SecretValue
                kind = 'OAuth'
            }
            pathMapping = @(
                @{ contentType = 'AnalyticsRule';      path = '/Detections' },
                @{ contentType = 'HuntingQuery';       path = '/Hunting Queries' },
                @{ contentType = 'Workbook';           path = '/Workbooks' },
                @{ contentType = 'AutomationRule';     path = '/Automation' },
                @{ contentType = 'Playbook';           path = '/Playbooks' }
            )
        }
    }

    try {
        $createUri  = "$sentinelBase/repositories/$repoResourceName`?$repoApiVer"
        $createResp = Invoke-RestMethod -Method PUT -Uri $createUri -Headers $headers `
                        -Body ($repoBody | ConvertTo-Json -Depth 10) -ErrorAction Stop
        Write-Host "  [CREATED] Repository connection: $repoResourceName" -ForegroundColor Green
        $createdRepo = $createResp
    } catch {
        $errMsg = $_.Exception.Message
        $statusCode = $_.Exception.Response?.StatusCode.value__ ?? 0
        Write-Warning "  [FAILED] Could not create repository connection (HTTP $statusCode): $errMsg"

        if ($errMsg -match 'auth|credential|unauthorized|permission' -or $statusCode -in @(401, 403)) {
            Write-Host ""
            Write-Host "" -ForegroundColor Magenta
            Write-Host "  MANUAL_ACTION: Configure Sentinel Repository credentials" -ForegroundColor Magenta
            Write-Host "" -ForegroundColor Magenta
            Write-Host "  Step 1: Go to https://portal.azure.com" -ForegroundColor Yellow
            Write-Host "  Step 2: Open Microsoft Sentinel > $workspaceName" -ForegroundColor Yellow
            Write-Host "  Step 3: Go to Content management > Repositories" -ForegroundColor Yellow
            Write-Host "  Step 4: Click '+ Add new' and authenticate with GitHub" -ForegroundColor Yellow
            Write-Host "  Step 5: Select repository: $ContentRepoUrl" -ForegroundColor Yellow
            Write-Host "  Step 6: Select branch: $BranchName" -ForegroundColor Yellow
            Write-Host "  Step 7: Configure path mappings and click Create" -ForegroundColor Yellow
            Write-Host "" -ForegroundColor Magenta
        }

        Write-Evidence @{
            scriptName        = $scriptName
            customerShortName = $customerShortName
            status            = 'failed'
            timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
            subscriptionId    = $subscriptionId
            workspaceName     = $workspaceName
            contentRepoUrl    = $ContentRepoUrl
            branchName        = $BranchName
            error             = $errMsg
            httpStatus        = $statusCode
            testRequired      = $testRequired
        }
        exit 1
    }
}

# 3. Trigger content sync
Write-Host "`n[3] Triggering content sync..." -ForegroundColor Cyan
$syncResult   = $null
$syncStatus   = 'unknown'
$repoId       = $createdRepo?.name ?? $repoResourceName

try {
    # POST to sync endpoint
    $syncUri  = "$sentinelBase/repositories/$repoId/sync?$repoApiVer"
    $syncResp = Invoke-RestMethod -Method POST -Uri $syncUri -Headers $headers `
                    -Body '{}' -ErrorAction Stop
    Write-Host "  [TRIGGERED] Content sync initiated for '$repoId'." -ForegroundColor Green
    $syncStatus = 'sync-triggered'
    $syncResult = $syncResp
} catch {
    $errMsg     = $_.Exception.Message
    $statusCode = $_.Exception.Response?.StatusCode.value__ ?? 0
    if ($statusCode -eq 404) {
        Write-Host "  [INFO] Sync endpoint returned 404 - sync may not be available or connection is still initializing." -ForegroundColor Yellow
        Write-Host "  The sync will occur automatically within a few minutes, or trigger manually in the portal." -ForegroundColor Yellow
        $syncStatus = 'sync-endpoint-not-found'
    } elseif ($statusCode -eq 202 -or $statusCode -eq 200) {
        Write-Host "  [TRIGGERED] Sync accepted (HTTP $statusCode)." -ForegroundColor Green
        $syncStatus = 'sync-triggered'
    } else {
        Write-Warning "  [WARN] Sync trigger failed (HTTP $statusCode): $errMsg"
        $syncStatus = "sync-failed-$statusCode"
    }
}

# 4. MANUAL_ACTION reminder
Write-Host ""
Write-Host "" -ForegroundColor Magenta
Write-Host "  MANUAL_ACTION: Sentinel Repositories Pre-requisites" -ForegroundColor Magenta
Write-Host "" -ForegroundColor Magenta
Write-Host "  - GitHub PAT or Managed Identity must be pre-configured in the Azure Portal" -ForegroundColor Yellow
Write-Host "  - Maximum 5 repositories per Sentinel workspace (currently $($existingRepos.Count))" -ForegroundColor Yellow
Write-Host "  - Content sync may take several minutes to complete" -ForegroundColor Yellow
Write-Host "  - Monitor sync status at: Content management > Repositories in Sentinel" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Magenta

$overallStatus = if ($syncStatus -match 'triggered') { 'succeeded' }
                 elseif ($syncStatus -match 'not-found') { 'partial-success' }
                 else { 'partial-success' }

Write-Evidence @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = $overallStatus
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    subscriptionId    = $subscriptionId
    workspaceName     = $workspaceName
    contentRepoUrl    = $ContentRepoUrl
    branchName        = $BranchName
    repoResourceName  = $repoResourceName
    repoCreated       = (-not $repoExists)
    syncStatus        = $syncStatus
    existingRepoCount = $existingRepos.Count
    manualActions     = @(
        "GitHub PAT or Managed Identity for Sentinel Repositories must be pre-configured in Azure Portal",
        "Maximum 5 repositories per workspace - validate before adding",
        "Monitor content sync status in Sentinel > Content management > Repositories"
    )
    testRequired      = $testRequired
}

Write-Host "=== Deploy-SentinelContent complete. Status: $overallStatus ===" -ForegroundColor Cyan
