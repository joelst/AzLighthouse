#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# TEST_REQUIRED: Requires Microsoft.Graph.Users and Microsoft.Graph.Identity.SignIns; MFA check may need Reports.Read.All

param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [string]$CustomerTenantId,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = ".\evidence"
)

$scriptName = "Test-CustomerOnboardingAccount"
$config     = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$customerShortName  = $config.customer.shortName
$resolvedTenantId   = $CustomerTenantId ?? $config.customer.tenantId
$upn                = $config.rsocOnboardingAccount.upn

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

Write-Host "`n=== Customer Onboarding Account Validation ===" -ForegroundColor Cyan
Write-Host "Customer: $customerShortName  |  Tenant: $resolvedTenantId  |  UPN: $upn`n"

 Connect to Microsoft Graph # 
Write-Host "Connecting to Microsoft Graph (tenant: $resolvedTenantId) ..." -ForegroundColor Yellow
try {
    Connect-MgGraph -TenantId $resolvedTenantId `
        -Scopes "User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All" `
        -NoWelcome -ErrorAction Stop
    Write-Host "Connected." -ForegroundColor Green
} catch {
    Write-Host "FATAL: Could not connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

 Account exists # 
$userObj = $null
try {
    $userObj = Get-MgUser -UserId $upn `
        -Property Id,DisplayName,AccountEnabled,UserPrincipalName -ErrorAction Stop
    Add-Check -Name "Account exists: $upn" -Passed $true `
        -Detail "DisplayName: $($userObj.DisplayName)  |  Id: $($userObj.Id)"
} catch {
    Add-Check -Name "Account exists: $upn" -Passed $false -Detail $_.Exception.Message
    $status = if ($WhatIfMode) { 'whatif-only' } else { 'failed' }
    Write-Evidence -Data @{
        scriptName        = $scriptName
        customerShortName = $customerShortName
        status            = $status
        timestampUtc      = (Get-Date).ToUniversalTime().ToString("o")
        testRequired      = @("Requires Microsoft.Graph.Users","MFA check may need Reports.Read.All")
        upn               = $upn
        tenantId          = $resolvedTenantId
        checks            = $checks.ToArray()
    } | Out-Null
    exit 1
}

 AccountEnabled # 
Add-Check -Name "Account is enabled" -Passed ($userObj.AccountEnabled -eq $true) `
    -Detail "AccountEnabled: $($userObj.AccountEnabled)"

 License check (AAD P1/P2) # 
$validPlanNames = @('AAD_PREMIUM_P2','AAD_PREMIUM','INTUNE_A_VL','SPE_E3','SPE_E5','M365EDU_A5_FACULTY')
try {
    $licenses       = Get-MgUserLicenseDetail -UserId $userObj.Id -ErrorAction Stop
    $hasValidLicense = $false
    $foundPlans      = [System.Collections.Generic.List[string]]::new()
    foreach ($lic in $licenses) {
        foreach ($plan in $lic.ServicePlans) {
            if ($plan.ServicePlanName -in $validPlanNames -and $plan.ProvisioningStatus -eq 'Success') {
                $hasValidLicense = $true
                $foundPlans.Add($plan.ServicePlanName)
            }
        }
    }
    Add-Check -Name "Has AAD P1/P2 (or equivalent) license" -Passed $hasValidLicense `
        -Detail "Matching plans: $($foundPlans -join ', ')  |  Total license objects: $($licenses.Count)"
} catch {
    Add-Check -Name "Has AAD P1/P2 (or equivalent) license" -Passed $false `
        -Detail $_.Exception.Message
}

 MFA registered # 
try {
    $authMethods = Get-MgUserAuthenticationMethod -UserId $userObj.Id -ErrorAction Stop
    $mfaCount    = $authMethods.Count
    $mfaOk       = $mfaCount -gt 1
    Add-Check -Name "MFA registered (auth methods > 1)" -Passed $mfaOk `
        -Detail "Authentication method count: $mfaCount  (1 = password only, 2+ = MFA configured)"
} catch {
    Add-Check -Name "MFA registered (auth methods > 1)" -Passed $false `
        -Detail $_.Exception.Message
}

 NOT in Global Administrators # 
try {
    $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop |
        Select-Object -First 1
    if ($null -ne $gaRole) {
        $gaMembers  = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -ErrorAction Stop
        $isGlobalAdmin = ($gaMembers | Where-Object { $_.Id -eq $userObj.Id } | Measure-Object).Count -gt 0
        Add-Check -Name "Account NOT in Global Administrators role" -Passed (-not $isGlobalAdmin) `
            -Detail "Is Global Admin: $isGlobalAdmin"
    } else {
        Add-Check -Name "Account NOT in Global Administrators role" -Passed $true `
            -Detail "Global Administrator role not found in directory"
    }
} catch {
    Add-Check -Name "Account NOT in Global Administrators role" -Passed $false `
        -Detail $_.Exception.Message
}

 Manual action notice # 
# MANUAL_ACTION: Verify account has Owner on target subscription (cannot check cross-tenant via Graph alone) -
#   go to Azure Portal > Subscriptions > IAM > confirm account UPN has Owner role
Write-Host "`n[MANUAL_ACTION] Cannot verify subscription Owner role cross-tenant via Graph." -ForegroundColor Magenta
Write-Host "  Please confirm in Azure Portal:" -ForegroundColor Magenta
Write-Host "    Subscriptions > $($config.deployment.subscriptionId) > IAM" -ForegroundColor Magenta
Write-Host "    Verify '$upn' has the 'Owner' role" -ForegroundColor Magenta

 Evidence # 
$failCount = ($checks | Where-Object { -not $_.passed } | Measure-Object).Count
$status    = if ($WhatIfMode) { 'whatif-only' } elseif ($failCount -eq 0) { 'passed' } else { 'failed' }

$evidenceData = @{
    scriptName        = $scriptName
    customerShortName = $customerShortName
    status            = $status
    timestampUtc      = (Get-Date).ToUniversalTime().ToString("o")
    testRequired      = @(
        "Requires Microsoft.Graph.Users",
        "Requires Microsoft.Graph.Identity.SignIns",
        "MFA check may need Reports.Read.All"
    )
    upn               = $upn
    tenantId          = $resolvedTenantId
    userId            = $userObj?.Id
    userDisplayName   = $userObj?.DisplayName
    checks            = $checks.ToArray()
    manualActions     = @(
        "Verify '$upn' has Owner role on subscription $($config.deployment.subscriptionId) via Azure Portal > Subscriptions > IAM"
    )
    failCount         = $failCount
}

$evidencePath = Write-Evidence -Data $evidenceData

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Checks: $($checks.Count)  Fail: $failCount  Status: $status"
Write-Host "Evidence: $evidencePath`n"

if ($failCount -gt 0) { exit 1 }
