# Verify Logic App Permissions for Data Collection Rules
# This script checks if the Logic App's managed identity has the required permissions
# to ingest data via DCE/DCR

param(
    [Parameter(Mandatory=$true)]
    [string]$LogicAppName,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [string]$DCRResourceGroup,
    
    [string]$DCRImmutableI,
    
    [string]$DCEName
)

Write-Host "`n=== Logic App Permission Verification ===" -ForegroundColor Cyan
Write-Host "Logic App: $LogicAppName" -ForegroundColor White
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "Subscription: $SubscriptionId`n" -ForegroundColor White

# Step 1: Get Logic App Identity
Write-Host "Step 1: Retrieving Logic App Identity..." -ForegroundColor Yellow
try {
    $logicApp = Get-AzLogicApp -Name $LogicAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
    
    if (-not $logicApp.Identity) {
        Write-Host "❌ ERROR: Logic App does not have a managed identity enabled!" -ForegroundColor Red
        Write-Host "   Enable it: Logic App → Settings → Identity → System assigned = On" -ForegroundColor Yellow
        exit 1
    }
    
    $principalId = $logicApp.Identity.PrincipalId
    $identityType = $logicApp.Identity.Type
    
    Write-Host "✓ Logic App Identity Found" -ForegroundColor Green
    Write-Host "  Type: $identityType" -ForegroundColor White
    Write-Host "  Principal ID: $principalId`n" -ForegroundColor White
}
catch {
    Write-Host "❌ ERROR: Could not retrieve Logic App: $_" -ForegroundColor Red
    exit 1
}

# Step 2: Check DCR Permissions
Write-Host "Step 2: Checking Data Collection Rule Permissions..." -ForegroundColor Yellow
$dcrScope = "/subscriptions/$SubscriptionId/resourceGroups/$DCRResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$DCRImmutableId"
Write-Host "  Scope: $dcrScope" -ForegroundColor Gray

try {
    $dcrRoles = Get-AzRoleAssignment -ObjectId $principalId -Scope $dcrScope -ErrorAction SilentlyContinue
    
    $hasMonitoringDataPublisher = $dcrRoles | Where-Object { $_.RoleDefinitionName -eq "Monitoring Data Publisher" }
    
    if ($hasMonitoringDataPublisher) {
        Write-Host "✓ Has 'Monitoring Data Publisher' role on DCR" -ForegroundColor Green
    }
    else {
        Write-Host "❌ MISSING: 'Monitoring Data Publisher' role on DCR" -ForegroundColor Red
        Write-Host "   To fix, run:" -ForegroundColor Yellow
        Write-Host "   New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName 'Monitoring Data Publisher' -Scope '$dcrScope'" -ForegroundColor White
    }
}
catch {
    Write-Host "⚠ Could not check DCR permissions: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 3: Check DCE Permissions
Write-Host "Step 3: Checking Data Collection Endpoint Permissions..." -ForegroundColor Yellow
$dceScope = "/subscriptions/$SubscriptionId/resourceGroups/$DCRResourceGroup/providers/Microsoft.Insights/dataCollectionEndpoints/$DCEName"
Write-Host "  Scope: $dceScope" -ForegroundColor Gray

try {
    $dceRoles = Get-AzRoleAssignment -ObjectId $principalId -Scope $dceScope -ErrorAction SilentlyContinue
    
    $hasMonitoringDCEDataSender = $dceRoles | Where-Object { 
        $_.RoleDefinitionName -eq "Monitoring Data Collection Endpoint Data Sender" -or
        $_.RoleDefinitionName -like "*DCE*Data*Sender*"
    }
    
    if ($hasMonitoringDCEDataSender) {
        Write-Host "✓ Has 'Monitoring Data Collection Endpoint Data Sender' role on DCE" -ForegroundColor Green
    }
    else {
        Write-Host "❌ MISSING: 'Monitoring Data Collection Endpoint Data Sender' role on DCE" -ForegroundColor Red
        Write-Host "   To fix, run:" -ForegroundColor Yellow
        Write-Host "   New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName 'Monitoring Data Collection Endpoint Data Sender' -Scope '$dceScope'" -ForegroundColor White
    }
}
catch {
    Write-Host "⚠ Could not check DCE permissions: $_" -ForegroundColor Yellow
}

Write-Host ""

# Step 4: Check all role assignments for this identity (helpful for troubleshooting)
Write-Host "Step 4: All Role Assignments for this Identity:" -ForegroundColor Yellow
try {
    $allRoles = Get-AzRoleAssignment -ObjectId $principalId | Select-Object RoleDefinitionName, Scope
    if ($allRoles) {
        $allRoles | Format-Table -AutoSize
    }
    else {
        Write-Host "  No role assignments found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  Could not retrieve all role assignments" -ForegroundColor Gray
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Cyan
Write-Host "Note: Role assignment changes can take 5-10 minutes to propagate." -ForegroundColor Yellow
