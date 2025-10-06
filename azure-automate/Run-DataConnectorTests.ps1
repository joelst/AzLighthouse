# Run-DataConnectorTests.ps1
# Executes Pester tests for Get-MsspDataConnectorStatus.ps1
# Requires: Pester 5+ (Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck)

[CmdletBinding()]
param(
    [switch]$Coverage,
    [switch]$CI
)

$ErrorActionPreference = 'Stop'

# Ensure we're in the script directory
Push-Location $PSScriptRoot

try {
    # Check Pester version
    $pesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
    
    if (-not $pesterModule) {
        Write-Error "Pester module not found. Install with: Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck"
        exit 1
    }
    
    if ($pesterModule.Version.Major -le 5) {
        Write-Error "Pester 6+ required. Current version: $($pesterModule.Version). Upgrade with: Install-Module Pester -MinimumVersion 6 -Force -SkipPublisherCheck"
        exit 1
    }
    
    Write-Host "Using Pester version: $($pesterModule.Version)" -ForegroundColor Cyan
    Import-Module Pester -MinimumVersion 5.0
    
    # Load configuration
    $configPath = Join-Path $PSScriptRoot 'PesterConfig-DataConnector.psd1'
    
    if (-not (Test-Path $configPath)) {
        Write-Error "Pester configuration not found at: $configPath"
        exit 1
    }
    
    # Modify config based on parameters
    $config = New-PesterConfiguration -Hashtable (Import-PowerShellDataFile -Path $configPath)
    
    if (-not $Coverage) {
        $config.CodeCoverage.Enabled = $false
    }
    
    if ($CI) {
        $config.Run.Exit = $true
        $config.Output.Verbosity = 'Detailed'
    }
    
    # Run tests
    Write-Host "`nRunning Get-MsspDataConnectorStatus tests..." -ForegroundColor Green
    Write-Host "============================================`n" -ForegroundColor Green
    
    $result = Invoke-Pester -Configuration $config
    
    # Display summary
    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "Test Results Summary" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Total Tests:  $($result.TotalCount)" -ForegroundColor White
    Write-Host "Passed:       $($result.PassedCount)" -ForegroundColor Green
    Write-Host "Failed:       $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Skipped:      $($result.SkippedCount)" -ForegroundColor Yellow
    Write-Host "Duration:     $($result.Duration)" -ForegroundColor White
    
    if ($Coverage -and $result.CodeCoverage) {
        $coveredPercent = [math]::Round(($result.CodeCoverage.CoveragePercent), 2)
        Write-Host "`nCode Coverage: $coveredPercent%" -ForegroundColor $(if ($coveredPercent -ge 80) { 'Green' } elseif ($coveredPercent -ge 60) { 'Yellow' } else { 'Red' })
        Write-Host "Covered:       $($result.CodeCoverage.CommandsExecutedCount) / $($result.CodeCoverage.CommandsAnalyzedCount) commands" -ForegroundColor White
    }
    
    Write-Host "============================================`n" -ForegroundColor Green
    
    # Exit with appropriate code
    if ($result.FailedCount -gt 0) {
        Write-Host "Tests FAILED" -ForegroundColor Red
        exit 1
    }
    else {
        Write-Host "All tests PASSED" -ForegroundColor Green
        exit 0
    }
}
catch {
    Write-Error "Test execution failed: $_"
    exit 1
}
finally {
    Pop-Location
}
