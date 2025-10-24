#Requires -Version 7.0
#Requires -Modules Pester

<#
.SYNOPSIS
    Test runner script for New-AppRegistrationCredentialCheck.ps1
.DESCRIPTION
    This script runs the Pester 5 tests for the Azure Automation credential check script
    with proper configuration and output formatting.
.PARAMETER ConfigPath
    Path to the Pester configuration file. Defaults to PesterConfig.psd1
.PARAMETER TestPath
    Path to the test file. Defaults to New-AppRegistrationCredentialCheck.Tests.ps1
.PARAMETER OutputPath
    Directory to store test results. Defaults to current directory
.PARAMETER CodeCoverage
    Enable code coverage analysis. Default is true
.PARAMETER Detailed
    Show detailed test output. Default is true
.EXAMPLE
    .\Run-Tests.ps1
    Runs tests with default configuration
.EXAMPLE
    .\Run-Tests.ps1 -CodeCoverage:$false -Detailed:$false
    Runs tests without code coverage or detailed output
#>

[CmdletBinding()]
param(
  [Parameter()]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$ConfigPath = '.\PesterConfig.psd1',

  [Parameter()]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$TestPath = '.\New-AppRegistrationCredentialCheck.Tests.ps1',

  [Parameter()]
  [ValidateScript({ Test-Path $_ -PathType Container })]
  [string]$OutputPath = '.',

  [Parameter()]
  [bool]$CodeCoverage = $true,

  [Parameter()]
  [bool]$Detailed = $true
)

# Ensure we're in the script directory
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $ScriptPath

try {
  Write-Host 'Starting Pester 5 tests for Azure Automation credential check script...' -ForegroundColor Green
  Write-Host "Script Location: $ScriptPath" -ForegroundColor Cyan
  Write-Host "Test File: $TestPath" -ForegroundColor Cyan
  Write-Host "Config File: $ConfigPath" -ForegroundColor Cyan
  Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan
  Write-Host ''

  # Check if Pester 5 is available
  $PesterModule = Get-Module -Name Pester -ListAvailable |
    Where-Object { $_.Version -ge [Version]'5.0.0' } |
    Sort-Object Version -Descending |
    Select-Object -First 1

  if (-not $PesterModule) {
    throw 'Pester 5.0 or higher is required. Please install with: Install-Module -Name Pester -Force -SkipPublisherCheck'
  }

  Write-Host "Using Pester version: $($PesterModule.Version)" -ForegroundColor Yellow

  # Import Pester module
  Import-Module -Name Pester -MinimumVersion 5.0.0 -Force

  # Load configuration
  if (Test-Path $ConfigPath) {
    Write-Host "Loading Pester configuration from: $ConfigPath" -ForegroundColor Yellow
    $Config = Import-PowerShellDataFile -Path $ConfigPath

    # Update paths to be absolute if needed
    if ($Config.Run.Path) {
      $Config.Run.Path = @(Resolve-Path $Config.Run.Path -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
    }

    if ($Config.CodeCoverage.Path) {
      $Config.CodeCoverage.Path = @(Resolve-Path $Config.CodeCoverage.Path -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
    }

    # Override code coverage setting if specified
    if (-not $CodeCoverage) {
      $Config.CodeCoverage.Enabled = $false
    }

    # Override verbosity if not detailed
    if (-not $Detailed) {
      $Config.Output.Verbosity = 'Normal'
    }

    # Update output paths to specified directory
    $Config.TestResult.OutputPath = Join-Path $OutputPath 'TestResults.xml'
    $Config.CodeCoverage.OutputPath = Join-Path $OutputPath 'coverage.xml'

    # Create Pester configuration object
    $PesterConfig = New-PesterConfiguration -Hashtable $Config
  }
  else {
    Write-Host 'No configuration file found, using default settings...' -ForegroundColor Yellow

    # Create default configuration
    $PesterConfig = New-PesterConfiguration
    $PesterConfig.Run.Path = $TestPath
    $PesterConfig.Run.PassThru = $true
    $PesterConfig.Run.Exit = $false

    $PesterConfig.TestResult.Enabled = $true
    $PesterConfig.TestResult.OutputFormat = 'NUnitXml'
    $PesterConfig.TestResult.OutputPath = Join-Path $OutputPath 'TestResults.xml'

    if ($CodeCoverage) {
      $PesterConfig.CodeCoverage.Enabled = $true
      $PesterConfig.CodeCoverage.Path = '.\New-AppRegistrationCredentialCheck.ps1'
      $PesterConfig.CodeCoverage.OutputFormat = 'JaCoCo'
      $PesterConfig.CodeCoverage.OutputPath = Join-Path $OutputPath 'coverage.xml'
    }

    if ($Detailed) {
      $PesterConfig.Output.Verbosity = 'Detailed'
    }
  }

  Write-Host 'Running tests...' -ForegroundColor Green
  Write-Host '===============================================' -ForegroundColor Cyan

  # Run tests
  $TestResults = Invoke-Pester -Configuration $PesterConfig

  Write-Host '===============================================' -ForegroundColor Cyan
  Write-Host 'Test execution completed!' -ForegroundColor Green
  Write-Host ''

  # Display summary
  Write-Host 'Test Summary:' -ForegroundColor Yellow
  Write-Host "  Total Tests: $($TestResults.TotalCount)" -ForegroundColor White
  Write-Host "  Passed: $($TestResults.PassedCount)" -ForegroundColor Green
  Write-Host "  Failed: $($TestResults.FailedCount)" -ForegroundColor Red
  Write-Host "  Skipped: $($TestResults.SkippedCount)" -ForegroundColor Yellow
  Write-Host "  Duration: $($TestResults.Duration)" -ForegroundColor White

  if ($TestResults.CodeCoverage) {
    $CoveragePercent = [math]::Round(($TestResults.CodeCoverage.NumberOfCommandsExecuted / $TestResults.CodeCoverage.NumberOfCommandsAnalyzed) * 100, 2)
    Write-Host "  Code Coverage: $CoveragePercent%" -ForegroundColor Cyan
  }

  Write-Host ''

  # Check for output files
  $TestResultPath = Join-Path $OutputPath 'TestResults.xml'
  if (Test-Path $TestResultPath) {
    Write-Host "Test results saved to: $TestResultPath" -ForegroundColor Cyan
  }

  if ($CodeCoverage) {
    $CoveragePath = Join-Path $OutputPath 'coverage.xml'
    if (Test-Path $CoveragePath) {
      Write-Host "Code coverage report saved to: $CoveragePath" -ForegroundColor Cyan
    }
  }

  # Exit with appropriate code
  if ($TestResults.FailedCount -gt 0) {
    Write-Host 'Some tests failed. Please review the output above.' -ForegroundColor Red
    exit $TestResults.FailedCount
  }
  else {
    Write-Host 'All tests passed successfully!' -ForegroundColor Green
    exit 0
  }
}
catch {
  Write-Error "Error running tests: $($_.Exception.Message)"
  Write-Host $_.ScriptStackTrace -ForegroundColor Red
  exit 1
}
finally {
  Pop-Location
}
