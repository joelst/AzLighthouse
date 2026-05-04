# Pester Configuration for Update-AppRegistrationCredential Tests
# This file configures how Pester 5 should run the tests

@{
  Run          = @{
    Path     = @('.\Update-AppRegistrationCredential.ps1.Tests.ps1')
    PassThru = $true
    Exit     = $false
  }

  TestResult   = @{
    Enabled      = $true
    OutputFormat = 'NUnitXml'
    OutputPath   = '.\TestResults.xml'
  }

  CodeCoverage = @{
    Enabled        = $true
    Path           = @('..\Update-AppRegistrationCredential.ps1')
    OutputFormat   = 'JaCoCo'
    OutputPath     = '.\coverage.xml'
    OutputEncoding = 'UTF8'
    UseBreakpoints = $false
  }

  Output       = @{
    Verbosity           = 'Detailed'
    StackTraceVerbosity = 'Filtered'
    CIFormat            = 'Auto'
  }

  Should       = @{
    ErrorAction = 'Stop'
  }

  Debug        = @{
    ShowFullErrors         = $true
    WriteDebugMessages     = $false
    WriteDebugMessagesFrom = @()
    ShowNavigationMarkers  = $false
    ReturnRawResultObject  = $false
  }
}
