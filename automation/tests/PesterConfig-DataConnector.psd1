# Pester Configuration for Get-DataConnectorStatus Tests
# This file configures how Pester 5 should run the data connector tests

@{
  Run          = @{
    Path     = @('.\Get-DataConnectorStatus.Tests.ps1')
    PassThru = $true
    Exit     = $false
  }

  TestResult   = @{
    Enabled      = $true
    OutputFormat = 'NUnitXml'
    OutputPath   = '.\TestResults-DataConnector.xml'
  }

  CodeCoverage = @{
    Enabled        = $true
    Path           = @('..\Get-DataConnectorStatus.ps1')
    OutputFormat   = 'JaCoCo'
    OutputPath     = '.\coverage-dataconnector.xml'
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
