# Data Connector Status Tests

## Quick Start

```powershell
# Run tests with default settings
.\Run-DataConnectorTests.ps1

# With code coverage
.\Run-DataConnectorTests.ps1 -Coverage
```

**Expected Result**: ✅ 45+ tests passing in ~340ms

## What's Tested

### 🎯 Core Logic: Connector Metadata Lookup
The primary focus validates how connectors are matched with metadata:

```powershell
# Primary: Match connector Id → $ConnectorInfo[].Id
# Fallback: Match connector Name → $ConnectorInfo[].Id  
# Always: Preserve connector's actual Id
```

**Test Scenarios**:
- ✅ Direct Id matching (case-insensitive)
- ✅ Name fallback when Id doesn't match
- ✅ Id preservation when no match found
- ✅ Title/Publisher population from metadata

### 🔧 Supporting Functions
- ✅ **Ingestion Status**: Classification (ActivelyIngesting, RecentlyActive, Stale)
- ✅ **Validation**: Subscription ID, resource group, workspace name formats
- ✅ **Connectivity**: Query execution and result handling
- ✅ **Retry Logic**: Exponential backoff for failed operations

## Test Categories

| Category | Tests | Focus |
|----------|-------|-------|
| **Connector Lookup** | 10 | Metadata matching logic |
| **Validation Functions** | 14 | Input parameter validation |
| **Helper Functions** | 12 | Utility function behavior |
| **Integration** | 5 | End-to-end scenarios |
| **Data Structures** | 4 | $ConnectorInfo array |

## Common Commands

```powershell
# Specific test groups
Invoke-Pester -FullNameFilter '*Lookup Logic*'     # Metadata matching
Invoke-Pester -FullNameFilter '*Validation*'       # Input validation  
Invoke-Pester -FullNameFilter '*Integration*'      # End-to-end

# Detailed output
Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1 -Output Detailed

# CI mode (exit codes)
Invoke-Pester -CI
```

## Key Test Examples

### Connector Lookup Logic
```powershell
# Test: Direct Id match
Connector: { Id="Office365", Name="SomeName" }
Expected:  { Id="Office365", Title="Office 365", Publisher="Microsoft" }

# Test: Name fallback
Connector: { Id="aa944eec-guid", Name="Office365" }
Expected:  { Id="aa944eec-guid", Title="Office 365", Publisher="Microsoft" }

# Test: No match
Connector: { Id="custom-id", Name="CustomConnector" }
Expected:  { Id="custom-id", Title=null, Publisher=null }
```

### Status Classification
```powershell
# ActivelyIngesting: Last log ≤ 12 hours
# RecentlyActive: Last log > 12h, ≤ 24h  
# Stale: Last log > 24 hours
```

## Troubleshooting

### Common Issues
```powershell
# Pester version
Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck

# Script execution during test load
$env:MSP_SKIP_CONNECTOR_RUN = '1'  # Set this before running

# Mock not working
# Ensure mocks are in BeforeAll blocks
```

### Debug Mode
```powershell
$DebugPreference = 'Continue'
.\Run-DataConnectorTests.ps1 -Detailed
```

## Current Status

```
✅ Tests: 45+
⏱️ Time: ~340ms  
🎯 Coverage: >80%
📊 Pass Rate: 100%
```

---

**Note**: Tests use extensive mocking - no Azure authentication required.  
**Last Updated**: October 24, 2025
