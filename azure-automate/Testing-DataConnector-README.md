# Get-MsspDataConnectorStatus Tests

## Overview
Comprehensive Pester 5 test suite for the Sentinel Data Connectors management runbook.

## Test Coverage

### Core Functions Tested

#### 1. `Get-LogIngestionMetrics` - Connector Metadata Lookup
**Primary Lookup Logic:**
- ✅ Matches connector's `Id` property against `$ConnectorInfo[].Id` (case-insensitive)
- ✅ Falls back to matching connector's `Name` property against `$ConnectorInfo[].Id`
- ✅ Preserves actual connector `Id` in output even when no mapping found
- ✅ Populates `Title` and `Publisher` from matched `$ConnectorInfo` entry
- ✅ Returns null `Title`/`Publisher` when no match found
- ✅ Sets `QueryStatus` to 'NoKql' when no mapping exists

**Scenarios Covered:**
```powershell
# Scenario 1: Id matches directly
Connector: { Id="Office365", Name="SomeName", Kind="Office365" }
Result:    { Id="Office365", Title="Office 365", Publisher="Microsoft" }

# Scenario 2: Id doesn't match, Name does
Connector: { Id="aa944eec-guid", Name="Office365", Kind="Office365" }
Result:    { Id="aa944eec-guid", Title="Office 365", Publisher="Microsoft" }

# Scenario 3: No match found
Connector: { Id="custom-id", Name="CustomConnector", Kind="Custom" }
Result:    { Id="custom-id", Title=null, Publisher=null }
```

#### 2. `Get-ConnectorStatus` - Integration Tests
- ✅ Passes `ConnectorId` to `Get-LogIngestionMetrics`
- ✅ Correctly handles connectors with `Id` property
- ✅ Preserves `Id` while using Name fallback for metadata
- ✅ Sets appropriate status for connectors without logs
- ✅ Handles 'NoKqlAndNoLogs' status correctly

#### 3. `Resolve-ConnectorKind`
- ✅ Handles StaticUI connectors (promotes Name to Kind)
- ✅ Falls back to 'UnknownKind' when name is GUID
- ✅ Collapses array kinds into comma-separated list
- ✅ Handles various connector object shapes

#### 4. `Get-IngestionStatus`
- ✅ Returns nulls when `LastLogTime` is missing
- ✅ Classifies 'ActivelyIngesting' (≤12 hours)
- ✅ Classifies 'RecentlyActive' (>12h, ≤24h)
- ✅ Classifies 'Stale' (>24 hours)
- ✅ Calculates `HoursSinceLastLog` correctly

#### 5. `Invoke-WithRetry`
- ✅ Retries operations with exponential backoff
- ✅ Returns result on eventual success
- ✅ Throws after max attempts exhausted

#### 6. Validation Functions
**Test-SubscriptionIdFormat:**
- ✅ Accepts valid GUID formats (upper/lowercase)
- ✅ Rejects invalid GUIDs
- ✅ Rejects null/empty strings

**Test-ResourceGroupName:**
- ✅ Accepts valid names with allowed characters
- ✅ Rejects names >90 characters
- ✅ Rejects invalid characters (@, spaces)
- ✅ Rejects null/empty strings

**Test-WorkspaceName:**
- ✅ Accepts valid names (4-63 chars, alphanumeric + hyphens)
- ✅ Rejects names <4 or >63 characters
- ✅ Rejects names starting/ending with hyphen
- ✅ Rejects null/empty strings

#### 7. `Get-ConnectivityResults`
- ✅ Returns false when no criteria provided
- ✅ Returns false when WorkspaceCustomerId is null
- ✅ Returns true when any criteria returns data
- ✅ Skips null or empty queries

#### 8. `$ConnectorInfo` Array Structure
- ✅ Contains expected connector entries (>10)
- ✅ Each entry has required properties (Id, Title, Publisher, Kql, ConnectivityCriteria)
- ✅ Office365 entry validated
- ✅ AzureActiveDirectory entry validated

## Running Tests

### Prerequisites
```powershell
# Install Pester 5+ (if not already installed)
Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

### Run All Tests
```powershell
# Basic run (no coverage)
.\Run-DataConnectorTests.ps1

# With code coverage
.\Run-DataConnectorTests.ps1 -Coverage

# CI mode (exits with error code on failure)
.\Run-DataConnectorTests.ps1 -CI -Coverage
```

### Run Specific Test Suite
```powershell
# Using Pester directly
Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1 -Output Detailed

# Using configuration file
$config = New-PesterConfiguration -Hashtable (Import-PowerShellDataFile .\PesterConfig-DataConnector.psd1)
Invoke-Pester -Configuration $config
```

### Run Specific Describe Block
```powershell
Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1 -FullNameFilter "*Get-LogIngestionMetrics*"
```

## Test Results

### Output Files
- **TestResults-DataConnector.xml**: NUnit XML format (for CI/CD integration)
- **coverage-dataconnector.xml**: JaCoCo code coverage report

### Expected Results
```
Total Tests:  40+
Passed:       40+
Failed:       0
Skipped:      0
Code Coverage: >80%
```

## Mocking Strategy

### Azure Cmdlets Mocked
- `Invoke-AzOperationalInsightsQuery`: Returns empty results to avoid actual Azure calls
- All tests run without requiring Azure authentication
- Tests focus on business logic, not Azure API behavior

### Test Isolation
- Each test is independent
- `BeforeAll` blocks set up mocks for describe blocks
- No state shared between tests

## Test Scenarios by Priority

### Critical Path (P0)
1. ✅ Connector Id → $ConnectorInfo.Id matching
2. ✅ Connector Name → $ConnectorInfo.Id fallback
3. ✅ Actual connector Id preserved in output
4. ✅ Title/Publisher populated from matched entry
5. ✅ Case-insensitive matching

### Important Path (P1)
1. ✅ No match returns null Title/Publisher
2. ✅ Status classification (ActivelyIngesting, RecentlyActive, Stale)
3. ✅ NoKqlAndNoLogs status handling
4. ✅ Validation functions

### Edge Cases (P2)
1. ✅ Null/empty parameters
2. ✅ StaticUI kind promotion
3. ✅ GUID pattern recognition
4. ✅ Retry logic

## Future Test Enhancements

### Integration Tests (Requires Azure)
- [ ] Actual Azure Log Analytics queries
- [ ] Real connector enumeration
- [ ] Role assignment verification
- [ ] Logic App posting

### Performance Tests
- [ ] Large connector set processing
- [ ] Parallel execution validation
- [ ] Query timeout handling

### End-to-End Tests
- [ ] Full runbook execution (mocked Azure)
- [ ] Output JSON validation
- [ ] Error handling and recovery

## Troubleshooting

### Common Issues

**Issue: "Pester module not found"**
```powershell
Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

**Issue: "MSP_SKIP_CONNECTOR_RUN not working"**
- Ensure environment variable is set before dot-sourcing script
- Check that `if ($env:MSP_SKIP_CONNECTOR_RUN -eq '1')` block exists in main script

**Issue: "Mock not being called"**
```powershell
# Verify mock is in correct scope (BeforeAll vs BeforeEach)
# Check that function name matches exactly
# Ensure -ModuleName parameter if function is in module
```

**Issue: "Tests pass locally but fail in CI"**
- Check PowerShell version (7+ for some features)
- Verify Pester version consistency
- Check for path issues (use $PSScriptRoot)

## Contributing

### Adding New Tests
1. Follow existing test structure (Describe → Context → It)
2. Use descriptive test names
3. Mock external dependencies
4. Test both success and failure paths
5. Include edge cases

### Test Naming Convention
```powershell
Describe 'FunctionName' {
    Context 'Specific scenario or condition' {
        It 'Should do expected behavior when condition met' {
            # Arrange, Act, Assert
        }
    }
}
```

### Best Practices
- One assertion per test (when possible)
- Clear arrange/act/assert sections
- Meaningful variable names
- Mock external dependencies
- Test edge cases
- Keep tests fast (<1s each)
