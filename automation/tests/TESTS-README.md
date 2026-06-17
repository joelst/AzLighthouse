# Test Suite Reference

## Quick Commands

```powershell
# All tests (run from automation/ root)
.\tools\Run-Tests.ps1                    # App registration tests
.\Tests\Run-DataConnectorTests.ps1       # Data connector tests

# Specific categories
Invoke-Pester -FullNameFilter '*Lookup Logic*'     # Connector lookup
Invoke-Pester -FullNameFilter '*Validation*'       # Input validation
Invoke-Pester -FullNameFilter '*Credential*'       # Credential tests
```

## Test Suites

### App Registration Tests (15+ tests)

**File**: `Update-AppRegistrationCredential.ps1.Tests.ps1`

**Key Areas**:

- Credential rotation and expiration
- Write-AppGroupSummary parameter handling (FIXED)
- Secret notification to Logic App
- Error handling and authentication

### Data Connector Tests (45+ tests)

**File**: `Get-DataConnectorStatus.Tests.ps1`

**Primary Focus - Connector Lookup Logic**:

```powershell
# Primary: connector.Id → $ConnectorInfo[].Id
# Fallback: connector.Name → $ConnectorInfo[].Id
# Always: preserve actual connector.Id
```

**Test Categories**:

- Metadata lookup (10 tests) Primary focus
- Validation functions (14 tests)
- Helper functions (12 tests)
- Integration scenarios (5 tests)
- Data structures (4 tests)

## Recent Updates (Oct 24, 2025)

### App Registration Tests

- **Parameter Type Fix**: Write-AppGroupSummary now handles single objects
- **Enhanced Error Handling**: Better error scenario coverage

### Data Connector Tests

- **Lookup Logic**: Comprehensive connector metadata matching
- **Status Classification**: ActivelyIngesting, RecentlyActive, Stale
- **Integration Testing**: End-to-end scenario validation

## Expected Results

```text
App Registration Tests: 15+ passing
Data Connector Tests:   45+ passing
  Total Execution Time:   < 1 minute
  Code Coverage:          > 75%
  Pass Rate:              100%
```

## Troubleshooting

```powershell
# Install/update Pester
Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck

# Execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Debug mode
$DebugPreference = 'Continue'
.\tools\Run-Tests.ps1 -Detailed
```

## CI/CD Integration

**Output Files**:

- `TestResults.xml` - NUnit format
- `coverage.xml` - JaCoCo coverage

**Azure DevOps**:

```yaml
- task: PowerShell@2
  inputs:
    filePath: 'automation/tools/Run-Tests.ps1'
```

**GitHub Actions**:

```yaml
- shell: pwsh
  run: .\automation\tools\Run-Tests.ps1
```

---

**Key Points**:

- No Azure authentication required (fully mocked)
- Focus on business logic, not Azure API behavior
- Comprehensive error scenario coverage
- Performance optimized for CI/CD pipelines

**Last Updated**: October 24, 2025
