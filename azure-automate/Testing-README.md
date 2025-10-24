# 🧪 Azure Automation Testing Guide

## Quick Start

```powershell
# Install Pester (if needed)
Install-Module -Name Pester -MinimumVersion 7.0.0 -Force -SkipPublisherCheck

# Run all tests
cd X:\git\AzLighthouse\azure-automate
.\Run-Tests.ps1                    # App Registration tests
.\Run-DataConnectorTests.ps1       # Data Connector tests
```

## Test Suites

### 1. App Registration Credential Management
**Script**: `Update-AppRegistrationCredential.ps1`  
**Tests**: `Update-RegistrationCredential.ps1.Tests.ps1`  
**Runner**: `Run-Tests.ps1`

**What's Tested**:
- ✅ Credential rotation and expiration logic
- ✅ Secret notification to Logic App
- ✅ Write-AppGroupSummary parameter handling (FIXED)
- ✅ Error handling and authentication
- ✅ Summary statistics tracking

### 2. Sentinel Data Connector Monitoring
**Script**: `Get-DataConnectorStatus.ps1`  
**Tests**: `Get-DataConnectorStatus.Tests.ps1`  
**Runner**: `Run-DataConnectorTests.ps1`

**What's Tested**:
- ✅ Connector metadata lookup logic (primary focus)
- ✅ Ingestion status classification
- ✅ KQL query execution
- ✅ Integration scenarios
- ✅ Validation functions

## Running Tests

### Basic Commands
```powershell
# All app registration tests
.\Run-Tests.ps1

# All data connector tests  
.\Run-DataConnectorTests.ps1

# With detailed output
.\Run-Tests.ps1 -Detailed

# With code coverage
.\Run-DataConnectorTests.ps1 -Coverage
```

### Advanced Usage
```powershell
# Specific test categories
Invoke-Pester -FullNameFilter '*Lookup Logic*'     # Connector lookup
Invoke-Pester -FullNameFilter '*Validation*'       # Input validation
Invoke-Pester -FullNameFilter '*Credential*'       # Credential tests

# Direct Pester execution
Invoke-Pester -Path ".\*.Tests.ps1" -Output Detailed
```

## Test Results

### Expected Outcomes
```
App Registration Tests:     15+ tests passing
Data Connector Tests:       45+ tests passing
Execution Time:             < 1 minute total
Code Coverage:              > 75%
```

### Output Files
- `TestResults.xml` - NUnit format (CI/CD compatible)
- `coverage.xml` - JaCoCo coverage report
- Console output with pass/fail summary

## Key Test Areas

### Recently Added (2024-10-24)
- **Write-AppGroupSummary**: Tests parameter type handling fix
- **Enhanced Error Handling**: Improved authentication and error scenarios

### Core Functionality
- **Credential Rotation**: Expiration detection, secret creation, cleanup
- **Connector Monitoring**: Metadata lookup, status classification, KQL execution
- **Integration**: Logic App posting, summary reporting, error recovery

## Troubleshooting

### Common Issues
```powershell
# Pester version conflicts
Get-Module Pester -ListAvailable | Where-Object Version -lt '5.0.0' | 
    ForEach-Object { Uninstall-Module -Name $_.Name -RequiredVersion $_.Version -Force }
Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck

# Execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Module loading
Import-Module -Name Pester -MinimumVersion 5.0.0 -Force
```

### Debug Mode
```powershell
$DebugPreference = 'Continue'
.\Run-Tests.ps1 -Detailed
```

## CI/CD Integration

### Azure DevOps
```yaml
steps:
- task: PowerShell@2
  displayName: 'Run Tests'
  inputs:
    targetType: 'filePath'
    filePath: '$(Build.SourcesDirectory)/azure-automate/Run-Tests.ps1'

- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '**/TestResults.xml'
```

### GitHub Actions
```yaml
steps:
- name: Run Tests
  shell: pwsh
  run: |
    .\azure-automate\Run-Tests.ps1
    .\azure-automate\Run-DataConnectorTests.ps1
```

## Test Structure

### Mocking Strategy
- **Azure Authentication**: All Azure/Graph calls mocked
- **External APIs**: Logic App posts mocked
- **Resource Operations**: Role assignments, app registrations mocked
- **Test Isolation**: Each test independent, no shared state

### Best Practices
- Tests run without Azure dependencies
- Comprehensive error scenario coverage
- Performance optimized (< 1 minute execution)
- CI/CD ready with standard output formats

---

**For detailed test specifications**: See `TESTS-README.md`  
**Last Updated**: October 24, 2025
