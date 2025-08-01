# Azure Automation Credential Check - Testing Guide

This directory contains comprehensive testing infrastructure for the Azure Automation credential check script.

## Files Overview

- `New-AppRegistrationCredentialCheck.ps1` - Main Azure Automation script
- `New-AppRegistrationCredentialCheck.Tests.ps1` - Pester 5 test suite
- `PesterConfig.psd1` - Pester configuration file
- `Run-Tests.ps1` - Test runner script
- `Testing-README.md` - This documentation

## Prerequisites

### Required Modules
```powershell
# Install Pester 5 (required)
Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck

# Azure modules (for integration testing)
Install-Module -Name Az.Accounts -Force
Install-Module -Name Az.Resources -Force
Install-Module -Name Microsoft.Graph.Authentication -Force
Install-Module -Name Microsoft.Graph.Applications -Force
```

### PowerShell Version
- PowerShell 5.1 or higher required
- PowerShell 7.x recommended for best performance

## Running Tests

### Quick Start
```powershell
# Run all tests with default configuration
.\Run-Tests.ps1
```

### Advanced Usage
```powershell
# Run tests without code coverage
.\Run-Tests.ps1 -CodeCoverage:$false

# Run tests with minimal output
.\Run-Tests.ps1 -Detailed:$false

# Run tests with custom configuration
.\Run-Tests.ps1 -ConfigPath ".\CustomConfig.psd1"

# Run specific test file
.\Run-Tests.ps1 -TestPath ".\New-AppRegistrationCredentialCheck.Tests.ps1"
```

### Direct Pester Execution
```powershell
# Using configuration file
$Config = Import-PowerShellDataFile -Path ".\PesterConfig.psd1"
$PesterConfig = New-PesterConfiguration -Hashtable $Config
Invoke-Pester -Configuration $PesterConfig

# Quick test run without configuration
Invoke-Pester -Path ".\New-AppRegistrationCredentialCheck.Tests.ps1"
```

## Test Structure

### Test Categories

1. **Function Tests**
   - `New-SecretNotification` function validation
   - `New-AppRegCredential` function validation
   - Parameter validation and error handling

2. **Parameter Validation Tests**
   - Required parameter validation
   - Value range validation
   - Type validation

3. **Error Handling Tests**
   - Authentication failures
   - API call failures
   - Invalid parameter scenarios

4. **Integration Simulation Tests**
   - End-to-end workflow simulation
   - Summary statistics validation
   - Multi-application scenarios

5. **Security Tests**
   - Secret handling validation
   - Partial secret exposure verification
   - Secure credential creation

### Mock Strategy

The tests use extensive mocking to avoid dependencies on actual Azure resources:

- **Azure Authentication**: Mocked `Connect-AzAccount`, `Get-AzContext`
- **Graph API**: Mocked `Connect-MgGraph`, `Get-MgApplication`, `New-MgApplicationPassword`
- **Azure Resources**: Mocked `Get-AzRoleAssignment`, `Get-AzADServicePrincipal`
- **Automation Variables**: Mocked `Get-AutomationVariable`

## Output and Reports

### Test Results
- **Console Output**: Real-time test execution feedback
- **NUnit XML**: `TestResults.xml` - Standard test result format
- **Code Coverage**: `coverage.xml` - JaCoCo format coverage report

### Test Result Analysis
```powershell
# View test results
[xml]$Results = Get-Content ".\TestResults.xml"
$Results.'test-results'.'test-suite'.results.'test-case' |
    Where-Object { $_.result -eq 'Failure' } |
    Select-Object name, message

# View code coverage summary
[xml]$Coverage = Get-Content ".\coverage.xml"
$Coverage.report.counter | Where-Object { $_.type -eq 'LINE' }
```

## Configuration Options

### Pester Configuration (`PesterConfig.psd1`)

```powershell
@{
    Run = @{
        Path = @('.\New-AppRegistrationCredentialCheck.Tests.ps1')
        PassThru = $true
        Exit = $false
    }
    TestResult = @{
        Enabled = $true
        OutputFormat = 'NUnitXml'
        OutputPath = '.\TestResults.xml'
    }
    CodeCoverage = @{
        Enabled = $true
        Path = @('.\New-AppRegistrationCredentialCheck.ps1')
        OutputFormat = 'JaCoCo'
        OutputPath = '.\coverage.xml'
    }
}
```

### Customizing Configuration

1. **Change Output Paths**
   ```powershell
   $Config.TestResult.OutputPath = 'C:\TestResults\MyResults.xml'
   $Config.CodeCoverage.OutputPath = 'C:\TestResults\MyCoverage.xml'
   ```

2. **Disable Code Coverage**
   ```powershell
   $Config.CodeCoverage.Enabled = $false
   ```

3. **Change Verbosity**
   ```powershell
   $Config.Output.Verbosity = 'Normal'  # or 'Minimal', 'Detailed', 'Diagnostic'
   ```

## Continuous Integration

### Azure DevOps Pipeline
```yaml
steps:
- task: PowerShell@2
  displayName: 'Run Pester Tests'
  inputs:
    targetType: 'filePath'
    filePath: '$(Build.SourcesDirectory)/azure-automate/Run-Tests.ps1'
    arguments: '-OutputPath "$(Agent.TempDirectory)"'

- task: PublishTestResults@2
  displayName: 'Publish Test Results'
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '$(Agent.TempDirectory)/TestResults.xml'

- task: PublishCodeCoverageResults@1
  displayName: 'Publish Code Coverage'
  inputs:
    codeCoverageTool: 'JaCoCo'
    summaryFileLocation: '$(Agent.TempDirectory)/coverage.xml'
```

### GitHub Actions
```yaml
steps:
- name: Run Pester Tests
  shell: pwsh
  run: |
    .\azure-automate\Run-Tests.ps1 -OutputPath "${{ runner.temp }}"

- name: Publish Test Results
  uses: dorny/test-reporter@v1
  if: always()
  with:
    name: Pester Tests
    path: '${{ runner.temp }}/TestResults.xml'
    reporter: java-junit
```

## Troubleshooting

### Common Issues

1. **Pester Version Conflicts**
   ```powershell
   # Remove old Pester versions
   Get-Module Pester -ListAvailable | Where-Object Version -lt '5.0.0' |
       ForEach-Object { Uninstall-Module -Name $_.Name -RequiredVersion $_.Version -Force }

   # Install Pester 5
   Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck
   ```

2. **Module Import Issues**
   ```powershell
   # Force import Pester 5
   Import-Module -Name Pester -MinimumVersion 5.0.0 -Force
   ```

3. **Path Resolution Issues**
   ```powershell
   # Ensure working directory is correct
   Set-Location "f:\git\AzLighthouse\azure-automate"
   .\Run-Tests.ps1
   ```

4. **Execution Policy Issues**
   ```powershell
   # Temporarily allow script execution
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Debug Mode

Run tests with debug information:
```powershell
$DebugPreference = 'Continue'
.\Run-Tests.ps1 -Detailed:$true
```

### Manual Test Execution

For debugging specific tests:
```powershell
# Run specific test blocks
Invoke-Pester -Path ".\New-AppRegistrationCredentialCheck.Tests.ps1" -Tag "Function"

# Run with breakpoints
Invoke-Pester -Path ".\New-AppRegistrationCredentialCheck.Tests.ps1" -EnableExit:$false
```

## Test Maintenance

### Adding New Tests

1. **Create new Describe block**
   ```powershell
   Describe "New Feature Tests" {
       Context "When testing new functionality" {
           It "Should perform expected behavior" {
               # Test implementation
           }
       }
   }
   ```

2. **Add appropriate mocks**
   ```powershell
   BeforeAll {
       Mock New-Function { return $MockObject }
   }
   ```

3. **Update configuration if needed**
   - Add new test files to `PesterConfig.psd1`
   - Update code coverage paths

### Best Practices

1. **Test Organization**
   - Group related tests in Context blocks
   - Use descriptive test names
   - Include both positive and negative test cases

2. **Mock Management**
   - Mock external dependencies
   - Use parameterized mocks for different scenarios
   - Verify mock calls with `Should -Invoke`

3. **Assertions**
   - Use specific assertions (`Should -Be`, `Should -Match`)
   - Test both success and failure paths
   - Validate error messages and types

## Performance Considerations

### Test Execution Time
- Average test run: 30-60 seconds
- Code coverage adds ~20% overhead
- Parallel execution not recommended due to mocking

### Resource Usage
- Memory: ~100MB during execution
- Disk: Test results ~1-5MB
- CPU: Moderate during mock setup

## Security Notes

### Test Data
- No real credentials used in tests
- Mock data only for Azure resources
- Test outputs safe for CI/CD logs

### Credential Handling
- Tests validate secure credential creation
- Verify partial secret exposure functionality
- No actual secrets generated during testing
