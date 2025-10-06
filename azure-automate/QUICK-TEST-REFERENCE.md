# Quick Test Reference

## Prerequisites
```powershell
Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

## Run Tests

### Data Connector Tests
```powershell
# Basic run
.\Run-DataConnectorTests.ps1

# With coverage
.\Run-DataConnectorTests.ps1 -Coverage

# CI mode
.\Run-DataConnectorTests.ps1 -CI -Coverage
```

### App Registration Tests
```powershell
# Basic run
.\Run-Tests.ps1

# Without coverage
.\Run-Tests.ps1 -CodeCoverage:$false
```

## Run Specific Tests
```powershell
# Data connector lookup tests only
Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1 -FullNameFilter "*Get-LogIngestionMetrics*"

# Validation tests only
Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1 -FullNameFilter "*Validation*"

# Integration tests only
Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1 -FullNameFilter "*Get-ConnectorStatus*"
```

## Expected Results
```
✓ 40+ tests passing
✓ 0 failures
✓ >80% code coverage
✓ <30 seconds execution
```

## Output Files
- `TestResults-DataConnector.xml` - NUnit format
- `coverage-dataconnector.xml` - JaCoCo format

## Troubleshooting

### Pester Version Issue
```powershell
Get-Module Pester -ListAvailable | 
    Where-Object Version -lt '5.0.0' |
    ForEach-Object { Uninstall-Module -Name $_.Name -RequiredVersion $_.Version -Force }
Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

### Import Issue
```powershell
Import-Module Pester -MinimumVersion 5.0 -Force
```

### Path Issue
```powershell
cd f:\git\AzLighthouse\azure-automate
.\Run-DataConnectorTests.ps1
```

## Documentation
- **Testing-DataConnector-README.md** - Comprehensive test docs
- **Testing-README.md** - General testing guide
- **TEST-IMPLEMENTATION-SUMMARY.md** - Implementation overview
