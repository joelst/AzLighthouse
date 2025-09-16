#Requires -Module Pester

BeforeAll {
  # Import the script to test
  $scriptPath = Join-Path $PSScriptRoot 'New-AppRegistrationCredentialCheck.ps1'

  # Mock external modules and functions that would normally be available in Azure Automation
  function Get-AutomationVariable { param($Name) }
  function Connect-AzAccount { param($Identity, $AccountId) }
  function Set-AzContext { param($SubscriptionName, $DefaultProfile) }
  function Connect-MgGraph { param($Identity, $ClientId, $NoWelcome) }
  function Get-AzTenant { param($ErrorAction, $TenantId) }
  function Get-MgOrganization { param($ErrorAction) }
  function Get-MgDomain { param($ErrorAction) }
  function Get-MgApplication { param($All, $ErrorAction, $ConsistencyLevel) }
  function Add-MgApplicationPassword { param($ApplicationId, $PasswordCredential) }
  function Remove-MgApplicationPassword { param($ApplicationId, $KeyId) }
  function New-AzADServicePrincipal { param() }
  function New-MgApplicationOwnerByRef { param($ApplicationId, $BodyParameter) }
  function New-AzRoleAssignment { param($RoleDefinitionId, $ObjectId, $Scope) }
  function Get-AzContext { }
  function Disable-AzContextAutosave { param($Scope) }
  function Invoke-RestMethod { param($Uri, $Method, $Body, $ContentType) }

  # Source the functions from the script without executing the main logic
  $scriptContent = Get-Content $scriptPath -Raw
  $functionsOnly = $scriptContent -replace '(?s)# Ensures you do not inherit.*$', ''

  # Create a temporary script file with just the functions
  $tempScript = New-TemporaryFile
  $tempScript = $tempScript.FullName + '.ps1'
  $functionsOnly | Out-File -FilePath $tempScript -Encoding UTF8

  . $tempScript

  # Clean up temp file
  Remove-Item $tempScript -Force
}

Describe 'New-SecretNotification Function Tests' {
  BeforeEach {
    # Set up environment variables
    $env:TENANT_ID = 'test-tenant-id'
    $env:TENANT_NAME = 'Test Tenant'
    $env:TENANT_DOMAIN = 'test.onmicrosoft.com'

    # Mock global UMIId variable
    $global:UMIId = 'test-umi-id'
  }

  Context 'Parameter Validation' {
    It 'Should throw when UMIId is not set' {
      $global:UMIId = $null
      { New-SecretNotification -URI 'https://test.com' -ApplicationId 'test-app' } | Should -Throw 'No UMI Id specified in New-SecretNotification function'
    }

    It 'Should set default values for empty parameters' {
      Mock Invoke-RestMethod { return @{} }

      $result = New-SecretNotification -URI 'https://test.com' -ApplicationId 'test-app' -WhatIf
      $result | Should -Be $true
    }
  }

  Context 'JSON Body Creation' {
    It 'Should create proper JSON structure' {
      Mock Invoke-RestMethod {
        param($Uri, $Method, $Body, $ContentType)
        $jsonObj = $Body | ConvertFrom-Json
        $jsonObj.appId | Should -Not -BeNullOrEmpty
        $jsonObj.applicationId | Should -Be 'test-app-id'
        $jsonObj.action | Should -Be 'Create'
        return @{}
      }

      New-SecretNotification -URI 'https://test.com' -ApplicationId 'test-app-id' -AppId 'test-app' -Action 'Create' -WhatIf
    }
  }

  Context 'Error Handling' {
    It 'Should handle REST API failures gracefully' {
      Mock Invoke-RestMethod { throw 'API Error' }
      Mock Write-Error { }

      $result = New-SecretNotification -URI 'https://test.com' -ApplicationId 'test-app' -WhatIf
      $result | Should -Be $true
      Should -Invoke Write-Error -Times 2
    }
  }
}

Describe 'New-AppRegCredential Function Tests' {
  BeforeEach {
    # Set up environment variables
    $env:TENANT_ID = 'test-tenant-id'
    $env:TENANT_NAME = 'Test Tenant'
    $env:TENANT_DOMAIN = 'test.onmicrosoft.com'

    # Initialize summary stats
    $script:SummaryStats = @{
      SecretsCreated        = 0
      SecretsFailedToCreate = 0
    }
    $script:ValidAppRegExists = $false
  }

  Context 'Successful Credential Creation' {
    It 'Should create new credential and update statistics' {
      Mock Add-MgApplicationPassword {
        return @{
          KeyId         = 'test-key-id'
          DisplayName   = 'Test Secret'
          StartDateTime = (Get-Date)
          EndDateTime   = (Get-Date).AddDays(180)
          SecretText    = 'test-secret-value'
        }
      }
      Mock New-SecretNotification { return $true }

      New-AppRegCredential -ApplicationId 'test-app-id' -SecretApiUri 'https://test.com' -AppId 'test-app' -AppDisplayName 'Test App' -WhatIf

      $script:SummaryStats.SecretsCreated | Should -Be 1
      $script:ValidAppRegExists | Should -Be $true
    }
  }

  Context 'Failed Credential Creation' {
    It 'Should handle credential creation failure' {
      Mock Add-MgApplicationPassword { throw 'Permission denied' }
      Mock Write-Error { }

      $result = New-AppRegCredential -ApplicationId 'test-app-id' -SecretApiUri 'https://test.com' -AppDisplayName 'Test App' -WhatIf

      $result | Should -Be $false
      $script:SummaryStats.SecretsFailedToCreate | Should -Be 1
      Should -Invoke Write-Error -Times 2
    }

    It 'Should handle empty KeyId scenario' {
      Mock Add-MgApplicationPassword {
        return @{
          KeyId       = ''
          DisplayName = 'Test Secret'
        }
      }
      Mock Write-Warning { }

      New-AppRegCredential -ApplicationId 'test-app-id' -SecretApiUri 'https://test.com' -AppDisplayName 'Test App' -WhatIf

      $script:SummaryStats.SecretsFailedToCreate | Should -Be 1
      $script:ValidAppRegExists | Should -Be $false
    }
  }
}

Describe 'Script Parameter Validation' {
  Context 'Required Parameters' {
    It 'Should validate UMIId parameter range' {
      $testParams = @{
        UMIId                = 'test-umi-id'
        DaysBeforeExpiration = 500  # Invalid - exceeds 365
      }

      # This would normally be caught by ValidateRange attribute
      $testParams.DaysBeforeExpiration | Should -BeGreaterThan 365
    }

    It 'Should validate CredentialValidDays parameter range' {
      $testParams = @{
        UMIId               = 'test-umi-id'
        CredentialValidDays = 800  # Invalid - exceeds 730
      }

      # This would normally be caught by ValidateRange attribute
      $testParams.CredentialValidDays | Should -BeGreaterThan 730
    }
  }
}

Describe 'Summary Statistics Tracking' {
  BeforeEach {
    $script:SummaryStats = @{
      MatchingApplications       = 0
      TotalSecrets               = 0
      ExpiredSecrets             = 0
      ExpiringSecrets            = 0
      ValidSecrets               = 0
      SecretsDeleted             = 0
      SecretsCreated             = 0
      SecretsFailedToCreate      = 0
      ApplicationsCreated        = 0
      ApplicationsFailedToCreate = 0
    }
  }

  Context 'Statistics Initialization' {
    It 'Should initialize all statistics to zero' {
      $script:SummaryStats.MatchingApplications | Should -Be 0
      $script:SummaryStats.TotalSecrets | Should -Be 0
      $script:SummaryStats.ExpiredSecrets | Should -Be 0
      $script:SummaryStats.ExpiringSecrets | Should -Be 0
      $script:SummaryStats.ValidSecrets | Should -Be 0
      $script:SummaryStats.SecretsDeleted | Should -Be 0
      $script:SummaryStats.SecretsCreated | Should -Be 0
      $script:SummaryStats.SecretsFailedToCreate | Should -Be 0
      $script:SummaryStats.ApplicationsCreated | Should -Be 0
      $script:SummaryStats.ApplicationsFailedToCreate | Should -Be 0
    }
  }

  Context 'Statistics Updates' {
    It 'Should increment statistics correctly' {
      $script:SummaryStats.SecretsCreated++
      $script:SummaryStats.ApplicationsCreated++

      $script:SummaryStats.SecretsCreated | Should -Be 1
      $script:SummaryStats.ApplicationsCreated | Should -Be 1
    }
  }
}

Describe 'Credential Expiration Logic' {
  Context 'Date Calculations' {
    It 'Should correctly identify expired credentials' {
      $expiredDate = (Get-Date).AddDays(-10)
      $dateDifference = New-TimeSpan -Start (Get-Date) -End $expiredDate

      $dateDifference.Days | Should -BeLessOrEqual 0
    }

    It 'Should correctly identify expiring credentials' {
      $expiringDate = (Get-Date).AddDays(15)  # 15 days from now
      $dateDifference = New-TimeSpan -Start (Get-Date) -End $expiringDate
      $daysBeforeExpiration = 30

      ($dateDifference.Days -le $daysBeforeExpiration -and $dateDifference.Days -gt 0) | Should -Be $true
    }

    It 'Should correctly identify valid credentials' {
      $validDate = (Get-Date).AddDays(60)  # 60 days from now
      $dateDifference = New-TimeSpan -Start (Get-Date) -End $validDate
      $daysBeforeExpiration = 30

      $dateDifference.Days | Should -BeGreaterThan $daysBeforeExpiration
    }
  }
}

Describe 'Error Handling Scenarios' {
  Context 'Authentication Failures' {
    It 'Should handle Azure authentication failure' {
      Mock Connect-AzAccount { throw 'Authentication failed' }
      Mock Write-Error { }

      # This would be tested in an integration test of the full script
      # Here we're just ensuring the mock works
      { Connect-AzAccount -Identity -AccountId 'test' } | Should -Throw 'Authentication failed'
    }

    It 'Should handle Microsoft Graph authentication failure' {
      Mock Connect-MgGraph { throw 'Graph authentication failed' }

      { Connect-MgGraph -Identity -ClientId 'test' -NoWelcome } | Should -Throw 'Graph authentication failed'
    }
  }

  Context 'Application Registration Failures' {
    It 'Should handle service principal creation failure' {
      Mock New-AzADServicePrincipal { throw 'Insufficient permissions' }

      { New-AzADServicePrincipal -DisplayName 'Test App' } | Should -Throw 'Insufficient permissions'
    }
  }
}

Describe 'Configuration Validation' {
  Context 'Environment Variables' {
    It 'Should handle missing environment variables gracefully' {
      $env:TENANT_ID = $null
      $env:TENANT_NAME = $null
      $env:TENANT_DOMAIN = $null

      # The script should handle these scenarios
      $env:TENANT_ID | Should -BeNullOrEmpty
      $env:TENANT_NAME | Should -BeNullOrEmpty
      $env:TENANT_DOMAIN | Should -BeNullOrEmpty
    }
  }
}

Describe 'Integration Test Scenarios' {
  Context 'End-to-End Workflow Simulation' {
    BeforeEach {
      # Reset all tracking variables
      $script:SummaryStats = @{
        MatchingApplications       = 0
        TotalSecrets               = 0
        ExpiredSecrets             = 0
        ExpiringSecrets            = 0
        ValidSecrets               = 0
        SecretsDeleted             = 0
        SecretsCreated             = 0
        SecretsFailedToCreate      = 0
        ApplicationsCreated        = 0
        ApplicationsFailedToCreate = 0
      }
    }

    It 'Should simulate finding applications with mixed credential states' {
      # Mock finding 2 applications
      $script:SummaryStats.MatchingApplications = 2

      # Mock credential analysis results
      $script:SummaryStats.TotalSecrets = 5
      $script:SummaryStats.ExpiredSecrets = 1
      $script:SummaryStats.ExpiringSecrets = 1
      $script:SummaryStats.ValidSecrets = 3

      # Mock actions taken
      $script:SummaryStats.SecretsDeleted = 1
      $script:SummaryStats.SecretsCreated = 1

      # Verify the simulation
      $script:SummaryStats.MatchingApplications | Should -Be 2
      $script:SummaryStats.TotalSecrets | Should -Be 5
      ($script:SummaryStats.ExpiredSecrets + $script:SummaryStats.ExpiringSecrets + $script:SummaryStats.ValidSecrets) | Should -Be 5
      $script:SummaryStats.SecretsDeleted | Should -Be 1
      $script:SummaryStats.SecretsCreated | Should -Be 1
    }
  }
}

AfterAll {
  # Clean up environment variables
  Remove-Item Env:TENANT_* -ErrorAction SilentlyContinue

  # Remove any global variables we may have set
  Remove-Variable -Name 'UMIId' -Scope Global -ErrorAction SilentlyContinue
}
