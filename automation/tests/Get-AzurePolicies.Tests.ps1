# Pester tests for Get-AzurePolicies runbook
# Requires: Pester 5+
# Run with: Invoke-Pester -Path .\Get-AzurePolicies.Tests.ps1

BeforeAll {
  $env:AZLH_SKIP_POLICY_RUN = '1'
  . "$PSScriptRoot\..\Get-AzurePolicies.ps1"
}

AfterAll {
  Remove-Item Env:AZLH_SKIP_POLICY_RUN -ErrorAction SilentlyContinue
}

# ============================================================================
# HELPER FUNCTION TESTS
# ============================================================================

Describe 'Assert-ValidGuid' {
  It 'Accepts a valid GUID' {
    { Assert-ValidGuid -value '11111111-1111-1111-1111-111111111111' -parameterName 'TestParam' } | Should -Not -Throw
  }

  It 'Rejects an invalid GUID' {
    { Assert-ValidGuid -value 'not-a-guid' -parameterName 'TestParam' } | Should -Throw '*valid GUID*'
  }

  It 'Rejects an empty string via ValidateNotNullOrEmpty' {
    { Assert-ValidGuid -value '' -parameterName 'TestParam' } | Should -Throw
  }
}

Describe 'Test-IsHttpsUri' {
  It 'Accepts HTTPS URI' {
    { Test-IsHttpsUri -uri 'https://example.com/path' -parameterName 'TestUri' } | Should -Not -Throw
  }

  It 'Rejects HTTP URI' {
    { Test-IsHttpsUri -uri 'http://example.com/path' -parameterName 'TestUri' } | Should -Throw '*HTTPS*'
  }

  It 'Rejects invalid URI' {
    { Test-IsHttpsUri -uri 'not a uri at all' -parameterName 'TestUri' } | Should -Throw '*valid URI*'
  }
}

Describe 'Get-UriHostForLog' {
  It 'Returns host portion only' {
    $result = Get-UriHostForLog -uri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
    $result | Should -Be 'prod-00.eastus.logic.azure.com'
  }

  It 'Returns placeholder for invalid URI' {
    $result = Get-UriHostForLog -uri 'not-a-uri'
    $result | Should -Be '(invalid-uri)'
  }
}

Describe 'Get-MaskedValue' {
  It 'Masks all but last 4 characters' {
    $result = Get-MaskedValue -value '11111111-1111-1111-1111-111111111111'
    $result | Should -Match '\*+1111$'
    $result | Should -Not -Be '11111111-1111-1111-1111-111111111111'
  }

  It 'Returns all stars for short values' {
    $result = Get-MaskedValue -value 'abc'
    $result | Should -Be '****'
  }
}

Describe 'Resolve-ConfiguredValue' {
  It 'Uses parameter value before environment variable' {
    $env:POLICYMONITORING_API = 'FromEnvironment'
    try {
      $result = Resolve-ConfiguredValue -parameterValue 'FromParameter' -environmentVariableNames @('POLICYMONITORING_API') -parameterName 'LogicAppUri'
      $result | Should -Be 'FromParameter'
    }
    finally {
      Remove-Item Env:POLICYMONITORING_API -ErrorAction SilentlyContinue
    }
  }

  It 'Uses environment variable when parameter is empty' {
    $env:POLICYMONITORING_API = 'FromEnvironment'
    try {
      $result = Resolve-ConfiguredValue -parameterValue '' -environmentVariableNames @('POLICYMONITORING_API') -parameterName 'LogicAppUri'
      $result | Should -Be 'FromEnvironment'
    }
    finally {
      Remove-Item Env:POLICYMONITORING_API -ErrorAction SilentlyContinue
    }
  }

  It 'Throws when neither parameter nor environment value is present' {
    Remove-Item Env:POLICYMONITORING_API -ErrorAction SilentlyContinue
    { Resolve-ConfiguredValue -parameterValue '' -environmentVariableNames @('POLICYMONITORING_API') -parameterName 'LogicAppUri' } | Should -Throw
  }
}

Describe 'Get-OptionalPropertyValue' {
  It 'Returns property value when present' {
    $obj = [PSCustomObject]@{ Name = 'TestPolicy' }
    Get-OptionalPropertyValue -inputObject $obj -propertyName 'Name' | Should -Be 'TestPolicy'
  }

  It 'Returns null when property is missing' {
    $obj = [PSCustomObject]@{ Name = 'TestPolicy' }
    Get-OptionalPropertyValue -inputObject $obj -propertyName 'MissingProp' | Should -BeNullOrEmpty
  }

  It 'Returns null when object is null' {
    Get-OptionalPropertyValue -inputObject $null -propertyName 'Name' | Should -BeNullOrEmpty
  }
}

# ============================================================================
# MAIN FUNCTION TESTS
# ============================================================================

Describe 'Invoke-AzurePolicyInventory' {
  BeforeEach {
    Mock Connect-AzAccount { }
    Mock Set-AzContext { }
    Mock Invoke-RestMethod { }

    Mock Get-AzPolicyAssignment {
      @(
        [PSCustomObject]@{
          Name               = 'audit-vm-extensions'
          DisplayName        = 'Audit VM Extensions'
          PolicyDefinitionId = '/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/policyDefinitions/def-1111'
          EnforcementMode    = 'Default'
          Scope              = '/subscriptions/22222222-2222-2222-2222-222222222222'
          Parameters         = @{}
        },
        [PSCustomObject]@{
          Name               = 'cis-benchmark'
          DisplayName        = 'CIS Benchmark'
          PolicyDefinitionId = '/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/policySetDefinitions/set-2222'
          EnforcementMode    = 'Default'
          Scope              = '/subscriptions/22222222-2222-2222-2222-222222222222'
          Parameters         = @{}
        }
      )
    }

    Mock Get-AzPolicyDefinition {
      [PSCustomObject]@{
        Name                       = 'def-1111'
        DisplayName                = 'Audit VM Extensions Policy'
        PolicyType                 = 'Custom'
        Description                = 'Audits VM extensions'
        PolicyRule                 = @{ if = @{ field = 'type'; equals = 'Microsoft.Compute/virtualMachines/extensions' }; then = @{ effect = 'audit' } }
        SystemDataLastModifiedBy   = 'user@contoso.com'
        SystemDataLastModifiedAt   = '2026-01-15T10:00:00Z'
      }
    }

    Mock Get-AzPolicySetDefinition {
      [PSCustomObject]@{
        Name                       = 'set-2222'
        DisplayName                = 'CIS Benchmark Initiative'
        PolicyType                 = 'Custom'
        Description                = 'CIS controls'
        SystemDataLastModifiedBy   = 'admin@contoso.com'
        SystemDataLastModifiedAt   = '2026-01-20T14:00:00Z'
      }
    }
  }

  It 'Authenticates with UAMI and resolves both definitions and policy sets' {
    $result = Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter { $Identity -and $AccountId -eq '11111111-1111-1111-1111-111111111111' }
    Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq '22222222-2222-2222-2222-222222222222' }
    Should -Invoke Get-AzPolicyAssignment -Times 1
    Should -Invoke Get-AzPolicyDefinition -Times 1
    Should -Invoke Get-AzPolicySetDefinition -Times 1
    Should -Invoke Invoke-RestMethod -Times 1

    $result.AssignmentCount | Should -Be 2
    $result.PolicyDefinitionCount | Should -Be 1
    $result.PolicySetDefinitionCount | Should -Be 1
    $result.FailedDefinitionLookups | Should -Be 0
    $result.PostStatus | Should -Be 'Success'
    $result.RunId | Should -Not -BeNullOrEmpty
    $result.RunbookVersion | Should -Not -BeNullOrEmpty
    $result.DurationSeconds | Should -BeGreaterOrEqual 0
  }

  It 'Does not include PolicyRule by default' {
    $script:capturedBody = $null
    Mock Invoke-RestMethod {
      param($Method, $Uri, $Body, $ContentType)
      $script:capturedBody = $Body
    }

    Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    $parsed = $script:capturedBody | ConvertFrom-Json
    $parsed.PolicyDefinitions[0].PSObject.Properties.Name | Should -Not -Contain 'PolicyRule'
  }

  It 'Includes PolicyRule when -IncludePolicyRule is specified' {
    $script:capturedBody = $null
    Mock Invoke-RestMethod {
      param($Method, $Uri, $Body, $ContentType)
      $script:capturedBody = $Body
    }

    Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret' `
      -IncludePolicyRule

    $parsed = $script:capturedBody | ConvertFrom-Json
    $parsed.PolicyDefinitions[0].PSObject.Properties.Name | Should -Contain 'PolicyRule'
  }

  It 'Does not POST when -WhatIf is specified' {
    $result = Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret' `
      -WhatIf

    Should -Invoke Invoke-RestMethod -Times 0
    $result.PostStatus | Should -Be 'Skipped (WhatIf)'
  }

  It 'Throws on invalid UmiClientId GUID' {
    { Invoke-AzurePolicyInventory `
        -UmiClientId 'not-a-guid' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
    } | Should -Throw '*valid GUID*'
  }

  It 'Throws on invalid SubscriptionId GUID' {
    { Invoke-AzurePolicyInventory `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId 'bad-sub-id' `
        -WorkspaceName 'law-prod' `
        -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
    } | Should -Throw '*valid GUID*'
  }

  It 'Throws on HTTP (non-HTTPS) Logic App URI' {
    { Invoke-AzurePolicyInventory `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -LogicAppUri 'http://insecure.example.com/workflows/abc'
    } | Should -Throw '*HTTPS*'
  }

  It 'Throws on missing required value' {
    { Invoke-AzurePolicyInventory `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName '' `
        -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
    } | Should -Throw '*Missing required value*'
  }

  It 'Captures per-definition failure without aborting the run' {
    Mock Get-AzPolicyDefinition { throw 'Definition not found' }

    $result = Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    $result.FailedDefinitionLookups | Should -BeGreaterThan 0
    $result.PostStatus | Should -Be 'Success'
  }

  It 'Summary has expected properties' {
    $result = Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    $props = $result.PSObject.Properties.Name
    $props | Should -Contain 'RunId'
    $props | Should -Contain 'RunbookVersion'
    $props | Should -Contain 'StartTimeUtc'
    $props | Should -Contain 'EndTimeUtc'
    $props | Should -Contain 'DurationSeconds'
    $props | Should -Contain 'SubscriptionId'
    $props | Should -Contain 'Scope'
    $props | Should -Contain 'WorkspaceName'
    $props | Should -Contain 'AssignmentCount'
    $props | Should -Contain 'PolicyDefinitionCount'
    $props | Should -Contain 'PolicySetDefinitionCount'
    $props | Should -Contain 'FailedDefinitionLookups'
    $props | Should -Contain 'IncludedPolicyRule'
    $props | Should -Contain 'LogicAppHost'
    $props | Should -Contain 'PostStatus'
    $props | Should -Contain 'PostHttpStatus'
  }

  It 'Never logs the full Logic App URI' {
    $logMessages = [System.Collections.Generic.List[string]]::new()

    Mock Write-Information {
      param($MessageData)
      $logMessages.Add([string]$MessageData)
    }
    Mock Write-Warning {
      param($Message)
      $logMessages.Add([string]$Message)
    }
    Mock Write-Verbose {
      param($Message)
      $logMessages.Add([string]$Message)
    }

    Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=supersecrettoken123'

    $allOutput = $logMessages -join "`n"
    $allOutput | Should -Not -Match 'supersecrettoken123'
    $allOutput | Should -Not -Match 'sig='
  }

  It 'Handles empty policy assignment list gracefully' {
    Mock Get-AzPolicyAssignment { @() }

    $result = Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    $result.AssignmentCount | Should -Be 0
    $result.PolicyDefinitionCount | Should -Be 0
    $result.PolicySetDefinitionCount | Should -Be 0
    $result.PostStatus | Should -Be 'Success'
  }

  It 'Handles assignment with empty PolicyDefinitionId' {
    Mock Get-AzPolicyAssignment {
      @(
        [PSCustomObject]@{
          Name               = 'empty-def-assignment'
          DisplayName        = 'Empty Def'
          PolicyDefinitionId = ''
          EnforcementMode    = 'Default'
          Scope              = '/subscriptions/22222222-2222-2222-2222-222222222222'
          Parameters         = @{}
        }
      )
    }

    $result = Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    $result.AssignmentCount | Should -Be 1
    $result.PolicyDefinitionCount | Should -Be 0
    Should -Invoke Get-AzPolicyDefinition -Times 0
  }

  It 'Deduplicates definition lookups for repeated PolicyDefinitionId' {
    Mock Get-AzPolicyAssignment {
      @(
        [PSCustomObject]@{
          Name               = 'assignment-a'
          DisplayName        = 'Assignment A'
          PolicyDefinitionId = '/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/policyDefinitions/same-def'
          EnforcementMode    = 'Default'
          Scope              = '/subscriptions/22222222-2222-2222-2222-222222222222'
          Parameters         = @{}
        },
        [PSCustomObject]@{
          Name               = 'assignment-b'
          DisplayName        = 'Assignment B'
          PolicyDefinitionId = '/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/policyDefinitions/same-def'
          EnforcementMode    = 'Default'
          Scope              = '/subscriptions/22222222-2222-2222-2222-222222222222'
          Parameters         = @{}
        }
      )
    }

    Invoke-AzurePolicyInventory `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -WorkspaceName 'law-prod' `
      -LogicAppUri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

    Should -Invoke Get-AzPolicyDefinition -Times 1
  }
}
