# Pester tests for Get-SentinelPricing runbook
# Requires: Pester 5+
# Run with: Invoke-Pester -Path .\Get-SentinelPricing.Tests.ps1

BeforeAll {
  $env:AZLH_SKIP_PRICING_RUN = '1'
  . "$PSScriptRoot\..\Get-SentinelPricing.ps1"
}

AfterAll {
  Remove-Item Env:AZLH_SKIP_PRICING_RUN -ErrorAction SilentlyContinue
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
}

Describe 'Test-IsHttpsUri' {
  It 'Accepts HTTPS URI' {
    { Test-IsHttpsUri -uri 'https://example.com/path' -parameterName 'TestUri' } | Should -Not -Throw
  }

  It 'Rejects HTTP URI' {
    { Test-IsHttpsUri -uri 'http://example.com/path' -parameterName 'TestUri' } | Should -Throw '*HTTPS*'
  }

  It 'Rejects non-absolute URI' {
    { Test-IsHttpsUri -uri '/relative/path' -parameterName 'TestUri' } | Should -Throw '*valid URI*'
  }
}

Describe 'Get-UriHostForLog' {
  It 'Returns host portion only, stripping query string' {
    $result = Get-UriHostForLog -uri 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
    $result | Should -Be 'prod-00.eastus.logic.azure.com'
  }
}

Describe 'Get-MaskedValue' {
  It 'Masks all but last 4 characters' {
    $result = Get-MaskedValue -value '11111111-1111-1111-1111-111111111111'
    $result | Should -Match '\*+1111$'
  }
}

Describe 'Resolve-ConfiguredValue' {
  It 'Uses parameter value before environment variable' {
    $env:PRICINGTIER_API = 'FromEnvironment'
    try {
      $result = Resolve-ConfiguredValue -parameterValue 'FromParameter' -environmentVariableNames @('PRICINGTIER_API') -parameterName 'pricingTierApi'
      $result | Should -Be 'FromParameter'
    }
    finally {
      Remove-Item Env:PRICINGTIER_API -ErrorAction SilentlyContinue
    }
  }

  It 'Uses environment variable when parameter is empty' {
    $env:PRICINGTIER_API = 'FromEnvironment'
    try {
      $result = Resolve-ConfiguredValue -parameterValue '' -environmentVariableNames @('PRICINGTIER_API') -parameterName 'pricingTierApi'
      $result | Should -Be 'FromEnvironment'
    }
    finally {
      Remove-Item Env:PRICINGTIER_API -ErrorAction SilentlyContinue
    }
  }

  It 'Throws when no value is found from any source' {
    Remove-Item Env:PRICINGTIER_API -ErrorAction SilentlyContinue
    { Resolve-ConfiguredValue -parameterValue '' -environmentVariableNames @('PRICINGTIER_API') -parameterName 'pricingTierApi' } | Should -Throw '*Missing required*'
  }
}

Describe 'Get-OptionalPropertyValue' {
  It 'Returns property value when present' {
    $obj = [PSCustomObject]@{ Name = 'TestWorkspace' }
    Get-OptionalPropertyValue -inputObject $obj -propertyName 'Name' | Should -Be 'TestWorkspace'
  }

  It 'Returns null when property is missing' {
    $obj = [PSCustomObject]@{ Name = 'TestWorkspace' }
    Get-OptionalPropertyValue -inputObject $obj -propertyName 'MissingProp' | Should -BeNullOrEmpty
  }

  It 'Returns null when object is null' {
    Get-OptionalPropertyValue -inputObject $null -propertyName 'Name' | Should -BeNullOrEmpty
  }
}

# ============================================================================
# MAIN FUNCTION TESTS
# ============================================================================

Describe 'Invoke-SentinelPricingCheck' {
  BeforeEach {
    Mock Connect-AzAccount { }
    Mock Set-AzContext { }
    Mock Invoke-RestMethod { }
  }

  Context 'PerGB2018 SKU (Pay-As-You-Go)' {
    BeforeEach {
      Mock Get-AzOperationalInsightsWorkspace {
        [PSCustomObject]@{
          Name = 'law-prod'
          Sku  = [PSCustomObject]@{ Name = 'PerGB2018' }
        }
      }
    }

    It 'Authenticates with UAMI and resolves Pay-As-You-Go tier' {
      $result = Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

      Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter { $Identity -and $AccountId -eq '11111111-1111-1111-1111-111111111111' }
      Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq '22222222-2222-2222-2222-222222222222' }
      Should -Invoke Invoke-RestMethod -Times 1

      $result.PricingTier | Should -Be 'Pay-As-You-Go'
      $result.SkuName | Should -Be 'PerGB2018'
      $result.PostStatus | Should -Be 'Success'
      $result.RunId | Should -Not -BeNullOrEmpty
    }

    It 'Does not POST when -WhatIf is specified' {
      $result = Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret' `
        -WhatIf

      Should -Invoke Invoke-RestMethod -Times 0
      $result.PostStatus | Should -Be 'Skipped (WhatIf)'
      $result.PricingTier | Should -Be 'Pay-As-You-Go'
    }

    It 'Summary has expected properties' {
      $result = Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

      $props = $result.PSObject.Properties.Name
      $props | Should -Contain 'RunId'
      $props | Should -Contain 'RunbookVersion'
      $props | Should -Contain 'StartTimeUtc'
      $props | Should -Contain 'EndTimeUtc'
      $props | Should -Contain 'DurationSeconds'
      $props | Should -Contain 'WorkspaceName'
      $props | Should -Contain 'PricingTier'
      $props | Should -Contain 'SkuName'
      $props | Should -Contain 'SubscriptionId'
      $props | Should -Contain 'ResourceGroupName'
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

      Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=supersecrettoken123'

      $allOutput = $logMessages -join "`n"
      $allOutput | Should -Not -Match 'supersecrettoken123'
      $allOutput | Should -Not -Match 'sig='
    }
  }

  Context 'CapacityReservation SKU' {
    It 'Maps CapacityReservation with level to N GB' {
      Mock Get-AzOperationalInsightsWorkspace {
        [PSCustomObject]@{
          Name = 'law-prod'
          Sku  = [PSCustomObject]@{
            Name                     = 'CapacityReservation'
            CapacityReservationLevel = 200
          }
        }
      }

      $result = Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

      $result.PricingTier | Should -Be '200 GB'
      $result.SkuName | Should -Be 'CapacityReservation'
    }

    It 'Falls back to Commitment Tier when capacity level is null' {
      Mock Get-AzOperationalInsightsWorkspace {
        [PSCustomObject]@{
          Name = 'law-prod'
          Sku  = [PSCustomObject]@{ Name = 'CapacityReservation' }
        }
      }

      $result = Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

      $result.PricingTier | Should -Be 'Commitment Tier'
    }
  }

  Context 'Unknown SKU' {
    It 'Preserves raw SKU name in output' {
      Mock Get-AzOperationalInsightsWorkspace {
        [PSCustomObject]@{
          Name = 'law-prod'
          Sku  = [PSCustomObject]@{ Name = 'Standalone' }
        }
      }

      $result = Invoke-SentinelPricingCheck `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -WorkspaceName 'law-prod' `
        -ResourceGroupName 'rg-prod' `
        -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'

      $result.PricingTier | Should -Be 'Unknown (Standalone)'
      $result.SkuName | Should -Be 'Standalone'
    }
  }

  Context 'Validation' {
    BeforeEach {
      Mock Get-AzOperationalInsightsWorkspace {
        [PSCustomObject]@{
          Name = 'law-prod'
          Sku  = [PSCustomObject]@{ Name = 'PerGB2018' }
        }
      }
    }

    It 'Throws on invalid UmiClientId GUID' {
      { Invoke-SentinelPricingCheck `
          -UmiClientId 'not-a-guid' `
          -SubscriptionId '22222222-2222-2222-2222-222222222222' `
          -WorkspaceName 'law-prod' `
          -ResourceGroupName 'rg-prod' `
          -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
      } | Should -Throw '*valid GUID*'
    }

    It 'Throws on invalid SubscriptionId GUID' {
      { Invoke-SentinelPricingCheck `
          -UmiClientId '11111111-1111-1111-1111-111111111111' `
          -SubscriptionId 'bad-sub' `
          -WorkspaceName 'law-prod' `
          -ResourceGroupName 'rg-prod' `
          -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
      } | Should -Throw '*valid GUID*'
    }

    It 'Throws on HTTP (non-HTTPS) Logic App URI' {
      { Invoke-SentinelPricingCheck `
          -UmiClientId '11111111-1111-1111-1111-111111111111' `
          -SubscriptionId '22222222-2222-2222-2222-222222222222' `
          -WorkspaceName 'law-prod' `
          -ResourceGroupName 'rg-prod' `
          -PricingTierApi 'http://insecure.example.com/workflows/abc'
      } | Should -Throw '*HTTPS*'
    }

    It 'Throws on missing required value' {
      { Invoke-SentinelPricingCheck `
          -UmiClientId '11111111-1111-1111-1111-111111111111' `
          -SubscriptionId '22222222-2222-2222-2222-222222222222' `
          -WorkspaceName '' `
          -ResourceGroupName 'rg-prod' `
          -PricingTierApi 'https://prod-00.eastus.logic.azure.com/workflows/abc?sig=secret'
      } | Should -Throw '*Missing required*'
    }
  }
}
