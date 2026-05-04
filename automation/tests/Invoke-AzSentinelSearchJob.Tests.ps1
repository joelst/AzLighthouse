# Pester tests for Invoke-AzSentinelSearchJob runbook

BeforeAll {
  $env:AZLH_SKIP_SEARCHJOB_RUN = '1'
  . "$PSScriptRoot\..\Invoke-AzSentinelSearchJob.ps1"
}

AfterAll {
  Remove-Item Env:AZLH_SKIP_SEARCHJOB_RUN -ErrorAction SilentlyContinue
}

Describe 'ConvertTo-SearchTableName' {
  It 'Appends _SRCH suffix when missing' {
    ConvertTo-SearchTableName -value 'HeartbeatByIp' | Should -Be 'HeartbeatByIp_SRCH'
  }

  It 'Keeps existing _SRCH suffix' {
    ConvertTo-SearchTableName -value 'HeartbeatByIp_SRCH' | Should -Be 'HeartbeatByIp_SRCH'
  }
}

Describe 'Resolve-ConfiguredValue' {
  It 'Uses parameter value before environment variable' {
    $env:SEARCH_TABLE_NAME = 'FromEnvironment'
    Resolve-ConfiguredValue -parameterValue 'FromParameter' -environmentVariableNames @('SEARCH_TABLE_NAME') -parameterName 'outputTableName' | Should -Be 'FromParameter'
  }

  It 'Uses environment variable when parameter is empty' {
    $env:SEARCH_TABLE_NAME = 'FromEnvironment'
    Resolve-ConfiguredValue -parameterValue '' -environmentVariableNames @('SEARCH_TABLE_NAME') -parameterName 'outputTableName' | Should -Be 'FromEnvironment'
  }

  It 'Throws when neither parameter nor environment value is present' {
    Remove-Item Env:SEARCH_TABLE_NAME -ErrorAction SilentlyContinue
    { Resolve-ConfiguredValue -parameterValue '' -environmentVariableNames @('SEARCH_TABLE_NAME') -parameterName 'outputTableName' } | Should -Throw
  }
}

Describe 'Invoke-SentinelSearchJob' {
  BeforeEach {
    Mock Connect-AzAccount { }
    Mock Set-AzContext { }
    Mock Get-AzOperationalInsightsWorkspace {
      [PSCustomObject]@{ Name = 'law-prod' }
    }
    Mock New-AzOperationalInsightsSearchTable {
      param(
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [string]$TableName,
        [string]$SearchQuery,
        [datetime]$StartSearchTime,
        [datetime]$EndSearchTime,
        [int]$TotalRetentionInDays
      )
      [PSCustomObject]@{
        TableName            = $TableName
        SearchQuery          = $SearchQuery
        TotalRetentionInDays = $TotalRetentionInDays
      }
    }
  }

  It 'Authenticates with UAMI and creates search table with normalized suffix' {
    $result = Invoke-SentinelSearchJob `
      -UmiClientId '11111111-1111-1111-1111-111111111111' `
      -SubscriptionId '22222222-2222-2222-2222-222222222222' `
      -ResourceGroupName 'rg-prod' `
      -WorkspaceName 'law-prod' `
      -OutputTableName 'HeartbeatByIp' `
      -SearchQuery 'Heartbeat' `
      -StartSearchTime '2026-01-01T00:00:00Z' `
      -EndSearchTime '2026-01-02T00:00:00Z' `
      -RetentionInDays 14 `
      -Limit 100

    Assert-MockCalled Connect-AzAccount -Times 1 -ParameterFilter { $Identity -and $AccountId -eq '11111111-1111-1111-1111-111111111111' }
    Assert-MockCalled Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq '22222222-2222-2222-2222-222222222222' }
    Assert-MockCalled New-AzOperationalInsightsSearchTable -Times 1 -ParameterFilter { $TableName -eq 'HeartbeatByIp_SRCH' -and $TotalRetentionInDays -eq 14 }

    $result.OutputTableName | Should -Be 'HeartbeatByIp_SRCH'
    $result.AppliedLimit | Should -Be 100
  }

  It 'Throws when start time is after end time' {
    {
      Invoke-SentinelSearchJob `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -ResourceGroupName 'rg-prod' `
        -WorkspaceName 'law-prod' `
        -OutputTableName 'HeartbeatByIp' `
        -SearchQuery 'Heartbeat' `
        -StartSearchTime '2026-01-02T00:00:00Z' `
        -EndSearchTime '2026-01-01T00:00:00Z'
    } | Should -Throw
  }

  Context 'When table already exists' {
    BeforeEach {
      Mock Get-AzOperationalInsightsTable {
        [PSCustomObject]@{
          Name              = 'HeartbeatByIp_SRCH'
          ProvisioningState = 'Succeeded'
        }
      }
      Mock Remove-AzOperationalInsightsTable { }
    }

    It 'Throws error by default when table exists' {
      {
        Invoke-SentinelSearchJob `
          -UmiClientId '11111111-1111-1111-1111-111111111111' `
          -SubscriptionId '22222222-2222-2222-2222-222222222222' `
          -ResourceGroupName 'rg-prod' `
          -WorkspaceName 'law-prod' `
          -OutputTableName 'HeartbeatByIp' `
          -SearchQuery 'Heartbeat' `
          -StartSearchTime '2026-01-01T00:00:00Z' `
          -EndSearchTime '2026-01-02T00:00:00Z' `
          -IfTableExists Error
      } | Should -Throw '*already exists*'
    }

    It 'Skips creation and returns existing table info when IfTableExists is Skip' {
      $result = Invoke-SentinelSearchJob `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -ResourceGroupName 'rg-prod' `
        -WorkspaceName 'law-prod' `
        -OutputTableName 'HeartbeatByIp' `
        -SearchQuery 'Heartbeat' `
        -StartSearchTime '2026-01-01T00:00:00Z' `
        -EndSearchTime '2026-01-02T00:00:00Z' `
        -IfTableExists Skip

      $result.Status | Should -Be 'Skipped'
      $result.OutputTableName | Should -Be 'HeartbeatByIp_SRCH'
      $result.ProvisioningState | Should -Be 'Succeeded'
      Assert-MockCalled New-AzOperationalInsightsSearchTable -Times 0
    }

    It 'Deletes existing table and creates new search when IfTableExists is Replace' {
      $result = Invoke-SentinelSearchJob `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -ResourceGroupName 'rg-prod' `
        -WorkspaceName 'law-prod' `
        -OutputTableName 'HeartbeatByIp' `
        -SearchQuery 'Heartbeat' `
        -StartSearchTime '2026-01-01T00:00:00Z' `
        -EndSearchTime '2026-01-02T00:00:00Z' `
        -IfTableExists Replace

      Assert-MockCalled Remove-AzOperationalInsightsTable -Times 1 -ParameterFilter { $TableName -eq 'HeartbeatByIp_SRCH' }
      Assert-MockCalled New-AzOperationalInsightsSearchTable -Times 1 -ParameterFilter { $TableName -eq 'HeartbeatByIp_SRCH' }
      $result.Status | Should -Be 'Submitted'
    }

    It 'Creates table with unique timestamp when IfTableExists is AutoRename' {
      $result = Invoke-SentinelSearchJob `
        -UmiClientId '11111111-1111-1111-1111-111111111111' `
        -SubscriptionId '22222222-2222-2222-2222-222222222222' `
        -ResourceGroupName 'rg-prod' `
        -WorkspaceName 'law-prod' `
        -OutputTableName 'HeartbeatByIp' `
        -SearchQuery 'Heartbeat' `
        -StartSearchTime '2026-01-01T00:00:00Z' `
        -EndSearchTime '2026-01-02T00:00:00Z' `
        -IfTableExists AutoRename

      Assert-MockCalled Remove-AzOperationalInsightsTable -Times 0
      Assert-MockCalled New-AzOperationalInsightsSearchTable -Times 1

      # Verify table name has timestamp format: TableName_YYYYMMDD_HHMMSS_SRCH
      $result.OutputTableName | Should -Match '^HeartbeatByIp_\d{8}_\d{6}_SRCH$'
      $result.Status | Should -Be 'Submitted'
    }
  }
}
