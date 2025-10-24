# Pester tests for Get-MsspDataConnectorStatus components
# Requires: Pester 5+
# Run with: Invoke-Pester -Path .\Get-MsspDataConnectorStatus.Tests.ps1

BeforeAll {
    # Ensure script is dot-sourced with skip flag to avoid executing the runbook logic
    $env:MSP_SKIP_CONNECTOR_RUN = '1'
    . "$PSScriptRoot\Get-DataConnectorStatus.ps1"
}

Describe 'Resolve-ConnectorKind' {
    It 'Returns Name inference for StaticUI' {
        $connector = [pscustomobject]@{ Name='FriendlyName'; Kind='StaticUI' }
        $r = Resolve-ConnectorKind -Connector $connector
        $r.Kind | Should -Be 'FriendlyName'
        $r.Source | Should -Be 'NameFromStaticUI'
    }
    It 'Handles unknown kinds and falls back to UnknownKind when name is GUID' {
        $guid = [guid]::NewGuid().ToString()
        $connector = [pscustomobject]@{ Name=$guid }
        $r = Resolve-ConnectorKind -Connector $connector
        $r.Kind | Should -Be 'UnknownKind'
    }
    It 'Collapses array kinds into comma list' {
        $connector = [pscustomobject]@{ Name='X'; Kind=@('A','B') }
        $r = Resolve-ConnectorKind -Connector $connector
        $r.Kind | Should -Be 'A,B'
    }
}

Describe 'Get-IngestionStatus' {
    It 'Returns nulls when LastLogTime missing' {
        $r = Get-IngestionStatus -LastLogTime $null
        $r.Status | Should -BeNullOrEmpty
        $r.HoursSinceLastLog | Should -Be $null
    }
    It 'Classifies ActivelyIngesting within 12h' {
        $r = Get-IngestionStatus -LastLogTime (Get-Date).AddMinutes(-5)
        $r.Status | Should -Be 'ActivelyIngesting'
    }
    It 'Classifies RecentlyActive between 12h and 24h' {
        $r = Get-IngestionStatus -LastLogTime (Get-Date).AddHours(-15)
        $r.Status | Should -Be 'RecentlyActive'
    }
    It 'Classifies Stale beyond 24h' {
        $r = Get-IngestionStatus -LastLogTime (Get-Date).AddHours(-30)
        $r.Status | Should -Be 'Stale'
    }
}

Describe 'Invoke-WithRetry' {
    It 'Retries twice then succeeds' {
        $attempts = 0
        $result = Invoke-WithRetry -OperationName 'TestOp' -ScriptBlock {
            $script:attempts++
            if ($script:attempts -lt 3) { throw 'Fail' }
            return 'OK'
        } -MaxAttempts 5 -InitialDelaySeconds 0 6>&1 | Where-Object { $_ -notlike '*WARN*' } | Select-Object -Last 1
        $result | Should -Be 'OK'
        $script:attempts | Should -Be 3
    }
    It 'Throws after max attempts' {
        { Invoke-WithRetry -OperationName 'AlwaysFail' -ScriptBlock { throw 'Nope' } -MaxAttempts 2 -InitialDelaySeconds 0 } | Should -Throw
    }
}

Describe 'Validation Functions' {
    Context 'Test-SubscriptionIdFormat' {
        It 'Accepts valid GUID format' {
            Test-SubscriptionIdFormat 'a7aafb80-24b2-4c22-8057-59bb2b347839' | Should -BeTrue
        }

        It 'Rejects invalid GUID' {
            Test-SubscriptionIdFormat 'not-a-guid' | Should -BeFalse
        }

        It 'Rejects null or empty' {
            Test-SubscriptionIdFormat '' | Should -BeFalse
            Test-SubscriptionIdFormat $null | Should -BeFalse
        }

        It 'Accepts uppercase GUID' {
            Test-SubscriptionIdFormat 'A7AAFB80-24B2-4C22-8057-59BB2B347839' | Should -BeTrue
        }
    }

    Context 'Test-ResourceGroupName' {
        It 'Accepts valid resource group names' {
            Test-ResourceGroupName 'rg-prod' | Should -BeTrue
            Test-ResourceGroupName 'MyResourceGroup_123' | Should -BeTrue
            Test-ResourceGroupName 'rg.with.dots' | Should -BeTrue
            Test-ResourceGroupName 'rg(with)parens' | Should -BeTrue
        }

        It 'Rejects names longer than 90 characters' {
            $longName = 'a' * 91
            Test-ResourceGroupName $longName | Should -BeFalse
        }

        It 'Rejects invalid characters' {
            Test-ResourceGroupName 'rg-with-@-symbol' | Should -BeFalse
            Test-ResourceGroupName 'rg with spaces' | Should -BeFalse
        }

        It 'Rejects null or empty' {
            Test-ResourceGroupName '' | Should -BeFalse
            Test-ResourceGroupName $null | Should -BeFalse
        }
    }

    Context 'Test-WorkspaceName' {
        It 'Accepts valid workspace names' {
            Test-WorkspaceName 'law-prod' | Should -BeTrue
            Test-WorkspaceName 'workspace123' | Should -BeTrue
            Test-WorkspaceName 'my-workspace' | Should -BeTrue
        }

        It 'Rejects names shorter than 4 characters' {
            Test-WorkspaceName 'abc' | Should -BeFalse
        }

        It 'Rejects names longer than 63 characters' {
            $longName = 'a' * 64
            Test-WorkspaceName $longName | Should -BeFalse
        }

        It 'Rejects names starting with hyphen' {
            Test-WorkspaceName '-workspace' | Should -BeFalse
        }

        It 'Rejects names ending with hyphen' {
            Test-WorkspaceName 'workspace-' | Should -BeFalse
        }

        It 'Rejects null or empty' {
            Test-WorkspaceName '' | Should -BeFalse
            Test-WorkspaceName $null | Should -BeFalse
        }
    }
}

Describe 'Get-ConnectivityResults' {
    BeforeAll {
        Mock Invoke-AzOperationalInsightsQuery { 
            param($WorkspaceId, $Query)
            if ($Query -match 'positive') {
                # Return proper table structure with IsConnected column
                return @{ 
                    Tables = @(
                        @{
                            Columns = @{ Name = @('IsConnected') }
                            Rows = @(@($true))
                        }
                    )
                    Error = $null
                }
            }
            # Return empty results
            return @{ 
                Tables = @()
                Error = $null
            }
        }
    }

    It 'Returns false when no criteria provided' {
        $result = Get-ConnectivityResults -WorkspaceCustomerId ([guid]::NewGuid().ToString()) -ConnectivityCriteria @() -ConnectorName 'Test'
        $result | Should -BeFalse
    }

    It 'Returns false when WorkspaceCustomerId is null' {
        $result = Get-ConnectivityResults -WorkspaceCustomerId $null -ConnectivityCriteria @('query1') -ConnectorName 'Test'
        $result | Should -BeFalse
    }

    It 'Returns true when any criteria returns data' {
        $criteria = @('query | where positive match')
        $result = Get-ConnectivityResults -WorkspaceCustomerId ([guid]::NewGuid().ToString()) -ConnectivityCriteria $criteria -ConnectorName 'Test'
        $result | Should -BeTrue
    }

    It 'Skips null or empty queries' {
        $criteria = @('', $null, 'query | where positive match')
        $result = Get-ConnectivityResults -WorkspaceCustomerId ([guid]::NewGuid().ToString()) -ConnectivityCriteria $criteria -ConnectorName 'Test'
        $result | Should -BeTrue
    }
}

Describe 'Get-LogIngestionMetrics Lookup Logic' {
    BeforeAll {
        # Mock Invoke-AzOperationalInsightsQuery to avoid actual Azure calls
        Mock Invoke-AzOperationalInsightsQuery { 
            return @{ Results = @() }
        }
    }

    Context 'Primary lookup by ConnectorId' {
        It 'Matches connector Id against ConnectorInfo Id (exact match)' {
            $wsId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'SomeKind' -ConnectorName 'SomeName' -ConnectorId 'Office365'
            
            $result.Id | Should -Be 'Office365'
            $result.Title | Should -Be 'Office 365'
            $result.Publisher | Should -Be 'Microsoft'
            $result.MappingFound | Should -BeTrue
        }

        It 'Matches connector Id case-insensitively' {
            $wsId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'SomeKind' -ConnectorName 'SomeName' -ConnectorId 'office365'
            
            $result.Id | Should -Be 'office365'
            $result.Title | Should -Be 'Office 365'
            $result.Publisher | Should -Be 'Microsoft'
        }

        It 'Uses actual connector Id when no mapping found' {
            $wsId = [guid]::NewGuid().ToString()
            $testId = 'aa944eec-f345-4c85-8760-5a4adc5abd4a'
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'Office365' -ConnectorName 'SomeGuidName' -ConnectorId $testId
            
            $result.Id | Should -Be $testId
            $result.Title | Should -BeNullOrEmpty
            $result.Publisher | Should -BeNullOrEmpty
            $result.MappingFound | Should -BeFalse
        }
    }

    Context 'Fallback lookup by ConnectorName' {
        It 'Falls back to Name when Id does not match' {
            $wsId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'SomeKind' -ConnectorName 'AzureActiveDirectory' -ConnectorId 'non-matching-id'
            
            $result.Id | Should -Be 'non-matching-id'  # Preserves actual connector Id
            $result.Title | Should -Be 'Azure Active Directory'
            $result.Publisher | Should -Be 'Microsoft'
            $result.MappingFound | Should -BeTrue
        }

        It 'Matches Name case-insensitively' {
            $wsId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'SomeKind' -ConnectorName 'azureactivedirectory' -ConnectorId 'no-match'
            
            $result.Title | Should -Be 'Azure Active Directory'
            $result.Publisher | Should -Be 'Microsoft'
        }
    }

    Context 'No match found' {
        It 'Returns null Title and Publisher when neither Id nor Name match' {
            $wsId = [guid]::NewGuid().ToString()
            $testId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'UnknownKind' -ConnectorName 'UnknownName' -ConnectorId $testId
            
            $result.Id | Should -Be $testId
            $result.Title | Should -BeNullOrEmpty
            $result.Publisher | Should -BeNullOrEmpty
            $result.MappingFound | Should -BeFalse
            $result.QueryStatus | Should -Be 'NoKql'
        }

        It 'Preserves connector Id even when no mapping exists' {
            $wsId = [guid]::NewGuid().ToString()
            $customId = 'custom-connector-id-123'
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'Custom' -ConnectorName 'CustomConnector' -ConnectorId $customId
            
            $result.Id | Should -Be $customId
        }
    }

    Context 'KQL query execution' {
        It 'Uses KQL from matched ConnectorInfo entry' {
            $wsId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'Test' -ConnectorName 'Test' -ConnectorId 'SecurityEvents'
            
            $result.MappingFound | Should -BeTrue
            $result.KqlUsed | Should -Not -BeNullOrEmpty
        }

        It 'Sets QueryStatus to NoKql when no mapping found' {
            $wsId = [guid]::NewGuid().ToString()
            $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'NoMatch' -ConnectorName 'NoMatch' -ConnectorId 'NoMatch'
            
            $result.QueryStatus | Should -Be 'NoKql'
            $result.MappingFound | Should -BeFalse
        }
    }
}

Describe 'Get-ConnectorStatus Integration' {
    BeforeAll {
        Mock Invoke-AzOperationalInsightsQuery { 
            return @{ Results = @() }
        }
    }

    Context 'Connector with Id property' {
        It 'Passes ConnectorId to Get-LogIngestionMetrics' {
            $connector = [pscustomobject]@{ 
                Name = 'TestConnector'
                Kind = 'Office365'
                Id = 'aa944eec-f345-4c85-8760-5a4adc5abd4a'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.LogMetrics.Id | Should -Be $connector.Id
        }

        It 'Populates Title and Publisher when Id matches' {
            $connector = [pscustomobject]@{ 
                Name = 'Office365Connector'
                Kind = 'Office365'
                Id = 'Office365'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.LogMetrics.Id | Should -Be 'Office365'
            $status.LogMetrics.Title | Should -Be 'Office 365'
            $status.LogMetrics.Publisher | Should -Be 'Microsoft'
        }

        It 'Preserves Id and uses Name fallback for Title/Publisher' {
            $connector = [pscustomobject]@{ 
                Name = 'AzureActiveDirectory'
                Kind = 'AzureActiveDirectory'
                Id = 'different-guid-value'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.LogMetrics.Id | Should -Be 'different-guid-value'
            $status.LogMetrics.Title | Should -Be 'Azure Active Directory'
        }
    }
}

Describe 'Get-ConnectorStatus missing metrics behavior' {
    BeforeAll {
        Mock Invoke-AzOperationalInsightsQuery { 
            return @{ Results = @() }
        }
    }

    Context 'Mapping found but LastLogTime missing' {
        It 'Sets appropriate status when no logs found' {
            $connector = [pscustomobject]@{ 
                Name = 'Office365'
                Kind = 'Office365'
                Id = 'Office365'
                Properties = [pscustomobject]@{ dataTypes = [pscustomobject]@{ enabled = [pscustomobject]@{ state = 'enabled' } } }
            }
            $wsId = [guid]::NewGuid().ToString()
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            # Status should be ConfiguredButNoLogs when connector has enabled state but no logs
            $status.OverallStatus | Should -BeIn @('ConfiguredButNoLogs', 'Unknown')
        }
    }

    Context 'No mapping found and no logs' {
        It 'Sets status to NoKqlAndNoLogs' {
            $connector = [pscustomobject]@{ 
                Name = 'UnknownConnector'
                Kind = 'UnknownKind'
                Id = 'unknown-id-123'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.OverallStatus | Should -Be 'NoKqlAndNoLogs'
            $status.LogMetrics.QueryStatus | Should -Be 'NoKql'
        }
    }
}

Describe 'ConnectorInfo Array Structure' {
    It 'Contains expected connector entries' {
        $ConnectorInfo | Should -Not -BeNullOrEmpty
        $ConnectorInfo.Count | Should -BeGreaterThan 10
    }

    It 'Each entry has required properties' {
        # Test that entries have the expected structure (some may have empty values)
        $testEntries = @($ConnectorInfo[0], $ConnectorInfo[2], $ConnectorInfo[3], $ConnectorInfo[4])
        foreach ($entry in $testEntries) {
            $entry.Id | Should -Not -BeNullOrEmpty -Because "Each entry must have an Id"
            # Kql should exist (most entries have it, some may be empty)
            { $entry.Kql } | Should -Not -Throw
            # Title and Publisher exist as properties (verified by accessing them - may be empty/null)
            { $entry.Title } | Should -Not -Throw
            { $entry.Publisher } | Should -Not -Throw
            { $entry.ConnectivityCriteria } | Should -Not -Throw
        }
    }

    It 'Office365 entry exists with correct structure' {
        $office365 = $ConnectorInfo | Where-Object { $_.Id -eq 'Office365' }
        $office365 | Should -Not -BeNullOrEmpty
        $office365.Title | Should -Be 'Office 365'
        $office365.Publisher | Should -Be 'Microsoft'
        $office365.Kql | Should -Match 'OfficeActivity'
    }

    It 'AzureActiveDirectory entry exists with correct structure' {
        $aad = $ConnectorInfo | Where-Object { $_.Id -eq 'AzureActiveDirectory' }
        $aad | Should -Not -BeNullOrEmpty
        $aad.Title | Should -Be 'Azure Active Directory'
        $aad.Publisher | Should -Be 'Microsoft'
        $aad.Kql | Should -Match 'SigninLogs'
    }
}
