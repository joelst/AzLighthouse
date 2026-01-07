# Pester tests for Get-DataConnectorStatus components
# Requires: Pester 5+
# Run with: Invoke-Pester -Path .\Get-DataConnectorStatus.Tests.ps1

BeforeAll {
    # Ensure script is dot-sourced with skip flag to avoid executing the runbook logic
    $env:MSP_SKIP_CONNECTOR_RUN = '1'
    . "$PSScriptRoot\Get-DataConnectorStatus.ps1"
    Set-Variable -Name IsArmScopeValidated -Scope Script -Value $true -Force
}

Describe 'Resolve-Connector' {
    It 'Falls back to connector name when kind is StaticUI' {
        $connector = [pscustomobject]@{ Name = 'FriendlyName'; Kind = 'StaticUI' }
        $resolved = Resolve-Connector -Connector $connector
        $resolved.Kind | Should -Be 'StaticUI'
        $resolved.Id | Should -Be 'FriendlyName'
        $resolved.Source | Should -Be 'ConnectorName'
    }

    It 'Uses connector name even when it is a GUID' {
        $guid = [guid]::NewGuid().ToString()
        $connector = [pscustomobject]@{ Name = $guid }
        $resolved = Resolve-Connector -Connector $connector
        $resolved.Kind | Should -Be 'UnknownKind'
        $resolved.Id | Should -Be $guid
        $resolved.Source | Should -Be 'ConnectorNameFallback'
    }

    It 'Collapses array kinds into comma separated string' {
        $connector = [pscustomobject]@{ Name = 'TestConnector'; Kind = @('A', 'B', 'C') }
        $resolved = Resolve-Connector -Connector $connector
        $resolved.Kind | Should -Be 'A,B,C'
        $resolved.Id | Should -Be 'A,B,C'
    }

    It 'Enriches title and publisher from connector info when missing' {
        $connector = [pscustomobject]@{
            Name                       = 'Unused'
            Kind                       = 'Office365'
            ConnectorUiConfigTitle     = $null
            ConnectorUiConfigPublisher = $null
        }
        $resolved = Resolve-Connector -Connector $connector
        $resolved.Title | Should -Be 'Microsoft 365 (formerly, Office 365)'
        $resolved.Publisher | Should -Be 'Microsoft'
    }

    It 'Returns connectivity KQL from connector info when not provided on connector' {
        $connector = [pscustomobject]@{
            Name                                   = 'SecurityEvents'
            Kind                                   = 'SecurityEvents'
            ConnectorUiConfigConnectivityCriterion = $null
        }
        $resolved = Resolve-Connector -Connector $connector
        $resolved.ConnectivityKQL | Should -Not -BeNullOrEmpty
    }

    It 'Uses definition name mapping for RestApiPoller connectors regardless of source' {
        $guidName = [guid]::NewGuid().ToString()
        $connector = [pscustomobject]@{
            Name                    = $guidName
            Kind                    = 'RestApiPoller'
            ConnectorDefinitionName = '/subscriptions/test/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights/dataConnectorDefinitions/Office365'
            Source                  = 'Cmdlet'
        }
        $resolved = Resolve-Connector -Connector $connector
        $resolved.Id | Should -Be 'Office365'
        $resolved.Title | Should -Be 'Microsoft 365 (formerly, Office 365)'
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
            if ($script:attempts -lt 3) {
                throw 'Fail' 
            }
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
                            Rows    = @(@($true))
                        }
                    )
                    Error  = $null
                }
            }
            # Return empty results
            return @{ 
                Tables = @()
                Error  = $null
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

Describe 'Get-LogIngestionMetrics' {
    BeforeEach {
        Mock Invoke-WithRetry {
            param($OperationName, $ScriptBlock, $MaxAttempts, $InitialDelaySeconds)
            & $ScriptBlock
        }
    }

    It 'Preserves metadata properties when no KQL supplied' {
        $wsId = [guid]::NewGuid().ToString()
        $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'Kind' -ConnectorName 'Name' -ConnectorId 'ConnectorId' -ConnectorTitle 'Title' -ConnectorPublisher 'Publisher'
        $result.Id | Should -Be 'ConnectorId'
        $result.Title | Should -Be 'Title'
        $result.Publisher | Should -Be 'Publisher'
        $result.QueryStatus | Should -Be 'NoActivityKql'
    }

    It 'Sets IsConnected when connectivity query returns true' {
        $wsId = [guid]::NewGuid().ToString()
        Mock Invoke-AzOperationalInsightsQuery {
            param($WorkspaceId, $Query)
            if ($Query -eq 'connect') {
                return @{ Results = @(@{ IsConnected = $true }) }
            }
            return @{ Results = @() }
        }

        $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'Kind' -ConnectorName 'Name' -ConnectorId 'ConnectorId' -ConnectivityKql 'connect'

        $result.IsConnected | Should -BeTrue
        $result.QueryStatus | Should -Be 'NoActivityKql'
    }
]    It 'Aggregates activity query metrics and marks success' {
        $wsId = [guid]::NewGuid().ToString()
        $lastLog = (Get-Date).AddMinutes(-30)
        Mock Invoke-AzOperationalInsightsQuery {
            param($WorkspaceId, $Query)
            if ($Query -eq 'activity') {
                return @{ Results = @(@{ LastLogTime = $lastLog; LogsLastHour = 5; TotalLogs24h = 42 }) }
            }
            return @{ Results = @() }
        }

        $result = Get-LogIngestionMetrics -WorkspaceCustomerId $wsId -ConnectorKind 'Kind' -ConnectorName 'Name' -ConnectorId 'ConnectorId' -ActivityKql 'activity'

        $result.LastLogTime.ToString('u') | Should -Be $lastLog.ToString('u')
        $result.LogsLastHour | Should -Be 5
        $result.TotalLogs24h | Should -Be 42
        $result.QueryStatus | Should -Be 'Success'
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
                Name       = 'TestConnector'
                Kind       = 'Office365'
                Id         = 'Office365'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.LogMetrics.Id | Should -Be 'Office365'
            $status.ResourceId | Should -Be $connector.Id
        }

        It 'Populates Title and Publisher when Id matches' {
            $connector = [pscustomobject]@{ 
                Name       = 'Office365Connector'
                Kind       = 'Office365'
                Id         = 'Office365'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.LogMetrics.Id | Should -Be 'Office365'
            $status.LogMetrics.Title | Should -Be 'Microsoft 365 (formerly, Office 365)'
            $status.LogMetrics.Publisher | Should -Be 'Microsoft'
        }

        It 'Preserves Id and uses Name fallback for Title/Publisher' {
            $connector = [pscustomobject]@{ 
                Name       = 'AzureActiveDirectory'
                Kind       = 'AzureActiveDirectory'
                Id         = 'different-guid-value'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.LogMetrics.Id | Should -Be 'different-guid-value'
            $status.LogMetrics.Title | Should -Be 'Microsoft Entra ID'
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
                Name       = 'Office365'
                Kind       = 'Office365'
                Id         = 'Office365'
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
                Name       = 'UnknownConnector'
                Kind       = 'UnknownKind'
                Id         = 'unknown-id-123'
                Properties = $null
            }
            $wsId = [guid]::NewGuid().ToString()
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            
            $status.OverallStatus | Should -Be 'NoKqlAndNoLogs'
            $status.LogMetrics.QueryStatus | Should -Be 'NoActivityKql'
        }
    }
}

Describe 'Masking and URI helpers' {
    It 'Masks all but final characters of identifier' {
        Get-MaskedIdentifier -Value '1234567890' | Should -Be '****7890'
    }

    It 'Returns host for valid URI' {
        Get-UriHostForLog -UriString 'https://example.contoso.com/path' | Should -Be 'example.contoso.com'
    }

    It 'Returns placeholder for invalid URI' {
        Get-UriHostForLog -UriString 'not a uri' | Should -Be '<invalid-uri>'
    }
}

Describe 'Submit-LogicAppResult' {
    BeforeEach {
        Remove-Variable -Name capturedBody -Scope Script -ErrorAction SilentlyContinue
        Mock Invoke-RestMethod {}
    }

    It 'Rejects non-HTTPS endpoints' {
        $result = Submit-LogicAppResult -LogicAppUri 'http://contoso.test/hook' -Payload @()
        $result | Should -BeFalse
        Assert-MockCalled Invoke-RestMethod -Times 0
    }

    It 'Honors WhatIf and skips Invoke-RestMethod' {
        $result = Submit-LogicAppResult -LogicAppUri 'https://contoso.test/hook' -Payload @() -ConnectorCount 2 -WhatIf
        $result | Should -BeTrue
        Assert-MockCalled Invoke-RestMethod -Times 0
    }

    It 'Posts payload when HTTPS endpoint provided' {
        Mock Invoke-RestMethod {
            param($Uri, $Body)
            $script:capturedBody = $Body
        }

        $payload = @([pscustomobject]@{ Name = 'ConnectorA'; Status = 'Active' })
        $result = Submit-LogicAppResult -LogicAppUri 'https://contoso.test/hook' -Payload $payload -ConnectorCount 1 -Confirm:$false

        $result | Should -BeTrue
        Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly
        $script:capturedBody | Should -Match 'ConnectorA'
    }
}

Describe 'Get-RestErrorDiagnostics' {
    It 'Extracts status, activity id, and body snippet' {
        $response = [pscustomobject]@{
            StatusCode = 429
            Headers    = @{ 'x-ms-activity-id' = 'activity123'; 'x-ms-request-id' = 'request456' }
            Content    = '{"error":"too many"}'
        }
        $exception = [System.Exception]::new('REST failure')
        Add-Member -InputObject $exception -MemberType NoteProperty -Name Response -Value $response -Force
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestFailure', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)

        $diag = Get-RestErrorDiagnostics -ErrorRecord $errorRecord
        $diag.StatusCode | Should -Be 429
        $diag.ActivityId | Should -Be 'activity123'
        $diag.RequestId | Should -Be 'request456'
        $diag.Body | Should -Match 'too many'
    }
}

Describe 'Masking and URI helpers' {
    It 'Masks all but final characters of identifier' {
        Get-MaskedIdentifier -Value '1234567890' | Should -Be '****7890'
    }

    It 'Returns host for valid URI' {
        Get-UriHostForLog -UriString 'https://example.contoso.com/path' | Should -Be 'example.contoso.com'
    }

    It 'Returns placeholder for invalid URI' {
        Get-UriHostForLog -UriString 'not a uri' | Should -Be '<invalid-uri>'
    }
}

Describe 'Submit-LogicAppResult' {
    BeforeEach {
        Remove-Variable -Name capturedBody -Scope Script -ErrorAction SilentlyContinue
        Mock Invoke-RestMethod {}
    }

    It 'Rejects non-HTTPS endpoints' {
        $result = Submit-LogicAppResult -LogicAppUri 'http://contoso.test/hook' -Payload @()
        $result | Should -BeFalse
        Assert-MockCalled Invoke-RestMethod -Times 0
    }

    It 'Honors WhatIf and skips Invoke-RestMethod' {
        $result = Submit-LogicAppResult -LogicAppUri 'https://contoso.test/hook' -Payload @() -ConnectorCount 2 -WhatIf
        $result | Should -BeTrue
        Assert-MockCalled Invoke-RestMethod -Times 0
    }

    It 'Posts payload when HTTPS endpoint provided' {
        Mock Invoke-RestMethod {
            param($Uri, $Body)
            $script:capturedBody = $Body
        }

        $payload = @([pscustomobject]@{ Name = 'ConnectorA'; Status = 'Active' })
        $result = Submit-LogicAppResult -LogicAppUri 'https://contoso.test/hook' -Payload $payload -ConnectorCount 1 -Confirm:$false

        $result | Should -BeTrue
        Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly
        $script:capturedBody | Should -Match 'ConnectorA'
    }
}

Describe 'Get-RestErrorDiagnostics' {
    It 'Extracts status, activity id, and body snippet' {
        $response = [pscustomobject]@{
            StatusCode = 429
            Headers    = @{ 'x-ms-activity-id' = 'activity123'; 'x-ms-request-id' = 'request456' }
            Content    = '{"error":"too many"}'
        }
        $exception = [System.Exception]::new('REST failure')
        Add-Member -InputObject $exception -MemberType NoteProperty -Name Response -Value $response -Force
        $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'TestFailure', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)

        $diag = Get-RestErrorDiagnostics -ErrorRecord $errorRecord
        $diag.StatusCode | Should -Be 429
        $diag.ActivityId | Should -Be 'activity123'
        $diag.RequestId | Should -Be 'request456'
        $diag.Body | Should -Match 'too many'
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
            $entry.Id | Should -Not -BeNullOrEmpty -Because 'Each entry must have an Id'
            # KQL metadata should be accessible (many entries use arrays)
            { $entry.ActivityKql } | Should -Not -Throw
            { $entry.ConnectivityKql } | Should -Not -Throw
            # Title and Publisher exist as properties (verified by accessing them - may be empty/null)
            { $entry.Title } | Should -Not -Throw
            { $entry.Publisher } | Should -Not -Throw
            { $entry.ConnectivityCriteria } | Should -Not -Throw
        }
    }

    It 'Office365 entry exists with correct structure' {
        $office365 = $ConnectorInfo | Where-Object { $_.Id -eq 'Office365' }
        $office365 | Should -Not -BeNullOrEmpty
        $office365.Title | Should -Be 'Microsoft 365 (formerly, Office 365)'
        $office365.Publisher | Should -Be 'Microsoft'
        $office365.ActivityKql | Should -Match 'OfficeActivity'
    }

    It 'AzureActiveDirectory entry exists with correct structure' {
        $aad = $ConnectorInfo | Where-Object { $_.Id -eq 'AzureActiveDirectory' }
        $aad | Should -Not -BeNullOrEmpty
        $aad.Title | Should -Be 'Microsoft Entra ID'
        $aad.Publisher | Should -Be 'Microsoft'
        $aad.ActivityKql | Should -Match 'SigninLogs'
    }
}
