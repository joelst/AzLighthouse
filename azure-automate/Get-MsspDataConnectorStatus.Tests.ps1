# Pester tests for Get-MsspDataConnectorStatus components
# Requires: Pester 5+

# Ensure script is dot-sourced with skip flag to avoid executing the runbook logic
$env:MSP_SKIP_CONNECTOR_RUN = '1'
. "$PSScriptRoot\Get-MsspDataConnectorStatus.ps1"

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
    It 'Classifies ActivelyIngesting within 1h' {
        $r = Get-IngestionStatus -LastLogTime (Get-Date).AddMinutes(-5)
        $r.Status | Should -Be 'ActivelyIngesting'
    }
    It 'Classifies RecentlyActive within 24h' {
        $r = Get-IngestionStatus -LastLogTime (Get-Date).AddHours(-5)
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
        } -MaxAttempts 5 -InitialDelaySeconds 0
        $result | Should -Be 'OK'
        $script:attempts | Should -Be 3
    }
    It 'Throws after max attempts' {
        { Invoke-WithRetry -OperationName 'AlwaysFail' -ScriptBlock { throw 'Nope' } -MaxAttempts 2 -InitialDelaySeconds 0 } | Should -Throw
    }
}

Describe 'Get-ConnectorStatus missing metrics behavior' {
    BeforeAll {
        # Ensure mocks don't leak between contexts
        Remove-Mock -ModuleName Pester -ErrorAction SilentlyContinue
    }

    Context 'Null metrics returned' {
        Mock Get-LogIngestionMetrics { return $null }
        It 'Sets QueryStatus MetricsUnavailable and NoLastLog true' {
            $connector = [pscustomobject]@{ Name='TestConnectorNull'; Kind='KindNull'; Properties=$null }
            $wsId = [guid]::NewGuid().ToString()
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            $status.LogMetrics.QueryStatus | Should -Be 'MetricsUnavailable'
            $status.LogMetrics.NoLastLog | Should -BeTrue
        }
    }

    Context 'Empty metrics hash' {
        Mock Get-LogIngestionMetrics { return @{} }
        It 'Converts to MetricsUnavailable with NoLastLog' {
            $connector = [pscustomobject]@{ Name='TestConnectorEmpty'; Kind='KindEmpty'; Properties=$null }
            $wsId = [guid]::NewGuid().ToString()
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            $status.LogMetrics.QueryStatus | Should -Be 'MetricsUnavailable'
            $status.LogMetrics.NoLastLog | Should -BeTrue
        }
    }

    Context 'Mapping found but LastLogTime missing' {
        Mock Get-LogIngestionMetrics { return @{ QueryStatus='Success'; MappingFound=$true; KqlUsed='fake'; LastLogTime=$null; LogsLastHour=0; TotalLogs24h=0 } }
        It 'Marks NoLastLog and chooses ConfiguredButNoLogs when enabled present' {
            $connector = [pscustomobject]@{ Name='ConnectorEnabled'; Kind='KindEnabled'; Properties=[pscustomobject]@{ status='Enabled' } }
            $wsId = [guid]::NewGuid().ToString()
            $status = Get-ConnectorStatus -Connector $connector -WorkspaceCustomerId $wsId
            $status.LogMetrics.NoLastLog | Should -BeTrue
            $status.OverallStatus | Should -Be 'ConfiguredButNoLogs'
        }
    }
}
