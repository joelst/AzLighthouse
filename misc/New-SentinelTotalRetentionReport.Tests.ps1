# Pester 5 tests for New-SentinelTotalRetentionReport.ps1
# All Azure cmdlets are mocked — no authentication required.

BeforeAll {
    $here = Split-Path -Parent $PSCommandPath
    $scriptPath = Join-Path $here 'New-SentinelTotalRetentionReport.ps1'

    # Prevent main logic from running when dot-sourcing
    $env:RETENTION_REPORT_SKIP_MAIN = '1'

    # Dot-source with mandatory params satisfied; skip-main guard prevents execution
    . $scriptPath -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg'

    # Helper: creates mock table objects matching Get-AzOperationalInsightsTable output
    function script:New-MockTable {
        param(
            [string]$Name, [int]$Retention = 90, [int]$TotalRetention = 365,
            [string]$Plan = 'Analytics',
            [string]$TableType = 'Microsoft', [string]$TableSubType = 'DataCollectionRuleBased',
            [string[]]$Solutions = @('SecurityInsights')
        )
        [PSCustomObject]@{
            Name                 = $Name
            RetentionInDays      = $Retention
            TotalRetentionInDays = $TotalRetention
            Plan                 = $Plan
            Schema               = [PSCustomObject]@{
                TableType    = $TableType
                TableSubType = $TableSubType
                Solutions    = $Solutions
            }
        }
    }
}

AfterAll {
    Remove-Item Env:RETENTION_REPORT_SKIP_MAIN -ErrorAction SilentlyContinue
}

# ============================================================================
# Connect-AzAccountIfNeeded
# ============================================================================

Describe 'Connect-AzAccountIfNeeded' {

    It 'Reuses existing Az context when available' {
        Mock Get-AzContext {
            [PSCustomObject]@{
                Account      = [PSCustomObject]@{ Id = 'user@test.com' }
                Subscription = [PSCustomObject]@{ Id = '00000000-0000-0000-0000-000000000001' }
            }
        }
        Mock Connect-AzAccount {}
        Mock Set-AzContext {}

        Connect-AzAccountIfNeeded

        Should -Invoke Connect-AzAccount -Times 0
    }

    It 'Switches subscription when context exists but subscription differs' {
        Mock Get-AzContext {
            [PSCustomObject]@{
                Account      = [PSCustomObject]@{ Id = 'user@test.com' }
                Subscription = [PSCustomObject]@{ Id = '00000000-0000-0000-0000-000000000001' }
            }
        }
        Mock Set-AzContext {}

        Connect-AzAccountIfNeeded -SubscriptionId '00000000-0000-0000-0000-000000000002'

        Should -Invoke Set-AzContext -Times 1 -ParameterFilter {
            $SubscriptionId -eq '00000000-0000-0000-0000-000000000002'
        }
    }

    It 'Connects via managed identity when no context exists' {
        Mock Get-AzContext { $null }
        Mock Connect-AzAccount {}
        Mock Set-AzContext {}

        Connect-AzAccountIfNeeded -UseManagedIdentity

        Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter {
            $Identity -eq $true
        }
    }

    It 'Connects via managed identity with client ID' {
        Mock Get-AzContext { $null }
        Mock Connect-AzAccount {}
        Mock Set-AzContext {}

        Connect-AzAccountIfNeeded -UseManagedIdentity -ManagedIdentityClientId '11111111-1111-1111-1111-111111111111'

        Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter {
            $Identity -eq $true -and $AccountId -eq '11111111-1111-1111-1111-111111111111'
        }
    }

    It 'Connects interactively when no context and no MI' {
        Mock Get-AzContext { $null }
        Mock Connect-AzAccount {}
        Mock Set-AzContext {}

        Connect-AzAccountIfNeeded -TenantId '22222222-2222-2222-2222-222222222222'

        Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter {
            $TenantId -eq '22222222-2222-2222-2222-222222222222'
        }
    }
}

# ============================================================================
# Get-WorkspaceRetentionData
# ============================================================================

Describe 'Get-WorkspaceRetentionData' {

    BeforeAll {
        $script:mockTables = @(
            (New-MockTable -Name 'SecurityEvent' -Retention 90 -TotalRetention 360 -Solutions @('SecurityInsights')),
            (New-MockTable -Name 'Syslog' -Retention 30 -TotalRetention 30 -Solutions @('SecurityInsights')),
            (New-MockTable -Name 'Usage' -Retention 0 -TotalRetention 0 -Plan 'Basic' -Solutions @('LogManagement'))
        )
    }

    BeforeEach {
        Mock Get-AzOperationalInsightsTable { $script:mockTables }
        # Workspace default retention is 90 days
        Mock Get-AzOperationalInsightsWorkspace { [PSCustomObject]@{ RetentionInDays = 90 } }
    }

    It 'Returns structured objects with correct properties' {
        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg' -IncludeZeroRetention

        $results | Should -HaveCount 3
        $results[0].WorkspaceName | Should -Be 'test-ws'
        $results[0].TableName | Should -Be 'SecurityEvent'
        $results[0].RetentionInDays | Should -Be 90
        $results[0].TotalRetentionInDays | Should -Be 360
        $results[0].Plan | Should -Be 'Analytics'
    }

    It 'Calculates ArchiveRetentionInDays from TotalRetentionInDays minus RetentionInDays' {
        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg' -IncludeZeroRetention

        $results[0].ArchiveRetentionInDays | Should -Be 270
        $results[1].ArchiveRetentionInDays | Should -Be 0
        $results[2].ArchiveRetentionInDays | Should -Be 0
    }

    It 'Excludes zero-retention tables by default' {
        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg'

        $results | Should -HaveCount 2
        $results.TableName | Should -Not -Contain 'Usage'
    }

    It 'Includes zero-retention tables when IncludeZeroRetention is set' {
        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg' -IncludeZeroRetention

        $results | Should -HaveCount 3
        $results.TableName | Should -Contain 'Usage'
    }

    It 'Returns empty array when no tables found' {
        Mock Get-AzOperationalInsightsTable { $null }

        $results = Get-WorkspaceRetentionData -WorkspaceName 'empty-ws' -ResourceGroupName 'test-rg'

        $results | Should -HaveCount 0
    }

    It 'Filters out tables without SecurityInsights, CustomLog, or DCR subtype' {
        $mixed = @(
            (New-MockTable -Name 'SecurityEvent' -Solutions @('SecurityInsights')),
            (New-MockTable -Name 'EmptyDef' -TableSubType 'Any' -Solutions @('LogManagement')),
            (New-MockTable -Name 'MyCustom_CL' -TableType 'CustomLog' -Solutions @()),
            (New-MockTable -Name 'SrchTable' -TableType 'SearchResults' -TableSubType 'DataCollectionRuleBased' -Solutions @())
        )
        Mock Get-AzOperationalInsightsTable { $mixed }

        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg'

        $results.TableName | Should -Contain 'SecurityEvent'
        $results.TableName | Should -Contain 'MyCustom_CL'
        $results.TableName | Should -Not -Contain 'EmptyDef'
        $results.TableName | Should -Not -Contain 'SrchTable'
        $results | Should -HaveCount 2
    }

    It 'Returns all table definitions when IncludeAllTables is set' {
        $mixed = @(
            (New-MockTable -Name 'SecurityEvent' -Solutions @('SecurityInsights')),
            (New-MockTable -Name 'EmptyDef' -TableSubType 'Any' -Solutions @())
        )
        Mock Get-AzOperationalInsightsTable { $mixed }

        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg' -IncludeAllTables

        $results | Should -HaveCount 2
        $results.TableName | Should -Contain 'EmptyDef'
    }

    It 'Shows Workspace Default when table retention matches workspace default' {
        # Workspace default is 90, SecurityEvent has 90
        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg' -IncludeZeroRetention

        $results[0].RetentionSource | Should -Be 'Workspace Default'
    }

    It 'Shows Table Override when table retention differs from workspace default' {
        # Workspace default is 90, Syslog has 30
        $results = Get-WorkspaceRetentionData -WorkspaceName 'test-ws' -ResourceGroupName 'test-rg' -IncludeZeroRetention

        $results[1].RetentionSource | Should -Be 'Table Override'
    }
}

# ============================================================================
# Export-RetentionReport
# ============================================================================

Describe 'Export-RetentionReport' {

    BeforeAll {
        $script:sampleData = @(
            [PSCustomObject]@{
                WorkspaceName          = 'ws1'
                TableName              = 'SecurityEvent'
                RetentionInDays        = 90
                ArchiveRetentionInDays = 270
                TotalRetentionInDays   = 360
                Plan                   = 'Analytics'
            }
        )
    }

    Context 'Table output' {
        It 'Returns objects to the pipeline' {
            $result = Export-RetentionReport -Data $script:sampleData -OutputFormat 'Table'

            $result | Should -HaveCount 1
            $result[0].TableName | Should -Be 'SecurityEvent'
        }
    }

    Context 'CSV output' {
        It 'Writes CSV file to OutputPath' {
            $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "retention-test-$(Get-Random).csv"
            try {
                Export-RetentionReport -Data $script:sampleData -OutputFormat 'CSV' -OutputPath $tempFile

                Test-Path $tempFile | Should -BeTrue
                $csv = Import-Csv -Path $tempFile
                $csv | Should -HaveCount 1
                $csv[0].TableName | Should -Be 'SecurityEvent'
                $csv[0].TotalRetentionInDays | Should -Be '360'
            }
            finally {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Throws when OutputPath is not provided for CSV' {
            { Export-RetentionReport -Data $script:sampleData -OutputFormat 'CSV' } | Should -Throw '*OutputPath*'
        }
    }

    Context 'JSON output' {
        It 'Writes JSON file to OutputPath' {
            $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "retention-test-$(Get-Random).json"
            try {
                Export-RetentionReport -Data $script:sampleData -OutputFormat 'JSON' -OutputPath $tempFile

                Test-Path $tempFile | Should -BeTrue
                $json = Get-Content -Path $tempFile -Raw | ConvertFrom-Json
                $json.TableName | Should -Be 'SecurityEvent'
                $json.TotalRetentionInDays | Should -Be 360
            }
            finally {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Throws when OutputPath is not provided for JSON' {
            { Export-RetentionReport -Data $script:sampleData -OutputFormat 'JSON' } | Should -Throw '*OutputPath*'
        }
    }

    Context 'Empty data' {
        It 'Handles empty data array without error' {
            { Export-RetentionReport -Data @() -OutputFormat 'Table' } | Should -Not -Throw
        }
    }
}

# ============================================================================
# Compare-RetentionCompliance
# ============================================================================

Describe 'Compare-RetentionCompliance' {

    BeforeAll {
        $script:complianceData = @(
            [PSCustomObject]@{
                WorkspaceName          = 'ws1'
                TableName              = 'SecurityEvent'
                RetentionInDays        = 90
                ArchiveRetentionInDays = 275
                TotalRetentionInDays   = 365
                Plan                   = 'Analytics'
            },
            [PSCustomObject]@{
                WorkspaceName          = 'ws1'
                TableName              = 'Syslog'
                RetentionInDays        = 30
                ArchiveRetentionInDays = 0
                TotalRetentionInDays   = 30
                Plan                   = 'Analytics'
            },
            [PSCustomObject]@{
                WorkspaceName          = 'ws1'
                TableName              = 'SecurityEvent_SRCH'
                RetentionInDays        = 30
                ArchiveRetentionInDays = 0
                TotalRetentionInDays   = 30
                Plan                   = 'Basic'
            },
            [PSCustomObject]@{
                WorkspaceName          = 'ws1'
                TableName              = 'SigninLogs'
                RetentionInDays        = 90
                ArchiveRetentionInDays = 640
                TotalRetentionInDays   = 730
                Plan                   = 'Analytics'
            }
        )
    }

    It 'Marks compliant tables as Compliant' {
        $results = Compare-RetentionCompliance -Data $script:complianceData.ForEach({ $_.PSObject.Copy() }) `
            -ExpectedRetentionInDays 90 -ExpectedTotalRetentionInDays 365

        $secEvent = $results | Where-Object { $_.TableName -eq 'SecurityEvent' }
        $secEvent.MeetsRetention | Should -Be 'Compliant'
        $secEvent.ComplianceDetail | Should -BeNullOrEmpty
    }

    It 'Marks non-compliant tables as Non-Compliant with detail' {
        $results = Compare-RetentionCompliance -Data $script:complianceData.ForEach({ $_.PSObject.Copy() }) `
            -ExpectedRetentionInDays 90 -ExpectedTotalRetentionInDays 365

        $syslog = $results | Where-Object { $_.TableName -eq 'Syslog' }
        $syslog.MeetsRetention | Should -Be 'Non-Compliant'
        $syslog.ComplianceDetail | Should -Match 'RetentionInDays 30 < expected 90'
        $syslog.ComplianceDetail | Should -Match 'TotalRetentionInDays 30 < expected 365'
    }

    It 'Excludes _SRCH tables from compliance checks' {
        $results = Compare-RetentionCompliance -Data $script:complianceData.ForEach({ $_.PSObject.Copy() }) `
            -ExpectedRetentionInDays 90 -ExpectedTotalRetentionInDays 365

        $srch = $results | Where-Object { $_.TableName -eq 'SecurityEvent_SRCH' }
        $srch.MeetsRetention | Should -Be 'Excluded'
        $srch.ComplianceDetail | Should -Match 'Search result table'
    }

    It 'Uses custom thresholds correctly' {
        $results = Compare-RetentionCompliance -Data $script:complianceData.ForEach({ $_.PSObject.Copy() }) `
            -ExpectedRetentionInDays 30 -ExpectedTotalRetentionInDays 30

        # With low thresholds, Syslog (30/0/30) should now be compliant
        $syslog = $results | Where-Object { $_.TableName -eq 'Syslog' }
        $syslog.MeetsRetention | Should -Be 'Compliant'
    }

    It 'Handles tables exceeding thresholds as Compliant' {
        $results = Compare-RetentionCompliance -Data $script:complianceData.ForEach({ $_.PSObject.Copy() }) `
            -ExpectedRetentionInDays 90 -ExpectedTotalRetentionInDays 365

        $signin = $results | Where-Object { $_.TableName -eq 'SigninLogs' }
        $signin.MeetsRetention | Should -Be 'Compliant'
    }

    It 'Returns all rows including excluded and non-compliant' {
        $results = Compare-RetentionCompliance -Data $script:complianceData.ForEach({ $_.PSObject.Copy() }) `
            -ExpectedRetentionInDays 90 -ExpectedTotalRetentionInDays 365

        $results | Should -HaveCount 4
    }
}

# ============================================================================
# Multi-Workspace
# ============================================================================

Describe 'Multi-Workspace Processing' {

    It 'Get-WorkspaceRetentionData stamps the correct workspace name on each result' {
        Mock Get-AzOperationalInsightsTable {
            @((New-MockTable -Name 'Heartbeat' -Retention 30 -TotalRetention 30 -Solutions @('SecurityInsights')))
        }
        Mock Get-AzOperationalInsightsWorkspace { [PSCustomObject]@{ RetentionInDays = 90 } }

        $results1 = Get-WorkspaceRetentionData -WorkspaceName 'ws-prod' -ResourceGroupName 'rg'
        $results2 = Get-WorkspaceRetentionData -WorkspaceName 'ws-dev' -ResourceGroupName 'rg'

        $results1[0].WorkspaceName | Should -Be 'ws-prod'
        $results2[0].WorkspaceName | Should -Be 'ws-dev'
    }
}
