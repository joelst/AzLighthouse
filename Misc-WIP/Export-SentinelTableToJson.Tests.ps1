# Pester tests for Export-SentinelTableToJson.ps1 helper functions and logging
# Requires Pester 5+

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here 'Export-SentinelTableToJson.ps1'

BeforeAll {
    # Skip main execution when dot-sourcing
    $env:EXPORT_TABLES_SKIP_MAIN = '1'
    . $scriptPath
}

AfterAll {
    Remove-Item Env:EXPORT_TABLES_SKIP_MAIN -ErrorAction SilentlyContinue
}

Describe 'Test-HourIncrementValidity' {
    It 'Returns true for 12 dividing 24' {
        Test-HourIncrementValidity -HourIncrements 12 -Base 24 | Should -BeTrue
    }
    It 'Returns false for 7 not dividing 24' {
        Test-HourIncrementValidity -HourIncrements 7 -Base 24 | Should -BeFalse
    }
    It 'Returns false for zero increment' {
        Test-HourIncrementValidity -HourIncrements 0 -Base 24 | Should -BeFalse
    }
}

Describe 'Get-ExportFileNames' {
    $table = 'DeviceInfo'
    $start = [datetime]'2025-01-01T00:00:00Z'
    $end   = $start.AddHours(12)
    $result = Get-ExportFileNames -Table $table -CurrentDate $start -NextDate $end
    It 'Produces .json filename with expected pattern' {
        # Pattern: Table-<start>-<end>.json where timestamps are yyyy-MM-dd-mmHHss
        $result.Json | Should -Match '^DeviceInfo-2025-01-01-\d{2}\d{2}\d{2}-2025-01-01-\d{2}\d{2}\d{2}\.json$'
    }
    It 'Produces Zip filename ending with matching json.zip' {
        $result.Zip | Should -Be "$($result.Json).zip"
    }
}

Describe 'Write-Log' {
    It 'Writes CSV line with correct severity' {
        $tempLog = New-TemporaryFile
        try {
            Write-Log -Message 'Test message' -Severity Warning -LogFilePath $tempLog.FullName
            $csv = Import-Csv -Path $tempLog.FullName
            $csv | Should -HaveCount 1
            $csv[0].Message | Should -Be 'Test message'
            $csv[0].Severity | Should -Be 'Warning'
            # Time field should parse
            { [datetime]::Parse($csv[0].Time) } | Should -Not -Throw
        }
        finally {
            Remove-Item $tempLog -Force -ErrorAction SilentlyContinue
        }
    }
}
