# Sample Logic App Payload - Enhanced ConnectorKql Demo
# This shows what the JSON payload sent to Logic Apps will look like with enhanced metadata

Write-Host "Sample Logic App Payload with Enhanced Metadata" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host

# Create a sample connector collection with enhanced metadata
$samplePayload = @(
    @{
        Name = 'Azure Active Directory'
        Kind = 'AzureActiveDirectory'
        Status = 'ActivelyIngesting'
        LastLogTime = '2025-09-29T17:15:00Z'
        LogsLastHour = 1250
        TotalLogs24h = 45600
        QueryStatus = 'Success'
        HoursSinceLastLog = 0.25
        StatusDetails = 'enabled=true'
        Workspace = 'law-security-prod'
        Subscription = 'Contoso Security Sub'
        NoLastLog = $false
        ConnectorId = 'AzureActiveDirectory'
        ConnectorTitle = 'Azure Active Directory'
        ConnectorPublisher = 'Microsoft'
        IsConnected = $true  # True because at least one connectivity criteria passed
    },
    @{
        Name = 'AbnormalSecurity'
        Kind = 'AbnormalSecurity'
        Status = 'RecentlyActive'
        LastLogTime = '2025-09-29T14:30:00Z'
        LogsLastHour = 0
        TotalLogs24h = 156
        QueryStatus = 'Success'
        HoursSinceLastLog = 2.75
        StatusDetails = 'enabled=true'
        Workspace = 'law-security-prod'
        Subscription = 'Contoso Security Sub'
        NoLastLog = $false
        ConnectorId = 'AbnormalSecurity'
        ConnectorTitle = 'AbnormalSecurity'
        ConnectorPublisher = 'AbnormalSecurity'
        IsConnected = $true  # True because at least one connectivity criteria passed
    },
    @{
        Name = 'AWS'
        Kind = 'AWS'
        Status = 'ConfiguredButNoLogs'
        LastLogTime = $null
        LogsLastHour = 0
        TotalLogs24h = 0
        QueryStatus = 'Success'
        HoursSinceLastLog = $null
        StatusDetails = 'enabled=true'
        Workspace = 'law-security-prod'
        Subscription = 'Contoso Security Sub'
        NoLastLog = $true
        Id = 'AWS'
        Title = 'Amazon Web Services'
        Publisher = 'Amazon'
        IsConnected = $false  # False because no connectivity criteria passed
    }
)

# Convert to JSON and display
$jsonPayload = $samplePayload | ConvertTo-Json -Depth 5
Write-Host "JSON Payload (formatted):" -ForegroundColor Yellow
Write-Host $jsonPayload

Write-Host
Write-Host "Key Benefits for Logic App Processing:" -ForegroundColor Cyan
Write-Host "  1. ConnectorId provides stable identifier for mapping/routing logic"
Write-Host "  2. ConnectorTitle offers human-readable names for notifications/reports"
Write-Host "  3. ConnectorPublisher enables vendor-specific processing workflows"
Write-Host "  4. IsConnected provides simple boolean connectivity status:"
Write-Host "     - True if ANY connectivity criteria query returns true"
Write-Host "     - False if ALL connectivity criteria queries return false"
Write-Host "     - Simplifies Logic App conditional logic"
Write-Host
Write-Host "Example Logic App Use Cases:" -ForegroundColor Magenta
Write-Host "  - Route Microsoft connectors to one workflow, third-party to another"
Write-Host "  - Create vendor-specific notifications (e.g., 'AWS CloudTrail connector down')"
Write-Host "  - Simple connectivity checks: if IsConnected = false, trigger alerts"
Write-Host "  - Generate compliance reports by publisher/vendor with connectivity status"
Write-Host "  - Implement different SLA thresholds by connector type/publisher"
Write-Host "  - Create dashboard indicators based on simple true/false connectivity"