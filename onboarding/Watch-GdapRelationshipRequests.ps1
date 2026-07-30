<#
.SYNOPSIS
    Monitors Tenant Governance invitation and request states during RSOC onboarding.
    Supports two modes: watch for a customer invitation (pre-request) or watch for
    request acceptance (post-request).

.DESCRIPTION
    Mode  Invitation watch (-WatchInvitation):1 
      Polls GET /beta/directory/tenantGovernance/governanceInvitations filtered by
      governedTenantId. Used while waiting for the customer to send their invitation
      from the Defender portal. Exits and prompts to run New-TenantGovernanceRelationship.ps1
      when invitation is detected.

    Mode  Request acceptance watch (default, -RequestId required):2 
      Polls GET /beta/directory/tenantGovernance/governanceRequests/{id} until the
      governed tenant approves, and confirms the resulting active governanceRelationship.

    Reference:
      https://learn.microsoft.com/en-us/unified-secops/governance-relationships
      https://learn.microsoft.com/en-us/graph/api/resources/tenantgovernanceservices-governancerequest?view=graph-rest-beta

.PARAMETER CustomerConfigPath
    Path to the customer intake JSON.

.PARAMETER RequestId
    Governance request ID (Mode 2). If omitted, tries evidence JSON. Required unless -WatchInvitation.

.PARAMETER WatchInvitation
    Switch to Mode  watch for the customer's governance invitation instead of request acceptance.1 

.PARAMETER CustomerTenantId
    Override the governed tenant ID from config.customer.tenantId.

.PARAMETER PollIntervalSeconds
    Seconds between polls. Default: 60.

.PARAMETER TimeoutMinutes
    Maximum wait time. Default: 120.

.PARAMETER StateFilePath
    Onboarding state file to update on success.

.PARAMETER WhatIfMode
    Preview polling actions without calling the API.

.PARAMETER EvidenceOutputPath
    Path for machine-readable evidence output.

.NOTES
    REQUIRES:
      - Microsoft.Graph.Authentication module
      - Scopes: TenantGovernance-Invitation.Read.All, TenantGovernance-Relationship.Read.All,
                TenantGovernance-Request.ReadWrite.All
      - User needs: Tenant Governance Relationship Administrator or Tenant Governance Reader

    TEST_REQUIRED:
      - API is Graph  endpoints subject to changebeta 
      - Mode 2: Customer approves via Defender portal (NOT Entra admin center)
        Path: https://security.microsoft.com > System > Permissions > Delegated Access > Approve
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CustomerConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$RequestId,

    [switch]$WatchInvitation,

    [Parameter(Mandatory = $false)]
    [string]$CustomerTenantId,

    [Parameter(Mandatory = $false)]
    [int]$PollIntervalSeconds = 60,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutMinutes = 120,

    [Parameter(Mandatory = $false)]
    [string]$StateFilePath,

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = '.\evidence\Watch-GdapRelationshipRequests.evidence.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TgBaseUrl = 'https://graph.microsoft.com/beta/directory/tenantGovernance'

function Write-Evidence {
    param([hashtable]$Data)
    $dir = Split-Path -Parent $EvidenceOutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $EvidenceOutputPath -Encoding utf8
}

function Invoke-TgGraph { param([string]$Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ 'Content-Type' = 'application/json' }
}

 Load config # 
if (-not (Test-Path $CustomerConfigPath)) { throw "Customer config not found: $CustomerConfigPath" }
$config           = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$governedTenantId = if ($CustomerTenantId) { $CustomerTenantId } else { $config.customer.tenantId }

# Resolve RequestId from prior evidence if not provided (Mode 2)
if (-not $WatchInvitation -and -not $RequestId) {
    $evidencePath = '.\evidence\New-TenantGovernanceRelationship.evidence.json'
    if (Test-Path $evidencePath) {
        $prevEvidence = Get-Content $evidencePath -Raw | ConvertFrom-Json
        $RequestId    = $prevEvidence.governanceRequestId
        Write-Host "Resolved RequestId from evidence: $RequestId"
    }
    if (-not $RequestId) {
        throw "No -RequestId provided and none found in evidence. Run New-TenantGovernanceRelationship.ps1 first, or use -WatchInvitation."
    }
}

$mode = if ($WatchInvitation) { 'invitation' } else { 'request-acceptance' }

Write-Host ""
Write-Host "=== Watch-GdapRelationshipRequests ===" -ForegroundColor Cyan
Write-Host "  Customer:         $($config.customer.shortName)"
Write-Host "  Governed tenant:  $governedTenantId"
Write-Host "  Mode:             $mode"
if ($RequestId) { Write-Host "  Request ID:       $RequestId" }
Write-Host "  Poll interval:    ${PollIntervalSeconds}s  |  Timeout: ${TimeoutMinutes}m"
Write-Host ""

if ($WhatIfMode) {
    if ($WatchInvitation) {
        Write-Host "[WHATIF] Would poll: GET $TgBaseUrl/governanceInvitations?`$filter=governedTenantId eq '$governedTenantId'" -ForegroundColor Yellow
    } else {
        Write-Host "[WHATIF] Would poll: GET $TgBaseUrl/governanceRequests/$RequestId" -ForegroundColor Yellow
        Write-Host "[WHATIF] And check:  GET $TgBaseUrl/governanceRelationships?`$filter=governedTenantId eq '$governedTenantId'"
    }
    Write-Evidence @{
        script          = 'Watch-GdapRelationshipRequests.ps1'
        mode            = $mode
        customer        = $config.customer.shortName
        governedTenantId = $governedTenantId
        whatIf          = $true; status = 'whatif-only'
        timestampUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }
    return
}

 Connect # 
Connect-MgGraph -Scopes @(
    'TenantGovernance-Invitation.Read.All',
    'TenantGovernance-Relationship.Read.All',
    'TenantGovernance-Request.ReadWrite.All'
) -NoWelcome

$timeoutAt   = (Get-Date).AddMinutes($TimeoutMinutes)
$pollCount   = 0
$finalStatus = $null
$resultId    = $null

# 
# MODE 1: Watch for customer invitation
# 
if ($WatchInvitation) {
    Write-Host "Polling for governance invitation from customer..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Waiting for customer to send invitation from Defender portal:"
    Write-Host "    https://security.microsoft.com"
    Write-Host "    System > Permissions > Delegated Access > Send invitation"
    Write-Host ""

    while ((Get-Date) -lt $timeoutAt) {
        $pollCount++
        $timestamp = (Get-Date).ToString('HH:mm:ss')

        try {
            $invitations = Invoke-TgGraph -Uri "$TgBaseUrl/governanceInvitations?`$filter=governedTenantId eq '$governedTenantId'"
            $validInvite = $invitations.value |
                Where-Object { (Get-Date $_.expirationDateTime) -gt (Get-Date) } |
                Sort-Object createdDateTime -Descending |
                Select-Object -First 1

            if ($validInvite) {
                Write-Host ""
                Write-Host "[SUCCESS] Invitation received from: $($validInvite.governedTenantName)!" -ForegroundColor Green
                Write-Host "  Invitation ID: $($validInvite.id)"
                Write-Host "  Created:       $($validInvite.createdDateTime)"
                Write-Host "  Expires:       $($validInvite.expirationDateTime)"
                Write-Host ""
                Write-Host "  Next step: Run New-TenantGovernanceRelationship.ps1 to send the governance request."
                $finalStatus = 'invitation-received'
                $resultId    = $validInvite.id
                break
            } else {
                Write-Host "  [$timestamp] Poll #$pollCount | No invitation yet from $governedTenantId"
            }
        } catch {
            Write-Host "  [$timestamp] Poll error: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if ((Get-Date).AddSeconds($PollIntervalSeconds) -lt $timeoutAt) {
            Start-Sleep -Seconds $PollIntervalSeconds
        } else { break }
    }

# 
# MODE 2: Watch for governance request acceptance
# 
} else {
    Write-Host "Polling for governance request acceptance..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Customer must approve via Defender portal:"
    Write-Host "    https://security.microsoft.com"
    Write-Host "    System > Permissions > Delegated Access > (pending request) > Approve"
    Write-Host ""

    while ((Get-Date) -lt $timeoutAt) {
        $pollCount++
        $timestamp = (Get-Date).ToString('HH:mm:ss')

        try {
            $request       = Invoke-TgGraph -Uri "$TgBaseUrl/governanceRequests/$RequestId"
            $requestStatus = $request.status

            $rels      = Invoke-TgGraph -Uri "$TgBaseUrl/governanceRelationships?`$filter=governedTenantId eq '$governedTenantId'"
            $activeRel = $rels.value | Where-Object { $_.status -ieq 'active' } | Select-Object -First 1
            $relStatus = if ($activeRel) { 'active' } else { 'not-yet-created' }

            Write-Host "  [$timestamp] Poll #$pollCount | Request: $requestStatus | Relationship: $relStatus"

            if ($requestStatus -ieq 'rejected') {
                Write-Host ""
                Write-Host "[FAIL] Governance request was REJECTED by the customer tenant." -ForegroundColor Red
                $finalStatus = 'rejected'
                break
            }

            if ($requestStatus -ieq 'accepted' -and $activeRel) {
                $resultId = $activeRel.id
                Write-Host ""
                Write-Host "[SUCCESS] Governance relationship is ACTIVE!" -ForegroundColor Green
                Write-Host "  Relationship ID: $resultId"
                Write-Host "  Created: $($activeRel.creationDateTime)"
                Write-Host "  Governing: $($activeRel.governingTenantName) | Governed: $($activeRel.governedTenantName)"
                Write-Host ""
                Write-Host "  NEXT STEP: Assign Azure RBAC 'Microsoft Sentinel Contributor' to remote tenant groups"
                Write-Host "  in the customer subscription via Azure Portal > IAM > Add role assignment > Remote tenant group"
                $finalStatus = 'active'
                break
            }

            if ($requestStatus -ieq 'accepted') {
                Write-Host "          waiting for relationship to materialize..."Accepted 
            }
        } catch {
            Write-Host "  [$timestamp] Poll error: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        if ((Get-Date).AddSeconds($PollIntervalSeconds) -lt $timeoutAt) {
            Start-Sleep -Seconds $PollIntervalSeconds
        } else { break }
    }
}

if (-not $finalStatus) {
    $finalStatus = 'timed-out'
    Write-Host ""
    Write-Host "[TIMEOUT] Polling timed out after ${TimeoutMinutes} minutes." -ForegroundColor Yellow
    if ($WatchInvitation) {
        Write-Host "  Customer has not yet sent the invitation. Remind them to:"
        Write-Host "  https://security.microsoft.com > System > Permissions > Delegated Access > Send invitation"
    } else {
        Write-Host "  Request may still be pending customer approval."
        Write-Host "  Reminder: https://security.microsoft.com > System > Permissions > Delegated Access > Approve"
    }
}

if ($StateFilePath -and (Test-Path $StateFilePath) -and $finalStatus -in @('active', 'invitation-received')) {
    $state = Get-Content $StateFilePath -Raw | ConvertFrom-Json -AsHashtable
    if (-not $state.ContainsKey('tenantGovernance')) { $state['tenantGovernance'] = @{} }
    if ($finalStatus -eq 'active') {
        $state['tenantGovernance']['governanceRelationshipId'] = $resultId
        $state['tenantGovernance']['relationshipStatus']       = 'active'
        $state['tenantGovernance']['activatedAt']              = (Get-Date).ToUniversalTime().ToString('o')
    } elseif ($finalStatus -eq 'invitation-received') {
        $state['tenantGovernance']['invitationId']    = $resultId
        $state['tenantGovernance']['invitationSeenAt'] = (Get-Date).ToUniversalTime().ToString('o')
    }
    $state | ConvertTo-Json -Depth 10 | Out-File -FilePath $StateFilePath -Encoding utf8
}

Write-Evidence @{
    script           = 'Watch-GdapRelationshipRequests.ps1'
    mode             = $mode
    customer         = $config.customer.shortName
    governedTenantId = $governedTenantId
    requestId        = $RequestId
    finalStatus      = $finalStatus
    resultId         = $resultId
    pollCount        = $pollCount
    whatIf           = $false
    status           = $finalStatus
    testRequired     = @(
        "API is Graph  endpoints subject to change",beta 
        "Mode 2: customer approves in Defender portal, NOT Entra admin center",
        "After active: assign Sentinel RBAC to remote tenant groups in Azure Portal"
    )
    timestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
}
