<#
.SYNOPSIS
    RSOC-side orchestrator for the Microsoft Entra Tenant Governance relationship handshake.
    Implements the mandatory invitation-first flow required by the Unified SecOps model.

.DESCRIPTION
    Implements the correct 3-step Tenant Governance handshake (per Microsoft Unified SecOps docs):

      STEP 1 (customer/ MANUAL, cannot be automated):governed 
        Customer sends governance invitation to RSOC via Defender portal:
          System > Permissions > Delegated Access > Send invitation
          Enter RSOC governing tenant ID.

      STEP 2 (RSOC/ THIS SCRIPT):governing 
        Polls for the customer's invitation.
        When found: creates or reuses governance policy template, then POSTs governance request.

      STEP 3 (customer/ MANUAL):governed 
        Customer approves the governance request via Defender portal:
          System > Permissions > Delegated Access > (pending request) > Approve

    Reference:
      https://learn.microsoft.com/en-us/unified-secops/governance-relationships
      https://learn.microsoft.com/en-us/graph/api/resources/tenantgovernanceservices-tenantgovernance-overview?view=graph-rest-beta

    IMPORTANT: This API is in Graph /beta. Subject to change. Review before production.

.PARAMETER CustomerConfigPath
    Path to the customer intake JSON (customer-intake.schema.json-compliant).

.PARAMETER CustomerTenantId
    Override the governed tenant ID from config.customer.tenantId.

.PARAMETER PolicyTemplateId
    Existing RSOC governance policy template ID. Skips template lookup/creation.

.PARAMETER CreateTemplate
    Force creation of a new governance policy template even if one exists.

.PARAMETER PolicyTemplateDisplayName
    Display name for a newly created template. Default: "RSOC TMNA Governance Policy".

.PARAMETER StateFilePath
    Onboarding state file to update after sending governance request.

.PARAMETER WhatIfMode
    Preview actions without making API calls.

.PARAMETER EvidenceOutputPath
    Path for machine-readable evidence output.

.NOTES
    REQUIRES:
      - Microsoft.Graph.Authentication module
      - Delegated auth: scopes TenantGovernance-Invitation.Read.All,
        TenantGovernance-Request.ReadWrite.All, TenantGovernance-Policy.ReadWrite.All
      - Signed-in user: Tenant Governance Administrator or Tenant Governance Relationship Administrator
        in the RSOC governing tenant
      - RSOC tenant must have governance invitations ENABLED before customer sends invitation.
        Enable via Defender MTO portal: System > Delegated Access > Enable invitations toggle.

    TEST_REQUIRED:
      - API is Graph  endpoints subject to changebeta 
      - Verify RSOC security group IDs match live group object IDs in RSOC Entra tenant
      - Confirm all RSOC groups have isAssignableToRole = true and are not Microsoft 365 groups
      - RSOC tenant must have invitations enabled BEFORE customer sends invitation
 approve flow in non-production first
      - Governance invitation expires 30 days from creation; re-request customer to resend if expired
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CustomerConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerTenantId,

    [Parameter(Mandatory = $false)]
    [string]$PolicyTemplateId,

    [switch]$CreateTemplate,

    [Parameter(Mandatory = $false)]
    [string]$PolicyTemplateDisplayName = 'RSOC TMNA Governance Policy',

    [Parameter(Mandatory = $false)]
    [string]$StateFilePath,

    [switch]$WhatIfMode,

    [string]$EvidenceOutputPath = '.\evidence\New-TenantGovernanceRelationship.evidence.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TgBaseUrl = 'https://graph.microsoft.com/beta/directory/tenantGovernance'

 RSOC security group -> Entra role delegated administration mappings # 
# Group IDs are object IDs from the RSOC (governing) Entra tenant.
# Source: AzLighthouse/lighthouse/lighthouse-offer1.json
# Role template IDs are Entra built-in roles assigned in the governed tenant.
# TEST_REQUIRED: Confirm group IDs match live RSOC tenant group object IDs.
# TEST_REQUIRED: Confirm all groups have isAssignableToRole = true, not M365 groups.
# Entra Role template IDs:
#   Security Administrator:   194ae4cb-b126-40b2-bd5b-6091b380977d
#   Security Operator:        8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2
#   Security Reader:          5d6b6bb7-de71-4623-b4af-96380a352509
$RsocRoleAssignments = @(
    @{
        GroupId          = 'c1f4a285-1b26-46b8-9a97-d298861ad503'
        GroupDisplayName = 'RSOC_Sentinel_Admin'
        RoleTemplateIds  = @('194ae4cb-b126-40b2-bd5b-6091b380977d')  # Security Administrator
    },
    @{
        GroupId          = 'cbe65060-f79c-4350-aaf2-fd901a95de33'
        GroupDisplayName = 'RSOC_Sentinel_Onboarding'
        RoleTemplateIds  = @('194ae4cb-b126-40b2-bd5b-6091b380977d')  # Security Administrator
    },
    @{
        GroupId          = '440ba293-8d18-430c-b4cc-3ea789d655e9'
        GroupDisplayName = 'RSOC_Sentinel_Threat_Detection_Engineering_Tier1'
        RoleTemplateIds  = @('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2')  # Security Operator
    },
    @{
        GroupId          = 'd4e11e0e-6300-4491-938f-e934a587f990'
        GroupDisplayName = 'RSOC_Sentinel_Threat_Detection_Engineering_Tier2'
        RoleTemplateIds  = @('194ae4cb-b126-40b2-bd5b-6091b380977d')  # Security Administrator
    },
    @{
        GroupId          = '4fd628b1-a5f8-43a1-9949-88a84e7f053b'
        GroupDisplayName = 'RSOC_Sentinel_Security_Engineers'
        RoleTemplateIds  = @('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2')  # Security Operator
    },
    @{
        GroupId          = 'a6539c63-c61b-459f-bdc6-22106aa0aed3'
        GroupDisplayName = 'RSOC_Sentinel_Red_Team'
        RoleTemplateIds  = @('5d6b6bb7-de71-4623-b4af-96380a352509')  # Security Reader
    },
    @{
        GroupId          = 'ef18438b-79fc-4b4a-8f3f-3b691f091aa2'
        GroupDisplayName = 'RSOC_Sentinel_Incident_Response'
        RoleTemplateIds  = @('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2')  # Security Operator
    },
    @{
        GroupId          = '0d593b30-eb20-4d83-a7eb-deff71e401d2'
        GroupDisplayName = 'RSOC_Sentinel_Incident_Detection_Tier1'
        RoleTemplateIds  = @('5d6b6bb7-de71-4623-b4af-96380a352509')  # Security Reader
    },
    @{
        GroupId          = 'fe773eea-b69d-40e7-9c90-0ccb5ea4447c'
        GroupDisplayName = 'RSOC_Sentinel_Incident_Detection_Tier2'
        RoleTemplateIds  = @('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2')  # Security Operator
    }
)

function Write-Evidence {
    param([hashtable]$Data)
    $dir = Split-Path -Parent $EvidenceOutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $EvidenceOutputPath -Encoding utf8
    Write-Host "Evidence written: $EvidenceOutputPath"
}

function Invoke-TgGraph {
    param([string]$Method = 'GET', [string]$Uri, [hashtable]$Body = $null)
    $params = @{ Method = $Method; Uri = $Uri; Headers = @{ 'Content-Type' = 'application/json' } }
    if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10) }
    Invoke-MgGraphRequest @params
}

 Load config # 
if (-not (Test-Path $CustomerConfigPath)) { throw "Customer config not found: $CustomerConfigPath" }
$config           = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json
$governedTenantId = if ($CustomerTenantId) { $CustomerTenantId } else { $config.customer.tenantId }
if ([string]::IsNullOrWhiteSpace($governedTenantId)) {
    throw "No customer.tenantId in config and -CustomerTenantId not provided."
}

Write-Host ""
Write-Host "=== New-TenantGovernanceRelationship ===" -ForegroundColor Cyan
Write-Host "  Customer:          $($config.customer.shortName)"
Write-Host "  Governed tenant:   $governedTenantId"
Write-Host "  Flow:              Invitation-first (customer initiates per Unified SecOps model)"
Write-Host "  API:               Graph beta /directory/tenantGovernance"
Write-Host ""

if ($WhatIfMode) {
    Write-Host "[WHATIF] Would check for governance invitation from: $governedTenantId" -ForegroundColor Yellow
    Write-Host "[WHATIF] If found: create/reuse policy template -> POST governance request"
    Write-Evidence @{
        script          = 'New-TenantGovernanceRelationship.ps1'
        customer        = $config.customer.shortName
        governedTenantId = $governedTenantId
        whatIf          = $true
        status          = 'whatif-only'
        timestampUtc    = (Get-Date).ToUniversalTime().ToString('o')
    }
    return
}

 Connect to Graph # 
Write-Host "Connecting to Microsoft Graph (delegated)..."
Connect-MgGraph -Scopes @(
    'TenantGovernance-Invitation.Read.All',
    'TenantGovernance-Request.ReadWrite.All',
    'TenantGovernance-Policy.ReadWrite.All',
    'TenantGovernance-Relationship.Read.All'
) -NoWelcome

$ctx = Get-MgContext
Write-Host "Connected as: $($ctx.Account) | RSOC tenant: $($ctx.TenantId)"

 Check for existing active relationship # 
Write-Host ""
Write-Host "[0] Checking for existing active governance relationship..."
$existingRels = Invoke-TgGraph -Uri "$TgBaseUrl/governanceRelationships?`$filter=governedTenantId eq '$governedTenantId'"
$activeRel    = $existingRels.value | Where-Object { $_.status -ieq 'active' } | Select-Object -First 1

if ($activeRel) {
    Write-Host "  Active governance relationship already exists: $($activeRel.id)" -ForegroundColor Green
    Write-Evidence @{
        script                 = 'New-TenantGovernanceRelationship.ps1'
        customer               = $config.customer.shortName
        governedTenantId       = $governedTenantId
        existingRelationshipId = $activeRel.id
        status                 = 'already-active'
        timestampUtc           = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Host "No action  relationship is already active."needed 
    return
}

 STEP 1: Check for pending governance invitation from customer # 
# The customer MUST send the invitation first from their Defender portal.
# RSOC cannot send the governance request without receiving an invitation first.
Write-Host ""
Write-Host "[1] Checking for governance invitation from customer tenant: $governedTenantId ..."
Write-Host "    (Customer must have already sent invitation via Defender portal)"

$invitations = Invoke-TgGraph -Uri "$TgBaseUrl/governanceInvitations?`$filter=governedTenantId eq '$governedTenantId'"
$pendingInvitation = $invitations.value |
    Where-Object { $_.governedTenantId -eq $governedTenantId } |
    Where-Object { (Get-Date $_.expirationDateTime) -gt (Get-Date) } |
    Sort-Object createdDateTime -Descending |
    Select-Object -First 1

if (-not $pendingInvitation) {
    # No  customer has not sent it yet or it expiredinvitation 
    $expiredInvitations = $invitations.value |
        Where-Object { $_.governedTenantId -eq $governedTenantId } |
        Where-Object { (Get-Date $_.expirationDateTime) -le (Get-Date) }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "  WAITING FOR CUSTOMER  No valid invitation found        " -ForegroundColor YellowACTION 
    Write-Host "================================================================" -ForegroundColor Yellow

    if ($expiredInvitations) {
        Write-Host ""
        Write-Host "  NOTE: $($expiredInvitations.Count) expired invitation(s) found from this tenant." -ForegroundColor Yellow
        Write-Host "  Customer must send a new invitation (30-day expiry)." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  Customer must perform STEP 1 before this script can proceed:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Sign in to the Defender portal as a Tenant Governance Administrator:"
    Write-Host "     https://security.microsoft.com"
    Write-Host ""
    Write-Host "  2. Navigate to:"
    Write-Host "     System > Permissions > Delegated Access"
    Write-Host ""
    Write-Host "  3. Select 'Send invitation'"
    Write-Host ""
    Write-Host "  4. Enter the RSOC governing tenant ID: $($ctx.TenantId)"
    Write-Host ""
    Write-Host "  5. Select 'Send' to submit the invitation."
    Write-Host ""
    Write-Host "  Invitation expires after 30 days. Re-run this script after customer sends."
    Write-Host ""
    Write-Host "  Alternatively, monitor via Watch-GdapRelationshipRequests.ps1 -WatchInvitation"

    Write-Evidence @{
        script             = 'New-TenantGovernanceRelationship.ps1'
        customer           = $config.customer.shortName
        governedTenantId   = $governedTenantId
        rsocTenantId       = $ctx.TenantId
        invitationFound    = $false
        expiredCount       = ($expiredInvitations | Measure-Object).Count
        status             = 'waiting-for-customer-invitation'
        manualActionsRequired = @(
            "Customer Tenant Governance Administrator must sign in to https://security.microsoft.com",
            "Navigate to: System > Permissions > Delegated Access",
            "Select 'Send invitation'",
            "Enter RSOC governing tenant ID: $($ctx.TenantId)",
            "Select 'Send'"
        )
        timestampUtc       = (Get-Date).ToUniversalTime().ToString('o')
    }
    return
}

Write-Host "  Invitation found from: $($pendingInvitation.governedTenantName)" -ForegroundColor Green
Write-Host "  Invitation ID:  $($pendingInvitation.id)"
Write-Host "  Created:        $($pendingInvitation.createdDateTime)"
Write-Host "  Expires:        $($pendingInvitation.expirationDateTime)"

 STEP 2: Resolve or create governance policy template # 
Write-Host ""
Write-Host "[2] Resolving governance policy template..."

if (-not $PolicyTemplateId) {
    $templates    = Invoke-TgGraph -Uri "$TgBaseUrl/governancePolicyTemplates"
    $rsocTemplate = $templates.value |
        Where-Object { $_.displayName -like '*RSOC*' -or $_.displayName -like '*TMNA*' } |
        Select-Object -First 1

    if ($rsocTemplate -and -not $CreateTemplate) {
        $PolicyTemplateId = $rsocTemplate.id
        Write-Host "  Found existing RSOC template: '$($rsocTemplate.displayName)' ($PolicyTemplateId)"
    } else {
        Write-Host "  Creating governance policy template: '$PolicyTemplateDisplayName'"

        $delegatedAssignments = foreach ($ra in $RsocRoleAssignments) {
            @{
                'group@odata.bind' = "https://graph.microsoft.com/beta/groups/$($ra.GroupId)"
                roleTemplates      = @($ra.RoleTemplateIds | ForEach-Object { @{ id = $_ } })
            }
        }

        $templateBody = @{
            displayName                            = $PolicyTemplateDisplayName
            description                            = 'RSOC TMNA delegated Sentinel/Defender admin policy. Groups from AzLighthouse/lighthouse/lighthouse-offer1.json.'
            delegatedAdministrationRoleAssignments = $delegatedAssignments
        }

        $newTemplate      = Invoke-TgGraph -Method POST -Uri "$TgBaseUrl/governancePolicyTemplates" -Body $templateBody
        $PolicyTemplateId = $newTemplate.id
        Write-Host "  Policy template created: $PolicyTemplateId" -ForegroundColor Green
    }
}

Write-Host "  Using policy template: $PolicyTemplateId"

 STEP 2 cont.: POST governance request # 
Write-Host ""
Write-Host "[2] Sending governance request to customer tenant..."

$requestBody = @{
    governedTenantId                      = $governedTenantId
    'governancePolicyTemplate@odata.bind' = "https://graph.microsoft.com/beta/directory/tenantGovernance/governancePolicyTemplates/$PolicyTemplateId"
}

$governanceRequest = Invoke-TgGraph -Method POST -Uri "$TgBaseUrl/governanceRequests" -Body $requestBody

$requestId     = $governanceRequest.id
$requestStatus = $governanceRequest.status
$expiresAt     = $governanceRequest.expirationDateTime

Write-Host "  Governance request sent!" -ForegroundColor Green
Write-Host "  Request ID:  $requestId"
Write-Host "  Status:      $requestStatus"
Write-Host "  Expires:     $expiresAt"

 Update state file # 
if ($StateFilePath -and (Test-Path $StateFilePath)) {
    $state = Get-Content $StateFilePath -Raw | ConvertFrom-Json -AsHashtable
    $state['tenantGovernance'] = @{
        invitationId              = $pendingInvitation.id
        governanceRequestId       = $requestId
        governancePolicyTemplateId = $PolicyTemplateId
        requestStatus             = $requestStatus
        requestExpiresAt          = $expiresAt
        governedTenantId          = $governedTenantId
        sentAt                    = (Get-Date).ToUniversalTime().ToString('o')
    }
    $state | ConvertTo-Json -Depth 10 | Out-File -FilePath $StateFilePath -Encoding utf8
    Write-Host "State file updated: $StateFilePath"
}

 STEP 3 guidance # 
Write-Host ""
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host "  MANUAL ACTION  Customer must approve request (STEP 3)" -ForegroundColor MagentaREQUIRED 
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  A Tenant Governance Administrator in the CUSTOMER tenant must:"
Write-Host ""
Write-Host "  1. Sign in to: https://security.microsoft.com (Defender portal)"
Write-Host "  2. Navigate to: System > Permissions > Delegated Access"
Write-Host "  3. Find the pending access request and select 'Approve'"
Write-Host ""
Write-Host "  Request ID: $requestId"
Write-Host "  Expires:    $expiresAt"
Write-Host ""
Write-Host "  After approval, run Watch-GdapRelationshipRequests.ps1 -RequestId '$requestId' to confirm."
Write-Host "  Then run New-LighthouseDelegationPackage.ps1 to complete Azure resource delegation."
Write-Host ""

Write-Evidence @{
    script                   = 'New-TenantGovernanceRelationship.ps1'
    customer                 = $config.customer.shortName
    governedTenantId         = $governedTenantId
    rsocTenantId             = $ctx.TenantId
    invitationId             = $pendingInvitation.id
    invitationCreated        = $pendingInvitation.createdDateTime
    invitationExpires        = $pendingInvitation.expirationDateTime
    governanceRequestId      = $requestId
    governancePolicyTemplateId = $PolicyTemplateId
    requestStatus            = $requestStatus
    requestExpiresAt         = $expiresAt
    status                   = 'request-sent-pending-customer-approval'
    manualActionsRequired    = @(
        "Customer Tenant Governance Admin must approve request $requestId",
        "Defender portal: https://security.microsoft.com",
        "Navigate: System > Permissions > Delegated Access > Approve pending request"
    )
    testRequired             = @(
        "API is Graph  verify endpoints before production",beta 
        "RSOC tenant must have governance invitations enabled before customer sends invitation",
        "Verify RSOC security group IDs match live RSOC tenant group object IDs",
        "Verify groups have isAssignableToRole = true and are not Microsoft 365 groups",
        "After relationship active: assign Azure RBAC 'Microsoft Sentinel Contributor' to remote tenant groups in customer subscription"
    )
    timestampUtc             = (Get-Date).ToUniversalTime().ToString('o')
}
