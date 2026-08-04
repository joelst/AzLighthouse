# MSSP Customer Onboarding Pipeline

This folder contains the RSOC engineer-run deployment scripts for onboarding affiliate tenants into the MSSP SOC service. These scripts are run **locally or from Azure Cloud Shell** by the RSOC onboarding engineer — they are not Azure Automation runbooks.

## Relationship to the rest of this repo

| This folder | Other repo folder | Relationship |
|---|---|---|
| `New-LighthouseDelegationPackage.ps1` | `lighthouse/lighthouse-offer1.json` | Deploys the Lighthouse ARM template from this repo |
| `Register-OnboardingMonitor.ps1` | `automation/automationAccount.json` | Deploys the Automation Account ARM template from this repo |
| `Set-RsocSubscriptionGovernance.ps1` | `identity/umi/deploy-umi.ps1` | Invokes UMI deployment from this repo |
| `Deploy-SentinelWorkspace.ps1` | `sentinel/custom/azuredeploy.json` | Deploys Sentinel workspace template from this repo |
| `Enable-DataConnectors.ps1` | `automation/Get-DataConnectorStatus.ps1` | Complementary: Enable (here) vs Monitor (automation runbook) |

All `raw.githubusercontent.com` URLs in these scripts point to `joelst/AzLighthouse/main/`.

## Pipeline sequence

Run `Start-OnboardingPipeline.ps1` to execute the full ordered sequence. It is idempotent — re-runs skip already-completed steps.

```
1.  Test-MsspPrerequisites
2.  New-LighthouseDelegationPackage
3.  Test-LighthouseDelegation
4.  Test-TenantGovernanceAccess
5.  Set-RsocSubscriptionGovernance
6.  Apply-RsocGovernanceBaseline
7.  Deploy-SentinelWorkspace
8.  Register-OnboardingMonitor
9.  Connect-DefenderPortalSentinel
10. Enable-DataConnectors
11. Deploy-SentinelContent
12. Deploy-DefenderCustomDetections
13. Send-CustomerInstructionPacket
14. Test-EndToEndDeployment
15. Export-MsspEvidencePackage
```

Use `-WhatIfMode` to preview without executing. Use `-SkipSteps` to bypass specific steps.

For private-repo content deployment, pass or configure:
- `-ContentRepoUrl` (for example `https://github.com/joelst/mssp-management`)
- `-ContentRepoBranch` (default `main`)
- `-MsspManagementRepoPath` (local clone path used for Lighthouse templates and repo-readiness checks)

## Async watch scripts

These run alongside the pipeline to monitor approval flows:

| Script | Purpose |
|---|---|
| `Watch-TmnaSubscriptionAcceptance.ps1` | Polls until subscription appears in affiliate tenant |
| `Watch-GdapRelationshipRequests.ps1` | Polls for GDAP relationship acceptance |
| `Watch-CustomerOnboarding.ps1` | General onboarding state watcher |

## Supporting scripts

| Script | Purpose |
|---|---|
| `New-CustomerBillingSubscriptionRequest.ps1` | Cross-tenant subscription creation under customer EA/MCA (in mssp-management repo) |
| `New-TenantGovernanceRelationship.ps1` | Creates GDAP tenant governance relationship |
| `Test-CustomerOnboardingAccount.ps1` | Validates bootstrap account before use |
| `Connect-DefenderPortalSentinel.ps1` | Connects Defender portal to Sentinel (emits MANUAL_ACTION) |
| `Deploy-DefenderCustomDetections.ps1` | Deploys Defender custom detection rules |
| `Invoke-ContentDriftRemediation.ps1` | Re-aligns Sentinel content with baseline manifest |
| `Export-MsspEvidencePackage.ps1` | Packages all evidence JSONs for record-keeping |
| `Update-OnboardingState.ps1` | Manual state file management |
| `Remove-MsspDelegation.ps1` | Off-boarding: removes Lighthouse delegation |

## Config

`Config/` contains JSON schemas and baseline data used by the scripts:

| File | Purpose |
|---|---|
| `customer-intake.schema.json` | Schema for customer config files passed to `-CustomerConfigPath` |
| `content-drift-manifest.schema.json` | Schema for manifest files used by `Invoke-ContentDriftRemediation.ps1` |
| `content-drift-manifest.sample.json` | Starter manifest with sample entries for analytics/workbooks/watchlists/parsers |
| `e2e-acceptance-criteria.json` | Gate criteria and evidence requirements for `Test-EndToEndDeployment.ps1` |
| `onboarding-state.schema.json` | Schema for the per-customer state file |
| `rbac-baseline.json` | RBAC role assignments applied by `Apply-RsocGovernanceBaseline.ps1` |
| `tenant-governance-template.parameters.json` | Parameters for tenant governance ARM template |
| `workload-validation-catalog.json` | Expected workloads checked by `Test-EndToEndDeployment.ps1` |

## Policies

`Policies/` contains deployable Azure Policy JSON files for the customer RSOC governance baseline:
- `deny-unapproved-resource-types-placeholder.json` (custom definition)
- `audit-role-assignment-changes-placeholder.json` (custom definition)
- `require-rsoc-mandatory-tags.json` (custom definition)
- `rsoc-sentinel-policy-initiative-placeholder.json` (initiative + assignment parameters)

`Apply-RsocGovernanceBaseline.ps1` now upserts these definitions and applies the initiative assignment. Keep policy effects in **Audit** during initial rollout before switching to **Deny**.

## Prerequisites

- PowerShell 7.0+
- `Az.Resources`, `Az.ManagedServices`, `Az.Automation`, `Az.OperationalInsights` modules
- Authenticated with `Connect-AzAccount` in the **customer tenant** (or use Lighthouse cross-tenant context)
- For Graph operations: `Connect-MgGraph` with appropriate scopes
- Customer config JSON file matching `Config/customer-intake.schema.json`
- Local clone of private `mssp-management` repository (clean working tree, required content paths present)
- Customer config includes `contentRepo.url` and `contentRepo.branch` (and `contentRepo.pinnedCommitSha` for production ring pinning)

## Current execution blockers (verification snapshot: 2026-07-30)

Static parse validation of the full onboarding chain found script syntax errors in:

- `New-LighthouseDelegationPackage.ps1`
- `Test-LighthouseDelegation.ps1`
- `Test-TenantGovernanceAccess.ps1`
- `Set-RsocSubscriptionGovernance.ps1`
- `Deploy-SentinelWorkspace.ps1`
- `Register-OnboardingMonitor.ps1`
- `Connect-DefenderPortalSentinel.ps1`
- `Enable-DataConnectors.ps1`
- `Deploy-SentinelContent.ps1`
- `Export-MsspEvidencePackage.ps1`

These are pre-existing blockers and must be remediated before the pipeline can run end-to-end in production.
