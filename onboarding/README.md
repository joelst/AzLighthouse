# MSSP Customer Onboarding Pipeline

This folder contains the RSOC engineer-run deployment scripts for onboarding affiliate tenants into the TMNA MSSP SOC service. These scripts are run **locally or from Azure Cloud Shell** by the RSOC onboarding engineer — they are not Azure Automation runbooks.

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
1. Test-MsspPrerequisites            → validates caller permissions and module prereqs
2. New-LighthouseDelegationPackage   → deploys Lighthouse delegation; lifecycle: WaitingForLighthouseAcceptance
3. Apply-RsocGovernanceBaseline      → applies RBAC baseline and policy initiative; lifecycle: ReadyForDeployment
4. Deploy-SentinelWorkspace          → deploys Log Analytics + Sentinel; lifecycle: Deploying
5. Register-OnboardingMonitor        → deploys Automation Account with all runbooks
6. Enable-DataConnectors             → enables connectors; lifecycle: WaitingForConnectorConsent
7. Deploy-SentinelContent            → deploys analytics rules and content; lifecycle: ValidatingDeployment
8. Send-CustomerInstructionPacket    → generates and sends customer HTML/text instruction packet
9. Test-EndToEndDeployment           → end-to-end validation; lifecycle: CustomerValidation
```

Use `-WhatIfMode` to preview without executing. Use `-SkipSteps` to bypass specific steps.

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
| `New-TmnaBillingSubscriptionRequest.ps1` | Cross-tenant subscription creation under TMNA EA/MCA |
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
| `onboarding-state.schema.json` | Schema for the per-customer state file |
| `rbac-baseline.json` | RBAC role assignments applied by `Apply-RsocGovernanceBaseline.ps1` |
| `tenant-governance-template.parameters.json` | Parameters for tenant governance ARM template |
| `workload-validation-catalog.json` | Expected workloads checked by `Test-EndToEndDeployment.ps1` |

## Policies

`Policies/` contains Azure Policy JSON files. Files named `*-placeholder.json` are stubs that require real policy definitions before production use. See `MANUAL_ACTION` notes in `Apply-RsocGovernanceBaseline.ps1`.

## Prerequisites

- PowerShell 7.0+
- `Az.Resources`, `Az.ManagedServices`, `Az.Automation`, `Az.OperationalInsights` modules
- Authenticated with `Connect-AzAccount` in the **customer tenant** (or use Lighthouse cross-tenant context)
- For Graph operations: `Connect-MgGraph` with appropriate scopes
- Customer config JSON file matching `Config/customer-intake.schema.json`
