# TMNA MSSP SOC Lighthouse Template

This is the **TMNA-specific** Azure Lighthouse delegation template. It contains the full set of TMNA RSOC security group principal IDs and role assignments. Do **not** use the generic `../lighthouse-offer1.json` template for TMNA deployments.

## Groups delegated

| Group | Principal ID | Roles |
|---|---|---|
| RSOC_Sentinel_Admin | c1f4a285-... | Managed Services Delete, Contributor (breakglass/PIM) |
| RSOC_Sentinel_Onboarding | cbe65060-... | Connected Machine Admin, Monitoring Contributor, Log Analytics Contributor, Sentinel Contributor, Managed App Contributor, Support Contributor, Storage Contributor, User Access Admin (delegated) |
| RSOC_Sentinel_Threat_Detection_Engineering_Tier1 | 440ba293-... | Sentinel Contributor, Log Analytics Contributor, Logic App Contributor, Support Contributor |
| RSOC_Sentinel_Threat_Detection_Engineering_Tier2 | d4e11e0e-... | Sentinel Contributor, Log Analytics Contributor, Logic App Contributor, Support Contributor, Contributor |
| RSOC_Sentinel_Security_Engineers | 4fd628b1-... | Logic App Contributor, Sentinel Contributor, Log Analytics Contributor |
| RSOC_Sentinel_Red_Team | a6539c63-... | Sentinel Reader |
| RSOC_Sentinel_Incident_Response | ef18438b-... | Sentinel Responder, Sentinel Playbook Operator, Log Analytics Contributor |
| RSOC_Sentinel_Incident_Detection_Tier1 | 0d593b30-... | Sentinel Responder, Sentinel Playbook Operator |
| RSOC_Sentinel_Incident_Detection_Tier2 | fe773eea-... | Sentinel Responder, Sentinel Playbook Operator, Log Analytics Contributor |
| RSOC_Sentinel_Incident_Detection_Tier3 | 125fe7d3-... | Sentinel Contributor, Sentinel Playbook Operator, Log Analytics Contributor |
| RSOC_Sentinel_Data_Loss_Prevention | e920125d-... | Sentinel Responder, Sentinel Playbook Operator, Sentinel Contributor |
| RSOC_Sentinel_Cyber_Threat_Intelligence | a1d8aba5-... | Sentinel Reader |
| RSOC_Sentinel_Threat_Hunting_Operations | 96d5dd3a-... | Sentinel Contributor, Logic App Contributor, Log Analytics Contributor, Support Contributor |
| RSOC_Sentinel_Cyber_Analytics_Platform | 59855648-... | Monitoring Contributor, Log Analytics Contributor, Sentinel Reader |
| RSOC_Sentinel_Reader | d99111b2-... | Sentinel Reader, Log Analytics Reader |

## Delegated role assignment rights

`RSOC_Sentinel_Onboarding` holds `User Access Administrator` with `delegatedRoleDefinitionIds` scoped to:
- Monitoring Metrics Publisher — for the Logstash ingest service principal
- Key Vault Administrator — for secret access setup
- Key Vault Secrets User — for UMI credential reads

## Deploy

The `onboarding/New-LighthouseDelegationPackage.ps1` script deploys this template. The RSOC engineer provides the TMNA managing tenant ID at runtime.

Portal deploy button (for manual/customer-run deployments):

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Flighthouse%2Ftmna-mssp%2Flighthouse-offer.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Flighthouse%2Ftmna-mssp%2FcreateUiDefinition.json" target="_blank">
    <img src="https://aka.ms/deploytoazurebutton"/>
</a>
