# Generic Azure Lighthouse delegation

This folder contains the public, customer-neutral Azure Lighthouse bootstrap
template used by the onboarding scripts and Deploy to Azure link.

The template prompts for the managing-tenant ID, managed-service offer text,
delegated group object IDs/display names, and automation principal object ID.
Do not replace those prompts with hardcoded customer values, secrets, or private
operational data.

## Deploy from the portal

Use the Deploy to Azure link below, then provide the values for the managing
tenant and the delegated principals:

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Flighthouse%2Flighthouse-offer1.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Flighthouse%2FcreateUiDefinition.json" target="_blank">
    <img src="https://aka.ms/deploytoazurebutton" alt="Deploy to Azure"/>
</a>

## Private overlays

If a service provider needs customer-specific group IDs, role mappings, or
offer text, keep that overlay in the private execution repository and pass its
local ARM template to `New-LighthouseDelegationPackage.ps1` with
`-LighthouseTemplatePath`. The generic public file remains reusable and
customer-neutral.

For local automation, use the onboarding script with a private parameter file
or `-PromptForLighthouseValues`; the script passes only parameters declared by
the selected ARM template, so older private overlays remain compatible.
