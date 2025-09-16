# MSSP SOC Azure Onboarding

## Azure Automation

This sets up an automation account with two runbooks. One rotates the service principal credentials and the other collects data connector metrics and sends them to the MSSP tenant via a logic app.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjoelst%2FAzLighthouse%2Fmain%2Fazure-automate%2FautomationAccount.json" target="_blank"><img src="https://aka.ms/deploytoazurebutton"/>

> **IMPORTANT**: After a successful deployment, you must manually enable the runbook experience to use the customized runtime environment.
