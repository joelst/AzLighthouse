#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Generates an HTML and plain-text customer instruction packet for Lighthouse onboarding.
.DESCRIPTION
    Produces a branded HTML instruction guide with 5 steps covering Lighthouse deployment,
    UMI setup, RSOC automation, connector enablement, and go-live validation.
    Also writes a plain-text version (.txt).
#>
param(
    [Parameter(Mandatory)][string]$CustomerConfigPath,
    [string]$OutputPath,
    [switch]$WhatIfMode,
    [string]$EvidenceOutputPath = '.\evidence'
)

 Helpers # 

function Write-Evidence {
    param([string]$Path, [hashtable]$Data)
    $null = New-Item -ItemType Directory -Force -Path $Path
    $file = Join-Path $Path ("instruction-packet-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    Write-Host "  Evidence written: $file" -ForegroundColor DarkGray
    return $file
}

function Write-Status {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

 Load Config # 

Write-Status "Loading customer config: $CustomerConfigPath"
$config = Get-Content $CustomerConfigPath -Raw | ConvertFrom-Json

$customerShortName  = $config.customer.shortName
$customerName       = $config.customer.displayName
$subscriptionId     = $config.deployment.subscriptionId
$dataSources        = $config.dataSources ?? @()

$lighthouseArmUrl   = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/lighthouse/tmna-mssp/lighthouse-offer.json'
$lighthouseUiUrl    = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/lighthouse/tmna-mssp/createUiDefinition.json'
$umiScriptUrl       = 'https://raw.githubusercontent.com/joelst/AzLighthouse/main/identity/umi/deploy-umi.ps1'

# Deploy-to-Azure portal button URL
$deployToAzureUrl   = "https://portal.azure.com/#create/Microsoft.Template/uri/$([uri]::EscapeDataString($lighthouseArmUrl))/uiFormDefinitionUri/$([uri]::EscapeDataString($lighthouseUiUrl))"

if (-not $OutputPath) {
    $OutputPath = ".\customer-packets\$customerShortName-instructions.html"
}
$txtOutputPath = [System.IO.Path]::ChangeExtension($OutputPath, '.txt')

Write-Status "Customer : $customerName ($customerShortName)"
Write-Status "Output   : $OutputPath"

$evidenceData = @{
    scriptName        = 'Send-CustomerInstructionPacket'
    customerShortName = $customerShortName
    outputPath        = $OutputPath
    txtOutputPath     = $txtOutputPath
    status            = 'started'
    timestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
    testRequired      = @(
        'Verify AzLighthouse portal deploy button works with customer subscription before sending',
        'Confirm UMI deploy script URL is accessible from customer Cloud Shell',
        'Review connector list matches customer contract scope'
    )
    checks            = [ordered]@{}
}

 Build Connector List for Step 4 # 

$connectorListHtml = ''
$connectorListTxt  = ''

if ($dataSources -and $dataSources.Count -gt 0) {
    $connectorItems = $dataSources | ForEach-Object {
        $name = if ($_.connectorName) { $_.connectorName } else { $_ }
        "<li><code>$name</code></li>"
    }
    $connectorListHtml = "<ul>`n" + ($connectorItems -join "`n") + "`n</ul>"
    $connectorListTxt  = ($dataSources | ForEach-Object {
 " + (if ($_.connectorName) { $_.connectorName } else { $_ })        "  
    }) -join "`n"
} else {
    $connectorListHtml = @"
<ul>
  <li>Microsoft 365 Defender</li>
  <li>Azure Active Directory (Entra ID)</li>
  <li>Office 365</li>
  <li>Microsoft Defender for Cloud Apps</li>
  <li><em>(Additional connectors as specified in your SOW)</em></li>
</ul>
"@
    $ Microsoft 365 Defender` Azure Active Directory (Entra ID)` Office 365` Microsoft Defender for Cloud Apps"n  n  n  connectorListTxt = "  
}

 Build HTML # 

$generatedDate = Get-Date -Format 'MMMM d, yyyy'

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TMNA  Customer Onboarding Instructions: $customerName</title>MSSP 
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #f4f6f9;
      color: #1a1a2e;
      margin: 0;
      padding: 0;
    }
    header {
      background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
      color: white;
      padding: 32px 48px;
      border-bottom: 4px solid #e94560;
    }
    header .brand { font-size: 13px; text-transform: uppercase; letter-spacing: 2px; color: #a8c0e0; margin-bottom: 8px; }
    header h1 { margin: 0 0 8px 0; font-size: 28px; font-weight: 600; }
    header .subtitle { font-size: 16px; color: #c5d5e8; margin: 0; }
    header .meta { margin-top: 16px; font-size: 13px; color: #8aa5c5; }
    .container { max-width: 860px; margin: 0 auto; padding: 40px 24px; }
    .intro {
      background: white;
      border-left: 4px solid #0f3460;
      border-radius: 6px;
      padding: 20px 24px;
      margin-bottom: 32px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    }
    .intro p { margin: 0; line-height: 1.7; }
    .step {
      background: white;
      border-radius: 8px;
      margin-bottom: 28px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      overflow: hidden;
    }
    .step-header {
      display: flex;
      align-items: center;
      padding: 18px 24px;
      border-bottom: 1px solid #eee;
    }
    .step-number {
      background: #0f3460;
      color: white;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 16px;
      flex-shrink: 0;
      margin-right: 14px;
    }
    .step-header h2 { margin: 0; font-size: 18px; font-weight: 600; color: #0f3460; }
    .step-body { padding: 20px 24px; }
    .step-body p { line-height: 1.7; margin: 0 0 12px 0; }
    .step-body p:last-child { margin-bottom: 0; }
    .step-body ul { padding-left: 24px; margin: 10px 0; }
    .step-body li { line-height: 1.7; margin-bottom: 6px; }
    .step-body code {
      background: #f0f4f8;
      border: 1px solid #d0d9e6;
      border-radius: 4px;
      padding: 2px 6px;
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 13px;
      color: #0f3460;
    }
    .step-body pre {
      background: #0f1b2d;
      color: #a8d8ea;
      border-radius: 6px;
      padding: 16px 20px;
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 13px;
      overflow-x: auto;
      line-height: 1.6;
      margin: 14px 0;
    }
    .deploy-button {
      display: inline-block;
      background: #0078d4;
      color: white !important;
      text-decoration: none;
      padding: 12px 24px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 15px;
      margin: 8px 0;
      transition: background 0.2s;
    }
    .deploy-button:hover { background: #005a9e; }
    .deploy-button img { vertical-align: middle; margin-right: 8px; }
    .badge-rsoc {
      display: inline-block;
      background: #e8f4fd;
      color: #0f3460;
      border: 1px solid #b3d4f0;
      border-radius: 20px;
      padding: 3px 12px;
      font-size: 12px;
      font-weight: 600;
      margin-left: 10px;
    }
    .badge-customer {
      display: inline-block;
      background: #fff4e8;
      color: #8a4f00;
      border: 1px solid #f0c896;
      border-radius: 20px;
      padding: 3px 12px;
      font-size: 12px;
      font-weight: 600;
      margin-left: 10px;
    }
    .note {
      background: #fff8e6;
      border-left: 3px solid #f5a623;
      border-radius: 4px;
      padding: 12px 16px;
      margin: 12px 0;
      font-size: 14px;
      line-height: 1.6;
    }
    .success-bar {
      background: #eaf7f0;
      border-left: 3px solid #27ae60;
      border-radius: 4px;
      padding: 12px 16px;
      margin: 12px 0;
      font-size: 14px;
    }
    footer {
      background: #0f3460;
      color: #8aa5c5;
      text-align: center;
      padding: 24px;
      font-size: 13px;
      margin-top: 32px;
    }
    footer strong { color: #c5d5e8; }
  </style>
</head>
<body>
  <header>
    <div class="brand">TMNA MSSP &bull; Security Operations Center</div>
    <h1>Customer Onboarding Instructions</h1>
    <p class="subtitle">Microsoft Sentinel &amp; Azure Lighthouse Integration Guide</p>
    <div class="meta">
      Prepared for: <strong>$customerName</strong> &nbsp;|&nbsp; Generated: $generatedDate &nbsp;|&nbsp; Subscription: <code style="color:#a8c0e0;background:transparent;border-color:transparent">$subscriptionId</code>
    </div>
  </header>

  <div class="container">

    <div class="intro">
      <p>Welcome to the TMNA MSSP onboarding process. This document guides you and our RSOC team through the five steps required to activate Sentinel-based security monitoring for your environment. Steps marked <span class="badge-customer">Customer Action</span> require action from your team. Steps marked <span class="badge-rsoc">RSOC Action</span> will be completed by our security engineers.</p>
    </div>

    <!-- Step 1 -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">1</div>
        <h2>Deploy Azure Lighthouse Delegation <span class="badge-customer">Customer Action</span></h2>
      </div>
      <div class="step-body">
        <p>Click the button below to deploy the Azure Lighthouse delegation from within your Azure portal. This grants our RSOC team delegated access to your subscription to deploy and manage Microsoft Sentinel on your behalf.</p>
        <p><strong>You must be signed in to the Azure portal as a subscription <u>Owner</u> or <u>User Access Administrator</u>.</strong></p>
        <div class="note">
 This does not give RSOC access to your data. Lighthouse delegation is scoped to the specific resource group and Sentinel workspace only.          
        </div>
        <p>
          <a class="deploy-button" href="$deployToAzureUrl" target="_blank">
            &#9654; Deploy to Azure (Lighthouse)
          </a>
        </p>
        <p>Alternatively, deploy via Azure CLI:</p>
        <pre>az deployment sub create \
  --location eastus \
  --template-uri "$lighthouseArmUrl"</pre>
        <p>After clicking Deploy, accept the terms and click <strong>Create</strong>. Our RSOC team will be notified automatically.</p>
      </div>
    </div>

    <!-- Step 2 -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">2</div>
        <h2>Deploy User-Managed Identity <span class="badge-customer">Customer Action</span></h2>
      </div>
      <div class="step-body">
        <p>Open <strong>Azure Cloud Shell</strong> (PowerShell mode) in your Azure portal and run the following command. This deploys the <code>RSOC-Sentinel-Ingestion-UMI</code> managed identity which the RSOC automation uses to ingest data into Sentinel.</p>
        <pre>Invoke-WebRequest -Uri "$umiScriptUrl" -OutFile deploy-umi.ps1
.\deploy-umi.ps1 -SubscriptionId "$subscriptionId"</pre>
        <p>To open Cloud Shell: In Azure portal, click the <strong>&gt;_</strong> icon in the top navigation bar. Select <strong>PowerShell</strong> when prompted.</p>
        <div class="note">
 If prompted for a storage account, click <strong>Show advanced settings</strong> and select your existing storage, or create a new one in your subscription.          
        </div>
      </div>
    </div>

    <!-- Step 3 -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">3</div>
        <h2>RSOC Deploys Automation &amp; Sentinel <span class="badge-rsoc">RSOC Action</span></h2>
      </div>
      <div class="step-body">
        <div class="success-bar">
 No action required from your team for this step.          
        </div>
        <p>After your Lighthouse delegation (Step 1) and UMI deployment (Step 2) are complete, our RSOC engineers will:</p>
        <ul>
          <li>Deploy the Microsoft Sentinel workspace in your subscription</li>
          <li>Configure the RSOC automation account and monitoring runbooks</li>
          <li>Set up baseline analytics rules, workbooks, and detection content</li>
          <li>Validate the deployment end-to-end</li>
        </ul>
        <p>You will receive a notification from our team when this step is complete (typically within 1 business day).</p>
      </div>
    </div>

    <!-- Step 4 -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">4</div>
        <h2>Enable GA-Required Data Connectors <span class="badge-customer">Customer Action</span></h2>
      </div>
      <div class="step-body">
        <p>Some Microsoft data connectors require consent from a <strong>Global Administrator</strong> in your tenant. After RSOC completes Step 3, your GA admin will need to enable the following connectors in the Sentinel portal:</p>
        $connectorListHtml
        <p><strong>How to enable connectors:</strong></p>
        <ol>
          <li>Sign in to the <a href="https://portal.azure.com" target="_blank">Azure portal</a> as Global Administrator</li>
          <li>Navigate to <strong>Microsoft Sentinel</strong> &rarr; your workspace</li>
          <li>Click <strong>Data connectors</strong> in the left menu</li>
          <li>For each connector above: click the connector name &rarr; click <strong>Open connector page</strong> &rarr; click <strong>Connect</strong></li>
        </ol>
        <div class="note">
 Please complete this step within 5 business days of receiving Step 3 completion notification. Delayed connector enablement may impact your SLA start date.          
        </div>
      </div>
    </div>

    <!-- Step 5 -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">5</div>
        <h2>Validation &amp; Go-Live <span class="badge-rsoc">RSOC Action</span></h2>
      </div>
      <div class="step-body">
        <div class="success-bar">
 Our RSOC team will handle the final validation and contact you to confirm go-live.          
        </div>
        <p>Once all connectors are enabled, our RSOC team will:</p>
        <ul>
          <li>Run end-to-end validation of data ingestion and detection coverage</li>
          <li>Confirm all RSOC analyst groups have correct access</li>
          <li>Send you a <strong>Go-Live Confirmation Report</strong></li>
          <li>Schedule a brief onboarding review call (30 minutes)</li>
        </ul>
        <p>Your official SOC service start date will be recorded as the date of go-live confirmation. You will receive SLA reporting from that date forward.</p>
        <p><strong>Your RSOC contact:</strong> Please reach out to your assigned TMNA MSSP onboarding engineer with any questions during this process.</p>
      </div>
    </div>

  </div>

  <footer>
    <strong>TMNA MSSP &mdash; Security Operations Center</strong><br>
    Offer: TMNA MSSP SOC Services &nbsp;|&nbsp; Generated by automated onboarding system<br>
    This document is confidential and intended for $customerName only.
  </footer>
</body>
</html>
"@

 Build Plain Text Version # 

$txt = @"
================================================================================
TMNA  Customer Onboarding InstructionsMSSP 
Customer  : $customerName ($customerShortName)
Generated : $generatedDate
================================================================================

STEP  Deploy Azure Lighthouse Delegation [CUSTOMER ACTION]1 
---------------------------------------------------------------
Deploy the Lighthouse ARM template from your Azure portal as subscription Owner.

Deploy-to-Azure URL:
  $deployToAzureUrl

Or via Azure CLI:
  az deployment sub create --location eastus --template-uri "$lighthouseArmUrl"


STEP  Deploy User-Managed Identity [CUSTOMER ACTION]2 
---------------------------------------------------------------
Open Azure Cloud Shell (PowerShell) and run:

  Invoke-WebRequest -Uri "$umiScriptUrl" -OutFile deploy-umi.ps1
  .\deploy-umi.ps1 -SubscriptionId "$subscriptionId"


STEP  RSOC Deploys Automation & Sentinel [RSOC ACTION]3 
---------------------------------------------------------------
No action required. RSOC will deploy Sentinel, automation account, and
baseline detection content. You will be notified when complete.


STEP  Enable GA-Required Data Connectors [CUSTOMER ACTION]4 
---------------------------------------------------------------
After RSOC Step 3 notification, a Global Admin must enable:
$connectorListTxt

Steps: Azure portal > Microsoft Sentinel > [workspace] > Data connectors
       > [connector] > Open connector page > Connect


STEP  Validation & Go-Live [RSOC ACTION]5 
---------------------------------------------------------------
RSOC will validate end-to-end, confirm go-live, and send a
Go-Live Confirmation Report. Your SOC SLA starts on go-live date.

================================================================================
TMNA MSSP SOC Services |  For $customerName onlyConfidential 
================================================================================
"@

 Write Files # 

if ($WhatIfMode) {
    Write-Status "[WHATIF] Would write HTML: $OutputPath" -Color Magenta
    Write-Status "[WHATIF] Would write TXT : $txtOutputPath" -Color Magenta
    $evidenceData.status = 'whatif-only'
    $evidenceData.checks['output'] = 'whatif-skipped'
    Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData | Out-Null
    return
}

# Ensure output directory exists
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    $null = New-Item -ItemType Directory -Force -Path $outputDir
}

$html | Set-Content -Path $OutputPath    -Encoding UTF8
Write-Status "HTML written : $OutputPath" -Color Green
$evidenceData.checks['htmlFile'] = $OutputPath

$txt  | Set-Content -Path $txtOutputPath -Encoding UTF8
Write-Status "TXT  written : $txtOutputPath" -Color Green
$evidenceData.checks['txtFile'] = $txtOutputPath

# TEST_REQUIRED: Verify AzLighthouse portal deploy button works with customer subscription before sending
# TEST_REQUIRED: Confirm UMI deploy script URL is accessible from customer Azure Cloud Shell

$evidenceData.status = 'succeeded'
$evidenceFile = Write-Evidence -Path $EvidenceOutputPath -Data $evidenceData

Write-Host ""
Write-Status "=== Send-CustomerInstructionPacket Complete ===" -Color Green
Write-Host "  HTML     : $OutputPath"
Write-Host "  TXT      : $txtOutputPath"
Write-Host "  Evidence : $evidenceFile"
