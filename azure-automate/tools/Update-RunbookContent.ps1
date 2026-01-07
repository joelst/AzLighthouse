<#

DISCLAIMER: This script is provided "as-is" without warranty of any kind.

.SYNOPSIS
    Updates the content of an Azure Automation runbook from a local file.
.DESCRIPTION
    This script updates the content of a specified Azure Automation runbook
    using the content from a local PowerShell script file.

.PARAMETER AutomationAccountName
    The name of the Azure Automation Account.
.PARAMETER SubscriptionId
    The Subscription ID where the Automation Account resides.
.PARAMETER ResourceGroupName
    The name of the Resource Group containing the Automation Account.
.PARAMETER RunbookName
    The name of the runbook to update.
.PARAMETER LocalFilePath
    The local file path of the PowerShell script to upload as the runbook content.
.PARAMETER Publish
    If specified, publishes the runbook after importing the new content.
.PARAMETER RunAfter
    If specified, runs the runbook after updating it.
    Provide a DateTime value.
    If the time is in the future, the script will wait until that time and then start
    the runbook.
    If the time is in the past (or now), the script will start the runbook immediately.

.EXAMPLE
    .\Update-RunbookContent.ps1 -AutomationAccountName "MyAutomationAccount" `
        -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-automation" `
        -RunbookName "Get-DataConnectorStatus" `
        -LocalFilePath ".\Get-DataConnectorStatus.ps1" `
        -Publish

.EXAMPLE
    # Dry-run (no changes)
      .\Update-RunbookContent.ps1 -AutomationAccountName "MyAutomationAccount" `
      -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-automation" `
        -RunbookName "Get-DataConnectorStatus" `
        -LocalFilePath ".\Get-DataConnectorStatus.ps1" `
        -WhatIf

.NOTES
    Requires Az PowerShell modules: Az.Accounts and Az.Automation.
    This script uses Import-AzAutomationRunbook with -Force to overwrite the runbook definition.

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
            [Guid]::TryParse($_, [ref]([Guid]::Empty))
        })]

    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunbookName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LocalFilePath,

    [Parameter()]
    [switch]$Publish,

    [Parameter()]
    [switch]$RecreateAsPowerShell,

    [Parameter()]
    [datetime]$RunAfter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AzModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName
    )

    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        $installHint = 'Install it with: Install-Module {0} -Scope CurrentUser' -f $ModuleName
        throw ("Required module '{0}' is not installed. {1}" -f $ModuleName, $installHint)
    }

    Import-Module -Name $ModuleName -ErrorAction Stop | Out-Null
}

function Assert-AzAuthenticated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $context = $null
    try {
        $context = Get-AzContext -ErrorAction Stop
    }
    catch {
        throw 'No Az context detected. Authenticate via Connect-AzAccount.'
    }

    if (-not $context.Subscription -or -not $context.Subscription.Id) {
        throw 'Az context is missing subscription details. Re-authenticate via Connect-AzAccount and Set-AzContext.'
    }

    if ($context.Subscription.Id -ne $SubscriptionId) {
        throw ("Az context subscription '{0}' does not match requested SubscriptionId '{1}'." -f $context.Subscription.Id, $SubscriptionId)
    }

    try {
        # Force a token acquisition to catch expired/invalid contexts early.
        $null = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
    }
    catch {
        throw ('Azure authentication appears invalid or expired: {0}. Re-authenticate via Connect-AzAccount.' -f $_.Exception.Message)
    }
}

function Set-AzLoginAndContext {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $currentContext = $null
    try {
        $currentContext = Get-AzContext -ErrorAction Stop
    }
    catch {
        $currentContext = $null
    }

    if (-not $currentContext) {
        # Authentication and context selection do not modify Azure resources. Avoid confirmation prompts.
        Write-Verbose 'No Az context detected. Prompting for login.'
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }

    Write-Verbose "Setting Az context to subscription '$SubscriptionId'."
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

    Assert-AzAuthenticated -SubscriptionId $SubscriptionId
}

function Resolve-ExistingFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "LocalFilePath does not exist or is not a file: $Path"
    }

    $resolved = (Resolve-Path -Path $Path -ErrorAction Stop).Path
    return $resolved
}

function Get-RunbookArmInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AutomationAccountName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunbookName
    )

    $encodedSub = [System.Uri]::EscapeDataString($SubscriptionId)
    $encodedRg = [System.Uri]::EscapeDataString($ResourceGroupName)
    $encodedAa = [System.Uri]::EscapeDataString($AutomationAccountName)
    $encodedRunbook = [System.Uri]::EscapeDataString($RunbookName)

    $apiVersions = @(
        '2023-11-01',
        '2022-08-08',
        '2019-06-01'
    )

    foreach ($apiVersion in $apiVersions) {
        $path = (
            '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Automation/automationAccounts/{2}/runbooks/{3}?api-version={4}' -f
            $encodedSub,
            $encodedRg,
            $encodedAa,
            $encodedRunbook,
            $apiVersion
        )

        try {
            $response = Invoke-AzRestMethod -Method Get -Path $path -ErrorAction Stop
        }
        catch {
            Write-Verbose ("ARM runbook lookup failed (apiVersion={0}) for '{1}': {2}" -f $apiVersion, $RunbookName, $_.Exception.Message)
            continue
        }

        if (-not $response -or -not $response.Content) {
            continue
        }
        $payload = $response.Content | ConvertFrom-Json -Depth 32
        $props = $payload.properties
        if (-not $props) {
            continue
        }

        $runtime = $null
        foreach ($candidate in @('runtime', 'runtimeVersion', 'runtimeEnvironment')) {
            if ($props.PSObject.Properties.Name -contains $candidate) {
                $runtime = $props.$candidate
                if ($runtime) { break }
            }
        }

        return [pscustomobject]@{
            ArmRunbookType = if ($props.PSObject.Properties.Name -contains 'runbookType') { $props.runbookType } else { $null }
            ArmRuntime     = $runtime
        }
    }

    return $null
}

function Set-RunbookDraftContentViaArm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AutomationAccountName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunbookName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$LocalFilePath
    )

    $encodedSub = [System.Uri]::EscapeDataString($SubscriptionId)
    $encodedRg = [System.Uri]::EscapeDataString($ResourceGroupName)
    $encodedAa = [System.Uri]::EscapeDataString($AutomationAccountName)
    $encodedRunbook = [System.Uri]::EscapeDataString($RunbookName)

    # Draft content endpoint. Use the active Azure environment's ARM endpoint (supports sovereign clouds).
    $context = Get-AzContext -ErrorAction Stop
    $rmUrl = $context.Environment.ResourceManagerUrl
    if ([string]::IsNullOrWhiteSpace($rmUrl)) {
        $rmUrl = 'https://management.azure.com/'
    }
    $rmUrl = $rmUrl.TrimEnd('/')

    # Using a stable API version for this route.
    $apiVersion = '2019-06-01'
    $uri = (
        '{0}/subscriptions/{1}/resourceGroups/{2}/providers/Microsoft.Automation/automationAccounts/{3}/runbooks/{4}/draft/content?api-version={5}' -f
        $rmUrl,
        $encodedSub,
        $encodedRg,
        $encodedAa,
        $encodedRunbook,
        $apiVersion
    )

    $content = [System.IO.File]::ReadAllText($LocalFilePath)

    function Get-JwtPayload {
        param([Parameter(Mandatory)][string]$Jwt)

        try {
            Add-Type -AssemblyName 'System.IdentityModel.Tokens.Jwt' -ErrorAction SilentlyContinue | Out-Null
            $handler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
            $token = $handler.ReadJwtToken($Jwt)
            if (-not $token) { return $null }
            $claims = @{}
            foreach ($claim in $token.Claims) {
                if (-not $claims.ContainsKey($claim.Type)) {
                    $claims[$claim.Type] = $claim.Value
                }
            }
            return [pscustomobject]$claims
        }
        catch {
            return $null
        }
    }

    function Invoke-PutWithToken {
        param(
            [Parameter(Mandatory)][string]$ResourceUrl,
            [Parameter(Mandatory)][string]$Uri,
            [Parameter(Mandatory)][string]$Body
        )

        $tokenObj = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
        $tokenValue = $tokenObj.Token
        if ($null -eq $tokenValue) {
            throw 'Get-AzAccessToken returned a null Token value.'
        }

        # Some Az.Accounts versions may return the Token as a SecureString. Convert it before use.
        if ($tokenValue -is [SecureString]) {
            Write-Verbose 'Get-AzAccessToken returned Token as SecureString; converting to plain text for Authorization header.'
            $jwt = [System.Net.NetworkCredential]::new('', $tokenValue).Password
        }
        else {
            $jwt = [string]$tokenValue
        }

        if ([string]::IsNullOrWhiteSpace($jwt) -or $jwt -notmatch '^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$') {
            $typeName = $tokenValue.GetType().FullName
            Write-Verbose ("Token does not look like a JWT. TokenType='{0}' TokenLength='{1}'" -f $typeName, ($jwt | Measure-Object -Character).Characters)
        }
        $claims = Get-JwtPayload -Jwt $jwt
        if ($claims) {
            $aud = $null
            $tid = $null
            if ($claims.PSObject.Properties.Name -contains 'aud') { $aud = $claims.aud }
            if ($claims.PSObject.Properties.Name -contains 'tid') { $tid = $claims.tid }
            if ($aud -or $tid) {
                Write-Verbose ("Using token aud='{0}' tid='{1}'" -f $aud, $tid)
            }
        }

        $headers = @{
            Authorization = "Bearer $jwt"
            Accept        = 'application/json'
        }

        try {
            Invoke-RestMethod -Method Put -Uri $Uri -Headers $headers -Body $Body -ContentType 'text/plain; charset=utf-8' -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            $response = $null
            if ($_.Exception.PSObject.Properties.Name -contains 'Response') {
                $response = $_.Exception.Response
            }
            $statusCode = $null
            if ($response -and $response.StatusCode) { $statusCode = [int]$response.StatusCode }
            elseif ($_.Exception.PSObject.Properties.Name -contains 'StatusCode') { $statusCode = [int]$_.Exception.StatusCode }

            $bodySnippet = $null
            if ($response -and $response.PSObject.Properties.Name -contains 'Content') {
                try {
                    $raw = $response.Content
                    if ($raw -is [System.Net.Http.HttpContent]) { $raw = $raw.ReadAsStringAsync().GetAwaiter().GetResult() }
                    if ($raw) {
                        $text = $raw.ToString().Trim()
                        if ($text.Length -gt 512) { $text = $text.Substring(0, 512) + '...' }
                        $bodySnippet = $text
                    }
                }
                catch { }
            }

            if (-not $bodySnippet -and $_.ErrorDetails -and $_.ErrorDetails.Message) {
                try {
                    $text = $_.ErrorDetails.Message.Trim()
                    if ($text.Length -gt 512) { $text = $text.Substring(0, 512) + '...' }
                    $bodySnippet = $text
                }
                catch { }
            }

            $statusLabel = if ($statusCode) { $statusCode } else { 'unknown' }
            $snippetLabel = if ($bodySnippet) { " ResponseBody: $bodySnippet" } else { '' }
            Write-Verbose ("PUT draft content failed (resourceUrl='{0}') status={1}.{2}" -f $ResourceUrl, $statusLabel, $snippetLabel)
            throw
        }
    }

    # Use the environment-specific ARM audience first; if it fails with 401, retry with classic management audience.
    try {
        $resourceUrl = $context.Environment.ResourceManagerUrl
        if ([string]::IsNullOrWhiteSpace($resourceUrl)) {
            $resourceUrl = 'https://management.azure.com/'
        }
        $null = Invoke-PutWithToken -ResourceUrl $resourceUrl -Uri $uri -Body $content
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '(?i)\b401\b|unauthorized') {
            Write-Verbose 'Retrying draft content update with management.core.windows.net token audience.'
            $null = Invoke-PutWithToken -ResourceUrl 'https://management.core.windows.net/' -Uri $uri -Body $content
        }
        else {
            throw
        }
    }
}

function Get-ExistingRunbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AutomationAccountName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RunbookName
    )

    try {
        return Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -ErrorAction Stop
    }
    catch {
        # Only treat "not found" as missing; all other errors should surface (permissions, bad RG/AA, etc.).
        $msg = $_.Exception.Message
        if ($msg -match '(?i)not\s*found|resource\s*not\s*found|404') {
            return $null
        }
        throw ("Failed to read existing runbook '{0}' in AutomationAccount='{1}' ResourceGroup='{2}': {3}" -f $RunbookName, $AutomationAccountName, $ResourceGroupName, $msg)
    }
}

function Resolve-ImportRunbookType {
    [CmdletBinding()]
    param(
        [Parameter()][object]$ExistingRunbook,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$LocalFilePath,
        [switch]$AllowRecreateAsPowerShell
    )

    # Default type for .ps1 content.
    $defaultType = 'PowerShell'

    if (-not $ExistingRunbook) {
        return $defaultType
    }

    $existingType = $ExistingRunbook.RunbookType
    if ([string]::IsNullOrWhiteSpace($existingType)) {
        return $defaultType
    }

    # Azure Automation will reject changing the runbook kind; match it where it makes sense.
    switch ($existingType) {
        'PowerShell' { return 'PowerShell' }
        'PowerShellWorkflow' { return 'PowerShellWorkflow' }
        default {
            if ($AllowRecreateAsPowerShell.IsPresent) {
                return $defaultType
            }
            $ext = [System.IO.Path]::GetExtension($LocalFilePath)
            throw (
                "Runbook '$($ExistingRunbook.Name)' already exists with type '$existingType'. " +
                'Updating a runbook with a different kind is not allowed. ' +
                "This script can only import PowerShell/PowerShellWorkflow from a '$ext' file. " +
                "Create a new PowerShell runbook (recommended) or use the appropriate tooling for '$existingType'."
            )
        }
    }
}

function Get-OptionalPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()][object]$InputObject,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject.PSObject.Properties.Name -contains $Name) {
        return $InputObject.$Name
    }

    return $null
}

Assert-AzModule -ModuleName 'Az.Accounts'
Assert-AzModule -ModuleName 'Az.Automation'

$resolvedLocalFilePath = Resolve-ExistingFilePath -Path $LocalFilePath
$extension = [System.IO.Path]::GetExtension($resolvedLocalFilePath)
if ($extension -ne '.ps1') {
    Write-Verbose "Local file does not have a .ps1 extension: $resolvedLocalFilePath"
}

Set-AzLoginAndContext -SubscriptionId $SubscriptionId

$existingRunbook = Get-ExistingRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName
$importType = Resolve-ImportRunbookType -ExistingRunbook $existingRunbook -LocalFilePath $resolvedLocalFilePath -AllowRecreateAsPowerShell:$RecreateAsPowerShell

$armInfo = Get-RunbookArmInfo -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName
if ($armInfo) {
    $armType = if ($armInfo.ArmRunbookType) { $armInfo.ArmRunbookType } else { '<null>' }
    $armRuntime = if ($armInfo.ArmRuntime) { $armInfo.ArmRuntime } else { '<null>' }
    Write-Verbose ("ARM runbook properties: runbookType='{0}' runtime='{1}'" -f $armType, $armRuntime)
}

if ($existingRunbook) {
    Write-Verbose ("Existing runbook type is '{0}'. Import type will be '{1}'." -f $existingRunbook.RunbookType, $importType)
}
else {
    Write-Verbose ("Existing runbook '{0}' was not found (or not readable). Import type will be '{1}'." -f $RunbookName, $importType)
}

$targetDescription = "AutomationAccount='$AutomationAccountName' ResourceGroup='$ResourceGroupName' Runbook='$RunbookName'"
if ($PSCmdlet.ShouldProcess($targetDescription, "Import runbook content from '$resolvedLocalFilePath'")) {
    try {
        Write-Verbose "Importing runbook '$RunbookName' into '$AutomationAccountName' (RG: '$ResourceGroupName')."

        if ($existingRunbook -and $RecreateAsPowerShell.IsPresent) {
            $existingType = $existingRunbook.RunbookType
            if ($existingType -and $existingType -ne $importType) {
                $recreateTarget = "AutomationAccount='$AutomationAccountName' ResourceGroup='$ResourceGroupName' Runbook='$RunbookName'"
                if ($PSCmdlet.ShouldProcess($recreateTarget, "Recreate runbook as type '$importType' (delete and create)")) {
                    Remove-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -Force -ErrorAction Stop
                    New-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -Type $importType -ErrorAction Stop | Out-Null
                    $existingRunbook = Get-ExistingRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName
                }
            }
        }

        $importParams = @{
            ResourceGroupName     = $ResourceGroupName
            AutomationAccountName = $AutomationAccountName
            Name                  = $RunbookName
            Path                  = $resolvedLocalFilePath
            Type                  = $importType
            Force                 = $true
            ErrorAction           = 'Stop'
        }

        if ($Publish.IsPresent) {
            $importParams['Published'] = $true
        }

        $runbook = $null
        try {
            $runbook = Import-AzAutomationRunbook @importParams
        }
        catch {
            $importError = $_
            $importMessage = $importError.Exception.Message
            if ($importMessage -match '(?i)different\s+runbook\s+kind') {
                Write-Warning 'Import-AzAutomationRunbook failed due to runbook kind mismatch. Attempting ARM draft content update fallback.'
                Set-RunbookDraftContentViaArm -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName -LocalFilePath $resolvedLocalFilePath
                if ($Publish.IsPresent) {
                    Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -ErrorAction Stop | Out-Null
                }
                $runbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -ErrorAction Stop
            }
            else {
                throw
            }
        }

        $result = [PSCustomObject]@{
            AutomationAccountName = $AutomationAccountName
            ResourceGroupName     = $ResourceGroupName
            RunbookName           = $RunbookName
            LocalFilePath         = $resolvedLocalFilePath
            Published             = [bool]$Publish
            ExistingRunbookType   = if ($existingRunbook) { $existingRunbook.RunbookType } else { $null }
            ImportedRunbookType   = $importType
            ProvisioningState     = Get-OptionalPropertyValue -InputObject $runbook -Name 'ProvisioningState'
            LastModifiedTime      = Get-OptionalPropertyValue -InputObject $runbook -Name 'LastModifiedTime'
            JobId                 = $null
            JobStartTime          = $null
            RunAfter              = $RunAfter

        }

        if ($null -ne $RunAfter) {
            if (-not $Publish.IsPresent) {
                Write-Warning 'RunAfter was specified without -Publish. Azure Automation jobs typically run the published version,
                 so your job may not use the newly imported draft content.'
            }

            $delay = $RunAfter - (Get-Date)
            if ($delay.TotalSeconds -gt 0) {
                Write-Verbose ("Waiting {0:N0} seconds until RunAfter time '{1:o}'." -f $delay.TotalSeconds, $RunAfter)
                Start-Sleep -Seconds ([int][Math]::Ceiling($delay.TotalSeconds))
            }

            if ($PSCmdlet.ShouldProcess($targetDescription, 'Start runbook')) {
                $job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName -ErrorAction Stop
                $result.JobId = $job.JobId
                $result.JobStartTime = Get-Date
            }
        }

        Write-Output $result
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match '(?i)different\s+runbook\s+kind') {
            $extra = $null
            if ($armInfo -and $armInfo.ArmRuntime) {
                $extra = "Existing runbook runtime appears to be '$($armInfo.ArmRuntime)'. " +
                'If this is a PowerShell 7.x runbook, Import-AzAutomationRunbook may fail because it cannot set runtime. ' +
                'Options: (1) recreate as classic PowerShell runbook using -RecreateAsPowerShell, or (2) update via portal/source control for PS7 runbooks.'
            }
            elseif ($armInfo -and $armInfo.ArmRunbookType) {
                $extra = "ARM reports runbookType='$($armInfo.ArmRunbookType)'. Import type was '$importType'."
            }
            if ($extra) {
                Write-Error "Failed to update runbook content. $message $extra"
            }
            else {
                Write-Error "Failed to update runbook content. $message"
            }
        }
        else {
            Write-Error "Failed to update runbook content. $message"
        }
        throw
    }
}

