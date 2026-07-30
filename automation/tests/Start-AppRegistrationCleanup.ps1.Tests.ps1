#Requires -Version 7.0
#Requires -Modules Pester

Describe 'Start-AppRegistrationCleanup parameter contract' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Start-AppRegistrationCleanup.ps1'
    $tokens = $null
    $errors = $null
    $script:RunbookAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
      throw "Failed to parse Start-AppRegistrationCleanup.ps1: $($errors[0].Message)"
    }
  }

  It 'Defaults MaxRemovalCount to zero' {
    $param = $script:RunbookAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MaxRemovalCount' }
    $param.DefaultValue.Extent.Text | Should -Be '0'
  }

  It 'Exposes ExecuteDeletion as a switch parameter' {
    $param = $script:RunbookAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ExecuteDeletion' }
    $param.StaticType.FullName | Should -Be 'System.Management.Automation.SwitchParameter'
    $param.DefaultValue | Should -BeNullOrEmpty
  }

  It 'Keeps ProductionAppId empty by default instead of using a placeholder string' {
    $param = $script:RunbookAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ProductionAppId' }
    $param.DefaultValue.Extent.Text | Should -Be '@()'
  }
}

Describe 'ConvertTo-ODataQuotedString' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Start-AppRegistrationCleanup.ps1'
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
      throw "Failed to parse Start-AppRegistrationCleanup.ps1: $($errors[0].Message)"
    }

    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-ODataQuotedString'
      }, $true)

    if (-not $functionAst) {
      throw "Function 'ConvertTo-ODataQuotedString' was not found in Start-AppRegistrationCleanup.ps1."
    }

    Invoke-Expression $functionAst.Extent.Text
  }

  It 'Doubles single quotes for OData filters' {
    ConvertTo-ODataQuotedString -Value "O'Brien" | Should -Be "O''Brien"
  }

  It 'Returns empty strings unchanged' {
    ConvertTo-ODataQuotedString -Value '' | Should -Be ''
  }
}

Describe 'Get-DestructiveRemovalCommandsForAppId' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Start-AppRegistrationCleanup.ps1'
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
      throw "Failed to parse Start-AppRegistrationCleanup.ps1: $($errors[0].Message)"
    }

    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-DestructiveRemovalCommandsForAppId'
      }, $true)

    if (-not $functionAst) {
      throw "Function 'Get-DestructiveRemovalCommandsForAppId' was not found in Start-AppRegistrationCleanup.ps1."
    }

    $convertToAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-ODataQuotedString'
      }, $true)

    if (-not $convertToAst) {
      throw "Function 'ConvertTo-ODataQuotedString' was not found in Start-AppRegistrationCleanup.ps1."
    }

    Invoke-Expression $convertToAst.Extent.Text
    Invoke-Expression $functionAst.Extent.Text

    if (-not (Get-Command Get-MgServicePrincipal -ErrorAction SilentlyContinue)) {
      Set-Item -Path function:Get-MgServicePrincipal -Value { }
    }

    if (-not (Get-Command Get-MgApplication -ErrorAction SilentlyContinue)) {
      Set-Item -Path function:Get-MgApplication -Value { }
    }
  }

  It 'Emits only destructive commands' {
    Set-Item -Path function:Get-MgServicePrincipal -Value {
      @([pscustomobject]@{ Id = 'sp-1' })
    }
    Set-Item -Path function:Get-MgApplication -Value {
      @([pscustomobject]@{ Id = 'app-1' })
    }

    $commands = @(Get-DestructiveRemovalCommandsForAppId -AppId '00000000-0000-0000-0000-000000000123')

    $commands | Should -Contain ' Remove-MgServicePrincipal -ServicePrincipalId sp-1'
    $commands | Should -Contain ' Remove-MgApplication -ApplicationId app-1'
  }
}

Describe 'Test-AppRegistrationExistsByAppId' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Start-AppRegistrationCleanup.ps1'
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
      throw "Failed to parse Start-AppRegistrationCleanup.ps1: $($errors[0].Message)"
    }

    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-AppRegistrationExistsByAppId'
      }, $true)

    if (-not $functionAst) {
      throw "Function 'Test-AppRegistrationExistsByAppId' was not found in Start-AppRegistrationCleanup.ps1."
    }

    $convertToAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-ODataQuotedString'
      }, $true)

    if (-not $convertToAst) {
      throw "Function 'ConvertTo-ODataQuotedString' was not found in Start-AppRegistrationCleanup.ps1."
    }

    Invoke-Expression $convertToAst.Extent.Text
    Invoke-Expression $functionAst.Extent.Text

    if (-not (Get-Command Get-MgServicePrincipal -ErrorAction SilentlyContinue)) {
      Set-Item -Path function:Get-MgServicePrincipal -Value { }
    }

    if (-not (Get-Command Get-MgApplication -ErrorAction SilentlyContinue)) {
      Set-Item -Path function:Get-MgApplication -Value { }
    }
  }

  It 'Returns true when either an application or service principal exists' {
    Set-Item -Path function:Get-MgServicePrincipal -Value { @() }
    Set-Item -Path function:Get-MgApplication -Value {
      @([pscustomobject]@{ Id = 'app-1' })
    }

    Test-AppRegistrationExistsByAppId -AppId '00000000-0000-0000-0000-000000000123' | Should -BeTrue
  }

  It 'Throws when Graph query fails instead of silently reporting missing' {
    Set-Item -Path function:Get-MgServicePrincipal -Value { throw 'service principal query failed' }
    Set-Item -Path function:Get-MgApplication -Value { @() }

    try {
      Test-AppRegistrationExistsByAppId -AppId '00000000-0000-0000-0000-000000000123'
      throw 'Expected Test-AppRegistrationExistsByAppId to throw.'
    } catch {
      $_.Exception.Message | Should -Match 'Failed to query service principal existence for appId .*service principal query failed'
    }
  }
}

Describe 'Wait-AppRegistrationDeletionByAppId' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Start-AppRegistrationCleanup.ps1'
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)

    if ($errors.Count -gt 0) {
      throw "Failed to parse Start-AppRegistrationCleanup.ps1: $($errors[0].Message)"
    }

    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Wait-AppRegistrationDeletionByAppId'
      }, $true)

    if (-not $functionAst) {
      throw "Function 'Wait-AppRegistrationDeletionByAppId' was not found in Start-AppRegistrationCleanup.ps1."
    }

    Invoke-Expression $functionAst.Extent.Text

    if (-not (Get-Command Test-AppRegistrationExistsByAppId -ErrorAction SilentlyContinue)) {
      Set-Item -Path function:Test-AppRegistrationExistsByAppId -Value { }
    }

    if (-not (Get-Command Start-Sleep -ErrorAction SilentlyContinue)) {
      Set-Item -Path function:Start-Sleep -Value { }
    }
  }

  It 'Returns true when the deletion verification helper reports the app is gone' {
    Set-Item -Path function:Test-AppRegistrationExistsByAppId -Value { $false }
    Set-Item -Path function:Start-Sleep -Value { }

    Wait-AppRegistrationDeletionByAppId -AppId '00000000-0000-0000-0000-000000000123' | Should -BeTrue
  }

  It 'Throws when deletion verification cannot query Graph' {
    Set-Item -Path function:Test-AppRegistrationExistsByAppId -Value { throw 'verification query failed' }
    Set-Item -Path function:Start-Sleep -Value { }

    { Wait-AppRegistrationDeletionByAppId -AppId '00000000-0000-0000-0000-000000000123' } | Should -Throw 'verification query failed'
  }
}
