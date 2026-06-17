#Requires -Version 7.0

BeforeAll {
  $templatePath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'automationAccount.json'
  $templateRaw = Get-Content -Path $templatePath -Raw
  $template = $templateRaw | ConvertFrom-Json -Depth 100

  $runbookResources = @(
    $template.resources |
      Where-Object { $_.type -eq 'Microsoft.Automation/automationAccounts/runbooks' }
  )

  $runtimeResources = @(
    $template.resources |
      Where-Object { $_.type -eq 'Microsoft.Automation/automationAccounts/runtimeEnvironments' }
  )
}

Describe 'automationAccount.json runtime parameter contract' {
  It 'Defines runtimeEnvironmentName and runtimeVersion parameters' {
    $template.parameters.PSObject.Properties.Name | Should -Contain 'runtimeEnvironmentName'
    $template.parameters.PSObject.Properties.Name | Should -Contain 'runtimeVersion'
  }

  It 'Defines runtime parameters with expected types and defaults' {
    $template.parameters.runtimeEnvironmentName.type | Should -Be 'string'
    $template.parameters.runtimeEnvironmentName.defaultValue | Should -Be 'PowerShell_74_SOC'

    $template.parameters.runtimeVersion.type | Should -Be 'string'
    $template.parameters.runtimeVersion.defaultValue | Should -Be '7.4'
  }

  It 'Maps pwshRuntimeName variable to runtimeEnvironmentName parameter' {
    $template.variables.pwshRuntimeName | Should -Be "[parameters('runtimeEnvironmentName')]"
  }
}

Describe 'automationAccount.json runtime environment resource wiring' {
  It 'Creates exactly one runtime environment resource' {
    $runtimeResources.Count | Should -Be 1
  }

  It 'Uses the automation account location parameter for runtime environment location' {
    $runtimeResources[0].location | Should -Be "[parameters('location')]"
  }

  It 'Configures runtime language and version from template inputs' {
    $runtime = $runtimeResources[0]

    $runtime.properties.runtime.language | Should -Be 'PowerShell'
    $runtime.properties.runtime.version | Should -Be "[parameters('runtimeVersion')]"

    # Name is scoped to automation account + runtime variable-backed name.
    $runtime.name | Should -Be "[format('{0}/{1}', parameters('automationAccountName'), variables('pwshRuntimeName'))]"
  }
}

Describe 'automationAccount.json runbook runtime binding' {
  It 'Deploys runbook resources' {
    $runbookResources.Count | Should -BeGreaterThan 0
  }

  It 'Uses the automation account location parameter for every runbook location' {
    foreach ($runbook in $runbookResources) {
      $runbook.location | Should -Be "[parameters('location')]"
    }
  }

  It 'Binds every runbook to the expected runtime environment variable' {
    foreach ($runbook in $runbookResources) {
      $runbook.properties.runtimeEnvironment | Should -Be "[variables('pwshRuntimeName')]"
    }
  }

  It 'Ensures every runbook depends on the runtime environment resource' {
    foreach ($runbook in $runbookResources) {
      $runbook.dependsOn | Should -Contain "[resourceId('Microsoft.Automation/automationAccounts/runtimeEnvironments', parameters('automationAccountName'), variables('pwshRuntimeName'))]"
    }
  }
}
