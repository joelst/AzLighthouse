#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
  $scriptPath = Join-Path $PSScriptRoot '..\Deploy-AutomationTemplate.ps1'
  $script:ScriptContent = Get-Content -Path $scriptPath -Raw
}

Describe 'Deploy-AutomationTemplate cleanup runbook wiring' {
  It 'Includes the cleanup runbook in the local upload map' {
    $script:ScriptContent | Should -Match "NameParameter = 'cleanupRunbookName'; FileName = 'Start-AppRegistrationCleanup\.ps1'"
  }

  It 'Verifies the cleanup runbook after deployment' {
    $script:ScriptContent | Should -Match "'cleanupRunbookName'"
  }
}
