#Requires -Version 7.0
#Requires -Modules Pester

BeforeAll {
  $uiPath = Join-Path $PSScriptRoot '..\createUiDefinition.json'
  $uiRaw = Get-Content -Path $uiPath -Raw
  $script:UiDefinition = $uiRaw | ConvertFrom-Json -Depth 100
}

Describe 'createUiDefinition cleanup runbook wiring' {
  It 'Exposes the cleanup runbook name and content URI fields in the runbooks step' {
    $runbooksStep = $script:UiDefinition.parameters.steps | Where-Object { $_.name -eq 'runbooks' }
    $runbooksStep.elements.name | Should -Contain 'cleanupRunbookNameText'
    $runbooksStep.elements.name | Should -Contain 'cleanupRunbookContentUri'
    $runbooksStep.elements.name | Should -Contain 'searchJobRunbookNameText'
    $runbooksStep.elements.name | Should -Contain 'searchJobRunbookContentUri'
  }

  It 'Maps cleanup runbook values into the deployment outputs' {
    $outputs = $script:UiDefinition.parameters.outputs
    $outputs.PSObject.Properties.Name | Should -Contain 'cleanupRunbookName'
    $outputs.PSObject.Properties.Name | Should -Contain 'cleanupRunbookContentUri'
    $outputs.PSObject.Properties.Name | Should -Contain 'searchJobRunbookName'
    $outputs.PSObject.Properties.Name | Should -Contain 'searchJobRunbookContentUri'
    $outputs.cleanupRunbookName | Should -Be 'Start-AppRegistrationCleanup'
    $outputs.searchJobRunbookName | Should -Be 'Invoke-AzSentinelSearchJob'
  }
}
