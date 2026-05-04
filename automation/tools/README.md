
# Tools

Small helper scripts intended for maintainers/operators of this repo.

## Scripts

### Update-RunbookContent.ps1

Updates the content of an Azure Automation runbook from a local `.ps1` file.

Common usage:

- Update + publish:
	- `pwsh .\Update-RunbookContent.ps1 -SubscriptionId <subId> -ResourceGroupName <rg> -AutomationAccountName <aa> -RunbookName <runbook> -LocalFilePath .\MyRunbook.ps1 -Publish`

- Dry-run:
	- `pwsh .\Update-RunbookContent.ps1 -SubscriptionId <subId> -ResourceGroupName <rg> -AutomationAccountName <aa> -RunbookName <runbook> -LocalFilePath .\MyRunbook.ps1 -WhatIf`

Notes:

- Requires Az PowerShell modules (`Az.Accounts`, `Az.Automation`).
- Only publishing/importing should have side-effects; you can use `-WhatIf` and/or `-Confirm:$false` as needed.

### Update-RunbookContentFromCsv.ps1

Bulk wrapper around `Update-RunbookContent.ps1`. Reads a CSV and updates one runbook per row.

Required CSV columns:

- `SubscriptionId`
- `ResourceGroupName`

Optional CSV columns:

- `AutomationAccountName` (per-row override)
- `RunbookName` (per-row override)
- `LocalFilePath` (per-row override)

If `AutomationAccountName` / `RunbookName` are not present in the CSV, pass them as parameters to apply defaults for all rows.

Examples:

- Same AA/runbook for all rows (CSV only has subscription + RG):
	- `pwsh .\Update-RunbookContentFromCsv.ps1 -CsvPath .\targets.csv -AutomationAccountName <aa> -RunbookName <runbook> -LocalFilePath .\MyRunbook.ps1 -Publish`

- Dry-run:
	- `pwsh .\Update-RunbookContentFromCsv.ps1 -CsvPath .\targets.csv -AutomationAccountName <aa> -RunbookName <runbook> -LocalFilePath .\MyRunbook.ps1 -WhatIf`
