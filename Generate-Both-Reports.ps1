Write-Host ""
Write-Host "==========================================="  -ForegroundColor Magenta
Write-Host "REPORT 1: All 411 Controls (Complete View)" -ForegroundColor Magenta
Write-Host "==========================================="  -ForegroundColor Magenta
Write-Host ""

& 'C:\SecureScore\SecureScore-Remediation-API.ps1' -WhatIf

Write-Host ""
Write-Host ""
Write-Host "==========================================="  -ForegroundColor Cyan
Write-Host "REPORT 2: Only 71 Applicable Controls"  -ForegroundColor Cyan
Write-Host "==========================================="  -ForegroundColor Cyan
Write-Host ""

& 'C:\SecureScore\SecureScore-Remediation-API.ps1' -WhatIf -OnlyApplicableControls
