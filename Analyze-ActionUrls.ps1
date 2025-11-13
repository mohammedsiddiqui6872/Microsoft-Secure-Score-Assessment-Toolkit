# Analyze ActionUrls from SecureScore-API-Controls.json
# This script categorizes URLs and identifies their types

$jsonPath = "C:\SecureScore\SecureScore-API-Controls.json"
$outputPath = "C:\SecureScore\ActionUrl-Analysis.csv"

Write-Host "Loading JSON data..." -ForegroundColor Cyan
$controls = Get-Content $jsonPath -Raw | ConvertFrom-Json

$urlAnalysis = @()

foreach ($control in $controls) {
    $url = $control.ActionUrl

    if (-not $url) {
        continue
    }

    # Determine URL type
    $urlType = "Unknown"
    $isConfiguration = $false
    $isDocumentation = $false

    if ($url -match "learn.microsoft.com") {
        $urlType = "Microsoft Learn Documentation"
        $isDocumentation = $true
    }
    elseif ($url -match "support.microsoft.com") {
        $urlType = "Microsoft Support Documentation"
        $isDocumentation = $true
    }
    elseif ($url -match "aka.ms") {
        $urlType = "Microsoft Short Link (likely documentation)"
        $isDocumentation = $true
    }
    elseif ($url -match "go.microsoft.com/fwlink") {
        $urlType = "Microsoft FWLink (redirect - mixed type)"
        $isDocumentation = $true
    }
    elseif ($url -match "security.microsoft.com") {
        $urlType = "Security Portal (Configuration)"
        $isConfiguration = $true
    }
    elseif ($url -match "admin.teams.microsoft.com") {
        $urlType = "Teams Admin Center (Configuration)"
        $isConfiguration = $true
    }
    elseif ($url -match "admin.exchange.microsoft.com") {
        $urlType = "Exchange Admin Center (Configuration)"
        $isConfiguration = $true
    }
    elseif ($url -match "compliance.microsoft.com") {
        $urlType = "Compliance Center (Configuration)"
        $isConfiguration = $true
    }
    elseif ($url -match "aad.portal.azure.com") {
        $urlType = "Azure AD Portal (Configuration)"
        $isConfiguration = $true
    }
    elseif ($url -match "portal.cloudappsecurity.com") {
        $urlType = "Cloud App Security Portal (Configuration)"
        $isConfiguration = $true
    }
    elseif ($url -match "help.salesforce.com|support.zendesk.com|docs.servicenow.com|docs.github.com|support.atlassian.com|support.zoom.us|docs.citrix.com|developer.okta.com|support.docusign.com|support.google.com|support.netdocuments.com|blog.zoom.us|www.workplace.com|www.dropbox.com|security.salesforce.com") {
        $urlType = "Third-Party Documentation"
        $isDocumentation = $true
    }

    $urlAnalysis += [PSCustomObject]@{
        ControlId = $control.Id
        ControlTitle = $control.Title
        Category = $control.ControlCategory
        ActionUrl = $url
        UrlType = $urlType
        IsConfiguration = $isConfiguration
        IsDocumentation = $isDocumentation
        Domain = ([System.Uri]$url).Host
    }
}

# Export to CSV
$urlAnalysis | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

# Summary statistics
Write-Host "`n=== URL Analysis Summary ===" -ForegroundColor Green
Write-Host "Total Controls with URLs: $($urlAnalysis.Count)" -ForegroundColor Cyan

$groupedByType = $urlAnalysis | Group-Object -Property UrlType | Sort-Object Count -Descending
Write-Host "`nBy URL Type:" -ForegroundColor Yellow
foreach ($group in $groupedByType) {
    Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor White
}

$configCount = ($urlAnalysis | Where-Object { $_.IsConfiguration }).Count
$docCount = ($urlAnalysis | Where-Object { $_.IsDocumentation }).Count

Write-Host "`n=== Type Breakdown ===" -ForegroundColor Green
Write-Host "Configuration Links: $configCount ($(([math]::Round($configCount/$urlAnalysis.Count*100,1)))%)" -ForegroundColor Cyan
Write-Host "Documentation Links: $docCount ($(([math]::Round($docCount/$urlAnalysis.Count*100,1)))%)" -ForegroundColor Yellow

Write-Host "`nAnalysis saved to: $outputPath" -ForegroundColor Green
