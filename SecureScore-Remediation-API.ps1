<#
.SYNOPSIS
    Microsoft Secure Score Remediation Script - API-Driven Version

.DESCRIPTION
    This script uses the Microsoft Graph Secure Score API to fetch ALL official Microsoft Secure Score controls.
    Instead of manually coding 57 checks, it fetches 411+ controls directly from Microsoft's API.

    Benefits:
    - Always up-to-date with Microsoft's latest security controls
    - 411+ controls instead of 57 manual checks
    - ActionUrls provided by Microsoft
    - Automatic remediation steps and impact assessments
    - Complete coverage across all Microsoft 365 services

.NOTES
    Author: Generated for Secure Score API Integration
    Date: 2025-11-12

    PREREQUISITES:
    - Global Administrator or Security Reader permissions
    - Required PowerShell modules:
      * Microsoft.Graph (with SecurityEvents.Read.All scope)
      * ExchangeOnlineManagement (optional, for current state checks)

    Run: Install-Module -Name Microsoft.Graph -Force -AllowClobber

.EXAMPLE
    .\SecureScore-Remediation-API.ps1 -WhatIf
    Fetches all controls and generates a comprehensive report

.EXAMPLE
    .\SecureScore-Remediation-API.ps1 -WhatIf -IncludeCurrentState
    Fetches controls and checks current implementation status

.EXAMPLE
    .\SecureScore-Remediation-API.ps1 -WhatIf -CategoryFilter "Identity"
    Only show Identity-related controls
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$SkipModuleCheck,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [ValidateSet("DeviceCode", "Interactive")]
    [string]$AuthMethod = "Interactive",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "C:\SecureScore\SecureScore-API-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$TenantName = "Your Organization",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeCurrentState,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Apps", "Device", "Identity", "Data", "All")]
    [string]$CategoryFilter = "All",

    [Parameter(Mandatory = $false)]
    [switch]$OnlyApplicableControls
)

# Error handling
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

# Report data structure
$script:reportData = @{
    ProposedChanges = @()
    ExecutiveSummary = @{
        TotalChecks = 0
        Compliant = 0
        NonCompliant = 0
        NotApplicable = 0
        HighRisk = 0
        MediumRisk = 0
        LowRisk = 0
        CurrentScore = 0
        MaxScore = 0
    }
}

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Add-ReportItem {
    param(
        [string]$Category,
        [string]$SettingName,
        [string]$CurrentValue,
        [string]$ProposedValue,
        [string]$Justification,
        [ValidateSet("High", "Medium", "Low")]
        [string]$Risk,
        [ValidateSet("Compliant", "NonCompliant", "NotApplicable", "Unknown")]
        [string]$Status,
        [string]$SecureScoreImpact,
        [string]$Reference,
        [string]$ActionUrl = ""
    )

    # Always collect report data for API version

    Write-Verbose "Add-ReportItem called: $SettingName (Status: $Status, Risk: $Risk)"

    $item = @{
        Category = $Category
        SettingName = $SettingName
        CurrentValue = $CurrentValue
        ProposedValue = $ProposedValue
        Justification = $Justification
        Risk = $Risk
        Status = $Status
        SecureScoreImpact = $SecureScoreImpact
        Reference = $Reference
        ActionUrl = $ActionUrl
    }

    $script:reportData.ProposedChanges += $item
    $script:reportData.ExecutiveSummary.TotalChecks++

    switch ($Status) {
        "Compliant" { $script:reportData.ExecutiveSummary.Compliant++ }
        "NonCompliant" { $script:reportData.ExecutiveSummary.NonCompliant++ }
        "NotApplicable" { $script:reportData.ExecutiveSummary.NotApplicable++ }
    }

    switch ($Risk) {
        "High" { $script:reportData.ExecutiveSummary.HighRisk++ }
        "Medium" { $script:reportData.ExecutiveSummary.MediumRisk++ }
        "Low" { $script:reportData.ExecutiveSummary.LowRisk++ }
    }

    Write-Verbose "Report data count now: $($script:reportData.ProposedChanges.Count)"
}

function Get-RiskLevel {
    param(
        [int]$MaxScore,
        [string]$UserImpact,
        [string]$Threats
    )

    # Determine risk based on MaxScore and UserImpact
    if ($MaxScore -ge 7 -or $UserImpact -eq "High") {
        return "High"
    }
    elseif ($MaxScore -ge 4 -or $UserImpact -eq "Medium") {
        return "Medium"
    }
    else {
        return "Low"
    }
}

function Get-ComplianceStatus {
    param(
        [string]$State,
        [string]$ControlId,
        [object]$ControlStates
    )

    # Check if we have actual control state data
    if ($ControlStates -and $ControlStates.ContainsKey($ControlId)) {
        $actualState = $ControlStates[$ControlId]
        switch ($actualState) {
            "Completed" { return "Compliant" }
            "Ignored" { return "NotApplicable" }
            "NotScored" { return "NotApplicable" }
            "ToAddress" { return "NonCompliant" }
            "Risk" { return "NonCompliant" }
            default { return "Unknown" }
        }
    }

    # Fallback to ControlStateUpdates state
    switch ($State) {
        "Completed" { return "Compliant" }
        "Ignored" { return "NotApplicable" }
        "NotScored" { return "NotApplicable" }
        "ToAddress" { return "NonCompliant" }
        "Risk" { return "NonCompliant" }
        "Default" { return "Unknown" }
        default { return "Unknown" }
    }
}

function ConvertFrom-HtmlString {
    param([string]$HtmlText)

    if ([string]::IsNullOrEmpty($HtmlText)) {
        return ""
    }

    # Remove HTML tags and decode entities
    $text = $HtmlText -replace '<[^>]+>', ''
    $text = $text -replace '&nbsp;', ' '
    $text = $text -replace '&lt;', '<'
    $text = $text -replace '&gt;', '>'
    $text = $text -replace '&amp;', '&'
    $text = $text -replace '&quot;', '"'
    $text = $text.Trim()

    return $text
}

#endregion

#region Module Installation and Connection

Write-Log "=== Microsoft Secure Score API-Driven Remediation ===" -Level Info
Write-Log "Starting API data collection..." -Level Info

if (-not $SkipModuleCheck) {
    Write-Log "Checking required modules..." -Level Info

    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph")) {
        Write-Log "Microsoft.Graph module is not installed" -Level Warning
        $install = Read-Host "Would you like to install Microsoft.Graph module? (Y/N)"
        if ($install -eq 'Y') {
            Write-Log "Installing Microsoft.Graph..." -Level Info
            Install-Module -Name "Microsoft.Graph" -Force -AllowClobber -Scope CurrentUser
        } else {
            Write-Log "Cannot proceed without Microsoft.Graph module" -Level Error
            exit 1
        }
    }
}

# Connect to Microsoft Graph
Write-Log "=== Authenticating to Microsoft Graph ===" -Level Info
Write-Log "Authentication Method: $AuthMethod" -Level Info

try {
    $graphScopes = @(
        "SecurityEvents.Read.All"
    )

    Write-Log "Connecting to Microsoft Graph..." -Level Info

    if ($AuthMethod -eq "DeviceCode") {
        Connect-MgGraph -Scopes $graphScopes -UseDeviceCode -NoWelcome -ErrorAction Stop
    }
    elseif ($TenantId) {
        Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
    }
    else {
        Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
    }

    Write-Log "Connected to Microsoft Graph successfully" -Level Success

    # Get tenant information
    $context = Get-MgContext
    $script:currentTenantId = $context.TenantId
    $script:currentUserAccount = $context.Account

    if ($script:currentTenantId) {
        Write-Log "Tenant ID: $script:currentTenantId" -Level Info
    }
    if ($script:currentUserAccount) {
        Write-Log "Signed in as: $script:currentUserAccount" -Level Info
    }
}
catch {
    Write-Log "Failed to connect to Microsoft Graph: $_" -Level Error
    Write-Log "Cannot proceed without Graph connection" -Level Error
    exit 1
}

#endregion

#region Fetch Secure Score Data

Write-Log "" -Level Info
Write-Log "=== Fetching Secure Score Data from API ===" -Level Info
Write-Log "" -Level Info

try {
    # Fetch current secure score
    Write-Log "Retrieving current secure score..." -Level Info
    $allScores = Get-MgSecuritySecureScore -Top 1

    # Handle both array and single object returns
    if ($allScores -is [Array]) {
        $currentScore = $allScores[0]
    } else {
        $currentScore = $allScores
    }

    if ($currentScore -and $currentScore.MaxScore -and $currentScore.MaxScore -gt 0) {
        $script:reportData.ExecutiveSummary.CurrentScore = $currentScore.CurrentScore
        $script:reportData.ExecutiveSummary.MaxScore = $currentScore.MaxScore
        $percentage = [math]::Round(($currentScore.CurrentScore / $currentScore.MaxScore) * 100, 1)

        Write-Log "Current Secure Score: $($currentScore.CurrentScore) / $($currentScore.MaxScore)" -Level Success
        Write-Log "Percentage: $percentage%" -Level Success
    } else {
        Write-Log "Current Secure Score: $($currentScore.CurrentScore)" -Level Success
    }

    Write-Log "" -Level Info

    # Fetch secure score control profiles
    Write-Log "Retrieving secure score control profiles..." -Level Info
    $controls = Get-MgSecuritySecureScoreControlProfile -All

    # Also fetch the actual control scores to get real compliance status
    Write-Log "Retrieving actual control scores for compliance status..." -Level Info
    $controlScores = @{}
    $scoredControlsList = @()

    # Get the actual count - PowerShell array truthiness is tricky
    $scoreCount = 0
    if ($currentScore.ControlScores) {
        # Force to array and get count
        $controlScoresArray = @($currentScore.ControlScores)
        $scoreCount = $controlScoresArray.Count
    }

    Write-Log "DEBUG: scoreCount = $scoreCount" -Level Info

    if ($scoreCount -gt 0) {
        foreach ($cs in $currentScore.ControlScores) {
            $controlScores[$cs.ControlName] = $cs
            $scoredControlsList += $cs.ControlName
        }
        Write-Log "Loaded actual scores for $($controlScores.Count) controls from your tenant" -Level Success
        Write-Log "These are the controls actively being scored in your environment" -Level Info
    } else {
        Write-Log "Warning: No control score data available from API" -Level Warning
    }

    Write-Log "Found $($controls.Count) Secure Score controls from API!" -Level Success
    Write-Log "" -Level Info

    # Filter by category if specified
    if ($CategoryFilter -ne "All") {
        $originalCount = $controls.Count
        $controls = $controls | Where-Object { $_.ControlCategory -eq $CategoryFilter }
        Write-Log "Filtered to $($controls.Count) controls in category: $CategoryFilter" -Level Info
    }

    # Filter to only applicable controls if specified
    if ($OnlyApplicableControls) {
        $originalCount = $controls.Count
        $controls = $controls | Where-Object { $scoredControlsList -contains $_.Id }
        Write-Log "Filtered to $($controls.Count) applicable controls (out of $originalCount total)" -Level Info
        Write-Log "Showing only controls that are actively scored in your tenant" -Level Info
    }

    # Group by category for summary
    $categories = $controls | Group-Object -Property ControlCategory | Sort-Object Count -Descending

    Write-Log "Control Summary by Category:" -Level Info
    Write-Log "=" * 60 -Level Info
    foreach ($category in $categories) {
        Write-Log "  $($category.Name): $($category.Count) controls" -Level Info
    }
    Write-Log "=" * 60 -Level Info
    Write-Log "" -Level Info

}
catch {
    Write-Log "Error fetching Secure Score data: $_" -Level Error
    Write-Log $_.Exception.Message -Level Error
    exit 1
}

#endregion

#region Process Controls and Build Report Data

Write-Log "=== Processing Controls ===" -Level Info
Write-Log "" -Level Info

$processedCount = 0
foreach ($control in $controls) {
    $processedCount++

    # Display progress bar
    $percentComplete = [math]::Round(($processedCount / $controls.Count) * 100, 1)
    Write-Progress -Activity "Processing Secure Score Controls" `
        -Status "Processing control $processedCount of $($controls.Count) - $percentComplete% complete" `
        -PercentComplete $percentComplete

    if ($processedCount % 50 -eq 0) {
        Write-Log "Processed $processedCount / $($controls.Count) controls..." -Level Info
    }

    # Extract control properties
    $controlId = $control.Id
    $title = $control.Title
    $category = $control.ControlCategory
    $actionUrl = $control.ActionUrl

    # Replace hardcoded tenant IDs with current tenant ID
    if ($actionUrl -and $script:currentTenantId -and $actionUrl -match 'tid=') {
        $actionUrl = $actionUrl -replace 'tid=[a-f0-9-]+', "tid=$script:currentTenantId"
    }

    $maxScore = $control.MaxScore
    $implementationCost = $control.ImplementationCost
    $userImpact = $control.UserImpact
    $threats = $control.Threats -join ", "
    $remediation = ConvertFrom-HtmlString -HtmlText $control.Remediation
    $remediationImpact = ConvertFrom-HtmlString -HtmlText $control.RemediationImpact
    $rank = $control.Rank

    # Get state from ControlStateUpdates
    $state = "Default"
    $assignedTo = ""
    if ($control.ControlStateUpdates -and $control.ControlStateUpdates.Count -gt 0) {
        $latestUpdate = $control.ControlStateUpdates[0]
        $state = $latestUpdate.State
        $assignedTo = $latestUpdate.AssignedTo
    }

    # Determine risk level
    $riskLevel = Get-RiskLevel -MaxScore $maxScore -UserImpact $userImpact -Threats $threats

    # Determine compliance status based on actual score from tenant
    if ($controlScores.ContainsKey($controlId)) {
        $scoreData = $controlScores[$controlId]
        $actualScore = $scoreData.Score

        if ($actualScore -eq $maxScore) {
            # Fully compliant - achieved max score
            $complianceStatus = "Compliant"
        } elseif ($actualScore -gt 0) {
            # Partially compliant - some points but not all
            $complianceStatus = "NonCompliant"
        } else {
            # Not compliant - 0 points
            $complianceStatus = "NonCompliant"
        }
    } else {
        # Control not being scored in this tenant - not applicable
        $complianceStatus = "NotApplicable"
    }

    # Build justification from threats and remediation
    $justification = $remediation
    if ($threats) {
        $justification = "Threats: $threats. " + $justification
    }

    # Calculate score impact
    $scoreImpact = "+$maxScore points"
    if ($script:reportData.ExecutiveSummary.MaxScore -gt 0) {
        $impactPercentage = [math]::Round(($maxScore / $script:reportData.ExecutiveSummary.MaxScore) * 100, 2)
        $scoreImpact = "+$impactPercentage%"
    }

    # Current value and proposed value
    if ($controlScores.ContainsKey($controlId)) {
        $scoreData = $controlScores[$controlId]
        $actualScore = $scoreData.Score
        $currentValue = "Score: $actualScore / $maxScore points"
        if ($scoreData.Description) {
            $currentValue += " - " + $scoreData.Description
        }
    } else {
        $currentValue = "Not applicable to your tenant (not being scored)"
    }

    $proposedValue = "Score: $maxScore / $maxScore points (Fully Compliant)"
    if ($implementationCost) {
        $proposedValue += " | Implementation Cost: $implementationCost, User Impact: $userImpact"
    }

    # Add to report
    Add-ReportItem `
        -Category $category `
        -SettingName $title `
        -CurrentValue $currentValue `
        -ProposedValue $proposedValue `
        -Justification $justification `
        -Risk $riskLevel `
        -Status $complianceStatus `
        -SecureScoreImpact $scoreImpact `
        -Reference $actionUrl `
        -ActionUrl $actionUrl
}

# Clear progress bar
Write-Progress -Activity "Processing Secure Score Controls" -Completed

Write-Log "" -Level Info
Write-Log "Processed all $($controls.Count) controls!" -Level Success
Write-Log "Collected $($script:reportData.ProposedChanges.Count) configuration items for report" -Level Success
Write-Log "" -Level Info

#endregion

#region Generate HTML Report

# Always generate report for API version
Write-Log "=== Generating HTML Report ===" -Level Info

    $reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"
    $actualTenantName = if ($TenantName -ne "Your Organization") { $TenantName } else { "Microsoft 365 Tenant" }
    $runByUser = if ($script:currentUserAccount) { $script:currentUserAccount } else { "Unknown User" }
    $tenantIdDisplay = if ($script:currentTenantId) { $script:currentTenantId } else { "Unknown" }

    $totalChecks = $script:reportData.ExecutiveSummary.TotalChecks
    $compliant = $script:reportData.ExecutiveSummary.Compliant
    $nonCompliant = $script:reportData.ExecutiveSummary.NonCompliant
    $notApplicable = $script:reportData.ExecutiveSummary.NotApplicable
    $highRisk = $script:reportData.ExecutiveSummary.HighRisk
    $mediumRisk = $script:reportData.ExecutiveSummary.MediumRisk
    $lowRisk = $script:reportData.ExecutiveSummary.LowRisk
    $currentScore = $script:reportData.ExecutiveSummary.CurrentScore
    $maxScore = $script:reportData.ExecutiveSummary.MaxScore

    $compliancePercentage = if ($totalChecks -gt 0) {
        [math]::Round(($compliant / $totalChecks) * 100, 1)
    } else {
        0
    }

    $scorePercentage = if ($maxScore -gt 0) {
        [math]::Round(($currentScore / $maxScore) * 100, 1)
    } else {
        0
    }

    # Group items by category
    $groupedItems = $script:reportData.ProposedChanges | Group-Object -Property Category | Sort-Object Name

    # Build category sections HTML
    $categorySectionsHtml = ""
    foreach ($group in $groupedItems) {
        $categoryName = $group.Name
        $categoryItems = $group.Group
        $categoryCount = $categoryItems.Count

        # Count compliant vs non-compliant
        $categoryCompliant = ($categoryItems | Where-Object { $_.Status -eq "Compliant" }).Count
        $categoryNonCompliant = ($categoryItems | Where-Object { $_.Status -eq "NonCompliant" }).Count

        $categorySectionsHtml += @"
        <div class="category-section">
            <div class="category-header">
                <div>
                    <div class="category-name">$categoryName</div>
                    <div class="category-stats">$categoryCount controls | $categoryCompliant Compliant | $categoryNonCompliant Non-Compliant</div>
                </div>
                <span class="expand-icon">▼</span>
            </div>
            <div class="category-content">
"@

        foreach ($item in $categoryItems) {
            $statusClass = switch ($item.Status) {
                "Compliant" { "status-compliant" }
                "NonCompliant" { "status-noncompliant" }
                "NotApplicable" { "status-na" }
                default { "status-na" }
            }

            $riskClass = switch ($item.Risk) {
                "High" { "risk-high" }
                "Medium" { "risk-medium" }
                "Low" { "risk-low" }
            }

            $statusText = switch ($item.Status) {
                "Compliant" { "Compliant" }
                "NonCompliant" { "Non-Compliant" }
                "NotApplicable" { "N/A" }
                default { "Unknown" }
            }

            $actionButtonsHtml = ""
            if ($item.ActionUrl) {
                $actionButtonsHtml = @"
                <div class="action-buttons">
                    <a href="$($item.ActionUrl)" target="_blank" class="action-btn action-btn-primary">
                        <span class="action-icon">&#9881;</span>
                        <span>Configure Setting</span>
                    </a>
                    <a href="$($item.Reference)" target="_blank" class="action-btn action-btn-secondary">
                        <span class="action-icon">&#128218;</span>
                        <span>View Documentation</span>
                    </a>
                </div>
"@
            } elseif ($item.Reference) {
                $actionButtonsHtml = @"
                <div class="action-buttons">
                    <a href="$($item.Reference)" target="_blank" class="action-btn action-btn-secondary">
                        <span class="action-icon">&#128218;</span>
                        <span>View Documentation</span>
                    </a>
                </div>
"@
            }

            $categorySectionsHtml += @"
                <div class="settings-row" data-status="$($item.Status)" data-risk="$($item.Risk)">
                    <div class="row-header">
                        <div class="setting-info">
                            <div class="setting-name">$($item.SettingName)</div>
                            <div class="setting-category">$($item.Category)</div>
                        </div>
                        <div class="badge $statusClass">$statusText</div>
                        <div class="badge $riskClass">$($item.Risk)</div>
                        <div class="impact-score">$($item.SecureScoreImpact)</div>
                    </div>
                    <div class="row-details">
                        <div class="justification-box">
                            $($item.Justification)
                        </div>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>Current Value</label>
                                <div class="detail-value">$($item.CurrentValue)</div>
                            </div>
                            <div class="detail-item">
                                <label>Proposed Value</label>
                                <div class="detail-value">$($item.ProposedValue)</div>
                            </div>
                        </div>
                        $actionButtonsHtml
                    </div>
                </div>
"@
        }

        $categorySectionsHtml += @"
            </div>
        </div>
"@
    }

    # Generate full HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Secure Score API Assessment - $actualTenantName</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #09090b;
            color: #fafafa;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 3px solid #60a5fa;
        }

        .header h1 {
            font-size: 1.8em;
            font-weight: 700;
            letter-spacing: -1px;
            margin: 0;
        }

        .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
            margin-top: 4px;
        }

        .header-right {
            text-align: right;
            font-size: 0.85em;
        }

        .header-right > div {
            margin-bottom: 2px;
        }

        /* Summary Cards */
        .summary {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 12px;
            padding: 20px 40px;
            background: #0a0a0c;
        }

        .summary-card {
            background: linear-gradient(135deg, #18181b 0%, #27272a 100%);
            border: 1px solid #3f3f46;
            border-radius: 8px;
            padding: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }

        .summary-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.4);
            border-color: #60a5fa;
        }

        .summary-card.active {
            border: 2px solid #60a5fa;
            box-shadow: 0 0 20px rgba(96, 165, 250, 0.3);
        }

        .summary-card h3 {
            font-size: 0.7em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #71717a;
            margin-bottom: 8px;
        }

        .summary-card .value {
            font-size: 2em;
            font-weight: 700;
            color: #fafafa;
        }

        .summary-card .subtext {
            font-size: 0.75em;
            color: #a1a1aa;
            margin-top: 6px;
        }

        .summary-card.highlight {
            background: linear-gradient(135deg, #064e3b 0%, #065f46 100%);
            border-color: #10b981;
        }

        .summary-card.highlight .value {
            color: #6ee7b7;
        }

        .summary-card.warning {
            background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
            border-color: #ef4444;
        }

        .summary-card.warning .value {
            color: #fca5a5;
        }

        /* Score Summary */
        .score-summary {
            padding: 20px 40px;
            background: #18181b;
            border-bottom: 1px solid #27272a;
        }

        .score-summary h2 {
            font-size: 1.5em;
            margin-bottom: 15px;
            color: #60a5fa;
        }

        .score-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .score-item {
            background: #27272a;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #3f3f46;
        }

        .score-item label {
            font-size: 0.8em;
            color: #71717a;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .score-item .score-value {
            font-size: 1.8em;
            font-weight: 700;
            color: #10b981;
            margin-top: 5px;
        }

        /* Category Sections */
        .content {
            padding: 30px 40px;
        }

        .category-section {
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .category-header {
            background: #1e3a8a;
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s;
        }

        .category-header:hover {
            background: #1e40af;
        }

        .category-name {
            font-size: 1.3em;
            font-weight: 600;
        }

        .category-stats {
            font-size: 0.85em;
            opacity: 0.9;
            margin-top: 4px;
        }

        .category-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .category-section.expanded .category-content {
            max-height: 100000px;
        }

        .category-section.expanded .expand-icon {
            transform: rotate(180deg);
        }

        .settings-row {
            border-bottom: 1px solid #27272a;
            background: #18181b;
            transition: background 0.2s;
        }

        .settings-row:last-child {
            border-bottom: none;
        }

        .settings-row:hover {
            background: #1f1f23;
        }

        .settings-row.hidden {
            display: none;
        }

        .row-header {
            padding: 16px 20px;
            display: grid;
            grid-template-columns: minmax(300px, 2fr) 100px 100px 80px;
            gap: 16px;
            align-items: start;
            cursor: pointer;
        }

        .setting-info {
            min-width: 0;
        }

        .setting-name {
            font-weight: 600;
            color: #fafafa;
            font-size: 0.95em;
            margin-bottom: 4px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .setting-category {
            font-size: 0.75em;
            color: #71717a;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 600;
            text-align: center;
            white-space: nowrap;
        }

        .status-compliant { background: #064e3b; color: #6ee7b7; }
        .status-noncompliant { background: #7f1d1d; color: #fca5a5; }
        .status-na { background: #3f3f46; color: #a1a1aa; }

        .risk-high { background: #7f1d1d; color: #fca5a5; }
        .risk-medium { background: #78350f; color: #fcd34d; }
        .risk-low { background: #1e3a8a; color: #93c5fd; }

        .impact-score {
            color: #10b981;
            font-weight: 600;
            font-size: 0.9em;
        }

        .row-details {
            padding: 0 20px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .settings-row.expanded .row-details {
            max-height: 1000px;
            padding: 0 20px 20px 20px;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 16px;
        }

        .detail-item label {
            display: block;
            font-size: 0.75em;
            text-transform: uppercase;
            color: #71717a;
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }

        .detail-value {
            background: #18181b;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.9em;
            border: 1px solid #3f3f46;
            color: #e4e4e7;
        }

        .justification-box {
            background: #1e3a5f;
            border-left: 3px solid #3b82f6;
            padding: 12px;
            border-radius: 4px;
            font-size: 0.85em;
            color: #bfdbfe;
            line-height: 1.5;
            margin-bottom: 12px;
        }

        .reference-link {
            font-size: 0.85em;
        }

        .reference-link a {
            color: #60a5fa;
            text-decoration: none;
        }

        .reference-link a:hover {
            text-decoration: underline;
        }

        .action-buttons {
            display: flex;
            gap: 12px;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid #3f3f46;
        }

        .action-btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: #fff;
        }

        .action-btn-primary:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }

        .action-btn-secondary {
            background: #27272a;
            color: #e4e4e7;
            border: 1px solid #3f3f46;
        }

        .action-btn-secondary:hover {
            background: #3f3f46;
            border-color: #52525b;
        }

        .action-icon {
            font-size: 1.1em;
        }

        .expand-icon {
            color: #71717a;
            font-size: 1.2em;
            transition: transform 0.3s;
        }

        .settings-row.expanded .expand-icon {
            transform: rotate(180deg);
        }

        /* Footer */
        /* Floating Action Buttons (Right Side) */
        .floating-actions {
            position: fixed;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            display: flex;
            flex-direction: column;
            gap: 12px;
            z-index: 1000;
        }
        .action-btn {
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            border: 2px solid #60a5fa;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            font-size: 20px;
            font-weight: bold;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            position: relative;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .action-btn:hover {
            transform: scale(1.1);
            box-shadow: 0 8px 20px rgba(96, 165, 250, 0.4);
            border-color: #93c5fd;
        }
        .action-btn::before {
            content: attr(data-tooltip);
            position: absolute;
            right: 70px;
            background: #18181b;
            color: #e4e4e7;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
            border: 1px solid #3f3f46;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .action-btn:hover::before {
            opacity: 1;
        }

        .footer {
            background: #0a0a0c;
            border-top: 1px solid #27272a;
            padding: 15px 40px;
            text-align: center;
            font-size: 0.85em;
            color: #71717a;
        }

        .api-badge {
            display: inline-block;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: #fff;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <h1>Microsoft SECURE SCORE ASSESSMENT</h1>
                <div class="subtitle">$actualTenantName</div>
                <div class="subtitle" style="font-size: 0.75em; margin-top: 4px; opacity: 0.8;">Tenant ID: $tenantIdDisplay</div>
            </div>
            <div class="header-right">
                <div>Generated: $reportDate</div>
                <div>Run by: $runByUser</div>
                <div>Controls Source: Microsoft Graph API</div>
                <div>Total Controls: $totalChecks</div>
            </div>
        </div>

        <!-- Score Summary -->
        <div class="score-summary">
            <h2>Microsoft Secure Score</h2>
            <div class="score-info">
                <div class="score-item">
                    <label>Current Score</label>
                    <div class="score-value">$currentScore</div>
                </div>
                <div class="score-item">
                    <label>Maximum Score</label>
                    <div class="score-value">$maxScore</div>
                </div>
                <div class="score-item">
                    <label>Score Percentage</label>
                    <div class="score-value">$scorePercentage%</div>
                </div>
                <div class="score-item">
                    <label>Compliance Rate</label>
                    <div class="score-value">$compliancePercentage%</div>
                </div>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="summary">
            <div class="summary-card highlight" data-filter="status" data-value="Compliant" onclick="filterControls(this)">
                <h3>Compliant Controls</h3>
                <div class="value">$compliant</div>
                <div class="subtext">Already implemented</div>
            </div>
            <div class="summary-card warning" data-filter="status" data-value="NonCompliant" onclick="filterControls(this)">
                <h3>Non-Compliant Controls</h3>
                <div class="value">$nonCompliant</div>
                <div class="subtext">Action required</div>
            </div>
            <div class="summary-card" data-filter="risk" data-value="High" onclick="filterControls(this)">
                <h3>High Risk</h3>
                <div class="value">$highRisk</div>
                <div class="subtext">Priority items</div>
            </div>
            <div class="summary-card" data-filter="risk" data-value="Medium" onclick="filterControls(this)">
                <h3>Medium Risk</h3>
                <div class="value">$mediumRisk</div>
                <div class="subtext">Important items</div>
            </div>
            <div class="summary-card" data-filter="risk" data-value="Low" onclick="filterControls(this)">
                <h3>Low Risk</h3>
                <div class="value">$lowRisk</div>
                <div class="subtext">Standard items</div>
            </div>
            <div class="summary-card" data-filter="status" data-value="NotApplicable" onclick="filterControls(this)">
                <h3>Not Applicable</h3>
                <div class="value">$notApplicable</div>
                <div class="subtext">Skipped controls</div>
            </div>
        </div>

        <!-- Content -->
        <div class="content">
            $categorySectionsHtml
        </div>

        <!-- Floating Action Buttons -->
        <div class="floating-actions">
            <a href="https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit" target="_blank" class="action-btn" data-tooltip="View on GitHub">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues" target="_blank" class="action-btn" data-tooltip="Report Issues">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 2c5.514 0 10 4.486 10 10s-4.486 10-10 10-10-4.486-10-10 4.486-10 10-10zm0-2c-6.627 0-12 5.373-12 12s5.373 12 12 12 12-5.373 12-12-5.373-12-12-12zm-1 6h2v8h-2v-8zm1 12.25c-.69 0-1.25-.56-1.25-1.25s.56-1.25 1.25-1.25 1.25.56 1.25 1.25-.56 1.25-1.25 1.25z"/></svg>
            </a>
            <a href="https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues/new" target="_blank" class="action-btn" data-tooltip="Submit Feedback">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12 3c5.514 0 10 3.592 10 8.007 0 4.917-5.145 7.961-9.91 7.961-1.937 0-3.383-.397-4.394-.644-1 .613-1.595 1.037-4.272 1.82.535-1.373.723-2.748.602-4.265-.838-1-2.025-2.4-2.025-4.872-.001-4.415 4.485-8.007 9.999-8.007zm0-2c-6.338 0-12 4.226-12 10.007 0 2.05.739 4.063 2.047 5.625.055 1.83-1.023 4.456-1.993 6.368 2.602-.47 6.301-1.508 7.978-2.536 1.418.345 2.775.503 4.059.503 7.084 0 11.91-4.837 11.91-9.961-.001-5.811-5.702-10.006-12.001-10.006z"/></svg>
            </a>
            <a href="https://www.linkedin.com/in/mohammedsiddiqui6872/" target="_blank" class="action-btn" data-tooltip="Let's Chat!">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>
            </a>
            <a href="https://buymeacoffee.com/mohammedsiddiqui" target="_blank" class="action-btn" data-tooltip="Buy Me a Coffee">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M20 3H4v10c0 2.21 1.79 4 4 4h6c2.21 0 4-1.79 4-4v-3h2c1.11 0 2-.9 2-2V5c0-1.11-.89-2-2-2zm0 5h-2V5h2v3zM4 19h16v2H4z"/></svg>
            </a>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>Microsoft Secure Score Remediation Toolkit</strong> | Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | $totalChecks controls | Run by: $runByUser</p>
        </div>
    </div>

    <script>
        let activeFilter = null;

        // Filter controls based on summary card clicks
        function filterControls(card) {
            const filterType = card.getAttribute('data-filter');
            const filterValue = card.getAttribute('data-value');
            const allRows = document.querySelectorAll('.settings-row');
            const allCards = document.querySelectorAll('.summary-card');

            // Toggle filter - if same card clicked, clear filter
            if (activeFilter && activeFilter.type === filterType && activeFilter.value === filterValue) {
                // Clear filter
                allRows.forEach(row => row.classList.remove('hidden'));
                allCards.forEach(c => c.classList.remove('active'));
                activeFilter = null;

                // Expand all categories to show all controls
                document.querySelectorAll('.category-section').forEach(cat => {
                    cat.classList.add('expanded');
                });
            } else {
                // Apply new filter
                activeFilter = { type: filterType, value: filterValue };

                // Remove active class from all cards
                allCards.forEach(c => c.classList.remove('active'));

                // Add active class to clicked card
                card.classList.add('active');

                // Filter rows
                allRows.forEach(row => {
                    const rowValue = row.getAttribute('data-' + filterType);
                    if (rowValue === filterValue) {
                        row.classList.remove('hidden');
                    } else {
                        row.classList.add('hidden');
                    }
                });

                // Expand all categories to show filtered results
                document.querySelectorAll('.category-section').forEach(cat => {
                    cat.classList.add('expanded');
                });
            }

            // Update category counts
            updateCategoryCounts();
        }

        // Update category counts based on visible rows
        function updateCategoryCounts() {
            document.querySelectorAll('.category-section').forEach(category => {
                const visibleRows = category.querySelectorAll('.settings-row:not(.hidden)');
                const totalRows = category.querySelectorAll('.settings-row');

                if (visibleRows.length === 0) {
                    category.style.display = 'none';
                } else {
                    category.style.display = 'block';
                }
            });
        }

        // Category expand/collapse
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', function() {
                this.parentElement.classList.toggle('expanded');
            });
        });

        // Row expand/collapse
        document.querySelectorAll('.row-header').forEach(header => {
            header.addEventListener('click', function() {
                this.parentElement.classList.toggle('expanded');
            });
        });

        // Expand first category by default
        if (document.querySelector('.category-section')) {
            document.querySelector('.category-section').classList.add('expanded');
        }
    </script>
</body>
</html>
"@

    # Write report to file
    try {
        $htmlContent | Set-Content -Path $ReportPath -Encoding UTF8 -WhatIf:$false
        Write-Log "Report generated successfully!" -Level Success
        Write-Log "Report location: $ReportPath" -Level Info
        Write-Log "" -Level Info
        Write-Log "Opening report in default browser..." -Level Info
        Start-Process $ReportPath
    }
    catch {
        Write-Log "Error generating report: $_" -Level Error
    }

#endregion

Write-Log "=== Script Completed ===" -Level Success
