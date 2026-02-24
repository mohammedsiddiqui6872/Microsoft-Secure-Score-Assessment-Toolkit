# Note: Models module is already imported by the main module
# ConvertTo-HtmlEncoded and other functions are available from the parent scope

function New-HtmlReport {
    <#
    .SYNOPSIS
        Generates an HTML report from report data using modern template.

    .DESCRIPTION
        Creates a comprehensive HTML report by loading the modern template and populating with data.

    .PARAMETER ReportData
        Report data hashtable containing all control information.

    .PARAMETER TemplatePath
        Path to the HTML template directory.

    .PARAMETER OutputPath
        Path where the HTML report will be saved.

    .PARAMETER InlineAssets
        If specified, CSS and JS will be inlined into the HTML file.

    .OUTPUTS
        Path to the generated HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,

        [Parameter(Mandatory = $true)]
        [string]$TemplatePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$InlineAssets
    )

    try {
        # Use the modern template
        $templateFile = Join-Path $TemplatePath "report-modern-template.html"

        if (-not (Test-Path $templateFile)) {
            throw "Modern template file not found: $templateFile"
        }

        # Load template content
        $htmlContent = Get-Content -Path $templateFile -Raw -Encoding UTF8

        # Load and embed logo as base64
        $logoPath = Join-Path (Split-Path $TemplatePath -Parent) "powershellnerdlogo.png"
        if (Test-Path $logoPath) {
            $logoBytes = [System.IO.File]::ReadAllBytes($logoPath)
            $logoBase64 = [System.Convert]::ToBase64String($logoBytes)
            $htmlContent = $htmlContent.Replace('{{LOGO_BASE64}}', $logoBase64)
            Write-Verbose "Embedded logo from $logoPath"
        }
        else {
            # Fallback: remove logo placeholders with a transparent 1x1 pixel
            $htmlContent = $htmlContent.Replace('{{LOGO_BASE64}}', 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
            Write-Verbose "Logo file not found at $logoPath, using fallback"
        }

        # Build control cards HTML
        $controlCards = Build-ControlCards -ReportData $ReportData
        Write-Verbose "Generated $($ReportData.ProposedChanges.Count) control cards, HTML length: $($controlCards.Length) characters"

        # Calculate summary statistics
        $summary = $ReportData.ExecutiveSummary
        $totalChecks = $summary.TotalChecks
        $compliant = $summary.Compliant
        $nonCompliant = $summary.NonCompliant
        $notApplicable = $summary.NotApplicable
        $currentScore = $summary.CurrentScore
        $maxScore = $summary.MaxScore

        $compliancePercentage = if ($totalChecks -gt 0) {
            [math]::Round(($compliant / $totalChecks) * 100, 1)
        } else { 0 }

        $scorePercentage = if ($maxScore -gt 0) {
            [math]::Round(($currentScore / $maxScore) * 100, 1)
        } else { 0 }

        # Calculate stroke-dashoffset for circular progress (628 is circumference of circle with r=100)
        $strokeDashoffset = [math]::Round(628 * (1 - ($scorePercentage / 100)), 0)

        # HTML encode all dynamic values
        $encodedTenantName = ConvertTo-HtmlEncoded -Text $ReportData.Metadata.TenantName
        $encodedTenantId = ConvertTo-HtmlEncoded -Text $ReportData.Metadata.TenantId
        $encodedRunByUser = ConvertTo-HtmlEncoded -Text $ReportData.Metadata.GeneratedBy
        $encodedReportDate = ConvertTo-HtmlEncoded -Text $ReportData.Metadata.GeneratedDate

        # Replace all template placeholders (using simple string replacement for reliability)
        $htmlContent = $htmlContent.Replace('{{TENANT_NAME}}', $encodedTenantName)
        $htmlContent = $htmlContent.Replace('{{TENANT_ID}}', $encodedTenantId)
        $htmlContent = $htmlContent.Replace('{{RUN_BY_USER}}', $encodedRunByUser)
        $htmlContent = $htmlContent.Replace('{{REPORT_DATE}}', $encodedReportDate)
        $htmlContent = $htmlContent.Replace('{{TOTAL_CHECKS}}', $totalChecks)
        $htmlContent = $htmlContent.Replace('{{COMPLIANT}}', $compliant)
        $htmlContent = $htmlContent.Replace('{{NON_COMPLIANT}}', $nonCompliant)
        $htmlContent = $htmlContent.Replace('{{NOT_APPLICABLE}}', $notApplicable)
        $htmlContent = $htmlContent.Replace('{{CURRENT_SCORE}}', $currentScore)
        $htmlContent = $htmlContent.Replace('{{MAX_SCORE}}', $maxScore)
        $htmlContent = $htmlContent.Replace('{{SCORE_PERCENTAGE}}', $scorePercentage)
        $htmlContent = $htmlContent.Replace('{{COMPLIANCE_PERCENTAGE}}', $compliancePercentage)
        $htmlContent = $htmlContent.Replace('{{STROKE_DASHOFFSET}}', $strokeDashoffset)
        $htmlContent = $htmlContent.Replace('{{CONTROL_CARDS}}', $controlCards)

        Write-Verbose "Placeholder replacements completed"

        # Write final HTML to file
        $htmlContent | Set-Content -Path $OutputPath -Encoding UTF8 -Force

        return $OutputPath
    }
    catch {
        throw "Failed to generate HTML report: $_"
    }
}

function Build-ControlCards {
    <#
    .SYNOPSIS
        Builds the HTML for individual control cards.

    .DESCRIPTION
        Generates modern control card HTML for all controls (no category grouping).

    .PARAMETER ReportData
        Report data containing all controls.

    .OUTPUTS
        HTML string containing all control cards.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData
    )

    $sb = [System.Text.StringBuilder]::new(4096)

    # Sort controls by risk (High first), then by compliance status
    $sortedControls = $ReportData.ProposedChanges | Sort-Object @{
        Expression = {
            switch ($_.Risk) {
                'High' { 1 }
                'Medium' { 2 }
                'Low' { 3 }
            }
        }
    }, @{
        Expression = {
            switch ($_.Status) {
                'NonCompliant' { 1 }
                'Compliant' { 2 }
                'NotApplicable' { 3 }
            }
        }
    }

    foreach ($item in $sortedControls) {
        [void]$sb.Append((Build-ModernControlCard -Item $item))
    }

    return $sb.ToString()
}

function Build-ModernControlCard {
    <#
    .SYNOPSIS
        Builds HTML for a single modern control card.

    .DESCRIPTION
        Generates the HTML markup for a control card in the new modern design.

    .PARAMETER Item
        Control item data.

    .OUTPUTS
        HTML string for the control card.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Item
    )

    # Map status to CSS classes
    $statusClass = switch ($Item.Status) {
        "Compliant" { "status-compliant" }
        "NonCompliant" { "status-noncompliant" }
        "NotApplicable" { "status-na" }
        default { "status-na" }
    }

    $statusDataValue = switch ($Item.Status) {
        "Compliant" { "compliant" }
        "NonCompliant" { "noncompliant" }
        "NotApplicable" { "na" }
        default { "na" }
    }

    $riskDataValue = $Item.Risk.ToLower()

    # Map status to badge classes
    $statusBadgeClass = switch ($Item.Status) {
        "Compliant" { "badge-status-compliant" }
        "NonCompliant" { "badge-status-noncompliant" }
        "NotApplicable" { "badge-status-na" }
        default { "badge-status-na" }
    }

    $riskBadgeClass = switch ($Item.Risk) {
        "High" { "badge-risk-high" }
        "Medium" { "badge-risk-medium" }
        "Low" { "badge-risk-low" }
    }

    $statusText = switch ($Item.Status) {
        "Compliant" { "Compliant" }
        "NonCompliant" { "Non-Compliant" }
        "NotApplicable" { "N/A" }
        default { "Unknown" }
    }

    # HTML encode all dynamic values
    $encodedSettingName = ConvertTo-HtmlEncoded -Text $Item.SettingName
    $encodedCategory = ConvertTo-HtmlEncoded -Text $Item.Category
    $encodedJustification = ConvertTo-HtmlEncoded -Text $Item.Justification
    $encodedCurrentValue = ConvertTo-HtmlEncoded -Text $Item.CurrentValue
    $encodedProposedValue = ConvertTo-HtmlEncoded -Text $Item.ProposedValue
    $encodedImpact = ConvertTo-HtmlEncoded -Text $Item.SecureScoreImpact
    $encodedRisk = ConvertTo-HtmlEncoded -Text $Item.Risk
    $encodedActionUrl = ConvertTo-HtmlEncoded -Text $Item.ActionUrl
    $encodedReference = ConvertTo-HtmlEncoded -Text $Item.Reference

    # Build action buttons
    $actionButtonsHtml = ""
    if ($Item.ActionUrl) {
        $actionButtonsHtml = @"
                            <a href="$encodedActionUrl" target="_blank" class="action-btn action-btn-primary">
                                <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg></span>
                                <span>Configure Setting</span>
                            </a>
                            <a href="$encodedReference" target="_blank" class="action-btn action-btn-secondary">
                                <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg></span>
                                <span>View Documentation</span>
                            </a>
"@
    }
    elseif ($Item.Reference) {
        $actionButtonsHtml = @"
                            <a href="$encodedReference" target="_blank" class="action-btn action-btn-secondary">
                                <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg></span>
                                <span>View Documentation</span>
                            </a>
"@
    }

    return @"
                <div class="control-card $statusClass fade-in" data-status="$statusDataValue" data-risk="$riskDataValue">
                    <div class="control-header" onclick="toggleControl(this)">
                        <div class="control-info">
                            <div class="control-title">$encodedSettingName</div>
                            <div class="control-meta">
                                <span class="control-category">$encodedCategory</span>
                                <div class="control-badges">
                                    <span class="badge $statusBadgeClass">$statusText</span>
                                    <span class="badge $riskBadgeClass">$encodedRisk Risk</span>
                                </div>
                            </div>
                        </div>
                        <span class="impact-score">$encodedImpact</span>
                        <div class="expand-toggle">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M4 6l4 4 4-4"/>
                            </svg>
                        </div>
                    </div>
                    <div class="control-details">
                        <div class="justification-box">
                            $encodedJustification
                        </div>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <div class="detail-label">Current Status</div>
                                <div class="detail-value">$encodedCurrentValue</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Recommended Configuration</div>
                                <div class="detail-value">$encodedProposedValue</div>
                            </div>
                        </div>
                        <div class="action-buttons">
$actionButtonsHtml
                        </div>
                    </div>
                </div>

"@
}

# Functions are exported via the main module manifest (.psd1)
