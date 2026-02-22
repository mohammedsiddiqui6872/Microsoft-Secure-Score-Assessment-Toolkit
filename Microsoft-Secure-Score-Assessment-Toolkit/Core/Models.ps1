function New-ReportData {
    <#
    .SYNOPSIS
        Creates a new report data structure.

    .DESCRIPTION
        Initializes an empty report data object with executive summary and proposed changes.

    .OUTPUTS
        Hashtable representing the report data structure.
    #>
    [CmdletBinding()]
    param()

    return @{
        ProposedChanges = [System.Collections.Generic.List[hashtable]]::new()
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
        Metadata = @{
            TenantId = $null
            TenantName = $null
            GeneratedBy = $null
            GeneratedDate = $null
        }
    }
}

function Add-ReportItem {
    <#
    .SYNOPSIS
        Adds a control item to the report data.

    .DESCRIPTION
        Adds a security control assessment to the report and updates executive summary counts.

    .PARAMETER ReportData
        The report data object to add the item to.

    .PARAMETER Category
        Control category (Identity, Device, Data, Apps, Infrastructure).

    .PARAMETER SettingName
        Name of the security control.

    .PARAMETER CurrentValue
        Current state/value of the control.

    .PARAMETER ProposedValue
        Recommended state/value for the control.

    .PARAMETER Justification
        Explanation of why the control is important.

    .PARAMETER Risk
        Risk level: High, Medium, or Low.

    .PARAMETER Status
        Compliance status: Compliant, NonCompliant, NotApplicable, or Unknown.

    .PARAMETER SecureScoreImpact
        Score impact (e.g., "+5 points" or "+2.3%").

    .PARAMETER Reference
        Reference URL for documentation.

    .PARAMETER ActionUrl
        Direct URL to configure the setting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$SettingName,

        [Parameter(Mandatory = $false)]
        [string]$CurrentValue = "",

        [Parameter(Mandatory = $false)]
        [string]$ProposedValue = "",

        [Parameter(Mandatory = $false)]
        [string]$Justification = "No description available",

        [Parameter(Mandatory = $true)]
        [ValidateSet("High", "Medium", "Low")]
        [string]$Risk,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Compliant", "NonCompliant", "NotApplicable", "Unknown")]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$SecureScoreImpact = "",

        [Parameter(Mandatory = $false)]
        [string]$Reference = "",

        [Parameter(Mandatory = $false)]
        [string]$ActionUrl = ""
    )

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

    $ReportData.ProposedChanges.Add($item)
    $ReportData.ExecutiveSummary.TotalChecks++

    switch ($Status) {
        "Compliant" { $ReportData.ExecutiveSummary.Compliant++ }
        "NonCompliant" { $ReportData.ExecutiveSummary.NonCompliant++ }
        "NotApplicable" { $ReportData.ExecutiveSummary.NotApplicable++ }
    }

    switch ($Risk) {
        "High" { $ReportData.ExecutiveSummary.HighRisk++ }
        "Medium" { $ReportData.ExecutiveSummary.MediumRisk++ }
        "Low" { $ReportData.ExecutiveSummary.LowRisk++ }
    }
}

function Update-ReportMetadata {
    <#
    .SYNOPSIS
        Updates report metadata.

    .DESCRIPTION
        Sets metadata fields like tenant info, generation time, and scores.

    .PARAMETER ReportData
        The report data object to update.

    .PARAMETER TenantId
        Tenant identifier.

    .PARAMETER TenantName
        Tenant display name.

    .PARAMETER GeneratedBy
        User account that generated the report.

    .PARAMETER GeneratedDate
        Date/time the report was generated.

    .PARAMETER CurrentScore
        Current secure score value.

    .PARAMETER MaxScore
        Maximum possible secure score.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData,

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$TenantName,

        [Parameter(Mandatory = $false)]
        [string]$GeneratedBy,

        [Parameter(Mandatory = $false)]
        [string]$GeneratedDate,

        [Parameter(Mandatory = $false)]
        [int]$CurrentScore,

        [Parameter(Mandatory = $false)]
        [int]$MaxScore
    )

    if ($TenantId) { $ReportData.Metadata.TenantId = $TenantId }
    if ($TenantName) { $ReportData.Metadata.TenantName = $TenantName }
    if ($GeneratedBy) { $ReportData.Metadata.GeneratedBy = $GeneratedBy }
    if ($GeneratedDate) { $ReportData.Metadata.GeneratedDate = $GeneratedDate }
    if ($PSBoundParameters.ContainsKey('CurrentScore')) { $ReportData.ExecutiveSummary.CurrentScore = $CurrentScore }
    if ($PSBoundParameters.ContainsKey('MaxScore')) { $ReportData.ExecutiveSummary.MaxScore = $MaxScore }
}

function ConvertFrom-HtmlString {
    <#
    .SYNOPSIS
        Converts HTML string to plain text.

    .DESCRIPTION
        Removes HTML tags and decodes HTML entities.

    .PARAMETER HtmlText
        HTML string to convert.

    .OUTPUTS
        Plain text string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HtmlText
    )

    if ([string]::IsNullOrEmpty($HtmlText)) {
        return ""
    }

    # Convert common HTML tags to formatted text
    $text = $HtmlText
    $text = $text -replace '<br\s*/?>', "`n"
    $text = $text -replace '<p>', "`n"
    $text = $text -replace '</p>', "`n"
    $text = $text -replace '<li>', "`n• "
    $text = $text -replace '</li>', ''
    $text = $text -replace '<ul>', ''
    $text = $text -replace '</ul>', "`n"
    $text = $text -replace '<ol>', ''
    $text = $text -replace '</ol>', "`n"
    $text = $text -replace '<strong>', ''
    $text = $text -replace '</strong>', ''
    $text = $text -replace '<b>', ''
    $text = $text -replace '</b>', ''
    $text = $text -replace '<em>', ''
    $text = $text -replace '</em>', ''
    $text = $text -replace '<i>', ''
    $text = $text -replace '</i>', ''
    $text = $text -replace '<h\d>', "`n"
    $text = $text -replace '</h\d>', "`n"
    $text = $text -replace '<[^>]+>', ''

    # Decode HTML entities
    $text = $text -replace '&nbsp;', ' '
    $text = $text -replace '&lt;', '<'
    $text = $text -replace '&gt;', '>'
    $text = $text -replace '&amp;', '&'
    $text = $text -replace '&quot;', '"'
    $text = $text -replace '&lsquo;', "'"
    $text = $text -replace '&rsquo;', "'"
    $text = $text -replace '&ldquo;', '"'
    $text = $text -replace '&rdquo;', '"'

    # Clean up extra whitespace and newlines
    $text = $text -replace "`n`n`n+", "`n`n"
    $text = $text.Trim()

    return $text
}

function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        Encodes text for safe HTML output.

    .DESCRIPTION
        HTML encodes special characters to prevent XSS attacks.

    .PARAMETER Text
        Text to encode.

    .OUTPUTS
        HTML-encoded string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return ""
    }

    # HTML encode special characters to prevent XSS
    $encoded = $Text -replace '&', '&amp;'
    $encoded = $encoded -replace '<', '&lt;'
    $encoded = $encoded -replace '>', '&gt;'
    $encoded = $encoded -replace '"', '&quot;'
    $encoded = $encoded -replace "'", '&#39;'

    return $encoded
}

# Functions are exported via the main module manifest (.psd1)
