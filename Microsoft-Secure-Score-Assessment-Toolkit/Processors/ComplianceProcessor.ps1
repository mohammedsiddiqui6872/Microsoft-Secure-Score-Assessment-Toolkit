function Get-RiskLevel {
    <#
    .SYNOPSIS
        Determines risk level for a control.

    .DESCRIPTION
        Calculates risk level based on MaxScore and UserImpact.

    .PARAMETER MaxScore
        Maximum score points for the control.

    .PARAMETER UserImpact
        User impact level (High, Medium, Low).

    .PARAMETER Threats
        Threat description (currently not used in calculation).

    .OUTPUTS
        String: "High", "Medium", or "Low".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$MaxScore,

        [Parameter(Mandatory = $false)]
        [string]$UserImpact,

        [Parameter(Mandatory = $false)]
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
    <#
    .SYNOPSIS
        Determines compliance status for a control.

    .DESCRIPTION
        Determines if a control is Compliant, NonCompliant, NotApplicable, or Unknown
        based on actual scores from the tenant.

    .PARAMETER ControlId
        Control identifier.

    .PARAMETER ControlScores
        Hashtable of control scores from the tenant.

    .PARAMETER MaxScore
        Maximum possible score for the control.

    .OUTPUTS
        String: "Compliant", "NonCompliant", "NotApplicable", or "Unknown".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlId,

        [Parameter(Mandatory = $true)]
        [hashtable]$ControlScores,

        [Parameter(Mandatory = $true)]
        [int]$MaxScore
    )

    # Check if control is being scored in this tenant
    if ($ControlScores.ContainsKey($ControlId)) {
        $scoreData = $ControlScores[$ControlId]
        $actualScore = $scoreData.Score

        if ($actualScore -eq $MaxScore) {
            # Fully compliant - achieved max score
            return "Compliant"
        }
        elseif ($actualScore -gt 0) {
            # Partially compliant - some points but not all
            return "NonCompliant"
        }
        else {
            # Not compliant - 0 points
            return "NonCompliant"
        }
    }
    else {
        # Control not being scored in this tenant - not applicable
        return "NotApplicable"
    }
}

function Get-ControlCurrentValue {
    <#
    .SYNOPSIS
        Gets the current value description for a control.

    .DESCRIPTION
        Builds a description of the control's current state based on score data.

    .PARAMETER ControlId
        Control identifier.

    .PARAMETER ControlScores
        Hashtable of control scores from the tenant.

    .PARAMETER MaxScore
        Maximum possible score for the control.

    .OUTPUTS
        String describing the current value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlId,

        [Parameter(Mandatory = $true)]
        [hashtable]$ControlScores,

        [Parameter(Mandatory = $true)]
        [int]$MaxScore
    )

    if ($ControlScores.ContainsKey($ControlId)) {
        $scoreData = $ControlScores[$ControlId]
        $actualScore = $scoreData.Score
        $currentValue = "Score: $actualScore / $MaxScore points"

        if ($scoreData.Description) {
            $description = ConvertFrom-HtmlString -HtmlText $scoreData.Description
            $currentValue += " - " + $description
        }

        return $currentValue
    }
    else {
        return "Not applicable to your tenant (not being scored)"
    }
}

function Get-ControlProposedValue {
    <#
    .SYNOPSIS
        Gets the proposed value description for a control.

    .DESCRIPTION
        Builds a description of what the control should be configured to.

    .PARAMETER MaxScore
        Maximum possible score for the control.

    .PARAMETER ImplementationCost
        Implementation cost level.

    .PARAMETER UserImpact
        User impact level.

    .OUTPUTS
        String describing the proposed value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$MaxScore,

        [Parameter(Mandatory = $false)]
        [string]$ImplementationCost,

        [Parameter(Mandatory = $false)]
        [string]$UserImpact
    )

    $proposedValue = "Score: $MaxScore / $MaxScore points (Fully Compliant)"

    if ($ImplementationCost -or $UserImpact) {
        $proposedValue += " | Implementation Cost: $ImplementationCost, User Impact: $UserImpact"
    }

    return $proposedValue
}

function Get-ControlJustification {
    <#
    .SYNOPSIS
        Builds justification text for a control.

    .DESCRIPTION
        Combines threats and remediation into a comprehensive justification.

    .PARAMETER Threats
        Threats mitigated by this control.

    .PARAMETER Remediation
        Remediation steps and impact.

    .OUTPUTS
        String containing the full justification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Threats,

        [Parameter(Mandatory = $false)]
        [string]$Remediation
    )

    $justification = if ([string]::IsNullOrWhiteSpace($Remediation)) {
        "No description available from API"
    } else {
        $Remediation
    }

    if (-not [string]::IsNullOrWhiteSpace($Threats)) {
        $justification = "Threats: $Threats. " + $justification
    }

    return $justification
}

function Get-ScoreImpact {
    <#
    .SYNOPSIS
        Calculates score impact as a percentage.

    .DESCRIPTION
        Calculates what percentage of the total score this control represents.

    .PARAMETER ControlMaxScore
        Maximum score for this control.

    .PARAMETER TotalMaxScore
        Total maximum score across all controls.

    .OUTPUTS
        String representing the score impact (e.g., "+2.3%").
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ControlMaxScore,

        [Parameter(Mandatory = $true)]
        [int]$TotalMaxScore
    )

    if ($TotalMaxScore -gt 0) {
        $impactPercentage = [math]::Round(($ControlMaxScore / $TotalMaxScore) * 100, 2)
        return "+$impactPercentage%"
    }
    else {
        return "+$ControlMaxScore points"
    }
}

function Test-ControlDataValid {
    <#
    .SYNOPSIS
        Validates control data from the API.

    .DESCRIPTION
        Performs basic validation on control properties to catch malformed or
        potentially malicious data before processing.

    .PARAMETER Control
        The control object from the Microsoft Graph API.

    .OUTPUTS
        Boolean indicating if the control data is valid.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Control
    )

    # Check required properties exist
    if (-not $Control.Id) {
        Write-Verbose "Control missing Id property"
        return $false
    }

    if (-not $Control.Title) {
        Write-Verbose "Control $($Control.Id) missing Title property"
        return $false
    }

    # Validate Id format (should be alphanumeric with possible underscores/hyphens)
    if ($Control.Id -notmatch '^[a-zA-Z0-9_\-\.]+$') {
        Write-Warning "Control Id contains invalid characters: $($Control.Id)"
        return $false
    }

    # Validate MaxScore is a reasonable number (0-100)
    if ($Control.MaxScore -and ($Control.MaxScore -lt 0 -or $Control.MaxScore -gt 100)) {
        Write-Warning "Control $($Control.Id) has invalid MaxScore: $($Control.MaxScore)"
        return $false
    }

    # Warn about non-standard ActionUrl but do not reject the control
    if ($Control.ActionUrl -and $Control.ActionUrl -notmatch '^https?://') {
        Write-Verbose "Control $($Control.Id) has non-standard ActionUrl format: $($Control.ActionUrl)"
    }

    return $true
}

# Functions are exported via the main module manifest (.psd1)
