#
# Microsoft Secure Score Remediation Toolkit
# PowerShell Module
#

# Script-level variables
$script:currentTenantId = $null
$script:currentUserAccount = $null

function Connect-MicrosoftSecureScore {
    <#
    .SYNOPSIS
        Authenticate to Microsoft Graph for Secure Score API access.

    .DESCRIPTION
        Establishes a connection to Microsoft Graph with the required permissions to access
        Microsoft Secure Score data. This function must be run before using Invoke-MicrosoftSecureScore.

    .PARAMETER UseDeviceCode
        Use device code authentication instead of interactive browser authentication.
        Useful for headless environments or remote sessions.

    .EXAMPLE
        Connect-MicrosoftSecureScore
        Connects using interactive browser authentication.

    .EXAMPLE
        Connect-MicrosoftSecureScore -UseDeviceCode
        Connects using device code authentication.

    .NOTES
        Requires SecurityEvents.Read.All permission in Microsoft Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$UseDeviceCode
    )

    Write-Host "`n=== Microsoft Secure Score Authentication ===" -ForegroundColor Cyan
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow

    # Check if Microsoft.Graph module is installed
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "Microsoft.Graph.Authentication module not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
            Write-Host "Microsoft.Graph.Authentication module installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install Microsoft.Graph.Authentication module: $_"
            return
        }
    }

    # Import the module
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    # Define required scopes
    $requiredScopes = @(
        "SecurityEvents.Read.All",
        "Organization.Read.All"
    )

    try {
        # Connect to Microsoft Graph
        if ($UseDeviceCode) {
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -ContextScope Process -NoWelcome
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -ContextScope Process -NoWelcome
        }

        # Get connection context
        $context = Get-MgContext
        if (-not $context) {
            Write-Error "Failed to establish Microsoft Graph connection."
            return
        }

        # Store tenant and user info
        $script:currentTenantId = $context.TenantId
        $script:currentUserAccount = $context.Account

        Write-Host "`nAuthentication successful!" -ForegroundColor Green
        Write-Host "Tenant ID: $($script:currentTenantId)" -ForegroundColor Cyan
        Write-Host "Account: $($script:currentUserAccount)" -ForegroundColor Cyan
        Write-Host "`nYou can now run: Invoke-MicrosoftSecureScore" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Authentication failed: $_"
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have Security Reader or Global Reader role" -ForegroundColor White
        Write-Host "2. Check your internet connection" -ForegroundColor White
        Write-Host "3. Try using -UseDeviceCode parameter for alternative authentication" -ForegroundColor White
    }
}

function Invoke-MicrosoftSecureScore {
    <#
    .SYNOPSIS
        Generate Microsoft Secure Score assessment report.

    .DESCRIPTION
        Fetches 411+ security controls from Microsoft Graph Secure Score API and generates
        a comprehensive HTML report with interactive filtering and remediation guidance.

    .PARAMETER TenantName
        Display name for your organization in the report. Defaults to "Your Organization".

    .PARAMETER ApplicableOnly
        Generate report showing only controls applicable to your tenant (typically ~70 controls).
        By default, shows all 411+ available controls.

    .PARAMETER ReportPath
        Path where the HTML report will be saved. Defaults to current directory with timestamp.

    .EXAMPLE
        Invoke-MicrosoftSecureScore
        Generates a full report with all 411+ controls.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -ApplicableOnly
        Generates a report showing only applicable controls for your tenant.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -TenantName "Contoso Corporation"
        Generates a report with custom organization name.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -ReportPath "C:\Reports\SecureScore.html"
        Generates a report at specified location.

    .NOTES
        You must run Connect-MicrosoftSecureScore before using this function.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantName = "Your Organization",

        [Parameter(Mandatory = $false)]
        [switch]$ApplicableOnly,

        [Parameter(Mandatory = $false)]
        [string]$ReportPath
    )

    # Check if authenticated
    $context = Get-MgContext
    if (-not $context) {
        Write-Error "Not authenticated to Microsoft Graph. Please run Connect-MicrosoftSecureScore first."
        Write-Host "`nExample:" -ForegroundColor Yellow
        Write-Host "  Connect-MicrosoftSecureScore" -ForegroundColor White
        Write-Host "  Invoke-MicrosoftSecureScore" -ForegroundColor White
        return
    }

    # Set default report path if not provided
    if (-not $ReportPath) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $ReportPath = Join-Path (Get-Location) "SecureScore-Report-$timestamp.html"
    }

    Write-Host "`n=== Microsoft Secure Score Assessment ===" -ForegroundColor Cyan
    Write-Host "Tenant: $TenantName" -ForegroundColor Yellow
    Write-Host "Mode: $(if ($ApplicableOnly) { 'Applicable Controls Only' } else { 'All Controls (411 plus)' })" -ForegroundColor Yellow

    # Build parameters for the main script
    $scriptPath = Join-Path $PSScriptRoot "SecureScore-Remediation-API.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Error "SecureScore-Remediation-API.ps1 not found in module directory."
        return
    }

    # Execute the main script
    $params = @{
        WhatIf = $true
        TenantName = $TenantName
        ReportPath = $ReportPath
        SkipModuleCheck = $true
    }

    if ($ApplicableOnly) {
        $params['OnlyApplicableControls'] = $true
    }

    & $scriptPath @params

    Write-Host "`nReport generated: $ReportPath" -ForegroundColor Green
}

function Get-MicrosoftSecureScoreInfo {
    <#
    .SYNOPSIS
        Display information about the Microsoft Secure Score Remediation Toolkit.

    .DESCRIPTION
        Shows version information, usage instructions, and helpful links for the toolkit.

    .EXAMPLE
        Get-MicrosoftSecureScoreInfo
        Displays toolkit information and usage guide.
    #>
    [CmdletBinding()]
    param()

    $version = "1.2.0"

    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Microsoft Secure Score Remediation Toolkit v$version        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    Write-Host "`nDESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Generate comprehensive security reports with 411 plus Microsoft" -ForegroundColor White
    Write-Host "  Secure Score controls fetched directly from Microsoft Graph API." -ForegroundColor White

    Write-Host "`nQUICK START:" -ForegroundColor Yellow
    Write-Host "  1. Connect-MicrosoftSecureScore" -ForegroundColor Green
    Write-Host "     Authenticate to Microsoft Graph" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Invoke-MicrosoftSecureScore" -ForegroundColor Green
    Write-Host "     Generate full assessment report (411 plus controls)" -ForegroundColor Gray

    Write-Host "`nCOMMON EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  # Full report with all controls" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Only applicable controls" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore -ApplicableOnly" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Custom organization name" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore -TenantName 'Contoso Corp'" -ForegroundColor White

    Write-Host "`nREQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "  • Microsoft Graph PowerShell SDK" -ForegroundColor White
    Write-Host "  • SecurityEvents.Read.All permission" -ForegroundColor White
    Write-Host "  • Security Reader or Global Reader role" -ForegroundColor White

    Write-Host "`nLINKS:" -ForegroundColor Yellow
    Write-Host "  GitHub: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit" -ForegroundColor Cyan
    Write-Host "  Issues: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues" -ForegroundColor Cyan

    Write-Host "`nSUPPORT:" -ForegroundColor Yellow
    Write-Host "  Buy Me a Coffee: https://buymeacoffee.com/mohammedsiddiqui" -ForegroundColor Magenta
    Write-Host ""
}

# Export module members
Export-ModuleMember -Function @(
    'Connect-MicrosoftSecureScore',
    'Invoke-MicrosoftSecureScore',
    'Get-MicrosoftSecureScoreInfo'
)
