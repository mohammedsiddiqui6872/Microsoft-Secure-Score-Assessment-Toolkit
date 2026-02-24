#
# Microsoft Secure Score Assessment Toolkit
# PowerShell Module - Refactored Architecture
#

# Module base path
$script:ModuleRoot = $PSScriptRoot

# Import all required modules (use Join-Path for cross-platform compatibility)
$CoreModules = @(
    (Join-Path 'Core' 'GraphApiClient.ps1'),
    (Join-Path 'Core' 'Models.ps1'),
    (Join-Path 'Core' 'Logger.ps1')
)

$ProcessorModules = @(
    (Join-Path 'Processors' 'ComplianceProcessor.ps1'),
    (Join-Path 'Processors' 'UrlProcessor.ps1')
)

$ReportModules = @(
    (Join-Path 'Reports' 'HtmlReportGenerator.ps1')
)

# Import all modules - fail fast if any are missing
$AllModules = $CoreModules + $ProcessorModules + $ReportModules
foreach ($module in $AllModules) {
    $modulePath = Join-Path $script:ModuleRoot $module
    if (Test-Path $modulePath) {
        . $modulePath
    }
    else {
        throw "Required module file not found: $modulePath. Please reinstall the module."
    }
}

# Module-level variables
$script:CurrentContext = $null

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

    try {
        Write-Host "`n=== Microsoft Secure Score Authentication ===" -ForegroundColor Cyan
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow

        # Check if Microsoft.Graph modules are installed
        $requiredModules = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Security'
        )

        foreach ($moduleName in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue)) {
                throw "$moduleName module is not installed. Please install it first:`n  Install-Module -Name $moduleName -Scope CurrentUser"
            }
        }

        # Import required modules
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Security -ErrorAction Stop

        # Connect using the GraphApiClient
        if ($UseDeviceCode) {
            $script:CurrentContext = Connect-SecureScoreGraph -UseDeviceCode
        }
        else {
            $script:CurrentContext = Connect-SecureScoreGraph
        }

        Write-Host "`nAuthentication successful!" -ForegroundColor Green
        Write-Host "Tenant ID: $($script:CurrentContext.TenantId)" -ForegroundColor Cyan
        Write-Host "Account: $($script:CurrentContext.Account)" -ForegroundColor Cyan
        Write-Host "`nYou can now run: Invoke-MicrosoftSecureScore" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Authentication failed: $_"
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have Security Reader or Global Reader role" -ForegroundColor White
        Write-Host "2. Check your internet connection" -ForegroundColor White
        Write-Host "3. Try using -UseDeviceCode parameter for alternative authentication" -ForegroundColor White
        throw
    }
}

function Disconnect-MicrosoftSecureScore {
    <#
    .SYNOPSIS
        Disconnect from Microsoft Graph and clean up session.

    .DESCRIPTION
        Disconnects the current Microsoft Graph session and clears the module's connection context.

    .EXAMPLE
        Disconnect-MicrosoftSecureScore
        Disconnects from Microsoft Graph.
    #>
    [CmdletBinding()]
    param()

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disconnected from Microsoft Graph successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Error during disconnect: $_"
    }
    finally {
        # Clean up all module-level state
        $script:CurrentContext = $null
        $script:ControlMappingsCache = $null
        $script:ControlMappingsFlat = $null
        $script:ConfigPath = $null
        $script:LogFilePath = $null
        $script:LogToFile = $false
        $script:LogToConsole = $true
    }
}

function Invoke-MicrosoftSecureScore {
    <#
    .SYNOPSIS
        Generate Microsoft Secure Score assessment report.

    .DESCRIPTION
        Fetches 400+ security controls from Microsoft Graph Secure Score API and generates
        a comprehensive HTML report with interactive filtering and assessment guidance.

    .PARAMETER TenantName
        Display name for your organization in the report. Defaults to "Your Organization".

    .PARAMETER ApplicableOnly
        Generate report showing only controls applicable to your tenant (typically ~70 controls).
        By default, shows all 400+ available controls.

    .PARAMETER ReportPath
        Path where the HTML report will be saved. Defaults to current directory with timestamp.

    .PARAMETER LogPath
        Path where the log file will be saved. If not specified, logging to file is disabled.

    .PARAMETER CsvPath
        Path where the CSV export will be saved. If not specified, CSV export is skipped.

    .PARAMETER NoOpen
        Do not automatically open the report in the default browser after generation.

    .PARAMETER ExcludeCategories
        Array of category names to exclude from the report.
        Valid categories: Identity, Defender, Exchange, SharePoint, Groups, Teams, Compliance, Intune.

    .EXAMPLE
        Invoke-MicrosoftSecureScore
        Generates a full report with all 400+ controls.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -ApplicableOnly
        Generates a report showing only applicable controls for your tenant.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -TenantName "Contoso Corporation"
        Generates a report with custom organization name.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -ReportPath "C:\Reports\SecureScore.html" -LogPath "C:\Logs\SecureScore.log"
        Generates a report and log at specified locations.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -ExcludeCategories @("Exchange", "SharePoint")
        Generates a report excluding Exchange and SharePoint controls.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -CsvPath "C:\Reports\SecureScore.csv"
        Generates an HTML report and exports results to CSV.

    .EXAMPLE
        Invoke-MicrosoftSecureScore -NoOpen
        Generates a report without opening it in the browser.

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
        [string]$ReportPath,

        [Parameter(Mandatory = $false)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [switch]$NoOpen,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Identity", "Defender", "Exchange", "SharePoint", "Groups", "Teams", "Compliance", "Intune")]
        [string[]]$ExcludeCategories
    )

    try {
        # Validate output paths - ensure parent directories exist
        if ($ReportPath) {
            $reportDir = Split-Path -Path $ReportPath -Parent
            if ($reportDir -and -not (Test-Path $reportDir)) {
                throw "Report output directory does not exist: $reportDir"
            }
        }
        if ($LogPath) {
            $logDir = Split-Path -Path $LogPath -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                throw "Log output directory does not exist: $logDir"
            }
        }
        if ($CsvPath) {
            $csvDir = Split-Path -Path $CsvPath -Parent
            if ($csvDir -and -not (Test-Path $csvDir)) {
                throw "CSV output directory does not exist: $csvDir"
            }
        }

        # Restore context from Graph if we lost it (e.g., module reload)
        if (-not $script:CurrentContext) {
            $context = Get-MgContext
            if ($context) {
                $script:CurrentContext = @{
                    TenantId = $context.TenantId
                    Account = $context.Account
                }
                Write-Verbose "Restored context from active Graph connection"
            }
        }

        # Check if authenticated
        if (-not (Test-GraphConnection)) {
            throw "Not authenticated to Microsoft Graph. Please run Connect-MicrosoftSecureScore first."
        }

        # Set default report path if not provided
        if (-not $ReportPath) {
            $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $ReportPath = Join-Path (Get-Location) "SecureScore-Report-$timestamp.html"
        }

        # Initialize logger
        if ($LogPath) {
            Initialize-Logger -LogPath $LogPath -LogToConsole $true -LogToFile $true
        }
        else {
            Initialize-Logger -LogToConsole $true -LogToFile $false
        }

        Write-LogSection -Title "Microsoft Secure Score Assessment" -Level Info
        Write-Log "Tenant: $TenantName" -Level Info
        Write-Log "Mode: $(if ($ApplicableOnly) { 'Applicable Controls Only' } else { 'All Controls' })" -Level Info
        Write-Log "Report Path: $ReportPath" -Level Info
        if ($LogPath) {
            Write-Log "Log Path: $LogPath" -Level Info
        }
        if ($CsvPath) {
            Write-Log "CSV Export Path: $CsvPath" -Level Info
        }
        if ($ExcludeCategories -and $ExcludeCategories.Count -gt 0) {
            Write-Log "Excluded Categories: $($ExcludeCategories -join ', ')" -Level Info
        }

        # Initialize URL processor with config
        $configPath = Join-Path $script:ModuleRoot (Join-Path 'Config' 'control-mappings.json')
        Initialize-UrlProcessor -ConfigPath $configPath
        Write-Log "URL processor initialized with mappings from config" -Level Success

        # Fetch organization information
        Write-LogSection -Title "Fetching Organization Information" -Level Info
        $orgInfo = Get-OrganizationInfo
        $actualTenantName = if ($TenantName -ne "Your Organization") {
            $TenantName
        }
        elseif ($orgInfo.DisplayName) {
            $orgInfo.DisplayName
        }
        else {
            "Organization"
        }
        Write-Log "Organization Name: $actualTenantName" -Level Success

        # Fetch secure score data
        Write-LogSection -Title "Fetching Secure Score Data" -Level Info
        $scoreData = Get-SecureScoreData
        Write-Log "Current Score: $($scoreData.CurrentScore) / $($scoreData.MaxScore)" -Level Success
        $scorePercentage = if ($scoreData.MaxScore -gt 0) {
            [math]::Round(($scoreData.CurrentScore / $scoreData.MaxScore) * 100, 1)
        } else { 0 }
        Write-Log "Percentage: $scorePercentage%" -Level Success

        # Fetch control profiles
        Write-LogSection -Title "Fetching Control Profiles" -Level Info
        $scoredControlsList = $scoreData.ControlScores.Keys

        $controlParams = @{
            FilterApplicableOnly = $ApplicableOnly
        }
        if ($ApplicableOnly) {
            $controlParams['ScoredControlsList'] = $scoredControlsList
        }

        $controls = Get-SecureScoreControlProfiles @controlParams
        Write-Log "Retrieved $($controls.Count) control profiles" -Level Success

        # Group by category for summary
        $categories = $controls | Group-Object -Property ControlCategory | Sort-Object Count -Descending
        Write-Log "Control Summary by Category:" -Level Info
        foreach ($category in $categories) {
            Write-Log "  $($category.Name): $($category.Count) controls" -Level Info
        }

        # Initialize report data
        Write-LogSection -Title "Processing Controls" -Level Info
        $reportData = New-ReportData

        # Update report metadata
        Update-ReportMetadata -ReportData $reportData `
            -TenantId $script:CurrentContext.TenantId `
            -TenantName $actualTenantName `
            -GeneratedBy $script:CurrentContext.Account `
            -GeneratedDate (Get-Date -Format "MMMM dd, yyyy HH:mm:ss") `
            -CurrentScore $scoreData.CurrentScore `
            -MaxScore $scoreData.MaxScore

        # Process each control
        # Pre-calculate the effective total for stable progress reporting
        $excludedCount = 0
        if ($ExcludeCategories -and $ExcludeCategories.Count -gt 0) {
            foreach ($ctrl in $controls) {
                if ($ctrl.ControlCategory -in $ExcludeCategories) {
                    $excludedCount++
                }
            }
        }
        $effectiveTotal = $controls.Count - $excludedCount
        $processedCount = 0
        $skippedCount = 0

        foreach ($control in $controls) {
            # Check if category should be excluded (before incrementing processed count)
            if ($ExcludeCategories -and $ExcludeCategories.Count -gt 0) {
                if ($control.ControlCategory -in $ExcludeCategories) {
                    Write-Log "Excluded control from category '$($control.ControlCategory)': $($control.Title)" -Level Info -NoConsole
                    continue
                }
            }

            $processedCount++

            # Log progress (based on pre-calculated non-excluded total)
            if ($effectiveTotal -gt 0) {
                Write-LogProgress -Activity "Processing Secure Score Controls" `
                    -Current $processedCount `
                    -Total $effectiveTotal `
                    -FileLogInterval 50
            }

            # Validate control data
            if (-not (Test-ControlDataValid -Control $control)) {
                $skippedCount++
                Write-Log "Skipped invalid control: $($control.Id)" -Level Warning -NoConsole
                continue
            }

            # Extract control properties
            $controlId = $control.Id
            $title = $control.Title
            $category = $control.ControlCategory
            $maxScore = $control.MaxScore
            $implementationCost = $control.ImplementationCost
            $userImpact = $control.UserImpact
            $threats = $control.Threats -join ", "
            $remediation = ConvertFrom-HtmlString -HtmlText $control.Remediation

            # Optimize action URL
            $actionUrl = Optimize-ControlUrl -Url $control.ActionUrl `
                -ControlName $title `
                -TenantId $script:CurrentContext.TenantId

            # Determine compliance status and risk
            $complianceStatus = Get-ComplianceStatus -ControlId $controlId `
                -ControlScores $scoreData.ControlScores `
                -MaxScore $maxScore

            $riskLevel = Get-RiskLevel -MaxScore $maxScore `
                -UserImpact $userImpact `
                -Threats $threats

            # Build values
            $currentValue = Get-ControlCurrentValue -ControlId $controlId `
                -ControlScores $scoreData.ControlScores `
                -MaxScore $maxScore

            $proposedValue = Get-ControlProposedValue -MaxScore $maxScore `
                -ImplementationCost $implementationCost `
                -UserImpact $userImpact

            $justification = Get-ControlJustification -Threats $threats `
                -Remediation $remediation

            $scoreImpact = Get-ScoreImpact -ControlMaxScore $maxScore `
                -TotalMaxScore $scoreData.MaxScore

            # Add to report
            Add-ReportItem -ReportData $reportData `
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

        Write-Log -Level Info
        Write-Log "Processed $processedCount controls" -Level Success
        if ($excludedCount -gt 0) {
            Write-Log "Excluded $excludedCount controls based on category filter" -Level Info
        }
        if ($skippedCount -gt 0) {
            Write-Log "Skipped $skippedCount invalid controls" -Level Warning
        }
        Write-Log "Collected $($reportData.ProposedChanges.Count) configuration items" -Level Success

        # Export to CSV if requested
        if ($CsvPath) {
            Write-LogSection -Title "Exporting CSV Report" -Level Info
            try {
                $csvData = $reportData.ProposedChanges | ForEach-Object {
                    [PSCustomObject]@{
                        Category          = $_.Category
                        SettingName       = $_.SettingName
                        Status            = $_.Status
                        Risk              = $_.Risk
                        CurrentValue      = $_.CurrentValue
                        ProposedValue     = $_.ProposedValue
                        Justification     = $_.Justification
                        SecureScoreImpact = $_.SecureScoreImpact
                        ActionUrl         = $_.ActionUrl
                    }
                }
                $csvData | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Log "CSV exported successfully: $CsvPath" -Level Success
            }
            catch {
                Write-Log "Failed to export CSV: $_" -Level Error
                Write-Warning "CSV export failed: $_"
            }
        }

        # Generate HTML report
        Write-LogSection -Title "Generating HTML Report" -Level Info
        $templatePath = Join-Path $script:ModuleRoot "Templates"

        $reportParams = @{
            ReportData   = $reportData
            TemplatePath = $templatePath
            OutputPath   = $ReportPath
        }

        $generatedReport = New-HtmlReport @reportParams
        Write-Log "Report generated successfully!" -Level Success
        Write-Log "Report location: $generatedReport" -Level Info

        # Close logger
        Close-Logger

        # Open report in browser unless suppressed
        if (-not $NoOpen) {
            Write-Host "`nOpening report in default browser..." -ForegroundColor Cyan
            Start-Process $generatedReport
        }

        Write-Host "`n=== Assessment Complete ===" -ForegroundColor Green
        Write-Host "Report: $generatedReport" -ForegroundColor Cyan
        if ($CsvPath) {
            Write-Host "CSV: $CsvPath" -ForegroundColor Cyan
        }
        if ($LogPath) {
            Write-Host "Log: $LogPath" -ForegroundColor Cyan
        }

        return $generatedReport
    }
    catch {
        Write-Error "Failed to generate secure score assessment: $_"
        Write-Log "Error: $_" -Level Error
        Close-Logger
        throw
    }
}

function Get-MicrosoftSecureScoreInfo {
    <#
    .SYNOPSIS
        Display information about the Microsoft Secure Score Assessment Toolkit.

    .DESCRIPTION
        Shows version information, usage instructions, and helpful links for the toolkit.
        Returns a PSCustomObject with module metadata for programmatic access.

    .EXAMPLE
        Get-MicrosoftSecureScoreInfo
        Displays toolkit information and usage guide.

    .EXAMPLE
        $info = Get-MicrosoftSecureScoreInfo
        $info.Version
        Gets the toolkit version programmatically.

    .OUTPUTS
        PSCustomObject containing Version, Description, Features, Requirements, and Links.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # Read version from module manifest
    $manifestPath = Join-Path $script:ModuleRoot "Microsoft-Secure-Score-Assessment-Toolkit.psd1"
    $version = "Unknown"
    if (Test-Path $manifestPath) {
        try {
            $manifestData = Import-PowerShellDataFile -Path $manifestPath
            $version = $manifestData.ModuleVersion
        }
        catch {
            $version = "Unknown"
        }
    }

    Write-Host "`n=====================================================================" -ForegroundColor Cyan
    Write-Host "   Microsoft Secure Score Assessment Toolkit v$version" -ForegroundColor Cyan
    Write-Host "   Modular Architecture - Enterprise Security Assessment" -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan

    Write-Host "`nDESCRIPTION:" -ForegroundColor Yellow
    Write-Host "  Generate comprehensive security reports with over 400 Microsoft" -ForegroundColor White
    Write-Host "  Secure Score controls fetched directly from Microsoft Graph API." -ForegroundColor White

    Write-Host "`nQUICK START:" -ForegroundColor Yellow
    Write-Host "  1. Connect-MicrosoftSecureScore" -ForegroundColor Green
    Write-Host "     Authenticate to Microsoft Graph" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Invoke-MicrosoftSecureScore" -ForegroundColor Green
    Write-Host "     Generate full assessment report with 400+ controls" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. Disconnect-MicrosoftSecureScore" -ForegroundColor Green
    Write-Host "     Clean up Microsoft Graph session" -ForegroundColor Gray

    Write-Host "`nCOMMON EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  # Full report with all controls" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Only applicable controls with logging" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore -ApplicableOnly -LogPath 'C:\Logs\assessment.log'" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Export to CSV for analysis" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore -CsvPath 'C:\Reports\SecureScore.csv'" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Exclude categories and suppress browser" -ForegroundColor Gray
    Write-Host "  Invoke-MicrosoftSecureScore -ExcludeCategories @('Exchange','SharePoint') -NoOpen" -ForegroundColor White

    Write-Host "`nFEATURES:" -ForegroundColor Yellow
    Write-Host "  - Modular architecture with separated concerns" -ForegroundColor Green
    Write-Host "  - Category filtering with ExcludeCategories parameter" -ForegroundColor Green
    Write-Host "  - CSV export for spreadsheet analysis" -ForegroundColor Green
    Write-Host "  - File-based logging support" -ForegroundColor Green
    Write-Host "  - Externalized configuration (JSON)" -ForegroundColor Green
    Write-Host "  - Template-based HTML generation" -ForegroundColor Green

    Write-Host "`nREQUIREMENTS:" -ForegroundColor Yellow
    Write-Host "  - Microsoft Graph PowerShell SDK" -ForegroundColor White
    Write-Host "  - SecurityEvents.Read.All permission" -ForegroundColor White
    Write-Host "  - Security Reader or Global Reader role" -ForegroundColor White

    Write-Host "`nLINKS:" -ForegroundColor Yellow
    Write-Host "  GitHub: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-Assessment-Toolkit" -ForegroundColor Cyan
    Write-Host "  Issues: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-Assessment-Toolkit/issues" -ForegroundColor Cyan

    Write-Host "`nSUPPORT:" -ForegroundColor Yellow
    Write-Host "  Buy Me a Coffee: https://buymeacoffee.com/mohammedsiddiqui" -ForegroundColor Magenta
    Write-Host ""

    # Return structured object for programmatic access
    return [PSCustomObject]@{
        Version      = $version
        Description  = "PowerShell toolkit for assessing Microsoft 365 security posture through Microsoft Secure Score API"
        Features     = @(
            "Modular architecture with separated concerns",
            "Category filtering with ExcludeCategories parameter",
            "CSV export for spreadsheet analysis",
            "File-based logging support",
            "Externalized configuration (JSON)",
            "Template-based HTML generation"
        )
        Requirements = @(
            "Microsoft.Graph.Authentication module",
            "Microsoft.Graph.Security module",
            "SecurityEvents.Read.All permission",
            "Security Reader or Global Reader role"
        )
        Links        = @{
            GitHub  = "https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-Assessment-Toolkit"
            Issues  = "https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-Assessment-Toolkit/issues"
            Support = "https://buymeacoffee.com/mohammedsiddiqui"
        }
    }
}

# Export only public functions - internal functions remain private
Export-ModuleMember -Function @(
    'Connect-MicrosoftSecureScore',
    'Disconnect-MicrosoftSecureScore',
    'Invoke-MicrosoftSecureScore',
    'Get-MicrosoftSecureScoreInfo'
)
