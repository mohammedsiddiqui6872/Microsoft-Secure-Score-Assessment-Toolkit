# Module-level variables for logger state
$script:LogFilePath = $null
$script:LogToFile = $false
$script:LogToConsole = $true

function Initialize-Logger {
    <#
    .SYNOPSIS
        Initializes the logging system.

    .DESCRIPTION
        Sets up logging configuration including file path and output options.

    .PARAMETER LogPath
        Path to the log file. If not specified, file logging is disabled.

    .PARAMETER LogToConsole
        Whether to write logs to console. Default is $true.

    .PARAMETER LogToFile
        Whether to write logs to file. Default is $true if LogPath is provided.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [bool]$LogToConsole = $true,

        [Parameter(Mandatory = $false)]
        [bool]$LogToFile = $true
    )

    $script:LogToConsole = $LogToConsole

    if ($LogPath) {
        $script:LogFilePath = $LogPath
        $script:LogToFile = $LogToFile

        # Create log directory if it doesn't exist
        $logDir = Split-Path -Path $LogPath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }

        # Create or clear log file
        if ($script:LogToFile) {
            try {
                # Write header to log file
                $header = @"
=================================================================
Microsoft Secure Score Assessment Toolkit - Log File
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
=================================================================

"@
                $header | Out-File -FilePath $LogPath -Encoding UTF8 -Force
            }
            catch {
                Write-Warning "Failed to initialize log file: $_"
                $script:LogToFile = $false
            }
        }
    }
    else {
        $script:LogToFile = $false
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message.

    .DESCRIPTION
        Writes a log message to console and/or file based on configuration.

    .PARAMETER Message
        The message to log. Can be empty for blank lines.

    .PARAMETER Level
        Log level: Info, Success, Warning, or Error.

    .PARAMETER NoConsole
        Suppress console output for this message only.

    .PARAMETER NoFile
        Suppress file output for this message only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Message = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug")]
        [string]$Level = "Info",

        [Parameter(Mandatory = $false)]
        [switch]$NoConsole,

        [Parameter(Mandatory = $false)]
        [switch]$NoFile
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output
    if ($script:LogToConsole -and -not $NoConsole) {
        $color = switch ($Level) {
            "Info" { "Cyan" }
            "Success" { "Green" }
            "Warning" { "Yellow" }
            "Error" { "Red" }
            "Debug" { "Gray" }
            default { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }

    # File output
    if ($script:LogToFile -and $script:LogFilePath -and -not $NoFile) {
        try {
            $logMessage | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
        }
        catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}

function Write-LogSection {
    <#
    .SYNOPSIS
        Writes a section header to the log.

    .DESCRIPTION
        Writes a formatted section header with separator lines.

    .PARAMETER Title
        Section title.

    .PARAMETER Level
        Log level for the section header.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $separator = "=" * 60
    Write-Log -Level $Level
    Write-Log -Message $separator -Level $Level
    Write-Log -Message $Title -Level $Level
    Write-Log -Message $separator -Level $Level
    Write-Log -Level $Level
}

function Write-LogProgress {
    <#
    .SYNOPSIS
        Writes progress information to the log.

    .DESCRIPTION
        Logs progress without cluttering the file (file logging only every Nth call).

    .PARAMETER Activity
        Activity description.

    .PARAMETER Current
        Current item number.

    .PARAMETER Total
        Total number of items.

    .PARAMETER FileLogInterval
        Write to file every N items. Default is 50.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter(Mandatory = $true)]
        [int]$Current,

        [Parameter(Mandatory = $true)]
        [int]$Total,

        [Parameter(Mandatory = $false)]
        [int]$FileLogInterval = 50
    )

    $percentComplete = [math]::Round(($Current / $Total) * 100, 1)

    # Always show progress bar in console
    Write-Progress -Activity $Activity `
        -Status "Processing item $Current of $Total - $percentComplete% complete" `
        -PercentComplete $percentComplete

    # Log to file only at intervals to avoid spam
    if ($Current % $FileLogInterval -eq 0 -or $Current -eq $Total) {
        Write-Log -Message "$Activity - $Current / $Total ($percentComplete%)" -Level Info -NoConsole
    }
}

function Get-LogPath {
    <#
    .SYNOPSIS
        Gets the current log file path.

    .OUTPUTS
        String path to log file, or $null if not set.
    #>
    [CmdletBinding()]
    param()

    return $script:LogFilePath
}

function Close-Logger {
    <#
    .SYNOPSIS
        Closes the logger and writes a footer.

    .DESCRIPTION
        Writes a closing message to the log file and resets logger state.
    #>
    [CmdletBinding()]
    param()

    if ($script:LogToFile -and $script:LogFilePath) {
        $footer = @"

=================================================================
Log session ended: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
=================================================================
"@
        try {
            $footer | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8
        }
        catch {
            Write-Warning "Failed to write log footer: $_"
        }
    }

    # Clear progress bar
    Write-Progress -Activity "Processing" -Completed

    $script:LogFilePath = $null
    $script:LogToFile = $false
}

Export-ModuleMember -Function @(
    'Initialize-Logger',
    'Write-Log',
    'Write-LogSection',
    'Write-LogProgress',
    'Get-LogPath',
    'Close-Logger'
)
