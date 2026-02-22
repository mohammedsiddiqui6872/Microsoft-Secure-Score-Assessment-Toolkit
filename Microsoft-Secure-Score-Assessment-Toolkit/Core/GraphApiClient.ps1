function Connect-SecureScoreGraph {
    <#
    .SYNOPSIS
        Establishes connection to Microsoft Graph API.

    .DESCRIPTION
        Connects to Microsoft Graph with required scopes for Secure Score operations.
        Returns connection context information.

    .PARAMETER UseDeviceCode
        Use device code authentication instead of interactive.

    .PARAMETER TenantId
        Specific tenant ID to connect to.

    .OUTPUTS
        Hashtable containing TenantId and Account information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )

    try {
        # Ensure required modules are imported
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        }
        catch {
            throw "Failed to import Microsoft.Graph.Authentication module. Ensure it is installed: Install-Module Microsoft.Graph.Authentication"
        }

        try {
            Import-Module Microsoft.Graph.Security -ErrorAction Stop
        }
        catch {
            throw "Failed to import Microsoft.Graph.Security module. Ensure it is installed: Install-Module Microsoft.Graph.Security"
        }

        $graphScopes = @(
            "SecurityEvents.Read.All",
            "Organization.Read.All"
        )

        # Disconnect any existing session to start fresh
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Ignore disconnect errors
        }

        # Connect to Microsoft Graph with appropriate method
        try {
            if ($UseDeviceCode) {
                Connect-MgGraph -Scopes $graphScopes -UseDeviceCode -ErrorAction Stop
            }
            elseif ($TenantId) {
                Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -ErrorAction Stop
            }
            else {
                Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
            }
        }
        catch {
            $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { "Unknown error during Connect-MgGraph" }
            throw "Failed during Connect-MgGraph: $errorMessage"
        }

        $context = Get-MgContext
        if (-not $context) {
            throw "Failed to establish Microsoft Graph connection - context is null"
        }

        return @{
            TenantId = $context.TenantId
            Account = $context.Account
            Scopes = $context.Scopes
        }
    }
    catch {
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { "Unknown connection error" }
        throw "Failed to connect to Microsoft Graph: $errorMessage"
    }
}

function Get-SecureScoreData {
    <#
    .SYNOPSIS
        Retrieves current secure score from Microsoft Graph API.

    .DESCRIPTION
        Fetches the most recent secure score information including current score,
        max score, and individual control scores.

    .OUTPUTS
        Hashtable containing CurrentScore, MaxScore, and ControlScores.
    #>
    [CmdletBinding()]
    param()

    try {
        $allScores = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop

        # Handle both array and single object returns
        if ($allScores -is [Array]) {
            $currentScore = $allScores[0]
        } else {
            $currentScore = $allScores
        }

        if (-not $currentScore) {
            throw "No secure score data returned from API"
        }

        $controlScores = @{}
        if ($currentScore.ControlScores) {
            $controlScoresArray = @($currentScore.ControlScores)
            foreach ($cs in $controlScoresArray) {
                $controlScores[$cs.ControlName] = $cs
            }
        }

        return @{
            CurrentScore = $currentScore.CurrentScore
            MaxScore = $currentScore.MaxScore
            ControlScores = $controlScores
            RawData = $currentScore
        }
    }
    catch {
        throw "Failed to retrieve secure score data: $_"
    }
}

function Get-SecureScoreControlProfiles {
    <#
    .SYNOPSIS
        Retrieves all secure score control profiles from Microsoft Graph API.

    .DESCRIPTION
        Fetches all available secure score control profiles (411+ controls).

    .PARAMETER FilterApplicableOnly
        If specified, returns only controls that are being scored in the tenant.

    .PARAMETER ScoredControlsList
        List of control names that are actively scored in the tenant.

    .OUTPUTS
        Array of control profile objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$FilterApplicableOnly,

        [Parameter(Mandatory = $false)]
        [string[]]$ScoredControlsList
    )

    try {
        $controls = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop

        if ($FilterApplicableOnly -and $ScoredControlsList) {
            $controls = $controls | Where-Object { $ScoredControlsList -contains $_.Id }
        }

        return $controls
    }
    catch {
        throw "Failed to retrieve secure score control profiles: $_"
    }
}

function Get-OrganizationInfo {
    <#
    .SYNOPSIS
        Retrieves organization information from Microsoft Graph API.

    .DESCRIPTION
        Fetches organization details including display name.

    .OUTPUTS
        Hashtable containing DisplayName and other organization properties.
    #>
    [CmdletBinding()]
    param()

    try {
        $organization = Get-MgOrganization -ErrorAction Stop

        if ($organization) {
            return @{
                DisplayName = $organization.DisplayName
                Id = $organization.Id
                RawData = $organization
            }
        }
        else {
            return @{
                DisplayName = "Organization"
                Id = $null
                RawData = $null
            }
        }
    }
    catch {
        Write-Warning "Could not fetch organization name: $_"
        return @{
            DisplayName = "Organization"
            Id = $null
            RawData = $null
        }
    }
}

function Test-GraphConnection {
    <#
    .SYNOPSIS
        Tests if Microsoft Graph connection is established and valid.

    .DESCRIPTION
        Checks if there is an active Microsoft Graph connection context.

    .OUTPUTS
        Boolean indicating connection status.
    #>
    [CmdletBinding()]
    param()

    try {
        $context = Get-MgContext
        return ($null -ne $context)
    }
    catch {
        return $false
    }
}

# Functions are exported via the main module manifest (.psd1)
