# Module-level cache for control mappings
$script:ControlMappingsCache = $null
$script:ConfigPath = $null

function Initialize-UrlProcessor {
    <#
    .SYNOPSIS
        Initializes the URL processor with configuration.

    .DESCRIPTION
        Loads control URL mappings from JSON configuration file.

    .PARAMETER ConfigPath
        Path to the control-mappings.json configuration file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    if (-not (Test-Path $ConfigPath)) {
        throw "Control mappings configuration file not found: $ConfigPath"
    }

    try {
        $script:ConfigPath = $ConfigPath
        $configContent = Get-Content -Path $ConfigPath -Raw -Encoding UTF8
        $script:ControlMappingsCache = $configContent | ConvertFrom-Json
        Write-Verbose "Loaded control mappings from $ConfigPath"
    }
    catch {
        throw "Failed to load control mappings configuration: $_"
    }
}

function Get-ControlMapping {
    <#
    .SYNOPSIS
        Gets the URL mapping for a specific control name.

    .DESCRIPTION
        Searches through all category mappings to find a matching control.

    .PARAMETER ControlName
        Name of the control to find mapping for.

    .OUTPUTS
        String URL if mapping found, otherwise $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlName
    )

    if (-not $script:ControlMappingsCache) {
        Write-Warning "URL processor not initialized. Call Initialize-UrlProcessor first."
        return $null
    }

    # Search through all category mappings
    foreach ($category in $script:ControlMappingsCache.controlMappings.PSObject.Properties) {
        foreach ($mapping in $category.Value.PSObject.Properties) {
            if ($ControlName -match [regex]::Escape($mapping.Name)) {
                Write-Verbose "Found exact mapping for '$ControlName': $($mapping.Value)"
                return $mapping.Value
            }
        }
    }

    return $null
}

function Get-FallbackUrl {
    <#
    .SYNOPSIS
        Gets a fallback URL based on control name keywords.

    .DESCRIPTION
        Analyzes control name for keywords and returns appropriate portal URL.

    .PARAMETER ControlName
        Name of the control.

    .OUTPUTS
        String URL for the appropriate portal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlName
    )

    if (-not $script:ControlMappingsCache) {
        return $null
    }

    # Check each fallback rule
    foreach ($rule in $script:ControlMappingsCache.fallbackRules.PSObject.Properties) {
        $keywords = $rule.Value.keywords
        $url = $rule.Value.url

        foreach ($keyword in $keywords) {
            if ($ControlName -match $keyword) {
                Write-Verbose "Using fallback URL for '$ControlName' based on keyword '$keyword': $url"
                return $url
            }
        }
    }

    return $null
}

function Update-LegacyPortalUrl {
    <#
    .SYNOPSIS
        Updates legacy portal URLs to current equivalents.

    .DESCRIPTION
        Replaces old portal URLs (portal.office.com, aad.portal.azure.com) with new ones.

    .PARAMETER Url
        URL to update.

    .OUTPUTS
        Updated URL string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    if (-not $script:ControlMappingsCache) {
        return $Url
    }

    $updatedUrl = $Url

    # Apply URL replacements from config
    foreach ($replacement in $script:ControlMappingsCache.urlReplacements.PSObject.Properties) {
        $oldUrl = $replacement.Name
        $newUrl = $replacement.Value
        $updatedUrl = $updatedUrl -replace [regex]::Escape($oldUrl), $newUrl
    }

    # Additional Entra ID specific updates
    if ($updatedUrl -match 'Microsoft_AAD' -and $updatedUrl -notmatch 'entra\.microsoft\.com') {
        $updatedUrl = $updatedUrl -replace 'https://portal\.azure\.com', 'https://entra.microsoft.com'
    }

    return $updatedUrl
}

function Add-TenantContext {
    <#
    .SYNOPSIS
        Adds tenant ID context to a URL.

    .DESCRIPTION
        Injects tenant ID parameter into portal URLs for proper tenant scoping.

    .PARAMETER Url
        URL to add tenant context to.

    .PARAMETER TenantId
        Tenant identifier to inject.

    .OUTPUTS
        URL with tenant context added.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )

    if ([string]::IsNullOrEmpty($TenantId)) {
        return $Url
    }

    $updatedUrl = $Url

    # Replace existing tenant ID if present
    if ($updatedUrl -match 'tid=') {
        $updatedUrl = $updatedUrl -replace 'tid=[a-f0-9-]+', "tid=$TenantId"
    }
    # Add tenant ID to Entra and Azure portal URLs that don't have it
    elseif ($updatedUrl -match '^https://(portal\.azure\.com|aad\.portal\.azure\.com|entra\.microsoft\.com)') {
        if ($updatedUrl -match '\?') {
            $updatedUrl = $updatedUrl -replace '\?', "?tid=$TenantId&"
        }
        elseif ($updatedUrl -match '#') {
            $updatedUrl = $updatedUrl -replace '#', "?tid=$TenantId#"
        }
        else {
            $updatedUrl += "?tid=$TenantId"
        }
    }

    return $updatedUrl
}

function Optimize-ControlUrl {
    <#
    .SYNOPSIS
        Optimizes and enhances a control's action URL.

    .DESCRIPTION
        Performs full URL optimization including:
        - Exact control mapping lookup
        - Documentation URL fallback routing
        - Legacy URL updates
        - Tenant context injection

    .PARAMETER Url
        Original URL from API.

    .PARAMETER ControlName
        Name of the control.

    .PARAMETER TenantId
        Tenant identifier for context injection.

    .OUTPUTS
        Optimized URL string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$ControlName,

        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )

    if ([string]::IsNullOrEmpty($Url)) {
        return $Url
    }

    $optimizedUrl = $Url

    # Step 1: Check for exact control mapping
    $exactMapping = Get-ControlMapping -ControlName $ControlName
    if ($exactMapping) {
        $optimizedUrl = $exactMapping
        Write-Verbose "Using exact mapping for '$ControlName'"
    }
    # Step 2: If URL points to documentation, find a better config URL
    elseif ($optimizedUrl -match 'learn\.microsoft\.com') {
        $fallbackUrl = Get-FallbackUrl -ControlName $ControlName
        if ($fallbackUrl) {
            $optimizedUrl = $fallbackUrl
            Write-Verbose "Replaced documentation URL with portal fallback for '$ControlName'"
        }
    }

    # Step 3: Update legacy portal URLs
    $optimizedUrl = Update-LegacyPortalUrl -Url $optimizedUrl

    # Step 4: Add tenant context
    $optimizedUrl = Add-TenantContext -Url $optimizedUrl -TenantId $TenantId

    return $optimizedUrl
}

function Test-UrlProcessorInitialized {
    <#
    .SYNOPSIS
        Checks if URL processor is initialized.

    .OUTPUTS
        Boolean indicating initialization status.
    #>
    [CmdletBinding()]
    param()

    return ($null -ne $script:ControlMappingsCache)
}

Export-ModuleMember -Function @(
    'Initialize-UrlProcessor',
    'Get-ControlMapping',
    'Get-FallbackUrl',
    'Update-LegacyPortalUrl',
    'Add-TenantContext',
    'Optimize-ControlUrl',
    'Test-UrlProcessorInitialized'
)
