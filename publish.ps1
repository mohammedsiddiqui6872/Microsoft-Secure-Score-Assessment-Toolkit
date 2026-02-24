<#
.SYNOPSIS
    Publishes the Microsoft Secure Score Assessment Toolkit to PowerShell Gallery.

.DESCRIPTION
    Copies root docs (README, CHANGELOG) into the module folder temporarily,
    publishes to PSGallery, then cleans up the copies.

.PARAMETER NuGetApiKey
    Your PowerShell Gallery API key.

.PARAMETER WhatIf
    Show what would happen without actually publishing.

.EXAMPLE
    .\publish.ps1 -NuGetApiKey "your-api-key-here"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NuGetApiKey,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$modulePath = Join-Path $repoRoot 'Microsoft-Secure-Score-Assessment-Toolkit'

# Files to copy from root into module folder for publishing
$docFiles = @('README.md', 'CHANGELOG.md')
$copied = @()

try {
    # Copy root docs into module folder
    foreach ($file in $docFiles) {
        $src = Join-Path $repoRoot $file
        $dst = Join-Path $modulePath $file
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dst -Force
            $copied += $dst
            Write-Host "Copied $file into module folder" -ForegroundColor Gray
        }
    }

    # Validate manifest
    $manifest = Test-ModuleManifest -Path (Join-Path $modulePath 'Microsoft-Secure-Score-Assessment-Toolkit.psd1')
    Write-Host "Module: $($manifest.Name) v$($manifest.Version)" -ForegroundColor Cyan

    # Publish
    if ($WhatIf) {
        Write-Host "WhatIf: Would publish $($manifest.Name) v$($manifest.Version) to PSGallery" -ForegroundColor Yellow
    }
    else {
        Publish-Module -Path $modulePath -NuGetApiKey $NuGetApiKey -Repository PSGallery -Verbose
        Write-Host "`nPublished $($manifest.Name) v$($manifest.Version) to PowerShell Gallery!" -ForegroundColor Green
    }
}
finally {
    # Always clean up copied files
    foreach ($file in $copied) {
        if (Test-Path $file) {
            Remove-Item $file -Force
            Write-Host "Cleaned up $(Split-Path $file -Leaf) from module folder" -ForegroundColor Gray
        }
    }
}
