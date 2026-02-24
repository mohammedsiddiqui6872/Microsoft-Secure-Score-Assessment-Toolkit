# Changelog

All notable changes to this project will be documented in this file.

## [2.3.0] - 2026-02-24

### Bug Fixes
- Fixed composable filter system: status + risk + search filters now work together correctly
- Added "All" reset button to risk filter group
- Fixed progress bar counting excluded controls incorrectly
- Fixed `Get-OrganizationInfo` not handling array return from API
- Fixed 2 GitHub controls (`MDA_GitHub_*`) silently dropped due to non-HTTP ActionUrl validation
- Non-standard ActionUrls now fall back to portal keyword match instead of rejecting the control

### Performance
- Replaced string concatenation with `StringBuilder` in HTML report generation
- Replaced O(n*m) nested loop with O(1) hashtable lookup for URL control mappings
- Async Google Fonts loading prevents render-blocking in offline environments

### Security
- Removed dangerous auto-install with `-Force -AllowClobber` (supply chain risk); module now throws with install instructions
- Prevented sovereign cloud URLs (`.azure.us`, `.azure.cn`, `.microsoftazure.de`) from being rewritten to commercial domains
- Replaced empty catch block with diagnostic `Write-Verbose` logging

### Portal URL Modernization
- Migrated all `compliance.microsoft.com` URLs to `purview.microsoft.com` (retired late 2024)
- Added URL rewrite rule to auto-correct API-returned `compliance.microsoft.com` URLs
- Added 6 new control-to-portal URL mappings (71 total), eliminating all docs-only URLs
- Added "Purview" keyword to compliance fallback rule

### Module Quality
- Declared `RequiredModules` in manifest (`Microsoft.Graph.Authentication` and `Microsoft.Graph.Security` >= 2.28.0)
- Cross-platform paths via `Join-Path` throughout module loader
- Clean up all module state in `Disconnect-MicrosoftSecureScore` finally block
- `Get-MicrosoftSecureScoreInfo` returns `PSCustomObject` for programmatic access
- Force array context with `@()` on API collection returns
- Added `-ErrorAction` to all critical cmdlet calls

## [1.4.0] - 2025-11-18

### Changed
- **Major Rename**: Renamed toolkit from "Microsoft Secure Score Remediation Toolkit" to "Microsoft Secure Score Assessment Toolkit"
  - Better reflects the tool's actual functionality (assessment, not remediation)
  - Tool performs read-only assessment and does not make any changes to tenant configurations
  - Provides assessment reports with links to configuration portals where administrators can manually remediate
- **Professional Header Design**: Completely redesigned report header to match CIS compliance report style
  - Implemented sticky header with dark background (#18181b)
  - Added 3px solid blue bottom border (#60a5fa)
  - Created expandable tenant info dropdown with comprehensive metadata

### Updated
- **Module Name**: Microsoft-Secure-Score-Assessment-Toolkit
- **PowerShell Gallery Package**: Microsoft-Secure-Score-Assessment-Toolkit
- **File Names**:
  - SecureScore-Assessment-API.ps1 (formerly SecureScore-Remediation-API.ps1)
  - Microsoft-Secure-Score-Assessment-Toolkit.psm1 (formerly .remediation-toolkit.psm1)
  - Microsoft-Secure-Score-Assessment-Toolkit.psd1 (formerly .remediation-toolkit.psd1)
- **Directory Structure**: Microsoft-Secure-Score-Assessment-Toolkit/ (formerly .remediation-toolkit/)
- **Documentation**: Updated all references in README files and comments
- **Display Text**: Changed "Remediation" to "Assessment" in all user-facing text

### Header Improvements
- **Sticky Positioning**: Header remains visible while scrolling
- **Expandable Details**: Click tenant info to reveal comprehensive report metadata
- **Professional Styling**: Clean, modern design matching enterprise standards
- **Animated Transitions**: Smooth dropdown animation for better UX
- **Complete Metadata**: Shows tenant ID, user, date, score, compliance rate, and data source
- **Removed Redundancy**: Eliminated separate score summary section (info now in header dropdown)

### Note
- GitHub repository URLs remain unchanged pending repository rename on GitHub
- Functionality remains identical - visual and naming changes only

## [1.1.0] - 2025-11-13

### Security
- **CRITICAL: Removed All Hardcoded Tenant IDs**: Eliminated security risk of exposing tenant information
  - Removed 198 hardcoded tenant IDs from JSON data file
  - No tenant IDs are stored anywhere in the repository
  - Script dynamically injects current user's tenant ID at runtime only

### Added
- **Dynamic Tenant ID Injection**: ActionUrls now automatically use the current tenant's ID
  - Works across all Microsoft portals (security.microsoft.com, compliance.microsoft.com, etc.)
- **Progress Indicators**: Real-time progress bar shows processing status
  - Displays current control number and percentage complete
  - Improves user experience during 411 control processing
- **Git Repository**: Project now under version control
  - Repository: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-Assessment-Toolkit.git
  - Proper .gitignore to exclude logs, reports, and temporary files

### Changed
- Enhanced logging to show tenant ID during connection
- Improved user feedback during control processing

### Technical Details
- Modified lines 279-280: Store current tenant ID in script variable
- Modified lines 410-413: Replace hardcoded tenant IDs with current context
- Modified lines 400-404: Added Write-Progress for visual feedback
- Added line 506: Clear progress bar upon completion

## [1.0.0] - 2025-11-12

### Initial Release
- Microsoft Graph API integration for Secure Score controls
- Fetch 411+ security controls directly from Microsoft
- Generate comprehensive HTML compliance reports
- Support for filtering by category and applicable controls
- Professional dark-themed report interface
- Direct action links to configuration portals
- Executive summary with compliance metrics

