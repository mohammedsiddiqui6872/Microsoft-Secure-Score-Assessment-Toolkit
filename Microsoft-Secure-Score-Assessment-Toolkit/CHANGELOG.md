Changelog
=========

All notable changes to this project will be documented in this file.


[2.3.0] - 2026-02-24
---------------------

Bug Fixes:
- Fixed composable filter system: status + risk + search filters now work together correctly
- Added "All" reset button to risk filter group
- Fixed progress bar counting excluded controls incorrectly
- Fixed Get-OrganizationInfo not handling array return from API
- Fixed 2 GitHub controls (MDA_GitHub_*) silently dropped due to non-HTTP ActionUrl validation
- Non-standard ActionUrls now fall back to portal keyword match instead of rejecting the control

Performance:
- Replaced string concatenation with StringBuilder in HTML report generation
- Replaced O(n*m) nested loop with O(1) hashtable lookup for URL control mappings
- Async Google Fonts loading prevents render-blocking in offline environments

Security:
- Removed dangerous auto-install with -Force -AllowClobber (supply chain risk); module now throws with install instructions
- Prevented sovereign cloud URLs (.azure.us, .azure.cn, .microsoftazure.de) from being rewritten to commercial domains
- Replaced empty catch block with diagnostic Write-Verbose logging

Portal URL Modernization:
- Migrated all compliance.microsoft.com URLs to purview.microsoft.com (retired late 2024)
- Added URL rewrite rule to auto-correct API-returned compliance.microsoft.com URLs
- Added 6 new control-to-portal URL mappings (71 total), eliminating all docs-only URLs
- Added "Purview" keyword to compliance fallback rule

Module Quality:
- Declared RequiredModules in manifest (Microsoft.Graph.Authentication and Microsoft.Graph.Security >= 2.28.0)
- Cross-platform paths via Join-Path throughout module loader
- Clean up all module state in Disconnect-MicrosoftSecureScore finally block
- Get-MicrosoftSecureScoreInfo returns PSCustomObject for programmatic access
- Force array context with @() on API collection returns
- Added -ErrorAction to all critical cmdlet calls


[2.2.1] - 2025-12-20
---------------------

Bug Fixes:
- Fixed non-ASCII characters (bullets, em dashes, smart quotes) displaying as garbled text in reports
- All non-ASCII characters now encoded as HTML numeric entities for reliable rendering


[2.2.0] - 2025-12-15
---------------------

New Features:
- CSV Export: New -CsvPath parameter exports all control data to CSV for spreadsheet analysis
- Disconnect Function: New Disconnect-MicrosoftSecureScore for proper session cleanup
- No-Open Switch: New -NoOpen parameter suppresses automatic browser launch

Bug Fixes:
- Fixed division by zero when MaxScore is 0
- Fixed missing closing div in HTML template causing layout issues
- Fixed JavaScript filter crash in Firefox/Safari (implicit event variable)
- Fixed score of 0 being silently dropped in report metadata
- Fixed internal functions being leaked to user session (namespace pollution)
- Fixed loading overlay never displaying
- Fixed URL mapping using substring match instead of exact match
- Fixed emoji characters showing as garbled text in reports
- Fixed progress bar counting excluded controls incorrectly
- Removed duplicate LinkedIn link in floating action menu
- Removed stale third-party email from help function

Improvements:
- O(n^2) array performance replaced with List collection
- Removed redundant Import-Module calls across all functions
- Removed dead JavaScript code (unused functions, setInterval, deprecated APIs)
- Eliminated duplicate HTML stripping code in ComplianceProcessor
- Version now read from manifest instead of hardcoded
- Path validation for ReportPath, LogPath, and CsvPath
- Replaced emoji characters with SVG icons for encoding compatibility
- Updated info function with current features


[2.1.0] - 2025-12-01
---------------------

New Features:
- ExcludeCategories parameter for filtering out specific control categories from reports
- Updated README with ExcludeCategories documentation


[2.0.0] - 2025-11-25
---------------------

Architecture:
- Complete modular rewrite: separated concerns into Core, Processors, Reports, Config, and Templates
- Externalized control URL mappings to JSON configuration (Config/control-mappings.json)
- Template-based HTML report generation (Templates/report-modern-template.html)
- Structured logging system with file and console output (Core/Logger.ps1)
- Data models separated into Core/Models.ps1
- URL optimization pipeline in Processors/UrlProcessor.ps1
- Compliance logic isolated in Processors/ComplianceProcessor.ps1
- Modern dark-themed interactive HTML report with filtering and search


[1.4.0] - 2025-11-18
---------------------

Changed:
- Major Rename: Renamed toolkit from "Microsoft Secure Score Remediation Toolkit" to "Microsoft Secure Score Assessment Toolkit"
  - Better reflects the tool's actual functionality (assessment, not remediation)
  - Tool performs read-only assessment and does not make any changes to tenant configurations
  - Provides assessment reports with links to configuration portals where administrators can manually remediate
- Professional Header Design: Completely redesigned report header to match CIS compliance report style
  - Implemented sticky header with dark background
  - Added 3px solid blue bottom border
  - Created expandable tenant info dropdown with comprehensive metadata

Updated:
- Module Name: Microsoft-Secure-Score-Assessment-Toolkit
- PowerShell Gallery Package: Microsoft-Secure-Score-Assessment-Toolkit
- File Names:
  - SecureScore-Assessment-API.ps1 (formerly SecureScore-Remediation-API.ps1)
  - Microsoft-Secure-Score-Assessment-Toolkit.psm1
  - Microsoft-Secure-Score-Assessment-Toolkit.psd1
- Directory Structure: Microsoft-Secure-Score-Assessment-Toolkit/
- Documentation: Updated all references in README files and comments
- Display Text: Changed "Remediation" to "Assessment" in all user-facing text

Header Improvements:
- Sticky Positioning: Header remains visible while scrolling
- Expandable Details: Click tenant info to reveal comprehensive report metadata
- Professional Styling: Clean, modern design matching enterprise standards
- Animated Transitions: Smooth dropdown animation for better UX
- Complete Metadata: Shows tenant ID, user, date, score, compliance rate, and data source
- Removed Redundancy: Eliminated separate score summary section (info now in header dropdown)

Note:
- GitHub repository URLs remain unchanged pending repository rename on GitHub
- Functionality remains identical - visual and naming changes only


[1.1.0] - 2025-11-13
---------------------

Security:
- CRITICAL: Removed All Hardcoded Tenant IDs - Eliminated security risk of exposing tenant information
  - Removed 198 hardcoded tenant IDs from JSON data file
  - No tenant IDs are stored anywhere in the repository
  - Script dynamically injects current user's tenant ID at runtime only

Added:
- Dynamic Tenant ID Injection: ActionUrls now automatically use the current tenant's ID
  - Works across all Microsoft portals (security.microsoft.com, entra.microsoft.com, etc.)
- Progress Indicators: Real-time progress bar shows processing status
  - Displays current control number and percentage complete
- Git Repository: Project now under version control
  - Repository: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-Assessment-Toolkit.git
  - Proper .gitignore to exclude logs, reports, and temporary files

Changed:
- Enhanced logging to show tenant ID during connection
- Improved user feedback during control processing


[1.0.0] - 2025-11-12
---------------------

Initial Release:
- Microsoft Graph API integration for Secure Score controls
- Fetch 400+ security controls directly from Microsoft
- Generate comprehensive HTML compliance reports
- Support for filtering by category and applicable controls
- Professional dark-themed report interface
- Direct action links to configuration portals
- Executive summary with compliance metrics
