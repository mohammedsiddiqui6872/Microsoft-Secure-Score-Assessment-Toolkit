# Microsoft Secure Score Assessment Toolkit

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Microsoft-Secure-Score-Assessment-Toolkit?label=PowerShell%20Gallery)](https://www.powershellgallery.com/packages/Microsoft-Secure-Score-Assessment-Toolkit)
[![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/Microsoft-Secure-Score-Assessment-Toolkit?label=Downloads)](https://www.powershellgallery.com/packages/Microsoft-Secure-Score-Assessment-Toolkit)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Compatible-orange)](https://www.cisecurity.org/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg)](https://buymeacoffee.com/mohammedsiddiqui)
[![PowerShellNerd Profile](https://img.shields.io/badge/PowerShellNerd-Profile-purple.svg)](https://powershellnerd.com/profile/mohammedsiddiqui)

A powerful PowerShell module for assessing and managing Microsoft 365 security posture through the Microsoft Secure Score API. Generate comprehensive, interactive HTML reports with 411+ security controls directly from Microsoft Graph API.

---

## ✨ Features

### 🚀 PowerShell Gallery Module
- **One-Command Installation**: Install directly from PowerShell Gallery
- **Cmdlet-Style Functions**: Follow PowerShell best practices with approved verbs
- **Auto-Loading**: No need to manually import - functions available immediately
- **Module Auto-Update**: Use `Update-Module` for seamless updates

### 📊 API-Driven Control Fetching
- **Real-time Data**: Fetches 411+ security controls directly from Microsoft Graph API
- **Always Up-to-Date**: No manual JSON updates needed - controls sync with Microsoft's latest recommendations
- **Dynamic Tenant Context**: Automatically uses your tenant ID for all portal links
- **Applicable Controls Mode**: Filter to show only controls relevant to your tenant (~70 controls)

### 🎨 Interactive HTML Reports
- **Professional Dark Theme**: Modern, responsive design optimized for readability
- **Interactive Filtering**: Click summary cards to filter controls by status or risk level
- **Quick Access Links**: Direct links to configuration portals for each control
- **Executive Summary**: At-a-glance compliance metrics and risk breakdown
- **Floating Action Buttons**: Chatbot-style buttons for quick access to documentation and support

### 🎯 Smart Features
- **Category Filtering**: Exclude specific control categories from reports (Exchange, SharePoint, Teams, etc.)
- **CSV Export**: Export all control data to CSV for spreadsheet analysis and reporting
- **Session Management**: Connect and Disconnect functions for proper Graph session lifecycle
- **No-Open Mode**: Suppress automatic browser launch for headless/automated runs
- **Tenant Attribution**: Shows tenant ID and user who generated the report
- **Category Organization**: Controls grouped by security domains (Identity, Data, Device, Apps, Infrastructure)
- **Risk-Based Prioritization**: Controls categorized as High, Medium, or Low risk
- **Portal Links**: Direct links to Microsoft 365 admin portals for configuration

---

## 📦 Installation

### From PowerShell Gallery (Recommended)

```powershell
# Install the module
Install-Module -Name Microsoft-Secure-Score-Assessment-Toolkit -Scope CurrentUser

# Update to latest version (recommended to always use latest)
Update-Module -Name Microsoft-Secure-Score-Assessment-Toolkit -Force

# Verify installation
Get-Module -ListAvailable Microsoft-Secure-Score-Assessment-Toolkit
```

### Prerequisites

- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+
- **Microsoft Graph PowerShell SDK**: Installed automatically by the module
- **Permissions**: Azure AD account with Security Reader or Global Reader role
- **API Permissions**: SecurityEvents.Read.All and Organization.Read.All

---

## 🚀 Quick Start

### Basic Usage

```powershell
# Step 1: Authenticate to Microsoft Graph
Connect-MicrosoftSecureScore

# Step 2: Generate assessment report (auto-opens in browser)
Invoke-MicrosoftSecureScore

# Step 3: When done, disconnect
Disconnect-MicrosoftSecureScore
```

That's it! The report will be saved in your current directory with a timestamp.

---

## 📖 Command Reference

### Connect-MicrosoftSecureScore

Authenticate to Microsoft Graph for Secure Score API access.

**Syntax:**
```powershell
Connect-MicrosoftSecureScore [-UseDeviceCode]
```

**Parameters:**
- `-UseDeviceCode`: Use device code authentication instead of interactive browser (useful for remote sessions)

**Examples:**
```powershell
# Interactive browser authentication
Connect-MicrosoftSecureScore

# Device code authentication (for headless/remote sessions)
Connect-MicrosoftSecureScore -UseDeviceCode
```

---

### Invoke-MicrosoftSecureScore

Generate Microsoft Secure Score assessment report with 411+ controls.

**Syntax:**
```powershell
Invoke-MicrosoftSecureScore
    [-TenantName <String>]
    [-ApplicableOnly]
    [-ReportPath <String>]
    [-LogPath <String>]
    [-CsvPath <String>]
    [-NoOpen]
    [-ExcludeCategories <String[]>]
```

**Parameters:**
- `-TenantName`: Display name for your organization in the report (default: "Your Organization")
- `-ApplicableOnly`: Show only controls applicable to your tenant (~70 controls instead of 411+)
- `-ReportPath`: Custom path for the HTML report (default: current directory with timestamp)
- `-LogPath`: Path where the log file will be saved (optional)
- `-CsvPath`: Path where the CSV export will be saved (optional)
- `-NoOpen`: Do not automatically open the report in the default browser
- `-ExcludeCategories`: Array of category names to exclude from the report. Valid categories: Identity, Defender, Exchange, SharePoint, Groups, Teams, Compliance, Intune

**Examples:**
```powershell
# Generate full report with all 411+ controls
Invoke-MicrosoftSecureScore

# Generate report with only applicable controls
Invoke-MicrosoftSecureScore -ApplicableOnly

# Custom organization name
Invoke-MicrosoftSecureScore -TenantName "Contoso Corporation"

# Custom report path
Invoke-MicrosoftSecureScore -ReportPath "C:\Reports\SecureScore.html"

# Export results to CSV for spreadsheet analysis
Invoke-MicrosoftSecureScore -CsvPath "C:\Reports\SecureScore.csv"

# Generate report without opening browser (for automation)
Invoke-MicrosoftSecureScore -NoOpen

# Exclude Exchange controls from report
Invoke-MicrosoftSecureScore -ExcludeCategories "Exchange"

# Exclude multiple categories
Invoke-MicrosoftSecureScore -ExcludeCategories @("Exchange", "SharePoint", "Teams")

# Full example with all options
Invoke-MicrosoftSecureScore -TenantName "Contoso" -ApplicableOnly -ExcludeCategories @("Exchange") -ReportPath "C:\Reports\Contoso.html" -CsvPath "C:\Reports\Contoso.csv" -LogPath "C:\Logs\assessment.log" -NoOpen
```

---

### Disconnect-MicrosoftSecureScore & Get-MicrosoftSecureScoreInfo

| Command | Description |
|---|---|
| `Disconnect-MicrosoftSecureScore` | Disconnect from Microsoft Graph and clean up session |
| `Get-MicrosoftSecureScoreInfo` | Display toolkit information, version, and usage guide |


## 💡 Usage Scenarios

### Scenario 1: Quick Security Assessment

```powershell
# Authenticate once
Connect-MicrosoftSecureScore

# Generate report
Invoke-MicrosoftSecureScore
```

### Scenario 2: Applicable Controls Only

```powershell
# Show only controls relevant to your tenant
Connect-MicrosoftSecureScore
Invoke-MicrosoftSecureScore -ApplicableOnly
```

### Scenario 3: Multi-Tenant Management

```powershell
# Generate reports for multiple tenants
Connect-MicrosoftSecureScore
Invoke-MicrosoftSecureScore -TenantName "Contoso Corp" -ReportPath "C:\Reports\Contoso.html"

# Reconnect for next tenant
Connect-MicrosoftSecureScore
Invoke-MicrosoftSecureScore -TenantName "Fabrikam Inc" -ReportPath "C:\Reports\Fabrikam.html"
```

### Scenario 4: Category Filtering

```powershell
# Focus only on Identity and Defender controls, excluding other categories
Connect-MicrosoftSecureScore
Invoke-MicrosoftSecureScore -ExcludeCategories @("Exchange", "SharePoint", "Teams", "Groups", "Compliance", "Intune")

# Skip Exchange and SharePoint for cloud-only environments
Invoke-MicrosoftSecureScore -ExcludeCategories @("Exchange", "SharePoint")

# Generate report excluding categories you don't manage
Invoke-MicrosoftSecureScore -TenantName "Contoso" -ExcludeCategories @("Intune", "Teams") -ApplicableOnly
```

### Scenario 5: CSV Export for Analysis

```powershell
# Export to CSV for spreadsheet analysis or SIEM integration
Connect-MicrosoftSecureScore
Invoke-MicrosoftSecureScore -CsvPath "C:\Reports\SecureScore.csv" -NoOpen
Disconnect-MicrosoftSecureScore
```

### Scenario 6: Scheduled Reporting

```powershell
# Create a scheduled task to run daily (headless mode)
$scriptBlock = {
    Import-Module Microsoft-Secure-Score-Assessment-Toolkit
    Connect-MicrosoftSecureScore
    Invoke-MicrosoftSecureScore -ReportPath "C:\Reports\Daily-SecureScore-$(Get-Date -Format 'yyyyMMdd').html" -CsvPath "C:\Reports\Daily-SecureScore-$(Get-Date -Format 'yyyyMMdd').csv" -NoOpen
    Disconnect-MicrosoftSecureScore
}

# Run via Task Scheduler or Azure Automation
```

---

## 📊 Report Features

### Interactive Summary Dashboard

The report includes **6 summary cards** in a single row:
- ✅ **Compliant Controls**: Already implemented controls
- ❌ **Non-Compliant Controls**: Action required
- 🔴 **High Risk Controls**: Critical security gaps
- 🟡 **Medium Risk Controls**: Important improvements
- 🟢 **Low Risk Controls**: Minor enhancements
- ⚪ **Not Applicable Controls**: Not relevant to your tenant

### Click-to-Filter

Click any summary card to instantly filter the entire report:
- Focus on high-risk items for immediate attention
- Review compliant controls for validation
- Identify non-compliant controls for improvement planning
- Click again to clear the filter

### Detailed Control Information

Each control displays:
- ✏️ Control name and description
- 📊 Current compliance status
- ⚠️ Risk level (High/Medium/Low)
- 📚 Microsoft documentation link
- 🔗 Direct action link to configuration portal
- 💼 Applicable Microsoft 365 plans

### Floating Action Buttons

Modern chatbot-style buttons fixed to the right side of the screen:
- 📖 **View on GitHub**: Access source code and documentation
- 🐛 **Report Issues**: Submit bug reports or feature requests
- 💬 **Submit Feedback**: Share suggestions and improvements
- 👔 **Let's Chat!**: Connect via LinkedIn
- ☕ **Buy Me a Coffee**: Support the project

---

## 🔒 Security & Privacy

### Zero Hardcoded Secrets
- ✅ No tenant IDs stored in repository
- ✅ No authentication tokens persisted
- ✅ All tenant context injected dynamically at runtime

### Read-Only Access
- ✅ Script only reads Secure Score data
- ✅ No modifications to your tenant configuration
- ✅ Safe execution with Microsoft Graph permissions

### Attribution & Transparency

Every report includes:
- 🆔 Tenant ID for clear identification
- 👤 User account that generated the report
- 📅 Generation timestamp
- 📝 Full audit trail

---

## 📋 Requirements

### Microsoft Graph Permissions
- **SecurityEvents.Read.All**: Read Secure Score data
- **Organization.Read.All**: Read organization information

### Supported Microsoft 365 Plans
- Microsoft 365 E3/E5
- Office 365 E3/E5
- Microsoft 365 Business Premium
- Azure Active Directory Premium P1/P2
- Individual Microsoft 365 services (Exchange, SharePoint, Teams, etc.)

### PowerShell Versions
- Windows PowerShell 5.1
- PowerShell 7.0+

---

## 🆘 Troubleshooting

### Authentication Issues

```powershell
# Disconnect and reconnect
Disconnect-MicrosoftSecureScore
Connect-MicrosoftSecureScore
```

### Module Not Loading

```powershell
# Uninstall and reinstall
Uninstall-Module Microsoft-Secure-Score-Assessment-Toolkit -AllVersions
Install-Module Microsoft-Secure-Score-Assessment-Toolkit -Force
```

### Permission Denied

Ensure your account has:
- ✅ Security Reader or Global Reader role in Azure AD
- ✅ SecurityEvents.Read.All API permission
- ✅ Organization.Read.All API permission

### Report Not Generating

```powershell
# Check authentication status
Get-MgContext

# Re-authenticate if needed
Connect-MicrosoftSecureScore

# Try again
Invoke-MicrosoftSecureScore
```

---

## 📝 Changelog

### [2.3.0] - 2026-02-24
**Security Hardening, Performance Fixes, and Portal URL Modernization:**
- **Bug Fixes**: Fixed composable filter system, progress bar counting, Get-OrganizationInfo array handling, 2 GitHub controls silently dropped
- **Performance**: StringBuilder for HTML generation, O(1) hashtable lookup for URL mappings, async Google Fonts loading
- **Security**: Removed dangerous auto-install with -Force -AllowClobber, prevented sovereign cloud URL rewriting, diagnostic logging for empty catch blocks
- **Portal URL Modernization**: Migrated compliance.microsoft.com to purview.microsoft.com, added 6 new control mappings (71 total)
- **Module Quality**: Declared RequiredModules in manifest, cross-platform paths, clean state teardown, PSCustomObject returns, array-safe API calls

[View Full Changelog](CHANGELOG.md)

---


## 📜 License

This project is provided as-is under the MIT License for security assessment purposes.

---

## 👨‍💻 Author

**Mohammed Siddiqui**
- 💼 LinkedIn: [Let's Chat!](https://www.linkedin.com/in/mohammedsiddiqui6872/)
- 🟣 PowerShellNerd: [My Profile](https://powershellnerd.com/profile/mohammedsiddiqui)

---

## 🙏 Acknowledgments

- Microsoft Graph API for Secure Score data
- Microsoft 365 Security & Compliance teams
- Community contributors and testers
- PowerShell Gallery team

---

## ⚠️ Disclaimer

This toolkit is not affiliated with or endorsed by Microsoft Corporation. Microsoft, Microsoft 365, Azure Active Directory, and related trademarks are property of Microsoft Corporation.

---

**Generated with** ❤️ **for better security posture**

© 2025-present Mohammed Siddiqui. All rights reserved.

