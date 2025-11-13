# Microsoft Secure Score Remediation Toolkit

A powerful PowerShell toolkit for assessing and managing Microsoft 365 security posture through the Microsoft Secure Score API. Generate comprehensive, interactive HTML reports with 411+ security controls directly from Microsoft Graph API.

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support%20This%20Project-yellow.svg)](https://buymeacoffee.com/mohammedsiddiqui)

---

## Features

### API-Driven Control Fetching
- **Real-time Data**: Fetches 411+ security controls directly from Microsoft Graph API
- **Always Up-to-Date**: No manual JSON updates needed - controls sync with Microsoft's latest recommendations
- **Dynamic Tenant Context**: Automatically uses your tenant ID for all portal links

### Interactive HTML Reports
- **Professional Dark Theme**: Modern, responsive design optimized for readability
- **Interactive Filtering**: Click summary cards to filter controls by status or risk level
- **Quick Access Links**: Direct links to configuration portals for each control
- **Executive Summary**: At-a-glance compliance metrics and risk breakdown

### Smart Features
- **Progress Tracking**: Real-time progress bar during control processing
- **Tenant Attribution**: Shows tenant ID and user who generated the report
- **Category Organization**: Controls grouped by security domains (Identity, Data, Device, Apps, Infrastructure)
- **Risk-Based Prioritization**: Controls categorized as High, Medium, or Low risk

---

## Quick Start

### Prerequisites

- Windows PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK
- Azure AD account with SecurityEvents.Read.All permission

### Installation

1. **Clone the repository**
   ```powershell
   git clone https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit.git
   cd Microsoft-Secure-Score-remediation-toolkit
   ```

2. **Install Microsoft Graph PowerShell Module**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

3. **Run the script**
   ```powershell
   .\SecureScore-Remediation-API.ps1 -WhatIf
   ```

---

## Usage

### Generate Full Assessment Report
```powershell
.\SecureScore-Remediation-API.ps1 -WhatIf
```
Generates an HTML report with all 411+ controls fetched from Microsoft Graph API.

### Generate Applicable Controls Report
```powershell
.\SecureScore-Remediation-API.ps1 -ApplicableOnly -WhatIf
```
Generates a report showing only controls applicable to your tenant (typically ~70 controls).

### Generate Both Reports
```powershell
.\Generate-Both-Reports.ps1
```
Generates both full and applicable-only reports in one execution.

### Custom Tenant Name
```powershell
.\SecureScore-Remediation-API.ps1 -TenantName "Contoso Corporation" -WhatIf
```

---

## Report Features

### Interactive Summary Dashboard
- **6 Summary Cards** in a single row for quick overview:
  - Compliant Controls (already implemented)
  - Non-Compliant Controls (action required)
  - High Risk Controls
  - Medium Risk Controls
  - Low Risk Controls
  - Not Applicable Controls

### Click-to-Filter
Click any summary card to instantly filter the entire report:
- See only compliant controls
- Focus on high-risk items
- Review non-compliant controls
- Click again to clear the filter

### Detailed Control Information
Each control displays:
- Control name and description
- Current compliance status
- Risk level
- Microsoft documentation link
- Direct action link to configuration portal
- Applicable Microsoft 365 plans

---

## Security & Privacy

### Zero Hardcoded Secrets
- No tenant IDs stored in repository
- No authentication tokens persisted
- All tenant context injected dynamically at runtime

### Read-Only Access
- Script only reads Secure Score data
- No modifications to your tenant configuration
- `-WhatIf` flag ensures safe execution

### Attribution & Transparency
Every report includes:
- Tenant ID for clear identification
- User account that generated the report
- Generation timestamp
- Full audit trail

---

## Project Structure

```
Microsoft-Secure-Score-remediation-toolkit/
├── SecureScore-Remediation-API.ps1          # Main script
├── Generate-Both-Reports.ps1                # Convenience wrapper
├── SecureScore-API-Controls.json            # Control definitions
├── CHANGELOG.md                             # Version history
├── SECURITY-FIX-SUMMARY.md                  # Security documentation
├── REPORT-ENHANCEMENTS.md                   # Feature documentation
└── ANALYSIS-AND-RECOMMENDATIONS.md          # Technical analysis
```

---

## Requirements

### Microsoft Graph Permissions
The script requires:
- **SecurityEvents.Read.All**: Read Secure Score data

### Supported Microsoft 365 Plans
- Microsoft 365 E3
- Microsoft 365 E5
- Office 365 E3
- Office 365 E5
- Azure Active Directory Premium P1/P2

---

## Troubleshooting

### Authentication Issues
```powershell
# Disconnect and reconnect
Disconnect-MgGraph
Connect-MgGraph -Scopes "SecurityEvents.Read.All"
```

### Module Not Found
```powershell
# Install Microsoft Graph module
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Permission Denied
Ensure your account has:
- Security Reader role in Azure AD
- SecurityEvents.Read.All API permission

---

## Contributing

We welcome contributions! Here's how you can help:

### Report Issues
Found a bug or have a feature request? [Open an issue](https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues)

### Submit Feedback
Have suggestions? [Share your feedback](https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues/new)

### Support This Project
If this toolkit has helped improve your security posture:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow.svg?style=for-the-badge)](https://buymeacoffee.com/mohammedsiddiqui)

---

## Changelog

### [1.1.0] - 2025-11-13

#### Security
- **CRITICAL**: Removed all hardcoded tenant IDs (198 instances)
- Implemented dynamic tenant ID injection at runtime

#### Added
- Interactive filtering via clickable summary cards
- 6-card single-row dashboard layout
- Real-time progress indicators
- Tenant attribution in reports
- GitHub repository links in footer
- Buy Me a Coffee support link

#### Enhanced
- Professional hover effects on summary cards
- Auto-hide empty categories during filtering
- Toggle filter behavior (click to activate/deactivate)

### [1.0.0] - 2025-11-12
- Initial release with Microsoft Graph API integration

[View Full Changelog](CHANGELOG.md)

---

## License

This project is provided as-is for security assessment purposes. Use at your own discretion.

---

## Author

**Mohammed Siddiqui**
- GitHub: [@mohammedsiddiqui6872](https://github.com/mohammedsiddiqui6872)
- Support: [Buy Me a Coffee](https://buymeacoffee.com/mohammedsiddiqui)

---

## Acknowledgments

- Microsoft Graph API for Secure Score data
- Microsoft 365 Security & Compliance teams
- Community contributors and testers

---

## Disclaimer

This toolkit is not affiliated with or endorsed by Microsoft Corporation. Microsoft, Microsoft 365, Azure Active Directory, and related trademarks are property of Microsoft Corporation.

---

**Generated with** ❤️ **for better security posture**

[View on GitHub](https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit) | [Report Issues](https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues) | [Submit Feedback](https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues/new) | [☕ Buy Me a Coffee](https://buymeacoffee.com/mohammedsiddiqui)
