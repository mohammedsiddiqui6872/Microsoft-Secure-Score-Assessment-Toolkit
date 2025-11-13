# HTML Report Enhancements

## Overview
Enhanced the HTML report to include tenant context, user information, and GitHub repository links for better transparency and accessibility.

---

## Changes Made

### 1. Header Section - Tenant Information

**Added to Header:**
- **Tenant ID Display**: Shows the actual tenant ID below the organization name
  ```
  Microsoft 365 Tenant
  Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  ```

- **Run By User**: Shows who executed the report in the header-right section
  ```
  Generated: November 13, 2025 10:30:45
  Run by: user@contoso.com
  Controls Source: Microsoft Graph API
  Total Controls: 411
  ```

### 2. Footer Section - GitHub Links & Attribution

**Added to Footer:**
```
Microsoft Secure Score Remediation Toolkit
View on GitHub | Report Issues | Submit Feedback
Run by: user@contoso.com
```

**Links Included:**
1. **View on GitHub**:
   - URL: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit
   - Opens repository homepage

2. **Report Issues**:
   - URL: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues
   - Opens issues list

3. **Submit Feedback**:
   - URL: https://github.com/mohammedsiddiqui6872/Microsoft-Secure-Score-remediation-toolkit/issues/new
   - Opens new issue form

### 3. User Context Variables

**New Variables Added:**
```powershell
# Line 527-528 in SecureScore-Remediation-API.ps1
$runByUser = if ($script:currentUserAccount) { $script:currentUserAccount } else { "Unknown User" }
$tenantIdDisplay = if ($script:currentTenantId) { $script:currentTenantId } else { "Unknown" }
```

**Data Source:**
```powershell
# Line 280 in SecureScore-Remediation-API.ps1
$script:currentUserAccount = $context.Account
```

---

## Benefits

### 1. Transparency
- **Audit Trail**: Clear attribution of who generated each report
- **Tenant Identification**: No confusion about which tenant the report belongs to
- **Traceability**: Full context for compliance and security reviews

### 2. Accessibility
- **Easy Issue Reporting**: Users can quickly report bugs or problems
- **Feedback Channel**: Direct path for suggestions and improvements
- **Documentation Access**: Link to repository for full documentation

### 3. Professional Presentation
- **Complete Context**: All relevant information displayed prominently
- **Consistent Styling**: Links styled to match report theme
- **Clear Attribution**: Toolkit branding in footer

---

## Visual Layout

### Header Layout
```
╔════════════════════════════════════════════════════════════╗
║ SECURE SCORE ASSESSMENT [API-DRIVEN]    Generated: [Date] ║
║ Organization Name                        Run by: [User]    ║
║ Tenant ID: [UUID]                       Controls: 411      ║
╚════════════════════════════════════════════════════════════╝
```

### Footer Layout
```
╔════════════════════════════════════════════════════════════╗
║ Microsoft Secure Score API Assessment Report              ║
║ Generated [DateTime] | Powered by Microsoft Graph API     ║
║ This report contains 411 controls from Secure Score API   ║
║ ---------------------------------------------------------- ║
║ Microsoft Secure Score Remediation Toolkit                 ║
║ View on GitHub | Report Issues | Submit Feedback           ║
║ Run by: user@contoso.com                                   ║
╚════════════════════════════════════════════════════════════╝
```

---

## Implementation Details

### Code Location
- **File**: `SecureScore-Remediation-API.ps1`
- **Header Section**: Lines 1082-1092
- **Footer Section**: Lines 1157-1168
- **Variables**: Lines 525-528

### Styling
```css
/* Footer links styled to match report theme */
color: #60a5fa;           /* Blue matching report colors */
text-decoration: none;     /* Clean look */
hover: underline;         /* Interactive feedback */
```

---

## Security Considerations

### What's Displayed
✅ **User Account**: Email/UPN of authenticated user (safe)
✅ **Tenant ID**: Organization identifier (needed for context)

### What's NOT Displayed
❌ **Tenant Secret/Keys**: Never included
❌ **Access Tokens**: Never stored or displayed
❌ **Sensitive Config**: Not exposed in reports

### Privacy Note
The tenant ID and user account are:
- Already visible in Microsoft portals
- Required for context and audit trails
- Standard practice for compliance reports
- Only displayed in reports (not stored in repo)

---

## Testing Checklist

To verify the enhancements:

1. ✅ Run the script: `.\SecureScore-Remediation-API.ps1 -WhatIf`
2. ✅ Open generated HTML report
3. ✅ Verify header shows:
   - Tenant ID
   - Run by user
4. ✅ Verify footer shows:
   - GitHub repository link
   - Report Issues link
   - Submit Feedback link
   - Run by user
5. ✅ Click each link to ensure they work
6. ✅ Verify links open in new tab

---

## Future Enhancements

Potential future additions:
- Report generation duration
- Script version number
- Last update timestamp
- Report expiration date
- Export to PDF button
- Share report button
- Print-friendly view toggle

---

*Last Updated: 2025-11-13*
*Commit: f27ad18*
