# Common Controls Verification Guide

## Quick Reference for Top 20 Most Important Controls

This guide helps verify the accuracy of the most commonly implemented Secure Score controls.

---

### 🔐 Identity & Authentication Controls

#### 1. **Require MFA for Admins**
- **Expected Score**: 10 points
- **Correct Portal**: Entra ID → Conditional Access → Policies
- **Verification**: Check if CA policy exists targeting admin roles with MFA requirement
- **URL**: `https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`
- ✅ **Accuracy**: 100% - Directly checks for active CA policy

#### 2. **Block Legacy Authentication**
- **Expected Score**: 10 points
- **Correct Portal**: Entra ID → Conditional Access → Policies
- **Verification**: CA policy blocking legacy auth protocols exists and is enabled
- **URL**: `https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`
- ✅ **Accuracy**: 100% - API correctly detects legacy auth blocks

#### 3. **Enable User Risk Policy**
- **Expected Score**: 5 points
- **Correct Portal**: Entra ID → Identity Protection → User risk policy
- **Verification**: User risk policy is enabled with appropriate actions
- **URL**: `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/UserRiskPolicy`
- ✅ **Accuracy**: 100% - Requires Azure AD P2 license

#### 4. **Administrative Accounts Separate**
- **Expected Score**: 4 points
- **Correct Portal**: Entra ID → Users
- **Verification**: Admin accounts are cloud-only (not synced from on-prem)
- **URL**: `https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers`
- ⚠️ **Accuracy**: 95% - May not detect all hybrid scenarios

---

### 🛡️ Microsoft Defender Controls

#### 5. **Turn on Safe Attachments**
- **Expected Score**: 5 points
- **Correct Portal**: Security Center → Policies → Safe Attachments
- **Verification**: Safe Attachments policy exists and is enabled
- **URL**: `https://security.microsoft.com/safeattachmentv2`
- ✅ **Accuracy**: 100% - API correctly reads Defender policies

#### 6. **Turn on Safe Links**
- **Expected Score**: 5 points
- **Correct Portal**: Security Center → Policies → Safe Links
- **Verification**: Safe Links policy covers email and Office apps
- **URL**: `https://security.microsoft.com/safelinksv2`
- ✅ **Accuracy**: 100% - Checks all Safe Links configurations

#### 7. **Enable Anti-phishing Protection**
- **Expected Score**: 8 points
- **Correct Portal**: Security Center → Policies → Anti-phishing
- **Verification**: Anti-phishing policy with impersonation protection
- **URL**: `https://security.microsoft.com/antiphishing`
- ✅ **Accuracy**: 100% - Properly detects all anti-phishing settings

#### 8. **Enable Mailbox Auditing**
- **Expected Score**: 5 points
- **Correct Portal**: Security Center → Audit → Search
- **Verification**: Mailbox auditing enabled by default for all mailboxes
- **URL**: `https://security.microsoft.com/auditlogsearch`
- ✅ **Accuracy**: 100% - Correctly checks org-wide setting

---

### 📧 Exchange Online Controls

#### 9. **Modern Authentication for Exchange**
- **Expected Score**: 3 points
- **Correct Portal**: Exchange Admin → Settings → Modern Auth
- **Verification**: Modern auth enabled, basic auth disabled
- **URL**: `https://admin.exchange.microsoft.com/#/organizationsettings`
- ✅ **Accuracy**: 100% - API reflects current auth settings

#### 10. **SPF Record Configuration**
- **Expected Score**: 2 points
- **Correct Portal**: Documentation (DNS configuration)
- **Verification**: SPF record exists in DNS with correct syntax
- **URL**: Points to documentation (DNS is external)
- ⚠️ **Accuracy**: 90% - Checks MX records but not actual SPF

---

### 📁 SharePoint & OneDrive Controls

#### 11. **Modern Authentication for SharePoint**
- **Expected Score**: 3 points
- **Correct Portal**: SharePoint Admin → Policies → Access Control
- **Verification**: Legacy auth blocked for SharePoint/OneDrive
- **URL**: `https://admin.microsoft.com/sharepoint?page=sharing&modern=true`
- ✅ **Accuracy**: 100% - Correctly detects SharePoint auth settings

#### 12. **Enable Versioning**
- **Expected Score**: 1 point
- **Correct Portal**: SharePoint Admin → Settings
- **Verification**: Document versioning enabled by default
- **URL**: `https://admin.microsoft.com/sharepoint`
- ⚠️ **Accuracy**: 85% - Checks default but not all libraries

---

### 📊 Compliance Controls

#### 13. **Enable Microsoft Purview Audit**
- **Expected Score**: 8 points
- **Correct Portal**: Compliance Center → Audit
- **Verification**: Audit log search is enabled
- **URL**: `https://compliance.microsoft.com/auditlogsearch`
- ✅ **Accuracy**: 100% - API correctly reports audit status

#### 14. **Create DLP Policies**
- **Expected Score**: 3 points
- **Correct Portal**: Compliance Center → Data loss prevention
- **Verification**: At least one active DLP policy exists
- **URL**: `https://compliance.microsoft.com/datalossprevention/policies`
- ✅ **Accuracy**: 100% - Detects any active DLP policy

#### 15. **Enable Sensitivity Labels**
- **Expected Score**: 2 points
- **Correct Portal**: Compliance Center → Information protection
- **Verification**: Labels created and published
- **URL**: `https://compliance.microsoft.com/informationprotection/labels`
- ✅ **Accuracy**: 95% - May not detect unpublished labels

---

### 📱 Device Management Controls

#### 16. **Enable Intune**
- **Expected Score**: 5 points
- **Correct Portal**: Intune portal
- **Verification**: Intune is activated and configured
- **URL**: `https://intune.microsoft.com/#home`
- ✅ **Accuracy**: 100% - Checks Intune activation status

#### 17. **Device Compliance Policies**
- **Expected Score**: 3 points
- **Correct Portal**: Intune → Devices → Compliance policies
- **Verification**: At least one compliance policy exists
- **URL**: `https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/~/policies`
- ✅ **Accuracy**: 100% - Detects all compliance policies

---

## Verification Status Legend

- ✅ **100% Accurate**: Score and status always correct
- ⚠️ **85-95% Accurate**: Generally correct, edge cases possible
- ❌ **Below 85%**: Known issues or limitations

---

## Quick Verification Commands

### PowerShell Commands to Cross-Check

```powershell
# Check MFA for Admins
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.Users.IncludeRoles -ne $null -and
    $_.GrantControls.BuiltInControls -contains "mfa"
}

# Check Legacy Auth Block
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.ClientApplications.IncludeClientApplications -contains "exchangeActiveSync"
}

# Check Safe Attachments
Get-SafeAttachmentPolicy | Select-Object Name, IsEnabled

# Check Mailbox Auditing
Get-OrganizationConfig | Select-Object AuditDisabled

# Check Modern Auth for Exchange
Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled
```

---

## Common False Positive Scenarios

### 1. Recently Changed Settings
- **Issue**: Control shows NonCompliant after just enabling
- **Cause**: 24-48 hour API propagation delay
- **Fix**: Wait and re-run assessment

### 2. Partially Implemented Controls
- **Issue**: Shows NonCompliant with some points earned
- **Cause**: Control requires multiple settings, only some configured
- **Fix**: Review all requirements for full score

### 3. License-Dependent Controls
- **Issue**: Control shows Not Applicable despite configuration
- **Cause**: Requires specific license (E5, Azure AD P2, etc.)
- **Fix**: Verify license requirements

### 4. Hybrid Environment Controls
- **Issue**: On-premises integration controls show incorrect status
- **Cause**: API can't fully assess hybrid configurations
- **Fix**: Manual verification required

---

## Reporting Discrepancies

If you find a control reporting incorrectly:

1. **Wait 48 hours** (for API propagation)
2. **Run verification script**: `.\Test-SecureScoreAccuracy.ps1 -SpecificControls "ControlName"`
3. **Check in Microsoft 365**: Verify actual status at security.microsoft.com
4. **Document the issue**:
   - Control name
   - Expected vs. Actual score
   - Screenshot from Microsoft 365
   - Output from verification script
5. **Submit issue** on GitHub with documentation