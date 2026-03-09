// ─── Forgot Password Email Templates ─────────────────────────────────────────
//
// Three themes:
//   • clean    — Minimal, focused on the CTA
//   • secure   — Trust-focused, shows security details
//   • friendly — Warm, approachable, reassuring
//
// Variables: userName, resetUrl, expiresIn, appName, appLogo, supportUrl

export const forgotPasswordClean = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#ffffff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#ffffff;padding:60px 0;">
  <tr><td align="center">
    <table role="presentation" width="440" cellpadding="0" cellspacing="0">
      <tr><td>
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="28" style="display:block;margin-bottom:48px;">{{/if}}
        {{#unless appLogo}}<p style="margin:0 0 48px;font-size:18px;font-weight:600;color:#111;">{{appName}}</p>{{/unless}}
        <p style="margin:0 0 12px;font-size:28px;font-weight:700;color:#111;letter-spacing:-0.5px;">Reset your password</p>
        <p style="margin:0 0 32px;font-size:15px;color:#666;line-height:1.7;">
          {{#if userName}}Hi {{userName}}, we{{/if}}{{#unless userName}}We{{/unless}} received a request to reset the password for your account. Click the button below to choose a new password.
        </p>
        <table role="presentation" cellpadding="0" cellspacing="0">
          <tr><td>
            <a href="{{resetUrl}}" style="display:inline-block;background-color:#111;color:#fff;padding:14px 36px;border-radius:6px;font-size:14px;font-weight:600;text-decoration:none;letter-spacing:0.2px;">Reset Password</a>
          </td></tr>
        </table>
        {{#if expiresIn}}<p style="margin:20px 0 0;font-size:12px;color:#aaa;">This link expires in {{expiresIn}}.</p>{{/if}}
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:48px;border-top:1px solid #f0f0f0;">
          <tr><td style="padding-top:20px;">
            <p style="margin:0;font-size:12px;color:#bbb;line-height:1.6;">
              If you didn't request this, you can safely ignore this email. Your password won't change.
              {{#if supportUrl}}<br><a href="{{supportUrl}}" style="color:#999;text-decoration:underline;">Contact support</a>{{/if}}
            </p>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;


export const forgotPasswordSecure = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="520" cellpadding="0" cellspacing="0">
      <!-- Header -->
      <tr><td style="background-color:#0c2340;padding:28px 32px;border-radius:10px 10px 0 0;" align="center">
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="30" style="display:block;">{{/if}}
        {{#unless appLogo}}<p style="margin:0;font-size:20px;font-weight:700;color:#ffffff;">🔒 {{appName}}</p>{{/unless}}
      </td></tr>
      <!-- Body -->
      <tr><td style="background-color:#ffffff;padding:36px 32px;border-radius:0 0 10px 10px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <tr><td>
            <p style="margin:0 0 6px;font-size:12px;font-weight:700;color:#0c2340;text-transform:uppercase;letter-spacing:1px;">Password Reset Request</p>
            <p style="margin:0 0 20px;font-size:14px;color:#556678;line-height:1.7;">
              {{#if userName}}Hello {{userName}},<br>{{/if}}
              A password reset was requested for your account. For your security, this link is valid for a limited time only.
            </p>
          </td></tr>
          <!-- Security notice -->
          <tr><td>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;">
              <tr><td style="padding:16px 20px;">
                <p style="margin:0 0 4px;font-size:11px;font-weight:700;color:#0c2340;text-transform:uppercase;letter-spacing:0.5px;">⚠️ Security Reminder</p>
                <p style="margin:0;font-size:12px;color:#556678;line-height:1.6;">
                  Never share this link. {{appName}} will never ask for your password via email. 
                  {{#if expiresIn}}This link expires in {{expiresIn}}.{{/if}}
                </p>
              </td></tr>
            </table>
          </td></tr>
          <!-- CTA -->
          <tr><td style="padding:28px 0 0;" align="center">
            <a href="{{resetUrl}}" style="display:inline-block;background-color:#0c2340;color:#ffffff;padding:14px 40px;border-radius:6px;font-size:14px;font-weight:700;text-decoration:none;">Reset My Password</a>
          </td></tr>
          <tr><td style="padding:12px 0 0;" align="center">
            <p style="margin:0;font-size:11px;color:#aaa;">Or copy this URL: <span style="color:#0c2340;word-break:break-all;">{{resetUrl}}</span></p>
          </td></tr>
        </table>
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:20px 0 0;" align="center">
        <p style="margin:0;font-size:11px;color:#999;">
          If you did not request this reset, no action is needed.
          {{#if supportUrl}}<br><a href="{{supportUrl}}" style="color:#888;text-decoration:underline;">Contact Support</a>{{/if}}
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;


export const forgotPasswordFriendly = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#fef9f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#fef9f3;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="500" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.05);">
      <!-- Accent bar -->
      <tr><td style="height:6px;background:linear-gradient(90deg,#f59e0b,#ef4444,#8b5cf6);"></td></tr>
      <!-- Content -->
      <tr><td style="padding:44px 40px;">
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="28" style="display:block;margin-bottom:28px;">{{/if}}
        {{#unless appLogo}}<p style="margin:0 0 28px;font-size:18px;font-weight:700;color:#1f1f1f;">{{appName}}</p>{{/unless}}
        <p style="margin:0 0 8px;font-size:26px;font-weight:700;color:#1f1f1f;">Forgot your password?</p>
        <p style="margin:0 0 4px;font-size:26px;font-weight:700;color:#1f1f1f;">No worries! 👋</p>
        <p style="margin:16px 0 32px;font-size:15px;color:#6b7280;line-height:1.7;">
          {{#if userName}}Hey {{userName}}! {{/if}}It happens to the best of us. Click below and you'll be back in your account in no time.
        </p>
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
          <tr><td align="center">
            <a href="{{resetUrl}}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#ffffff;padding:16px 44px;border-radius:50px;font-size:15px;font-weight:700;text-decoration:none;box-shadow:0 4px 14px rgba(239,68,68,0.3);">Choose a New Password</a>
          </td></tr>
        </table>
        {{#if expiresIn}}<p style="margin:16px 0 0;font-size:12px;color:#bbb;text-align:center;">⏳ Heads up — this link expires in {{expiresIn}}</p>{{/if}}
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:0 40px 36px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #f3f4f6;padding-top:20px;">
          <tr><td>
            <p style="margin:0;font-size:12px;color:#aaa;line-height:1.6;">
              Didn't ask for this? No problem — just ignore this email and nothing changes.
              {{#if supportUrl}}<br>Need help? <a href="{{supportUrl}}" style="color:#f59e0b;text-decoration:none;font-weight:600;">We're here for you</a>{{/if}}
            </p>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
