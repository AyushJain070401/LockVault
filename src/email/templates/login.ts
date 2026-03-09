// ─── Login Notification Email Templates ──────────────────────────────────────
//
// Three themes:
//   • minimal   — Clean, whitespace-heavy, understated
//   • corporate  — Professional, structured, enterprise-ready
//   • vibrant   — Bold colors, modern feel, consumer-facing
//
// Variables: userName, loginTime, ipAddress, deviceInfo, location,
//            appName, appLogo, dashboardUrl, supportUrl

export const loginMinimal = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#fafafa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#fafafa;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:2px;border:1px solid #e8e8e8;">
      <tr><td style="padding:48px 40px 0;">
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="28" style="display:block;margin-bottom:32px;">{{/if}}
        {{#unless appLogo}}<p style="margin:0 0 32px;font-size:18px;font-weight:600;color:#111;letter-spacing:-0.3px;">{{appName}}</p>{{/unless}}
        <p style="margin:0 0 8px;font-size:13px;font-weight:500;color:#999;text-transform:uppercase;letter-spacing:1.2px;">New Sign-In</p>
        <p style="margin:0 0 24px;font-size:15px;color:#333;line-height:1.6;">
          Hi{{#if userName}} {{userName}}{{/if}}, a new login to your account was detected.
        </p>
      </td></tr>
      <tr><td style="padding:0 40px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #f0f0f0;border-bottom:1px solid #f0f0f0;padding:20px 0;">
          <tr>
            <td style="padding:6px 0;font-size:13px;color:#999;width:100px;">Time</td>
            <td style="padding:6px 0;font-size:13px;color:#333;">{{loginTime}}</td>
          </tr>
          {{#if ipAddress}}<tr>
            <td style="padding:6px 0;font-size:13px;color:#999;">IP Address</td>
            <td style="padding:6px 0;font-size:13px;color:#333;">{{ipAddress}}</td>
          </tr>{{/if}}
          {{#if deviceInfo}}<tr>
            <td style="padding:6px 0;font-size:13px;color:#999;">Device</td>
            <td style="padding:6px 0;font-size:13px;color:#333;">{{deviceInfo}}</td>
          </tr>{{/if}}
          {{#if location}}<tr>
            <td style="padding:6px 0;font-size:13px;color:#999;">Location</td>
            <td style="padding:6px 0;font-size:13px;color:#333;">{{location}}</td>
          </tr>{{/if}}
        </table>
      </td></tr>
      <tr><td style="padding:24px 40px 48px;">
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6;">
          If this wasn't you, secure your account immediately.
          {{#if supportUrl}}<a href="{{supportUrl}}" style="color:#111;text-decoration:underline;">Get help</a>{{/if}}
        </p>
      </td></tr>
    </table>
    <p style="margin:24px 0 0;font-size:11px;color:#bbb;">&copy; {{appName}}</p>
  </td></tr>
</table>
</body>
</html>`;


export const loginCorporate = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f4f5f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f7;padding:32px 0;">
  <tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0">
      <!-- Header bar -->
      <tr><td style="background-color:#1a1a2e;padding:24px 32px;border-radius:8px 8px 0 0;">
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="32" style="display:block;">{{/if}}
        {{#unless appLogo}}<p style="margin:0;font-size:20px;font-weight:700;color:#ffffff;">{{appName}}</p>{{/unless}}
      </td></tr>
      <!-- Body -->
      <tr><td style="background-color:#ffffff;padding:32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <tr><td>
            <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#1a1a2e;text-transform:uppercase;letter-spacing:1px;">Security Notice</p>
            <p style="margin:0 0 20px;font-size:22px;font-weight:700;color:#1a1a2e;">New Login Detected</p>
            <p style="margin:0 0 24px;font-size:14px;color:#4a4a68;line-height:1.7;">
              {{#if userName}}Hello {{userName}},<br>{{/if}}
              We noticed a new sign-in to your {{appName}} account. Please review the details below.
            </p>
          </td></tr>
          <!-- Details card -->
          <tr><td>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8f9fb;border-radius:6px;border-left:4px solid #1a1a2e;">
              <tr><td style="padding:20px 24px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="padding:4px 0;font-size:12px;font-weight:600;color:#8888a0;width:110px;">DATE &amp; TIME</td>
                    <td style="padding:4px 0;font-size:13px;color:#1a1a2e;">{{loginTime}}</td>
                  </tr>
                  {{#if ipAddress}}<tr>
                    <td style="padding:4px 0;font-size:12px;font-weight:600;color:#8888a0;">IP ADDRESS</td>
                    <td style="padding:4px 0;font-size:13px;color:#1a1a2e;font-family:'Courier New',monospace;">{{ipAddress}}</td>
                  </tr>{{/if}}
                  {{#if deviceInfo}}<tr>
                    <td style="padding:4px 0;font-size:12px;font-weight:600;color:#8888a0;">DEVICE</td>
                    <td style="padding:4px 0;font-size:13px;color:#1a1a2e;">{{deviceInfo}}</td>
                  </tr>{{/if}}
                  {{#if location}}<tr>
                    <td style="padding:4px 0;font-size:12px;font-weight:600;color:#8888a0;">LOCATION</td>
                    <td style="padding:4px 0;font-size:13px;color:#1a1a2e;">{{location}}</td>
                  </tr>{{/if}}
                </table>
              </td></tr>
            </table>
          </td></tr>
          <tr><td style="padding-top:24px;">
            <p style="margin:0;font-size:13px;color:#8888a0;line-height:1.6;">
              If you did not initiate this login, please change your password immediately and contact support.
            </p>
            {{#if dashboardUrl}}<p style="margin:16px 0 0;">
              <a href="{{dashboardUrl}}" style="display:inline-block;background-color:#1a1a2e;color:#ffffff;padding:10px 24px;border-radius:4px;font-size:13px;font-weight:600;text-decoration:none;">Review Account Activity</a>
            </p>{{/if}}
          </td></tr>
        </table>
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:20px 32px;border-top:1px solid #eee;">
        <p style="margin:0;font-size:11px;color:#aaa;text-align:center;">
          &copy; {{appName}} &middot; This is an automated security notification
          {{#if supportUrl}}&middot; <a href="{{supportUrl}}" style="color:#888;text-decoration:underline;">Support</a>{{/if}}
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;


export const loginVibrant = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#0f0f23;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f0f23;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="500" cellpadding="0" cellspacing="0">
      <!-- Logo -->
      <tr><td style="padding:0 0 32px;" align="center">
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="36" style="display:block;">{{/if}}
        {{#unless appLogo}}<p style="margin:0;font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.5px;">{{appName}}</p>{{/unless}}
      </td></tr>
      <!-- Card -->
      <tr><td style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:16px;padding:3px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#1a1a2e;border-radius:14px;">
          <tr><td style="padding:40px 36px;">
            <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#667eea;text-transform:uppercase;letter-spacing:2px;">🔐 Login Alert</p>
            <p style="margin:0 0 20px;font-size:24px;font-weight:800;color:#ffffff;line-height:1.3;">
              New sign-in{{#if userName}},<br>{{userName}}{{/if}}
            </p>
            <p style="margin:0 0 28px;font-size:14px;color:#a0a0c0;line-height:1.7;">
              Someone just signed into your account. If this was you, no action is needed.
            </p>
            <!-- Details -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#12122a;border-radius:10px;">
              <tr><td style="padding:20px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="padding:6px 0;font-size:12px;color:#667eea;font-weight:600;width:90px;">Time</td>
                    <td style="padding:6px 0;font-size:13px;color:#e0e0f0;">{{loginTime}}</td>
                  </tr>
                  {{#if ipAddress}}<tr>
                    <td style="padding:6px 0;font-size:12px;color:#667eea;font-weight:600;">IP</td>
                    <td style="padding:6px 0;font-size:13px;color:#e0e0f0;font-family:'Courier New',monospace;">{{ipAddress}}</td>
                  </tr>{{/if}}
                  {{#if deviceInfo}}<tr>
                    <td style="padding:6px 0;font-size:12px;color:#667eea;font-weight:600;">Device</td>
                    <td style="padding:6px 0;font-size:13px;color:#e0e0f0;">{{deviceInfo}}</td>
                  </tr>{{/if}}
                  {{#if location}}<tr>
                    <td style="padding:6px 0;font-size:12px;color:#667eea;font-weight:600;">Location</td>
                    <td style="padding:6px 0;font-size:13px;color:#e0e0f0;">{{location}}</td>
                  </tr>{{/if}}
                </table>
              </td></tr>
            </table>
            <!-- Action -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding-top:28px;">
              <tr><td>
                <p style="margin:0;font-size:13px;color:#666680;">
                  Wasn't you? 
                  {{#if supportUrl}}<a href="{{supportUrl}}" style="color:#667eea;font-weight:600;text-decoration:none;">Secure your account →</a>{{/if}}
                  {{#unless supportUrl}}Change your password immediately.{{/unless}}
                </p>
              </td></tr>
            </table>
          </td></tr>
        </table>
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:24px 0 0;" align="center">
        <p style="margin:0;font-size:11px;color:#444460;">&copy; {{appName}}</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
