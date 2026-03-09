// ─── Alert Email Templates ───────────────────────────────────────────────────
//
// Three themes:
//   • standard — Balanced, informational
//   • urgent   — High-contrast, red-accented, demands attention
//   • subtle   — Soft, non-intrusive, informational
//
// Variables: userName, alertTitle, alertMessage, actionUrl, actionLabel,
//            appName, appLogo, severity, timestamp

export const alertStandard = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f5f5f5;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
      <!-- Header -->
      <tr><td style="background-color:#2d3748;padding:20px 32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td>
              {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="24" style="display:block;">{{/if}}
              {{#unless appLogo}}<p style="margin:0;font-size:16px;font-weight:600;color:#ffffff;">{{appName}}</p>{{/unless}}
            </td>
            <td align="right">
              <p style="margin:0;font-size:11px;font-weight:600;color:#a0aec0;text-transform:uppercase;letter-spacing:0.5px;">Security Alert</p>
            </td>
          </tr>
        </table>
      </td></tr>
      <!-- Body -->
      <tr><td style="padding:32px;">
        <p style="margin:0 0 6px;font-size:20px;font-weight:700;color:#1a202c;">{{alertTitle}}</p>
        {{#if timestamp}}<p style="margin:0 0 20px;font-size:12px;color:#a0aec0;">{{timestamp}}</p>{{/if}}
        <p style="margin:0 0 24px;font-size:14px;color:#4a5568;line-height:1.7;">
          {{#if userName}}Hi {{userName}},<br><br>{{/if}}
          {{alertMessage}}
        </p>
        {{#if actionUrl}}<table role="presentation" cellpadding="0" cellspacing="0">
          <tr><td>
            <a href="{{actionUrl}}" style="display:inline-block;background-color:#2d3748;color:#ffffff;padding:12px 28px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none;">{{#if actionLabel}}{{actionLabel}}{{/if}}{{#unless actionLabel}}Take Action{{/unless}}</a>
          </td></tr>
        </table>{{/if}}
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:20px 32px;background-color:#f7fafc;border-top:1px solid #edf2f7;">
        <p style="margin:0;font-size:11px;color:#a0aec0;text-align:center;">
          This is an automated alert from {{appName}}. Please do not reply to this email.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;


export const alertUrgent = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#1a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#1a0a0a;padding:40px 0;">
  <tr><td align="center">
    <table role="presentation" width="520" cellpadding="0" cellspacing="0">
      <!-- Red accent top -->
      <tr><td style="height:4px;background-color:#ef4444;border-radius:8px 8px 0 0;"></td></tr>
      <tr><td style="background-color:#1f1215;padding:32px;border-radius:0 0 8px 8px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
          <!-- Header -->
          <tr><td style="padding-bottom:24px;border-bottom:1px solid #2d1a1e;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="24" style="display:block;">{{/if}}
                  {{#unless appLogo}}<p style="margin:0;font-size:16px;font-weight:600;color:#ffffff;">{{appName}}</p>{{/unless}}
                </td>
                <td align="right">
                  <span style="display:inline-block;background-color:#7f1d1d;color:#fca5a5;padding:4px 12px;border-radius:50px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">
                    ⚠ Urgent
                  </span>
                </td>
              </tr>
            </table>
          </td></tr>
          <!-- Content -->
          <tr><td style="padding:28px 0;">
            <p style="margin:0 0 8px;font-size:24px;font-weight:800;color:#fecaca;">{{alertTitle}}</p>
            {{#if timestamp}}<p style="margin:0 0 20px;font-size:11px;color:#6b3a3a;">{{timestamp}}</p>{{/if}}
            <p style="margin:0 0 28px;font-size:14px;color:#d4a0a0;line-height:1.8;">
              {{#if userName}}{{userName}},<br><br>{{/if}}
              {{alertMessage}}
            </p>
            {{#if actionUrl}}<table role="presentation" cellpadding="0" cellspacing="0" width="100%">
              <tr><td align="center">
                <a href="{{actionUrl}}" style="display:inline-block;background-color:#ef4444;color:#ffffff;padding:14px 36px;border-radius:6px;font-size:14px;font-weight:700;text-decoration:none;">{{#if actionLabel}}{{actionLabel}}{{/if}}{{#unless actionLabel}}Take Immediate Action{{/unless}}</a>
              </td></tr>
            </table>{{/if}}
          </td></tr>
          <!-- Warning box -->
          <tr><td>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#2d1a1e;border-radius:6px;border:1px solid #4c1d1d;">
              <tr><td style="padding:14px 18px;">
                <p style="margin:0;font-size:12px;color:#f87171;line-height:1.6;">
                  If you did not trigger this action, your account may be compromised. Change your password and enable two-factor authentication immediately.
                </p>
              </td></tr>
            </table>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:16px 0 0;" align="center">
        <p style="margin:0;font-size:10px;color:#4a2020;">&copy; {{appName}} &middot; Automated security alert</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;


export const alertSubtle = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#fafbfc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#fafbfc;padding:48px 0;">
  <tr><td align="center">
    <table role="presentation" width="480" cellpadding="0" cellspacing="0">
      <tr><td>
        {{#if appLogo}}<img src="{{appLogo}}" alt="{{appName}}" height="24" style="display:block;margin-bottom:36px;opacity:0.7;">{{/if}}
        {{#unless appLogo}}<p style="margin:0 0 36px;font-size:15px;font-weight:600;color:#94a3b8;">{{appName}}</p>{{/unless}}
      </td></tr>
      <tr><td>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;border:1px solid #e2e8f0;">
          <!-- Info accent -->
          <tr><td style="padding:28px 32px 0;">
            <table role="presentation" cellpadding="0" cellspacing="0">
              <tr><td style="background-color:#eff6ff;border-radius:50px;padding:6px 14px;">
                <p style="margin:0;font-size:11px;font-weight:600;color:#3b82f6;text-transform:uppercase;letter-spacing:0.5px;">ℹ Notice</p>
              </td></tr>
            </table>
          </td></tr>
          <tr><td style="padding:16px 32px 28px;">
            <p style="margin:0 0 6px;font-size:17px;font-weight:600;color:#1e293b;">{{alertTitle}}</p>
            {{#if timestamp}}<p style="margin:0 0 16px;font-size:12px;color:#cbd5e1;">{{timestamp}}</p>{{/if}}
            <p style="margin:0;font-size:14px;color:#64748b;line-height:1.7;">
              {{#if userName}}Hi {{userName}},<br><br>{{/if}}
              {{alertMessage}}
            </p>
            {{#if actionUrl}}<p style="margin:20px 0 0;">
              <a href="{{actionUrl}}" style="color:#3b82f6;font-size:13px;font-weight:600;text-decoration:none;">
                {{#if actionLabel}}{{actionLabel}}{{/if}}{{#unless actionLabel}}View Details{{/unless}} →
              </a>
            </p>{{/if}}
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="padding:20px 0 0;">
        <p style="margin:0;font-size:11px;color:#cbd5e1;text-align:center;">
          Automated notification from {{appName}}
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
