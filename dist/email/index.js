'use strict';

var fs = require('fs');
var path = require('path');

function _interopNamespace(e) {
  if (e && e.__esModule) return e;
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var fs__namespace = /*#__PURE__*/_interopNamespace(fs);
var path__namespace = /*#__PURE__*/_interopNamespace(path);

// src/email/index.ts

// src/email/engine.ts
function resolve(path2, variables) {
  const parts = path2.split(".");
  let current = variables;
  for (const part of parts) {
    if (current === null || current === void 0) return void 0;
    current = current[part];
  }
  return current;
}
function renderTemplate(template, variables) {
  let result = template;
  result = result.replace(
    /\{\{#each\s+([\w.]+)\}\}([\s\S]*?)\{\{\/each\}\}/g,
    (_match, varPath, body) => {
      const arr = resolve(varPath, variables);
      if (!Array.isArray(arr)) return "";
      return arr.map((item, index) => {
        const loopVars = {
          ...variables,
          "@index": index,
          "@first": index === 0,
          "@last": index === arr.length - 1
        };
        if (typeof item === "object" && item !== null) {
          Object.assign(loopVars, item);
        } else {
          loopVars["this"] = item;
        }
        return renderTemplate(body, loopVars);
      }).join("");
    }
  );
  result = result.replace(
    /\{\{#if\s+([\w.@]+)\}\}([\s\S]*?)\{\{\/if\}\}/g,
    (_match, varPath, content) => {
      const value = resolve(varPath, variables);
      if (value !== void 0 && value !== null && value !== "" && value !== false) {
        return renderTemplate(content, variables);
      }
      return "";
    }
  );
  result = result.replace(
    /\{\{#unless\s+([\w.@]+)\}\}([\s\S]*?)\{\{\/unless\}\}/g,
    (_match, varPath, content) => {
      const value = resolve(varPath, variables);
      if (!value) {
        return renderTemplate(content, variables);
      }
      return "";
    }
  );
  result = result.replace(/\{\{\{([\w.@]+)\}\}\}/g, (_match, varPath) => {
    const value = resolve(varPath, variables);
    if (value === void 0 || value === null) return "";
    return String(value);
  });
  result = result.replace(/\{\{([\w.@]+)\}\}/g, (_match, varPath) => {
    const value = resolve(varPath, variables);
    if (value === void 0 || value === null) return "";
    return escapeHtml(String(value));
  });
  return result;
}
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function htmlToText(html) {
  return html.replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<br\s*\/?>/gi, "\n").replace(/<\/p>/gi, "\n\n").replace(/<\/div>/gi, "\n").replace(/<\/tr>/gi, "\n").replace(/<\/td>/gi, " ").replace(/<a\s[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, "$2 ($1)").replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/\n{3,}/g, "\n\n").trim();
}

// src/email/templates/login.ts
var loginMinimal = `
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
var loginCorporate = `
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
var loginVibrant = `
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
            <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#667eea;text-transform:uppercase;letter-spacing:2px;">\u{1F510} Login Alert</p>
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
                  {{#if supportUrl}}<a href="{{supportUrl}}" style="color:#667eea;font-weight:600;text-decoration:none;">Secure your account \u2192</a>{{/if}}
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

// src/email/templates/forgot-password.ts
var forgotPasswordClean = `
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
var forgotPasswordSecure = `
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
        {{#unless appLogo}}<p style="margin:0;font-size:20px;font-weight:700;color:#ffffff;">\u{1F512} {{appName}}</p>{{/unless}}
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
                <p style="margin:0 0 4px;font-size:11px;font-weight:700;color:#0c2340;text-transform:uppercase;letter-spacing:0.5px;">\u26A0\uFE0F Security Reminder</p>
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
var forgotPasswordFriendly = `
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
        <p style="margin:0 0 4px;font-size:26px;font-weight:700;color:#1f1f1f;">No worries! \u{1F44B}</p>
        <p style="margin:16px 0 32px;font-size:15px;color:#6b7280;line-height:1.7;">
          {{#if userName}}Hey {{userName}}! {{/if}}It happens to the best of us. Click below and you'll be back in your account in no time.
        </p>
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
          <tr><td align="center">
            <a href="{{resetUrl}}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#ffffff;padding:16px 44px;border-radius:50px;font-size:15px;font-weight:700;text-decoration:none;box-shadow:0 4px 14px rgba(239,68,68,0.3);">Choose a New Password</a>
          </td></tr>
        </table>
        {{#if expiresIn}}<p style="margin:16px 0 0;font-size:12px;color:#bbb;text-align:center;">\u23F3 Heads up \u2014 this link expires in {{expiresIn}}</p>{{/if}}
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:0 40px 36px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #f3f4f6;padding-top:20px;">
          <tr><td>
            <p style="margin:0;font-size:12px;color:#aaa;line-height:1.6;">
              Didn't ask for this? No problem \u2014 just ignore this email and nothing changes.
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

// src/email/templates/alert.ts
var alertStandard = `
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
var alertUrgent = `
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
                    \u26A0 Urgent
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
var alertSubtle = `
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
                <p style="margin:0;font-size:11px;font-weight:600;color:#3b82f6;text-transform:uppercase;letter-spacing:0.5px;">\u2139 Notice</p>
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
                {{#if actionLabel}}{{actionLabel}}{{/if}}{{#unless actionLabel}}View Details{{/unless}} \u2192
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

// src/email/templates/index.ts
var registry = {
  "login": {
    minimal: loginMinimal,
    corporate: loginCorporate,
    vibrant: loginVibrant
  },
  "forgot-password": {
    clean: forgotPasswordClean,
    secure: forgotPasswordSecure,
    friendly: forgotPasswordFriendly
  },
  "alert": {
    standard: alertStandard,
    urgent: alertUrgent,
    subtle: alertSubtle
  },
  // Placeholder categories — users can register templates for these
  "welcome": {},
  "verification": {},
  "magic-link": {},
  "password-changed": {},
  "account-locked": {},
  "two-factor": {},
  "invite": {}
};
var defaultThemes = {
  "login": "minimal",
  "forgot-password": "clean",
  "alert": "standard",
  "welcome": "warm",
  "verification": "modern",
  "magic-link": "sleek",
  "password-changed": "standard",
  "account-locked": "urgent",
  "two-factor": "standard",
  "invite": "warm"
};
var namedTemplates = {};
function getTemplate(category, theme) {
  const categoryTemplates = registry[category];
  if (!categoryTemplates) {
    throw new Error(
      `Unknown email template category: "${category}". Register it with registerCategory() or registerTemplate().`
    );
  }
  const selectedTheme = theme ?? defaultThemes[category] ?? Object.keys(categoryTemplates)[0];
  const template = categoryTemplates[selectedTheme];
  if (!template) {
    const available = Object.keys(categoryTemplates);
    if (available.length === 0) {
      throw new Error(
        `No templates registered for category "${category}". Register a custom template with registerTemplate().`
      );
    }
    throw new Error(
      `Unknown theme "${selectedTheme}" for category "${category}". Available themes: ${available.join(", ")}`
    );
  }
  return template;
}
function registerTemplate(category, theme, html) {
  if (!registry[category]) {
    registry[category] = {};
  }
  registry[category][theme] = html;
}
function registerCategory(category, defaultTheme) {
  if (!registry[category]) {
    registry[category] = {};
  }
  if (defaultTheme) {
    defaultThemes[category] = defaultTheme;
  }
}
function setDefaultTheme(category, theme) {
  defaultThemes[category] = theme;
}
function removeTemplate(category, theme) {
  if (registry[category] && registry[category][theme]) {
    delete registry[category][theme];
    return true;
  }
  return false;
}
function removeCategory(category) {
  if (registry[category]) {
    delete registry[category];
    delete defaultThemes[category];
    return true;
  }
  return false;
}
function listThemes(category) {
  return Object.keys(registry[category] ?? {});
}
function listCategories() {
  return Object.keys(registry);
}
function registerNamedTemplate(name, definition) {
  namedTemplates[name] = definition;
}
function getNamedTemplate(name) {
  const def = namedTemplates[name];
  if (!def) {
    throw new Error(
      `Named template "${name}" not found. Register it with registerNamedTemplate().`
    );
  }
  return def;
}
function removeNamedTemplate(name) {
  if (namedTemplates[name]) {
    delete namedTemplates[name];
    return true;
  }
  return false;
}
function listNamedTemplates() {
  return Object.keys(namedTemplates);
}
function hasNamedTemplate(name) {
  return name in namedTemplates;
}

// src/email/index.ts
function createEmailManager(config) {
  let transporter = null;
  let nodemailer = null;
  const fileCache = /* @__PURE__ */ new Map();
  async function getTransporter() {
    if (transporter) return transporter;
    const moduleName = "nodemailer";
    try {
      nodemailer = await import(
        /* webpackIgnore: true */
        moduleName
      );
    } catch {
      throw new Error("LockVault Email: `nodemailer` is required but not installed.\nInstall it with:\n  npm install nodemailer\n  npm install -D @types/nodemailer");
    }
    const { smtp } = config;
    transporter = nodemailer.createTransport({ host: smtp.host, port: smtp.port, secure: smtp.secure ?? smtp.port === 465, auth: smtp.auth, pool: smtp.pool ?? false, maxConnections: smtp.maxConnections ?? 5, tls: smtp.tls });
    return transporter;
  }
  async function renderSource(source, variables) {
    const vars = { ...config.defaults, ...variables };
    if (typeof source === "string") return renderHtml(source, vars);
    switch (source.type) {
      case "html":
        return renderHtml(source.content, vars);
      case "file":
        return renderHtml(await loadFile(source.path), vars);
      case "render":
        return source.fn(vars);
      default:
        throw new Error(`Unknown template source type`);
    }
  }
  async function renderHtml(html, vars) {
    return config.customRenderer ? config.customRenderer(html, vars) : renderTemplate(html, vars);
  }
  async function loadFile(filePath) {
    const cached = fileCache.get(filePath);
    if (cached) return cached;
    const content = await fs__namespace.promises.readFile(path__namespace.resolve(filePath), "utf-8");
    fileCache.set(filePath, content);
    return content;
  }
  function renderSubject(subject, variables) {
    return renderTemplate(subject, { ...config.defaults, ...variables });
  }
  const mgr = {
    async sendMail(options) {
      const transport = await getTransporter();
      const info = await transport.sendMail({
        from: options.from ?? config.smtp.from,
        to: Array.isArray(options.to) ? options.to.join(", ") : options.to,
        subject: options.subject,
        html: options.html,
        text: options.text ?? (options.html ? htmlToText(options.html) : void 0),
        cc: options.cc,
        bcc: options.bcc,
        replyTo: options.replyTo ?? config.smtp.replyTo,
        headers: options.headers,
        priority: options.priority,
        attachments: options.attachments
      });
      return { messageId: info.messageId, accepted: info.accepted ?? [], rejected: info.rejected ?? [], response: info.response ?? "" };
    },
    async send(options) {
      return mgr.sendMail(options);
    },
    async sendCustom(options) {
      const vars = options.variables ?? {};
      const html = await renderSource(options.html, vars);
      return mgr.sendMail({ to: options.to, subject: renderSubject(options.subject, vars), html, from: options.from, cc: options.cc, bcc: options.bcc, replyTo: options.replyTo, priority: options.priority, attachments: options.attachments });
    },
    async sendWithTemplate(options) {
      const def = getNamedTemplate(options.template);
      const vars = options.variables ?? {};
      const html = await renderSource(def.source, vars);
      let subject = options.subject ?? def.defaultSubject ?? "(No subject)";
      subject = renderSubject(subject, vars);
      return mgr.sendMail({ to: options.to, subject, html, from: options.from, cc: options.cc, bcc: options.bcc, replyTo: options.replyTo, priority: options.priority, attachments: options.attachments });
    },
    async sendTemplate(options) {
      const template = getTemplate(options.category, options.theme);
      const vars = { ...config.defaults, ...options.variables };
      const html = await renderHtml(template, vars);
      return mgr.sendMail({ to: options.to, subject: renderSubject(options.subject, vars), html, from: options.from, cc: options.cc, bcc: options.bcc, replyTo: options.replyTo, attachments: options.attachments });
    },
    async sendLoginNotification(to, vars) {
      const { theme, ...variables } = vars;
      return mgr.sendTemplate({ to, subject: `New login to your ${variables.appName ?? config.defaults?.appName ?? "account"}`, category: "login", theme: theme ?? config.templates?.login?.theme, variables: { appName: config.defaults?.appName ?? "", ...variables } });
    },
    async sendForgotPassword(to, vars) {
      const { theme, ...variables } = vars;
      return mgr.sendTemplate({ to, subject: `Reset your ${variables.appName ?? config.defaults?.appName ?? ""} password`, category: "forgot-password", theme: theme ?? config.templates?.forgotPassword?.theme, variables: { appName: config.defaults?.appName ?? "", ...variables } });
    },
    async sendAlert(to, vars) {
      const { theme, ...variables } = vars;
      return mgr.sendTemplate({ to, subject: `[${variables.severity?.toUpperCase() ?? "ALERT"}] ${variables.alertTitle}`, category: "alert", theme: theme ?? config.templates?.alert?.theme, variables: { appName: config.defaults?.appName ?? "", ...variables } });
    },
    async sendBulk(options) {
      const results = [];
      let sent = 0;
      let failed = 0;
      for (let i = 0; i < options.recipients.length; i++) {
        const recipient = options.recipients[i];
        const vars = { ...config.defaults, ...recipient.variables };
        const subject = recipient.subject ?? options.subject;
        try {
          let html;
          if (options.template) {
            const def = getNamedTemplate(options.template);
            html = await renderSource(def.source, vars);
          } else if (options.category) {
            html = await renderHtml(getTemplate(options.category, options.theme), vars);
          } else if (options.html) {
            html = await renderSource(options.html, vars);
          } else throw new Error("sendBulk requires one of: html, template, or category");
          const result = await mgr.sendMail({ to: recipient.to, subject: renderSubject(subject, vars), html, from: options.from, attachments: options.attachments });
          results.push({ to: recipient.to, success: true, messageId: result.messageId });
          sent++;
        } catch (err) {
          results.push({ to: recipient.to, success: false, error: err.message });
          failed++;
        }
        if (options.delayMs && i < options.recipients.length - 1) await new Promise((r) => setTimeout(r, options.delayMs));
      }
      return { total: options.recipients.length, sent, failed, results };
    },
    registerNamedTemplate(name, definition) {
      registerNamedTemplate(name, definition);
    },
    removeNamedTemplate(name) {
      return removeNamedTemplate(name);
    },
    listNamedTemplates() {
      return listNamedTemplates();
    },
    hasNamedTemplate(name) {
      return hasNamedTemplate(name);
    },
    registerTemplate(category, theme, html) {
      registerTemplate(category, theme, html);
    },
    registerCategory(category, defaultTheme) {
      registerCategory(category, defaultTheme);
    },
    setDefaultTheme(category, theme) {
      setDefaultTheme(category, theme);
    },
    removeTemplate(category, theme) {
      return removeTemplate(category, theme);
    },
    removeCategory(category) {
      return removeCategory(category);
    },
    listThemes(category) {
      return listThemes(category);
    },
    listCategories() {
      return listCategories();
    },
    async verify() {
      const t = await getTransporter();
      try {
        await t.verify();
        return true;
      } catch {
        return false;
      }
    },
    preview(category, theme, variables) {
      return renderTemplate(getTemplate(category, theme), { ...config.defaults, ...variables });
    },
    async previewNamedTemplate(name, variables) {
      return renderSource(getNamedTemplate(name).source, variables);
    },
    renderInline(html, variables) {
      return renderTemplate(html, { ...config.defaults, ...variables });
    },
    clearFileCache() {
      fileCache.clear();
    },
    async close() {
      if (transporter?.close) transporter.close();
      transporter = null;
    }
  };
  return mgr;
}

exports.createEmailManager = createEmailManager;
exports.getNamedTemplate = getNamedTemplate;
exports.hasNamedTemplate = hasNamedTemplate;
exports.htmlToText = htmlToText;
exports.listCategories = listCategories;
exports.listNamedTemplates = listNamedTemplates;
exports.listThemes = listThemes;
exports.registerCategory = registerCategory;
exports.registerNamedTemplate = registerNamedTemplate;
exports.registerTemplate = registerTemplate;
exports.removeCategory = removeCategory;
exports.removeNamedTemplate = removeNamedTemplate;
exports.removeTemplate = removeTemplate;
exports.renderTemplate = renderTemplate;
exports.setDefaultTheme = setDefaultTheme;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map