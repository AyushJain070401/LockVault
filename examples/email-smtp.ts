/**
 * LockVault — Email / SMTP Integration Example
 *
 * Shows every way you can use the EmailManager:
 *   1. General-purpose mailing (plain text, HTML, attachments)
 *   2. Inline custom templates with {{variable}} interpolation
 *   3. Built-in auth-themed templates (login, forgot-password, alert)
 *   4. Named templates (inline HTML, file-based, custom render function)
 *   5. Custom rendering engine (Handlebars, EJS, MJML, etc.)
 *   6. Custom categories and themes
 *   7. Bulk/batch sending with per-recipient variables
 *   8. Template preview for development
 *
 * Prerequisites:
 *   npm install nodemailer
 *   npm install -D @types/nodemailer
 */
import express from 'express';
import { createLockVault, createMemoryAdapter } from 'lockvault';
import { authenticate, setAuthCookies } from 'lockvault/middleware/express';
import { createEmailManager } from 'lockvault/email';

// ─── Initialize LockVault Auth ───────────────────────────────────────────

const auth = createLockVault({
  jwt: {
    accessTokenSecret: process.env.JWT_SECRET!,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
    issuer: 'my-app',
  },
  adapter: createMemoryAdapter(),
});

// ─── Initialize Email Manager ────────────────────────────────────────────
//
// This is your mailer — use it for auth emails AND general-purpose emails.
// Nodemailer is only imported when you actually send the first email.

const mailer = createEmailManager({
  smtp: {
    host: process.env.SMTP_HOST ?? 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: false,
    auth: {
      user: process.env.SMTP_USER!,
      pass: process.env.SMTP_PASS!,
    },
    from: `"My App" <${process.env.SMTP_USER}>`,
  },
  // Default themes for built-in auth templates
  templates: {
    login: { theme: 'vibrant' },
    forgotPassword: { theme: 'friendly' },
    alert: { theme: 'standard' },
  },
  // Global defaults — automatically injected into every template
  defaults: {
    appName: 'My App',
    appLogo: 'https://myapp.com/logo.png',
    supportUrl: 'https://myapp.com/support',
    dashboardUrl: 'https://myapp.com/dashboard',
    year: new Date().getFullYear().toString(),
  },
  // OPTIONAL: Plug in a custom rendering engine
  // customRenderer: (html, vars) => Handlebars.compile(html)(vars),
  // customRenderer: (html, vars) => ejs.render(html, vars),
});

const app = express();
app.use(express.json());


// ═════════════════════════════════════════════════════════════════════════════
//  1. GENERAL-PURPOSE MAILING — use LockVault as a normal mailer
// ═════════════════════════════════════════════════════════════════════════════

// Plain text email
app.post('/send/text', async (req, res) => {
  const result = await mailer.sendMail({
    to: req.body.to,
    subject: 'Quick update',
    text: 'Hey! Just wanted to let you know that your report is ready.',
  });
  res.json({ messageId: result.messageId });
});

// HTML email
app.post('/send/html', async (req, res) => {
  const result = await mailer.sendMail({
    to: req.body.to,
    subject: 'Your Invoice #1234',
    html: `
      <h1>Invoice #1234</h1>
      <p>Amount due: <strong>$99.00</strong></p>
      <p>Due date: March 15, 2026</p>
    `,
    priority: 'high',
  });
  res.json({ messageId: result.messageId });
});

// Email with attachments
app.post('/send/attachment', async (req, res) => {
  const result = await mailer.sendMail({
    to: 'team@myapp.com',
    subject: 'Monthly Report — February 2026',
    html: '<p>Please find the report attached.</p>',
    attachments: [
      { filename: 'report.pdf', path: './reports/feb-2026.pdf' },
      { filename: 'data.csv', content: 'name,email\nAyush,ayush@example.com' },
    ],
  });
  res.json({ messageId: result.messageId });
});

// Email with CC, BCC, custom from, headers
app.post('/send/advanced', async (req, res) => {
  const result = await mailer.sendMail({
    to: 'user@example.com',
    cc: ['manager@example.com'],
    bcc: ['audit@example.com'],
    from: '"Finance Team" <finance@myapp.com>',  // Override the default "from"
    replyTo: 'billing@myapp.com',
    subject: 'Payment Confirmation',
    html: '<p>Your payment of $299.00 has been received.</p>',
    headers: { 'X-Transaction-ID': 'txn_abc123' },
  });
  res.json({ messageId: result.messageId });
});


// ═════════════════════════════════════════════════════════════════════════════
//  2. INLINE CUSTOM TEMPLATES — pass HTML + variables directly, no registration
// ═════════════════════════════════════════════════════════════════════════════

app.post('/send/custom', async (req, res) => {
  const result = await mailer.sendCustom({
    to: req.body.to,
    subject: 'Order #{{orderId}} Confirmed',  // Subject also supports {{variables}}
    html: `
      <div style="font-family: sans-serif; padding: 20px;">
        <h1>Thanks, {{name}}!</h1>
        <p>Your order <strong>#{{orderId}}</strong> has been confirmed.</p>

        {{#if trackingUrl}}
          <p><a href="{{trackingUrl}}">Track your shipment →</a></p>
        {{/if}}

        {{#each items}}
          <p>• {{name}} — {{price}}</p>
        {{/each}}

        <hr>
        <p style="color: #999; font-size: 12px;">
          Need help? <a href="{{supportUrl}}">Contact us</a>
        </p>
      </div>
    `,
    variables: {
      name: 'Ayush',
      orderId: 'ORD-12345',
      trackingUrl: 'https://track.example.com/ORD-12345',
      items: [
        { name: 'Widget Pro', price: '$29.99' },
        { name: 'Gadget Mini', price: '$19.99' },
      ],
      // supportUrl is already in defaults, so it's auto-injected!
    },
  });
  res.json({ messageId: result.messageId });
});


// ═════════════════════════════════════════════════════════════════════════════
//  3. BUILT-IN AUTH-THEMED TEMPLATES
// ═════════════════════════════════════════════════════════════════════════════

app.post('/auth/login', async (req, res) => {
  const { email: userEmail, password } = req.body;
  const userId = 'user-123';

  const { tokens, session } = await auth.login(userId, {
    customClaims: { email: userEmail },
    deviceInfo: { userAgent: req.headers['user-agent'] },
    ipAddress: req.ip,
  });

  // 🔔 Login notification (fire-and-forget)
  mailer.sendLoginNotification(userEmail, {
    userName: 'Ayush',
    loginTime: new Date().toLocaleString(),
    ipAddress: req.ip ?? 'Unknown',
    deviceInfo: req.headers['user-agent'] ?? 'Unknown',
    // theme: 'corporate',  ← override per-send if you want
  }).catch(console.error);

  setAuthCookies(res, tokens);
  res.json({ tokens, sessionId: session.id });
});

app.post('/auth/forgot-password', async (req, res) => {
  const resetToken = 'abc123';
  await mailer.sendForgotPassword(req.body.email, {
    userName: 'Ayush',
    resetUrl: `https://myapp.com/reset?token=${resetToken}`,
    expiresIn: '15 minutes',
    // theme: 'secure',  ← override the default 'friendly' theme
  });
  res.json({ message: 'If that email exists, a reset link has been sent.' });
});

app.post('/auth/alert', async (_req, res) => {
  await mailer.sendAlert('admin@myapp.com', {
    alertTitle: 'Multiple Failed Login Attempts',
    alertMessage: '15 failed attempts from IP 192.168.1.100 in the last 5 minutes.',
    severity: 'critical',
    actionUrl: 'https://myapp.com/admin/security',
    actionLabel: 'Review Logs',
    theme: 'urgent',  // Use the red urgent theme
  });
  res.json({ message: 'Alert sent' });
});


// ═════════════════════════════════════════════════════════════════════════════
//  4. NAMED TEMPLATES — register once, send by name
// ═════════════════════════════════════════════════════════════════════════════

// Register templates at startup (inline HTML)
mailer.registerNamedTemplate('order-shipped', {
  source: {
    type: 'html',
    content: `
      <div style="font-family: sans-serif; padding: 20px;">
        <h1>📦 Your order is on its way!</h1>
        <p>Hi {{name}}, your order #{{orderId}} has shipped.</p>
        {{#if trackingUrl}}
          <p><a href="{{trackingUrl}}">Track your package →</a></p>
        {{/if}}
        <p style="color: #999;">— The {{appName}} Team</p>
      </div>
    `,
  },
  defaultSubject: '📦 Order #{{orderId}} has shipped!',
});

// Register template from a file
mailer.registerNamedTemplate('monthly-digest', {
  source: { type: 'file', path: './templates/monthly-digest.html' },
  defaultSubject: '{{appName}} Monthly Digest — {{month}}',
});

// Register template with a custom render function
// (Use this to plug in Handlebars, EJS, MJML, React Email, or anything)
mailer.registerNamedTemplate('custom-engine-demo', {
  source: {
    type: 'render',
    fn: (vars) => {
      // This could be Handlebars.compile(template)(vars)
      // or ejs.render(template, vars)
      // or mjml2html(mjmlTemplate).html
      return `<p>Custom rendered: Hello ${vars.name}!</p>`;
    },
  },
  defaultSubject: 'Custom: {{name}}',
});

// Send using a named template
app.post('/send/named', async (req, res) => {
  const result = await mailer.sendWithTemplate({
    to: req.body.to,
    template: 'order-shipped',
    variables: {
      name: 'Ayush',
      orderId: 'ORD-7890',
      trackingUrl: 'https://track.example.com/ORD-7890',
    },
    // subject: 'Custom subject',  ← override the default subject if needed
  });
  res.json({ messageId: result.messageId });
});


// ═════════════════════════════════════════════════════════════════════════════
//  5. CUSTOM CATEGORIES AND THEMES — extend the built-in registry
// ═════════════════════════════════════════════════════════════════════════════

// Create a brand-new "invoice" category with multiple themes
mailer.registerCategory('invoice', 'simple');

mailer.registerTemplate('invoice', 'simple', `
  <div style="font-family: sans-serif; padding: 20px;">
    <h1>Invoice #{{invoiceId}}</h1>
    <p>Amount: {{amount}}</p>
    <p>Due: {{dueDate}}</p>
  </div>
`);

mailer.registerTemplate('invoice', 'detailed', `
  <div style="font-family: sans-serif; padding: 20px;">
    <h1>Invoice #{{invoiceId}}</h1>
    <table>
      {{#each lineItems}}
      <tr><td>{{description}}</td><td>{{amount}}</td></tr>
      {{/each}}
    </table>
    <p><strong>Total: {{total}}</strong></p>
    <p>Due: {{dueDate}}</p>
  </div>
`);

// Override a built-in template if you don't like it
// mailer.registerTemplate('login', 'minimal', myCustomLoginHtml);

// Send using your custom category
app.post('/send/invoice', async (req, res) => {
  const result = await mailer.sendTemplate({
    to: req.body.to,
    subject: 'Invoice #{{invoiceId}}',
    category: 'invoice',
    theme: 'detailed',  // or 'simple'
    variables: {
      invoiceId: 'INV-001',
      total: '$149.98',
      dueDate: 'March 30, 2026',
      lineItems: [
        { description: 'Pro Plan (Monthly)', amount: '$99.99' },
        { description: 'Extra Storage (50GB)', amount: '$49.99' },
      ],
    },
  });
  res.json({ messageId: result.messageId });
});


// ═════════════════════════════════════════════════════════════════════════════
//  6. BULK / BATCH SENDING — same template, different recipients + variables
// ═════════════════════════════════════════════════════════════════════════════

app.post('/send/bulk', async (_req, res) => {
  const result = await mailer.sendBulk({
    subject: 'Your {{appName}} monthly summary',
    html: `
      <p>Hi {{name}},</p>
      <p>You had <strong>{{loginCount}}</strong> logins this month.</p>
      <p>Active sessions: {{sessionCount}}</p>
    `,
    recipients: [
      { to: 'alice@example.com', variables: { name: 'Alice', loginCount: 42, sessionCount: 3 } },
      { to: 'bob@example.com', variables: { name: 'Bob', loginCount: 7, sessionCount: 1 } },
      { to: 'carol@example.com', variables: { name: 'Carol', loginCount: 128, sessionCount: 5 } },
    ],
    delayMs: 100, // 100ms between sends (avoid rate limits)
  });

  res.json({
    total: result.total,
    sent: result.sent,
    failed: result.failed,
  });
});

// Bulk send with a named template
app.post('/send/bulk-named', async (_req, res) => {
  const result = await mailer.sendBulk({
    subject: 'Your order has shipped!',
    template: 'order-shipped',
    recipients: [
      { to: 'alice@example.com', variables: { name: 'Alice', orderId: 'ORD-001' } },
      { to: 'bob@example.com', variables: { name: 'Bob', orderId: 'ORD-002' } },
    ],
  });
  res.json(result);
});


// ═════════════════════════════════════════════════════════════════════════════
//  7. TEMPLATE PREVIEW (development / testing)
// ═════════════════════════════════════════════════════════════════════════════

// Preview a built-in category+theme template
app.get('/dev/preview/:category/:theme', (req, res) => {
  try {
    const html = mailer.preview(req.params.category, req.params.theme, {
      userName: 'Ayush Jain',
      loginTime: new Date().toLocaleString(),
      ipAddress: '192.168.1.42',
      deviceInfo: 'Chrome on macOS',
      location: 'Bhopal, India',
      resetUrl: 'https://myapp.com/reset?token=demo',
      expiresIn: '15 minutes',
      alertTitle: 'Test Alert',
      alertMessage: 'This is a preview of the alert template.',
      severity: 'warning',
      actionUrl: 'https://myapp.com/action',
      actionLabel: 'Take Action',
      timestamp: new Date().toLocaleString(),
    });
    res.send(html);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// Preview a named template
app.get('/dev/preview-named/:name', async (req, res) => {
  try {
    const html = await mailer.previewNamedTemplate(req.params.name, {
      name: 'Ayush',
      orderId: 'ORD-DEMO',
      trackingUrl: 'https://track.example.com/demo',
    });
    res.send(html);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// Preview with inline rendering (no template needed)
app.get('/dev/render-test', (_req, res) => {
  const html = mailer.renderInline(
    '<p>Hello {{userName}}, welcome to {{appName}}!</p>',
    { userName: 'Ayush' },
  );
  res.send(html);
});

// List all available templates
app.get('/dev/templates', (_req, res) => {
  const categories = mailer.listCategories();
  const themed: Record<string, string[]> = {};
  for (const cat of categories) {
    themed[cat] = mailer.listThemes(cat);
  }
  res.json({
    themed,
    named: mailer.listNamedTemplates(),
  });
});


// ═════════════════════════════════════════════════════════════════════════════
//  START
// ═════════════════════════════════════════════════════════════════════════════

async function start() {
  await auth.initialize();
  auth.startCleanup(3600_000);

  // Optionally verify SMTP on startup
  const smtpOk = await mailer.verify();
  console.log('SMTP:', smtpOk ? '✅ Connected' : '❌ Failed');

  app.listen(3000, () => {
    console.log('Server: http://localhost:3000');
    console.log('');
    console.log('Preview templates:');
    console.log('  http://localhost:3000/dev/preview/login/vibrant');
    console.log('  http://localhost:3000/dev/preview/forgot-password/friendly');
    console.log('  http://localhost:3000/dev/preview/alert/urgent');
    console.log('  http://localhost:3000/dev/preview-named/order-shipped');
    console.log('  http://localhost:3000/dev/templates');
  });
}

start();
