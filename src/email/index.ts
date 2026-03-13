import * as fs from 'fs';
import * as path from 'path';

import type {
  EmailConfig, SendEmailOptions, SendTemplateEmailOptions, SendCustomTemplateOptions,
  SendNamedTemplateOptions, SendBulkOptions, EmailResult, BulkEmailResult, TemplateVars,
  TemplateDefinition, TemplateSource, LoginEmailVars, ForgotPasswordEmailVars, AlertEmailVars,
} from './types.js';
import { renderTemplate, htmlToText } from './engine.js';
import {
  getTemplate, registerTemplate as regTemplate, registerCategory as regCategory,
  setDefaultTheme as setDefTheme, removeTemplate as remTemplate,
  removeCategory as remCategory, listThemes as lsThemes, listCategories as lsCats,
  registerNamedTemplate as regNamed, getNamedTemplate as getNamed,
  removeNamedTemplate as remNamed, listNamedTemplates as lsNamed, hasNamedTemplate as hasNamed,
} from './templates/index.js';

export { regTemplate as registerTemplate, regCategory as registerCategory, setDefTheme as setDefaultTheme, remTemplate as removeTemplate, remCategory as removeCategory, lsThemes as listThemes, lsCats as listCategories, regNamed as registerNamedTemplate, getNamed as getNamedTemplate, remNamed as removeNamedTemplate, lsNamed as listNamedTemplates, hasNamed as hasNamedTemplate };
export { renderTemplate, htmlToText } from './engine.js';

export interface EmailManager {
  sendMail(options: SendEmailOptions): Promise<EmailResult>;
  send(options: SendEmailOptions): Promise<EmailResult>;
  sendCustom(options: SendCustomTemplateOptions): Promise<EmailResult>;
  sendWithTemplate(options: SendNamedTemplateOptions): Promise<EmailResult>;
  sendTemplate<T extends TemplateVars>(options: SendTemplateEmailOptions<T>): Promise<EmailResult>;
  sendLoginNotification(to: string, vars: Omit<LoginEmailVars, 'appName'> & { appName?: string; theme?: string }): Promise<EmailResult>;
  sendForgotPassword(to: string, vars: Omit<ForgotPasswordEmailVars, 'appName'> & { appName?: string; theme?: string }): Promise<EmailResult>;
  sendAlert(to: string, vars: Omit<AlertEmailVars, 'appName'> & { appName?: string; theme?: string }): Promise<EmailResult>;
  sendBulk(options: SendBulkOptions): Promise<BulkEmailResult>;
  registerNamedTemplate(name: string, definition: TemplateDefinition): void;
  removeNamedTemplate(name: string): boolean;
  listNamedTemplates(): string[];
  hasNamedTemplate(name: string): boolean;
  registerTemplate(category: string, theme: string, html: string): void;
  registerCategory(category: string, defaultTheme?: string): void;
  setDefaultTheme(category: string, theme: string): void;
  removeTemplate(category: string, theme: string): boolean;
  removeCategory(category: string): boolean;
  listThemes(category: string): string[];
  listCategories(): string[];
  verify(): Promise<boolean>;
  preview(category: string, theme: string, variables: Record<string, unknown>): string;
  previewNamedTemplate(name: string, variables: Record<string, unknown>): Promise<string>;
  renderInline(html: string, variables: Record<string, unknown>): string;
  clearFileCache(): void;
  close(): Promise<void>;
}

export function createEmailManager(config: EmailConfig): EmailManager {
  let transporter: any = null;
  let nodemailer: any = null;
  const fileCache = new Map<string, string>();

  async function getTransporter(): Promise<any> {
    if (transporter) return transporter;
    // Use a variable so TypeScript doesn't try to resolve the module at compile time
    const moduleName = 'nodemailer';
    try { nodemailer = await import(/* webpackIgnore: true */ moduleName); } catch {
      throw new Error('LockVault Email: `nodemailer` is required but not installed.\nInstall it with:\n  npm install nodemailer\n  npm install -D @types/nodemailer');
    }
    const { smtp } = config;
    transporter = nodemailer.createTransport({ host: smtp.host, port: smtp.port, secure: smtp.secure ?? smtp.port === 465, auth: smtp.auth, pool: smtp.pool ?? false, maxConnections: smtp.maxConnections ?? 5, tls: smtp.tls } as any);
    return transporter;
  }

  async function renderSource(source: TemplateSource | string, variables: Record<string, unknown>): Promise<string> {
    const vars = { ...config.defaults, ...variables };
    if (typeof source === 'string') return renderHtml(source, vars);
    switch (source.type) {
      case 'html': return renderHtml(source.content, vars);
      case 'file': return renderHtml(await loadFile(source.path), vars);
      case 'render': return source.fn(vars);
      default: throw new Error(`Unknown template source type`);
    }
  }
  async function renderHtml(html: string, vars: Record<string, unknown>): Promise<string> {
    return config.customRenderer ? config.customRenderer(html, vars) : renderTemplate(html, vars);
  }
  async function loadFile(filePath: string): Promise<string> {
    const cached = fileCache.get(filePath);
    if (cached) return cached;

    // Resolve and validate path to prevent directory traversal
    const resolved = path.resolve(filePath);
    const templateDir = config.templateDir;
    if (templateDir) {
      const resolvedDir = path.resolve(templateDir);
      if (!resolved.startsWith(resolvedDir + path.sep) && resolved !== resolvedDir) {
        throw new Error(`Template path "${filePath}" is outside the allowed template directory`);
      }
    }

    const content = await fs.promises.readFile(resolved, 'utf-8');
    fileCache.set(filePath, content);
    return content;
  }
  function renderSubject(subject: string, variables: Record<string, unknown>): string {
    return renderTemplate(subject, { ...config.defaults, ...variables });
  }

  const mgr: EmailManager = {
    async sendMail(options) {
      const transport = await getTransporter();
      const info = await transport.sendMail({
        from: options.from ?? config.smtp.from, to: Array.isArray(options.to) ? options.to.join(', ') : options.to,
        subject: options.subject, html: options.html, text: options.text ?? (options.html ? htmlToText(options.html) : undefined),
        cc: options.cc, bcc: options.bcc, replyTo: options.replyTo ?? config.smtp.replyTo, headers: options.headers, priority: options.priority, attachments: options.attachments,
      });
      return { messageId: info.messageId, accepted: info.accepted ?? [], rejected: info.rejected ?? [], response: info.response ?? '' };
    },
    async send(options) { return mgr.sendMail(options); },

    async sendCustom(options) {
      const vars = options.variables ?? {};
      const html = await renderSource(options.html, vars);
      return mgr.sendMail({ to: options.to, subject: renderSubject(options.subject, vars), html, from: options.from, cc: options.cc, bcc: options.bcc, replyTo: options.replyTo, priority: options.priority, attachments: options.attachments });
    },

    async sendWithTemplate(options) {
      const def = getNamed(options.template);
      const vars = options.variables ?? {};
      const html = await renderSource(def.source, vars);
      let subject = options.subject ?? def.defaultSubject ?? '(No subject)';
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
      return mgr.sendTemplate({ to, subject: `New login to your ${variables.appName ?? config.defaults?.appName ?? 'account'}`, category: 'login', theme: theme ?? config.templates?.login?.theme, variables: { appName: config.defaults?.appName ?? '', ...variables } });
    },
    async sendForgotPassword(to, vars) {
      const { theme, ...variables } = vars;
      return mgr.sendTemplate({ to, subject: `Reset your ${variables.appName ?? config.defaults?.appName ?? ''} password`, category: 'forgot-password', theme: theme ?? config.templates?.forgotPassword?.theme, variables: { appName: config.defaults?.appName ?? '', ...variables } });
    },
    async sendAlert(to, vars) {
      const { theme, ...variables } = vars;
      return mgr.sendTemplate({ to, subject: `[${variables.severity?.toUpperCase() ?? 'ALERT'}] ${variables.alertTitle}`, category: 'alert', theme: theme ?? config.templates?.alert?.theme, variables: { appName: config.defaults?.appName ?? '', ...variables } });
    },

    async sendBulk(options) {
      const results: BulkEmailResult['results'] = []; let sent = 0; let failed = 0;
      for (let i = 0; i < options.recipients.length; i++) {
        const recipient = options.recipients[i]; const vars = { ...config.defaults, ...recipient.variables }; const subject = recipient.subject ?? options.subject;
        try {
          let html: string;
          if (options.template) { const def = getNamed(options.template); html = await renderSource(def.source, vars); }
          else if (options.category) { html = await renderHtml(getTemplate(options.category, options.theme), vars); }
          else if (options.html) { html = await renderSource(options.html, vars); }
          else throw new Error('sendBulk requires one of: html, template, or category');
          const result = await mgr.sendMail({ to: recipient.to, subject: renderSubject(subject, vars), html, from: options.from, attachments: options.attachments });
          results.push({ to: recipient.to, success: true, messageId: result.messageId }); sent++;
        } catch (err: any) { results.push({ to: recipient.to, success: false, error: err.message }); failed++; }
        if (options.delayMs && i < options.recipients.length - 1) await new Promise(r => setTimeout(r, options.delayMs));
      }
      return { total: options.recipients.length, sent, failed, results };
    },

    registerNamedTemplate(name, definition) { regNamed(name, definition); },
    removeNamedTemplate(name) { return remNamed(name); },
    listNamedTemplates() { return lsNamed(); },
    hasNamedTemplate(name) { return hasNamed(name); },
    registerTemplate(category, theme, html) { regTemplate(category, theme, html); },
    registerCategory(category, defaultTheme?) { regCategory(category, defaultTheme); },
    setDefaultTheme(category, theme) { setDefTheme(category, theme); },
    removeTemplate(category, theme) { return remTemplate(category, theme); },
    removeCategory(category) { return remCategory(category); },
    listThemes(category) { return lsThemes(category); },
    listCategories() { return lsCats(); },

    async verify() { const t = await getTransporter(); try { await t.verify(); return true; } catch { return false; } },
    preview(category, theme, variables) { return renderTemplate(getTemplate(category, theme), { ...config.defaults, ...variables }); },
    async previewNamedTemplate(name, variables) { return renderSource(getNamed(name).source, variables); },
    renderInline(html, variables) { return renderTemplate(html, { ...config.defaults, ...variables }); },
    clearFileCache() { fileCache.clear(); },
    async close() { if (transporter?.close) transporter.close(); transporter = null; },
  };
  return mgr;
}
