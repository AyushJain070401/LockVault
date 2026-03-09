import { T as TemplateDefinition, h as SendEmailOptions, b as EmailResult, g as SendCustomTemplateOptions, i as SendNamedTemplateOptions, l as TemplateVars, j as SendTemplateEmailOptions, L as LoginEmailVars, F as ForgotPasswordEmailVars, A as AlertEmailVars, f as SendBulkOptions, B as BulkEmailResult, E as EmailConfig } from '../types-1dgdkzJw.mjs';

/**
 * Register a template for a category + theme.
 * Creates the category if it doesn't exist.
 * Can also override built-in templates.
 */
declare function registerTemplate(category: string, theme: string, html: string): void;
/**
 * Register a new custom category with an optional default theme.
 *
 * @example
 * registerCategory('invoice', 'default');
 * registerTemplate('invoice', 'default', '<html>...</html>');
 */
declare function registerCategory(category: string, defaultTheme?: string): void;
/**
 * Set the default theme for a category.
 */
declare function setDefaultTheme(category: string, theme: string): void;
/**
 * Remove a template from a category.
 */
declare function removeTemplate(category: string, theme: string): boolean;
/**
 * Remove an entire category and all its templates.
 */
declare function removeCategory(category: string): boolean;
/**
 * List available themes for a category.
 */
declare function listThemes(category: string): string[];
/**
 * List all registered categories.
 */
declare function listCategories(): string[];
/**
 * Register a named template. Named templates have their own namespace
 * separate from category/theme templates.
 *
 * @example
 * // Inline HTML
 * registerNamedTemplate('invoice', {
 *   source: { type: 'html', content: '<html>{{total}}</html>' },
 *   defaultSubject: 'Invoice #{{invoiceNumber}}',
 * });
 *
 * // From a file
 * registerNamedTemplate('monthly-report', {
 *   source: { type: 'file', path: '/templates/report.html' },
 *   defaultSubject: 'Monthly Report — {{month}}',
 * });
 *
 * // Custom render function (Handlebars, EJS, MJML, React Email, etc.)
 * registerNamedTemplate('newsletter', {
 *   source: {
 *     type: 'render',
 *     fn: (vars) => Handlebars.compile(myTemplate)(vars),
 *   },
 *   defaultSubject: 'Newsletter — {{title}}',
 * });
 */
declare function registerNamedTemplate(name: string, definition: TemplateDefinition): void;
/**
 * Get a named template definition.
 */
declare function getNamedTemplate(name: string): TemplateDefinition;
/**
 * Remove a named template.
 */
declare function removeNamedTemplate(name: string): boolean;
/**
 * List all registered named templates.
 */
declare function listNamedTemplates(): string[];
/**
 * Check if a named template exists.
 */
declare function hasNamedTemplate(name: string): boolean;

/**
 * Built-in template engine for LockVault Email.
 *
 * Supports:
 *   {{variable}}                — HTML-escaped interpolation
 *   {{{variable}}}              — Raw (unescaped) interpolation
 *   {{#if var}}...{{/if}}       — Conditional block
 *   {{#unless var}}...{{/unless}} — Inverse conditional
 *   {{#each items}}...{{/each}} — Loop over arrays
 *   {{nested.path}}             — Dot-notation access
 *
 * Users can bypass this engine entirely by providing a customRenderer
 * in their EmailConfig (for Handlebars, EJS, MJML, etc.).
 */
declare function renderTemplate(template: string, variables: Record<string, unknown>): string;
/**
 * Strip HTML tags to produce a plain-text version of the email.
 */
declare function htmlToText(html: string): string;

interface EmailManager {
    sendMail(options: SendEmailOptions): Promise<EmailResult>;
    send(options: SendEmailOptions): Promise<EmailResult>;
    sendCustom(options: SendCustomTemplateOptions): Promise<EmailResult>;
    sendWithTemplate(options: SendNamedTemplateOptions): Promise<EmailResult>;
    sendTemplate<T extends TemplateVars>(options: SendTemplateEmailOptions<T>): Promise<EmailResult>;
    sendLoginNotification(to: string, vars: Omit<LoginEmailVars, 'appName'> & {
        appName?: string;
        theme?: string;
    }): Promise<EmailResult>;
    sendForgotPassword(to: string, vars: Omit<ForgotPasswordEmailVars, 'appName'> & {
        appName?: string;
        theme?: string;
    }): Promise<EmailResult>;
    sendAlert(to: string, vars: Omit<AlertEmailVars, 'appName'> & {
        appName?: string;
        theme?: string;
    }): Promise<EmailResult>;
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
declare function createEmailManager(config: EmailConfig): EmailManager;

export { type EmailManager, createEmailManager, getNamedTemplate, hasNamedTemplate, htmlToText, listCategories, listNamedTemplates, listThemes, registerCategory, registerNamedTemplate, registerTemplate, removeCategory, removeNamedTemplate, removeTemplate, renderTemplate, setDefaultTheme };
