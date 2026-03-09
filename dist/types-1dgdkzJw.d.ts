interface SMTPConfig {
    host: string;
    port: number;
    secure?: boolean;
    auth: {
        user: string;
        pass: string;
    };
    /** Default "from" address for all emails */
    from: string;
    /** Optional reply-to address */
    replyTo?: string;
    /** Connection pool size (default: 5) */
    pool?: boolean;
    /** Max connections in pool (default: 5) */
    maxConnections?: number;
    /** TLS options */
    tls?: {
        rejectUnauthorized?: boolean;
        minVersion?: string;
    };
}
type LoginTheme = 'minimal' | 'corporate' | 'vibrant';
type ForgotPasswordTheme = 'clean' | 'secure' | 'friendly';
type AlertTheme = 'standard' | 'urgent' | 'subtle';
type WelcomeTheme = 'warm' | 'professional' | 'bold';
type VerificationTheme = 'modern' | 'classic' | 'playful';
type MagicLinkTheme = 'sleek' | 'gradient' | 'mono';
/**
 * Built-in template categories. Users can also register fully custom
 * categories via registerCategory() — they are not limited to this list.
 */
type BuiltInCategory = 'login' | 'forgot-password' | 'alert' | 'welcome' | 'verification' | 'magic-link' | 'password-changed' | 'account-locked' | 'two-factor' | 'invite';
/**
 * Template category identifier. Can be any of the built-in categories
 * or any custom string the user registers.
 */
type EmailTemplateCategory = BuiltInCategory | (string & {});
interface LoginEmailVars {
    userName?: string;
    loginTime: string;
    ipAddress?: string;
    deviceInfo?: string;
    location?: string;
    appName: string;
    appLogo?: string;
    dashboardUrl?: string;
    supportUrl?: string;
}
interface ForgotPasswordEmailVars {
    userName?: string;
    resetUrl: string;
    expiresIn?: string;
    appName: string;
    appLogo?: string;
    supportUrl?: string;
}
interface AlertEmailVars {
    userName?: string;
    alertTitle: string;
    alertMessage: string;
    actionUrl?: string;
    actionLabel?: string;
    appName: string;
    appLogo?: string;
    severity?: 'info' | 'warning' | 'critical';
    timestamp?: string;
}
interface WelcomeEmailVars {
    userName?: string;
    appName: string;
    appLogo?: string;
    dashboardUrl?: string;
    docsUrl?: string;
    supportUrl?: string;
}
interface VerificationEmailVars {
    userName?: string;
    verificationUrl?: string;
    verificationCode?: string;
    expiresIn?: string;
    appName: string;
    appLogo?: string;
}
interface MagicLinkEmailVars {
    userName?: string;
    magicLinkUrl: string;
    expiresIn?: string;
    appName: string;
    appLogo?: string;
    ipAddress?: string;
}
type TemplateVars = LoginEmailVars | ForgotPasswordEmailVars | AlertEmailVars | WelcomeEmailVars | VerificationEmailVars | MagicLinkEmailVars | Record<string, unknown>;
/**
 * A custom render function. Return the final HTML string.
 * Allows users to plug in any engine (EJS, Handlebars, MJML, React Email, etc.).
 */
type CustomRenderFn = (variables: Record<string, unknown>) => string | Promise<string>;
/**
 * The source for a template. Can be:
 *   - A raw HTML string (inline)
 *   - An absolute file path to an .html file
 *   - A render function (for custom engines)
 */
type TemplateSource = {
    type: 'html';
    content: string;
} | {
    type: 'file';
    path: string;
} | {
    type: 'render';
    fn: CustomRenderFn;
};
/**
 * Definition for a named registered template.
 */
interface TemplateDefinition {
    /** The template source */
    source: TemplateSource;
    /** Default subject line (can use {{variable}} interpolation) */
    defaultSubject?: string;
}
interface SendEmailOptions {
    to: string | string[];
    subject: string;
    /** Fully rendered HTML body */
    html?: string;
    /** Plain-text body (auto-generated from HTML if omitted) */
    text?: string;
    /** Override the default "from" address for this email */
    from?: string;
    cc?: string | string[];
    bcc?: string | string[];
    replyTo?: string;
    /** Custom email headers */
    headers?: Record<string, string>;
    /** Priority: 'high' | 'normal' | 'low' */
    priority?: 'high' | 'normal' | 'low';
    attachments?: Array<{
        filename: string;
        content?: string | Buffer;
        contentType?: string;
        /** Content-ID for inline images: use "cid:yourId" in html src */
        cid?: string;
        /** Path to a file to attach (alternative to content) */
        path?: string;
        /** Encoding: 'base64' | 'binary' | 'utf-8' etc. */
        encoding?: string;
    }>;
}
/**
 * Send a built-in themed template email.
 */
interface SendTemplateEmailOptions<T extends TemplateVars = TemplateVars> {
    to: string | string[];
    subject: string;
    category: EmailTemplateCategory;
    theme?: string;
    variables: T;
    from?: string;
    cc?: string | string[];
    bcc?: string | string[];
    replyTo?: string;
    attachments?: SendEmailOptions['attachments'];
}
/**
 * Send an email using a custom inline HTML template with variable interpolation.
 */
interface SendCustomTemplateOptions {
    to: string | string[];
    subject: string;
    /** Raw HTML template string (supports {{variable}} syntax) */
    html: string;
    /** Variables to interpolate into the template */
    variables?: Record<string, unknown>;
    from?: string;
    cc?: string | string[];
    bcc?: string | string[];
    replyTo?: string;
    priority?: 'high' | 'normal' | 'low';
    attachments?: SendEmailOptions['attachments'];
}
/**
 * Send an email using a named registered template (custom or built-in).
 */
interface SendNamedTemplateOptions {
    to: string | string[];
    /** Override the default subject (if the template has one) */
    subject?: string;
    /** Template name (the key used in registerNamedTemplate) */
    template: string;
    /** Variables to pass to the template */
    variables?: Record<string, unknown>;
    from?: string;
    cc?: string | string[];
    bcc?: string | string[];
    replyTo?: string;
    priority?: 'high' | 'normal' | 'low';
    attachments?: SendEmailOptions['attachments'];
}
/**
 * Options for sending bulk emails.
 */
interface SendBulkOptions {
    /** Array of recipients — each can have their own variables */
    recipients: Array<{
        to: string;
        variables?: Record<string, unknown>;
        /** Override subject per recipient */
        subject?: string;
    }>;
    /** Default subject for all recipients */
    subject: string;
    /** HTML template (with {{variable}} syntax) */
    html?: string;
    /** Or use a named registered template */
    template?: string;
    /** Or use a category + theme */
    category?: EmailTemplateCategory;
    theme?: string;
    from?: string;
    /** Delay between sends in ms (rate limiting) — default 0 */
    delayMs?: number;
    attachments?: SendEmailOptions['attachments'];
}
interface BulkEmailResult {
    total: number;
    sent: number;
    failed: number;
    results: Array<{
        to: string;
        success: boolean;
        messageId?: string;
        error?: string;
    }>;
}
interface EmailResult {
    messageId: string;
    accepted: string[];
    rejected: string[];
    response: string;
}
interface EmailConfig {
    smtp: SMTPConfig;
    templates?: {
        login?: {
            theme?: LoginTheme;
        };
        forgotPassword?: {
            theme?: ForgotPasswordTheme;
        };
        alert?: {
            theme?: AlertTheme;
        };
        welcome?: {
            theme?: WelcomeTheme;
        };
        verification?: {
            theme?: VerificationTheme;
        };
        magicLink?: {
            theme?: MagicLinkTheme;
        };
    };
    /** Global template variables injected into every template render */
    defaults?: {
        appName?: string;
        appLogo?: string;
        supportUrl?: string;
        dashboardUrl?: string;
        primaryColor?: string;
        footerText?: string;
        /** Any additional global defaults */
        [key: string]: unknown;
    };
    /**
     * Plug in a custom rendering engine. When set, all templates
     * using type: 'html' or type: 'file' will be processed through
     * this function instead of the built-in {{variable}} engine.
     *
     * @example
     * // Use Handlebars
     * import Handlebars from 'handlebars';
     * customRenderer: (html, vars) => Handlebars.compile(html)(vars)
     *
     * @example
     * // Use EJS
     * import ejs from 'ejs';
     * customRenderer: (html, vars) => ejs.render(html, vars)
     */
    customRenderer?: (template: string, variables: Record<string, unknown>) => string | Promise<string>;
}

export type { AlertEmailVars as A, BulkEmailResult as B, CustomRenderFn as C, EmailConfig as E, ForgotPasswordEmailVars as F, LoginEmailVars as L, MagicLinkEmailVars as M, SMTPConfig as S, TemplateDefinition as T, VerificationEmailVars as V, WelcomeEmailVars as W, AlertTheme as a, EmailResult as b, EmailTemplateCategory as c, ForgotPasswordTheme as d, LoginTheme as e, SendBulkOptions as f, SendCustomTemplateOptions as g, SendEmailOptions as h, SendNamedTemplateOptions as i, SendTemplateEmailOptions as j, TemplateSource as k, TemplateVars as l };
