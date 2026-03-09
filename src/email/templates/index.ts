import { loginMinimal, loginCorporate, loginVibrant } from './login.js';
import { forgotPasswordClean, forgotPasswordSecure, forgotPasswordFriendly } from './forgot-password.js';
import { alertStandard, alertUrgent, alertSubtle } from './alert.js';
import type { EmailTemplateCategory, TemplateDefinition, TemplateSource } from '../types.js';

type TemplateMap = Record<string, string>;

// ─── Category + Theme Registry (built-in themed templates) ───────────────────

const registry: Record<string, TemplateMap> = {
  'login': {
    minimal: loginMinimal,
    corporate: loginCorporate,
    vibrant: loginVibrant,
  },
  'forgot-password': {
    clean: forgotPasswordClean,
    secure: forgotPasswordSecure,
    friendly: forgotPasswordFriendly,
  },
  'alert': {
    standard: alertStandard,
    urgent: alertUrgent,
    subtle: alertSubtle,
  },
  // Placeholder categories — users can register templates for these
  'welcome': {},
  'verification': {},
  'magic-link': {},
  'password-changed': {},
  'account-locked': {},
  'two-factor': {},
  'invite': {},
};

/**
 * Default theme for built-in categories.
 */
const defaultThemes: Record<string, string> = {
  'login': 'minimal',
  'forgot-password': 'clean',
  'alert': 'standard',
  'welcome': 'warm',
  'verification': 'modern',
  'magic-link': 'sleek',
  'password-changed': 'standard',
  'account-locked': 'urgent',
  'two-factor': 'standard',
  'invite': 'warm',
};

// ─── Named Template Registry (for fully custom templates) ────────────────────

const namedTemplates: Record<string, TemplateDefinition> = {};

// ─── Category + Theme API ────────────────────────────────────────────────────

/**
 * Retrieve an email template by category and theme.
 * Falls back to the default theme for the category.
 */
export function getTemplate(category: EmailTemplateCategory, theme?: string): string {
  const categoryTemplates = registry[category];
  if (!categoryTemplates) {
    throw new Error(
      `Unknown email template category: "${category}". ` +
      `Register it with registerCategory() or registerTemplate().`
    );
  }

  const selectedTheme = theme ?? defaultThemes[category] ?? Object.keys(categoryTemplates)[0];
  const template = categoryTemplates[selectedTheme];

  if (!template) {
    const available = Object.keys(categoryTemplates);
    if (available.length === 0) {
      throw new Error(
        `No templates registered for category "${category}". ` +
        `Register a custom template with registerTemplate().`
      );
    }
    throw new Error(
      `Unknown theme "${selectedTheme}" for category "${category}". ` +
      `Available themes: ${available.join(', ')}`
    );
  }

  return template;
}

/**
 * Register a template for a category + theme.
 * Creates the category if it doesn't exist.
 * Can also override built-in templates.
 */
export function registerTemplate(
  category: string,
  theme: string,
  html: string,
): void {
  if (!registry[category]) {
    registry[category] = {};
  }
  registry[category][theme] = html;
}

/**
 * Register a new custom category with an optional default theme.
 *
 * @example
 * registerCategory('invoice', 'default');
 * registerTemplate('invoice', 'default', '<html>...</html>');
 */
export function registerCategory(category: string, defaultTheme?: string): void {
  if (!registry[category]) {
    registry[category] = {};
  }
  if (defaultTheme) {
    defaultThemes[category] = defaultTheme;
  }
}

/**
 * Set the default theme for a category.
 */
export function setDefaultTheme(category: string, theme: string): void {
  defaultThemes[category] = theme;
}

/**
 * Remove a template from a category.
 */
export function removeTemplate(category: string, theme: string): boolean {
  if (registry[category] && registry[category][theme]) {
    delete registry[category][theme];
    return true;
  }
  return false;
}

/**
 * Remove an entire category and all its templates.
 */
export function removeCategory(category: string): boolean {
  if (registry[category]) {
    delete registry[category];
    delete defaultThemes[category];
    return true;
  }
  return false;
}

/**
 * List available themes for a category.
 */
export function listThemes(category: string): string[] {
  return Object.keys(registry[category] ?? {});
}

/**
 * List all registered categories.
 */
export function listCategories(): string[] {
  return Object.keys(registry);
}

// ─── Named Template API (standalone templates, not tied to category/theme) ───

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
export function registerNamedTemplate(name: string, definition: TemplateDefinition): void {
  namedTemplates[name] = definition;
}

/**
 * Get a named template definition.
 */
export function getNamedTemplate(name: string): TemplateDefinition {
  const def = namedTemplates[name];
  if (!def) {
    throw new Error(
      `Named template "${name}" not found. Register it with registerNamedTemplate().`
    );
  }
  return def;
}

/**
 * Remove a named template.
 */
export function removeNamedTemplate(name: string): boolean {
  if (namedTemplates[name]) {
    delete namedTemplates[name];
    return true;
  }
  return false;
}

/**
 * List all registered named templates.
 */
export function listNamedTemplates(): string[] {
  return Object.keys(namedTemplates);
}

/**
 * Check if a named template exists.
 */
export function hasNamedTemplate(name: string): boolean {
  return name in namedTemplates;
}
