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

/** Maximum recursion depth to prevent stack overflow from crafted templates */
const MAX_RENDER_DEPTH = 16;

/** Maximum array length for {{#each}} to prevent CPU exhaustion */
const MAX_EACH_ITEMS = 1000;

/** Keys that must never be copied from untrusted objects */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Resolve a dot-notation path from a variables object.
 * e.g. resolve('user.name', { user: { name: 'Ayush' } }) → 'Ayush'
 */
function resolve(path: string, variables: Record<string, unknown>): unknown {
  // Block prototype access via dot notation
  const parts = path.split('.');
  if (parts.some(p => DANGEROUS_KEYS.has(p))) return undefined;

  let current: unknown = variables;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function renderTemplate(template: string, variables: Record<string, unknown>, depth: number = 0): string {
  // Guard against infinite/deep recursion from crafted templates
  if (depth > MAX_RENDER_DEPTH) {
    return '[template recursion limit exceeded]';
  }

  let result = template;

  // Process {{#each items}}...{{/each}} loops
  result = result.replace(
    /\{\{#each\s+([\w.]+)\}\}([\s\S]*?)\{\{\/each\}\}/g,
    (_match, varPath: string, body: string) => {
      const arr = resolve(varPath, variables);
      if (!Array.isArray(arr)) return '';

      // Cap iteration count to prevent CPU exhaustion
      const items = arr.length > MAX_EACH_ITEMS ? arr.slice(0, MAX_EACH_ITEMS) : arr;

      return items
        .map((item, index) => {
          // Inside the loop, inject item properties + @index
          const loopVars: Record<string, unknown> = {
            ...variables,
            '@index': index,
            '@first': index === 0,
            '@last': index === items.length - 1,
          };
          if (typeof item === 'object' && item !== null) {
            // Filter out dangerous keys to prevent prototype pollution
            for (const [key, value] of Object.entries(item as Record<string, unknown>)) {
              if (!DANGEROUS_KEYS.has(key)) {
                loopVars[key] = value;
              }
            }
          } else {
            loopVars['this'] = item;
          }
          return renderTemplate(body, loopVars, depth + 1);
        })
        .join('');
    },
  );

  // Process {{#if variable}}...{{/if}} blocks
  result = result.replace(
    /\{\{#if\s+([\w.@]+)\}\}([\s\S]*?)\{\{\/if\}\}/g,
    (_match, varPath: string, content: string) => {
      const value = resolve(varPath, variables);
      if (value !== undefined && value !== null && value !== '' && value !== false) {
        return renderTemplate(content, variables, depth + 1);
      }
      return '';
    },
  );

  // Process {{#unless variable}}...{{/unless}} blocks
  result = result.replace(
    /\{\{#unless\s+([\w.@]+)\}\}([\s\S]*?)\{\{\/unless\}\}/g,
    (_match, varPath: string, content: string) => {
      const value = resolve(varPath, variables);
      if (!value) {
        return renderTemplate(content, variables, depth + 1);
      }
      return '';
    },
  );

  // Process {{{variable}}} raw interpolation (no escaping) — must come before {{variable}}
  result = result.replace(/\{\{\{([\w.@]+)\}\}\}/g, (_match, varPath: string) => {
    const value = resolve(varPath, variables);
    if (value === undefined || value === null) return '';
    return String(value);
  });

  // Process {{variable}} escaped interpolation
  result = result.replace(/\{\{([\w.@]+)\}\}/g, (_match, varPath: string) => {
    const value = resolve(varPath, variables);
    if (value === undefined || value === null) return '';
    return escapeHtml(String(value));
  });

  return result;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Strip HTML tags to produce a plain-text version of the email.
 */
export function htmlToText(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<\/td>/gi, ' ')
    .replace(/<a\s[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '$2 ($1)')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
