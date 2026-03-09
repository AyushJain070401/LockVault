import { describe, it, expect, beforeEach } from 'vitest';
import { renderTemplate, htmlToText } from '../../../src/email/engine';
import {
  getTemplate,
  registerTemplate,
  registerCategory,
  setDefaultTheme,
  removeTemplate,
  removeCategory,
  listThemes,
  listCategories,
  registerNamedTemplate,
  getNamedTemplate,
  removeNamedTemplate,
  listNamedTemplates,
  hasNamedTemplate,
} from '../../../src/email/templates/index';

// ═════════════════════════════════════════════════════════════════════════════
//  Template Engine
// ═════════════════════════════════════════════════════════════════════════════

describe('Template Engine', () => {
  it('should interpolate simple variables', () => {
    const result = renderTemplate('Hello {{name}}!', { name: 'Ayush' });
    expect(result).toBe('Hello Ayush!');
  });

  it('should escape HTML in {{variable}} interpolation', () => {
    const result = renderTemplate('Hello {{name}}!', { name: '<script>alert("xss")</script>' });
    expect(result).toContain('&lt;script&gt;');
    expect(result).not.toContain('<script>');
  });

  it('should handle raw {{{variable}}} without escaping', () => {
    const result = renderTemplate('{{{raw}}}', { raw: '<b>Bold</b>' });
    expect(result).toBe('<b>Bold</b>');
  });

  it('should replace missing variables with empty string', () => {
    const result = renderTemplate('Hello {{missing}}!', {});
    expect(result).toBe('Hello !');
  });

  // ─── Dot-Notation ───────────────────────────────────────────────────────

  it('should resolve dot-notation paths', () => {
    const result = renderTemplate('Hi {{user.name}}', { user: { name: 'Ayush' } });
    expect(result).toBe('Hi Ayush');
  });

  it('should resolve deeply nested paths', () => {
    const result = renderTemplate('{{a.b.c}}', { a: { b: { c: 'deep' } } });
    expect(result).toBe('deep');
  });

  it('should return empty for missing nested path', () => {
    const result = renderTemplate('{{a.b.c}}', { a: {} });
    expect(result).toBe('');
  });

  // ─── Conditionals ──────────────────────────────────────────────────────

  it('should handle {{#if}} — truthy', () => {
    expect(renderTemplate('{{#if show}}Visible{{/if}}', { show: true })).toBe('Visible');
  });

  it('should handle {{#if}} — falsy', () => {
    expect(renderTemplate('{{#if show}}Visible{{/if}}', { show: false })).toBe('');
  });

  it('should handle {{#if}} — missing variable', () => {
    expect(renderTemplate('{{#if missing}}Visible{{/if}}', {})).toBe('');
  });

  it('should handle {{#if}} with dot-notation', () => {
    expect(renderTemplate('{{#if user.active}}Yes{{/if}}', { user: { active: true } })).toBe('Yes');
  });

  it('should handle {{#unless}} conditionals', () => {
    expect(renderTemplate('{{#unless show}}Fallback{{/unless}}', { show: false })).toBe('Fallback');
    expect(renderTemplate('{{#unless show}}Fallback{{/unless}}', { show: true })).toBe('');
  });

  // ─── Loops ─────────────────────────────────────────────────────────────

  it('should iterate over arrays with {{#each}}', () => {
    const template = '{{#each items}}<li>{{name}}</li>{{/each}}';
    const result = renderTemplate(template, {
      items: [{ name: 'One' }, { name: 'Two' }, { name: 'Three' }],
    });
    expect(result).toBe('<li>One</li><li>Two</li><li>Three</li>');
  });

  it('should provide @index, @first, @last in loops', () => {
    const template = '{{#each items}}{{@index}}{{#if @first}}F{{/if}}{{#if @last}}L{{/if}},{{/each}}';
    const result = renderTemplate(template, { items: ['a', 'b', 'c'] });
    expect(result).toBe('0F,1,2L,');
  });

  it('should handle empty arrays gracefully', () => {
    const result = renderTemplate('{{#each items}}<li>{{this}}</li>{{/each}}', { items: [] });
    expect(result).toBe('');
  });

  it('should handle non-array in {{#each}} gracefully', () => {
    const result = renderTemplate('{{#each missing}}<li>{{this}}</li>{{/each}}', {});
    expect(result).toBe('');
  });

  // ─── Combined ──────────────────────────────────────────────────────────

  it('should support conditionals inside loops', () => {
    const template = '{{#each users}}{{#if active}}✓{{/if}}{{name}};{{/each}}';
    const result = renderTemplate(template, {
      users: [
        { name: 'Ayush', active: true },
        { name: 'Bob', active: false },
        { name: 'Carol', active: true },
      ],
    });
    expect(result).toBe('✓Ayush;Bob;✓Carol;');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//  htmlToText
// ═════════════════════════════════════════════════════════════════════════════

describe('htmlToText', () => {
  it('should strip HTML tags', () => {
    const result = htmlToText('<p>Hello <b>world</b></p>');
    expect(result).toContain('Hello');
    expect(result).toContain('world');
    expect(result).not.toContain('<b>');
  });

  it('should convert <br> to newlines', () => {
    expect(htmlToText('Line 1<br>Line 2')).toContain('Line 1\nLine 2');
  });

  it('should preserve link URLs in text conversion', () => {
    const result = htmlToText('<a href="https://example.com">Click here</a>');
    expect(result).toContain('Click here');
    expect(result).toContain('https://example.com');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//  Category + Theme Registry
// ═════════════════════════════════════════════════════════════════════════════

describe('Template Registry — Category + Theme', () => {
  it('should list all built-in categories', () => {
    const cats = listCategories();
    expect(cats).toContain('login');
    expect(cats).toContain('forgot-password');
    expect(cats).toContain('alert');
    expect(cats).toContain('welcome');
    expect(cats).toContain('verification');
  });

  it('should list themes for built-in login category', () => {
    const themes = listThemes('login');
    expect(themes).toContain('minimal');
    expect(themes).toContain('corporate');
    expect(themes).toContain('vibrant');
  });

  it('should list themes for built-in forgot-password category', () => {
    const themes = listThemes('forgot-password');
    expect(themes).toContain('clean');
    expect(themes).toContain('secure');
    expect(themes).toContain('friendly');
  });

  it('should list themes for built-in alert category', () => {
    const themes = listThemes('alert');
    expect(themes).toContain('standard');
    expect(themes).toContain('urgent');
    expect(themes).toContain('subtle');
  });

  it('should get a login template', () => {
    const html = getTemplate('login', 'minimal');
    expect(html).toContain('{{appName}}');
    expect(html).toContain('{{loginTime}}');
  });

  it('should get a forgot-password template', () => {
    const html = getTemplate('forgot-password', 'friendly');
    expect(html).toContain('{{resetUrl}}');
  });

  it('should get an alert template', () => {
    const html = getTemplate('alert', 'urgent');
    expect(html).toContain('{{alertTitle}}');
  });

  it('should throw on unknown theme', () => {
    expect(() => getTemplate('login', 'nonexistent')).toThrow('Unknown theme');
  });

  it('should throw on unknown category', () => {
    expect(() => getTemplate('totally-fake' as any, 'default')).toThrow('Unknown email template category');
  });

  // ─── Custom Category Registration ─────────────────────────────────────

  it('should register a completely new custom category', () => {
    registerCategory('invoice', 'default');
    registerTemplate('invoice', 'default', '<p>Invoice #{{id}}</p>');

    const cats = listCategories();
    expect(cats).toContain('invoice');

    const html = getTemplate('invoice', 'default');
    expect(html).toBe('<p>Invoice #{{id}}</p>');
  });

  it('should allow multiple themes in a custom category', () => {
    registerTemplate('invoice', 'detailed', '<p>Detailed invoice #{{id}}</p>');
    const themes = listThemes('invoice');
    expect(themes).toContain('default');
    expect(themes).toContain('detailed');
  });

  it('should override a built-in template', () => {
    const original = getTemplate('login', 'minimal');
    registerTemplate('login', 'minimal', '<p>Custom login</p>');
    expect(getTemplate('login', 'minimal')).toBe('<p>Custom login</p>');
    // Restore it
    registerTemplate('login', 'minimal', original);
  });

  it('should set a default theme for a category', () => {
    registerCategory('receipt');
    registerTemplate('receipt', 'simple', '<p>Receipt</p>');
    setDefaultTheme('receipt', 'simple');
    // getTemplate without specifying a theme should use the default
    const html = getTemplate('receipt');
    expect(html).toBe('<p>Receipt</p>');
  });

  it('should remove a template from a category', () => {
    registerTemplate('receipt', 'temp', '<p>Temp</p>');
    expect(listThemes('receipt')).toContain('temp');
    const removed = removeTemplate('receipt', 'temp');
    expect(removed).toBe(true);
    expect(listThemes('receipt')).not.toContain('temp');
  });

  it('should remove an entire category', () => {
    registerCategory('disposable');
    registerTemplate('disposable', 'a', '<p>A</p>');
    expect(listCategories()).toContain('disposable');
    removeCategory('disposable');
    expect(listCategories()).not.toContain('disposable');
  });

  it('should render a built-in template with variables', () => {
    const html = getTemplate('login', 'corporate');
    const rendered = renderTemplate(html, {
      appName: 'TestApp',
      userName: 'Ayush',
      loginTime: '2025-06-15 09:30:00',
      ipAddress: '10.0.0.1',
    });
    expect(rendered).toContain('TestApp');
    expect(rendered).toContain('Ayush');
    expect(rendered).toContain('10.0.0.1');
    expect(rendered).not.toContain('{{appName}}');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//  Named Template Registry
// ═════════════════════════════════════════════════════════════════════════════

describe('Template Registry — Named Templates', () => {
  beforeEach(() => {
    // Clean up any test templates
    if (hasNamedTemplate('test-inline')) removeNamedTemplate('test-inline');
    if (hasNamedTemplate('test-render')) removeNamedTemplate('test-render');
  });

  it('should register and retrieve an inline named template', () => {
    registerNamedTemplate('test-inline', {
      source: { type: 'html', content: '<p>Hello {{name}}</p>' },
      defaultSubject: 'Hi {{name}}',
    });

    expect(hasNamedTemplate('test-inline')).toBe(true);
    const def = getNamedTemplate('test-inline');
    expect(def.source).toEqual({ type: 'html', content: '<p>Hello {{name}}</p>' });
    expect(def.defaultSubject).toBe('Hi {{name}}');
  });

  it('should register a render-function template', () => {
    const customFn = (vars: Record<string, unknown>) => `<p>Hi ${vars.name}</p>`;
    registerNamedTemplate('test-render', {
      source: { type: 'render', fn: customFn },
    });

    const def = getNamedTemplate('test-render');
    expect(def.source.type).toBe('render');
  });

  it('should register a file-based template definition', () => {
    registerNamedTemplate('test-file', {
      source: { type: 'file', path: '/templates/welcome.html' },
      defaultSubject: 'Welcome!',
    });

    const def = getNamedTemplate('test-file');
    expect(def.source).toEqual({ type: 'file', path: '/templates/welcome.html' });
    removeNamedTemplate('test-file');
  });

  it('should throw on unknown named template', () => {
    expect(() => getNamedTemplate('nonexistent')).toThrow('not found');
  });

  it('should list registered named templates', () => {
    registerNamedTemplate('test-inline', {
      source: { type: 'html', content: '<p>test</p>' },
    });
    expect(listNamedTemplates()).toContain('test-inline');
  });

  it('should remove a named template', () => {
    registerNamedTemplate('test-inline', {
      source: { type: 'html', content: '<p>test</p>' },
    });
    expect(removeNamedTemplate('test-inline')).toBe(true);
    expect(hasNamedTemplate('test-inline')).toBe(false);
  });

  it('should return false when removing nonexistent named template', () => {
    expect(removeNamedTemplate('nope')).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//  createEmailManager (unit tests — no actual SMTP, just logic)
// ═════════════════════════════════════════════════════════════════════════════

describe('createEmailManager — renderInline', () => {
  // We import createEmailManager but only test non-SMTP methods
  // (send methods would fail without nodemailer and an SMTP server)
  let createEmailManager: any;

  beforeEach(async () => {
    const mod = await import('../../../src/email/index');
    createEmailManager = mod.createEmailManager;
  });

  it('should render inline templates with defaults merged', () => {
    const mailer = new createEmailManager({
      smtp: { host: 'localhost', port: 587, auth: { user: '', pass: '' }, from: 'test@test.com' },
      defaults: { appName: 'TestApp', supportUrl: 'https://support.test.com' },
    });

    const result = mailer.renderInline(
      '<p>Welcome to {{appName}}, {{userName}}! Support: {{supportUrl}}</p>',
      { userName: 'Ayush' },
    );

    expect(result).toContain('TestApp');
    expect(result).toContain('Ayush');
    expect(result).toContain('https://support.test.com');
  });

  it('should allow user variables to override defaults', () => {
    const mailer = new createEmailManager({
      smtp: { host: 'localhost', port: 587, auth: { user: '', pass: '' }, from: 'test@test.com' },
      defaults: { appName: 'DefaultApp' },
    });

    const result = mailer.renderInline('{{appName}}', { appName: 'OverriddenApp' });
    expect(result).toBe('OverriddenApp');
  });

  it('should preview a category+theme template', () => {
    const mailer = new createEmailManager({
      smtp: { host: 'localhost', port: 587, auth: { user: '', pass: '' }, from: 'test@test.com' },
      defaults: { appName: 'PreviewApp' },
    });

    const html = mailer.preview('login', 'vibrant', {
      userName: 'Ayush',
      loginTime: '2025-01-01',
    });

    expect(html).toContain('PreviewApp');
    expect(html).toContain('Ayush');
    expect(html).not.toContain('{{appName}}');
  });

  it('should expose category and theme management methods', () => {
    const mailer = new createEmailManager({
      smtp: { host: 'localhost', port: 587, auth: { user: '', pass: '' }, from: 'test@test.com' },
    });

    mailer.registerCategory('custom-flow', 'v1');
    mailer.registerTemplate('custom-flow', 'v1', '<p>Version 1</p>');
    mailer.registerTemplate('custom-flow', 'v2', '<p>Version 2</p>');

    expect(mailer.listCategories()).toContain('custom-flow');
    expect(mailer.listThemes('custom-flow')).toEqual(['v1', 'v2']);

    mailer.removeTemplate('custom-flow', 'v2');
    expect(mailer.listThemes('custom-flow')).toEqual(['v1']);

    mailer.removeCategory('custom-flow');
    expect(mailer.listCategories()).not.toContain('custom-flow');
  });

  it('should expose named template management methods', () => {
    const mailer = new createEmailManager({
      smtp: { host: 'localhost', port: 587, auth: { user: '', pass: '' }, from: 'test@test.com' },
    });

    mailer.registerNamedTemplate('my-email', {
      source: { type: 'html', content: '<p>{{msg}}</p>' },
      defaultSubject: 'Subject: {{msg}}',
    });

    expect(mailer.hasNamedTemplate('my-email')).toBe(true);
    expect(mailer.listNamedTemplates()).toContain('my-email');

    mailer.removeNamedTemplate('my-email');
    expect(mailer.hasNamedTemplate('my-email')).toBe(false);
  });
});
