import { describe, expect, it } from 'vitest';
import { scanSource } from '../src/integrations/code-scan.js';

describe('scanSource', () => {
  it('blanks block comments in code while preserving file length', () => {
    const source = `before /* hidden eval() */ after`;
    const { code } = scanSource(source);
    expect(code.length).toBe(source.length);
    expect(code).toBe('before                     after');
    expect(/\beval\s*\(/.test(code)).toBe(false);
  });

  it('blanks line comments in code', () => {
    const source = `keep // drop eval() this\nresume`;
    const { code } = scanSource(source);
    expect(/\beval\s*\(/.test(code)).toBe(false);
    expect(code.includes('keep')).toBe(true);
    expect(code.includes('resume')).toBe(true);
  });

  it('moves single- and double-quoted string contents into `strings`', () => {
    const { code, strings } = scanSource(`const x = 'hello'; const y = "world";`);
    expect(/\bhello\b/.test(code)).toBe(false);
    expect(/\bworld\b/.test(code)).toBe(false);
    expect(strings).toContain('hello');
    expect(strings).toContain('world');
  });

  it('moves template-literal content into `strings`', () => {
    const { code, strings } = scanSource('const x = `template content here`;');
    expect(code.includes('template')).toBe(false);
    expect(strings).toContain('template content here');
  });

  it('handles escapes without prematurely terminating the string', () => {
    const source = String.raw`const a = 'it\'s safe'; const b = "esc\"ape";`;
    const { code, strings } = scanSource(source);
    // The post-escape content is part of the string, not code.
    expect(/\bsafe\b/.test(code)).toBe(false);
    expect(/\bape\b/.test(code)).toBe(false);
    expect(strings).toContain('safe');
    expect(strings).toContain('ape');
  });

  it('keeps eval() in code when it lives outside strings or comments', () => {
    const source = `function go() { eval("payload"); }`;
    const { code, strings } = scanSource(source);
    expect(/\beval\s*\(/.test(code)).toBe(true);
    expect(strings).toContain('payload');
  });

  it('reports the longest line — the minified-bundle signal', () => {
    const longLine = 'x'.repeat(15000);
    const { longestLineLength } = scanSource(`short\n${longLine}\nshort again`);
    expect(longestLineLength).toBe(15000);
  });

  it('survives unterminated strings and comments without throwing', () => {
    expect(() => scanSource(`const x = 'never closed`)).not.toThrow();
    expect(() => scanSource(`/* never closed`)).not.toThrow();
  });
});
