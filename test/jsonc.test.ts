import { describe, expect, it } from 'vitest';
import { parseJsonc } from '../src/util/jsonc.js';

describe('parseJsonc', () => {
  it('parses plain JSON', () => {
    expect(parseJsonc('{"a":1,"b":[2,3]}')).toEqual({ a: 1, b: [2, 3] });
  });

  it('tolerates trailing commas in objects and arrays', () => {
    expect(parseJsonc('{"a":1,"b":[2,3,],}')).toEqual({ a: 1, b: [2, 3] });
  });

  it('strips line and block comments', () => {
    const text = '{\n  // a line comment\n  "a": 1, /* inline */ "b": 2\n}';
    expect(parseJsonc(text)).toEqual({ a: 1, b: 2 });
  });

  it('leaves comment- and comma-like content inside strings untouched', () => {
    const text = '{"url":"https://example.com","trick":",]"}';
    expect(parseJsonc(text)).toEqual({ url: 'https://example.com', trick: ',]' });
  });

  it('throws on genuinely invalid input', () => {
    expect(() => parseJsonc('{ not json')).toThrow();
  });
});
