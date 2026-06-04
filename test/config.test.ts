import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config/load.js';
import { parseConfig } from '../src/config/schema.js';
import { ConfigError } from '../src/util/errors.js';

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'jadguard-cfg-'));
}

describe('parseConfig', () => {
  it('applies defaults for an empty config', () => {
    const config = parseConfig({}, 'test');
    expect(config.mode).toBe('enforce');
    expect(config.failOn).toBe('high');
    expect(config.cooldownDays).toBe(7);
    expect(config.cooldown.exclude).toEqual([]);
    expect(config.blocklist.online).toBe(false);
    expect(config.registry).toBe('https://registry.npmjs.org');
  });

  it('parses blocklist.online', () => {
    expect(parseConfig({ blocklist: { online: true } }, 'test').blocklist.online).toBe(true);
  });

  it('rejects a non-boolean blocklist.online', () => {
    expect(() => parseConfig({ blocklist: { online: 'yes' } }, 'test')).toThrow(/blocklist\.online/);
  });

  it('parses a complete config', () => {
    const config = parseConfig(
      {
        mode: 'warn',
        failOn: 'critical',
        onDegraded: 'warn',
        cooldownDays: 30,
        registry: 'https://npm.example.com/',
        rules: { cooldown: { enabled: false }, integrity: { severity: 'high' } },
        ignores: [{ rule: 'cooldown', package: 'lodash', reason: 'pinned deliberately' }],
      },
      'test',
    );
    expect(config.mode).toBe('warn');
    expect(config.failOn).toBe('critical');
    expect(config.cooldownDays).toBe(30);
    expect(config.registry).toBe('https://npm.example.com'); // trailing slash trimmed
    expect(config.rules.cooldown?.enabled).toBe(false);
    expect(config.rules.integrity?.severity).toBe('high');
    expect(config.ignores).toHaveLength(1);
  });

  it('parses cooldown.days and cooldown.exclude', () => {
    const config = parseConfig(
      { cooldown: { days: 3, exclude: ['@myscope/*', 'internal-*'] } },
      'test',
    );
    expect(config.cooldownDays).toBe(3);
    expect(config.cooldown.exclude).toEqual(['@myscope/*', 'internal-*']);
  });

  it('lets cooldown.days override the legacy cooldownDays', () => {
    const config = parseConfig({ cooldownDays: 14, cooldown: { days: 5 } }, 'test');
    expect(config.cooldownDays).toBe(5);
  });

  it('rejects a non-array cooldown.exclude', () => {
    expect(() => parseConfig({ cooldown: { exclude: 'nope' } }, 'test')).toThrow(
      /cooldown\.exclude/,
    );
  });

  it('rejects a negative cooldown.days', () => {
    expect(() => parseConfig({ cooldown: { days: -1 } }, 'test')).toThrow(/cooldown\.days/);
  });

  it('rejects an invalid mode', () => {
    expect(() => parseConfig({ mode: 'strict' }, 'test')).toThrow(ConfigError);
  });

  it('rejects an invalid severity', () => {
    expect(() => parseConfig({ failOn: 'extreme' }, 'test')).toThrow(/failOn/);
  });

  it('rejects a negative cooldown', () => {
    expect(() => parseConfig({ cooldownDays: -1 }, 'test')).toThrow(/cooldownDays/);
  });

  it('rejects an ignore entry without a rule', () => {
    expect(() => parseConfig({ ignores: [{ package: 'lodash' }] }, 'test')).toThrow(/rule/);
  });

  it('rejects a non-ISO ignore expiry', () => {
    expect(() =>
      parseConfig({ ignores: [{ rule: 'cooldown', expires: 'soon' }] }, 'test'),
    ).toThrow(/expires/);
  });
});

describe('loadConfig', () => {
  it('returns defaults when no config file exists', async () => {
    const dir = await tmp();
    const loaded = await loadConfig({ dir });
    expect(loaded.source).toBeNull();
    expect(loaded.config.mode).toBe('enforce');
  });

  it('loads jadguard.config.json from the project root', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'jadguard.config.json'), JSON.stringify({ mode: 'warn' }));
    const loaded = await loadConfig({ dir });
    expect(loaded.source).toContain('jadguard.config.json');
    expect(loaded.config.mode).toBe('warn');
  });

  it('tolerates a UTF-8 BOM (Windows-saved config files)', async () => {
    const dir = await tmp();
    const bom = String.fromCharCode(0xfeff);
    await writeFile(
      join(dir, 'jadguard.config.json'),
      bom + JSON.stringify({ mode: 'warn' }),
    );
    const loaded = await loadConfig({ dir });
    expect(loaded.config.mode).toBe('warn');
  });

  it('throws on invalid JSON', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'jadguard.config.json'), '{ not json');
    await expect(loadConfig({ dir })).rejects.toThrow(ConfigError);
  });

  it('throws when an explicit config path is missing', async () => {
    const dir = await tmp();
    await expect(loadConfig({ dir, explicitPath: 'nope.json' })).rejects.toThrow(ConfigError);
  });
});
