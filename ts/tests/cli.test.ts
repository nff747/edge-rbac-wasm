import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { runCLI } from '../src/cli';

describe('Edge RBAC CLI', () => {
  const tempFile = path.join(__dirname, 'temp_policy.json');

  it('validates valid policy file from CLI argument', () => {
    fs.writeFileSync(tempFile, JSON.stringify({
      version: '1.0',
      rules: [{ role: 'admin', resource: '*', permissions: ['admin'], effect: 'allow' }]
    }));

    const code = runCLI(['node', 'cli.js', 'validate', tempFile]);
    expect(code).toBe(0);

    fs.unlinkSync(tempFile);
  });

  it('returns non-zero exit code for invalid policy', () => {
    const code = runCLI(['node', 'cli.js', 'validate', 'non_existent.json']);
    expect(code).toBe(1);
  });
});
