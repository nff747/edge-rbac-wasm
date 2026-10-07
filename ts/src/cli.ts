import * as fs from 'fs';
import { PolicySchemaParser } from './policy_loader';

export function runCLI(argv: string[]): number {
  const args = argv.slice(2);
  const command = args[0] || 'help';

  switch (command) {
    case 'validate': {
      const file = args[1];
      if (!file || !fs.existsSync(file)) {
        console.error('File not found:', file);
        return 1;
      }
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const policy = PolicySchemaParser.parse(content);
        console.log(`Policy valid: ${policy.rules.length} rules loaded.`);
        return 0;
      } catch (err: any) {
        console.error('Validation error:', err.message);
        return 1;
      }
    }
    case 'help':
    default:
      console.log(`
Edge RBAC Engine CLI 🛡️
Usage:
  npx edge-rbac validate <policy.json>
      `);
      return 0;
  }
}
